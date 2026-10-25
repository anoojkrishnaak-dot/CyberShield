"""
detector.py
-----------
Rule-based detection of suspicious login behaviour.

IMPORTANT: every rule here is a HEURISTIC. A rule firing means "this pattern
deserves a human look". It does not prove an attack or malicious intent.
A forgotten password, a shared office network or a monitoring script can
produce the same patterns.

This file has no Streamlit or database code, so each rule can be tested alone.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass

import numpy as np
import pandas as pd

# ----------------------------------------------------------------------
# Names and constants
# ----------------------------------------------------------------------
RULE_REPEATED_FAILURES = "Repeated failed logins"
RULE_MULTIPLE_USERNAMES = "Multiple usernames from one IP"
RULE_SUCCESS_AFTER_FAILURES = "Success after repeated failures"
RULE_HIGH_ACTIVITY = "High login activity"
RULE_MALFORMED_RECORDS = "Malformed records"

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
STATUS_NEW = "New"
STATUS_REVIEWED = "Reviewed"
NOT_APPLICABLE = "N/A"

ALERT_COLUMNS = [
    "alert_id", "detected_at", "source_ip", "rule", "severity",
    "description",  # what the data shows (facts)
    "indicator",    # what it MIGHT mean (suspicion)
    "event_count", "first_seen", "last_seen", "usernames", "status",
]

# Plain-English explanation of each rule. Used by the dashboard and the report.
RULE_DOCS = {
    RULE_REPEATED_FAILURES: {
        "what": "One IP address has at least N failed logins inside a time window "
                "(default: 5 failures within 5 minutes).",
        "severity": "MEDIUM at N failures, HIGH at 2x N, CRITICAL at 4x N.",
    },
    RULE_MULTIPLE_USERNAMES: {
        "what": "One IP address fails to log in as at least N different usernames "
                "inside a time window (default: 5 usernames within 10 minutes).",
        "severity": "MEDIUM at N usernames, HIGH at 2x N.",
    },
    RULE_SUCCESS_AFTER_FAILURES: {
        "what": "A successful login from an IP address that had at least N failed logins "
                "in the minutes before it (default: 5 failures in the previous 10 minutes).",
        "severity": "MEDIUM if a different username succeeded, HIGH if the successful "
                    "username was one of the failed ones, CRITICAL if that is also true "
                    "and there were 2x N or more failures.",
    },
    RULE_HIGH_ACTIVITY: {
        "what": "One IP address makes at least N login attempts of any kind inside a "
                "short window (default: 10 attempts within 1 minute).",
        "severity": "LOW at N attempts, MEDIUM at 2x N, HIGH at 4x N.",
    },
    RULE_MALFORMED_RECORDS: {
        "what": "Some records in the file could not be understood and were rejected "
                "(bad timestamp, invalid IP address, unknown status, ...).",
        "severity": "LOW below 10% of records, MEDIUM from 10%, HIGH from 50%.",
    },
}


# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class DetectionConfig:
    failed_threshold: int = 5              # failures needed (rule 1 and rule 3)
    window_minutes: float = 5.0            # window for rule 1
    user_threshold: int = 5                # different usernames needed (rule 2)
    user_window_minutes: float = 10.0      # window for rule 2
    success_lookback_minutes: float = 10.0 # how far back rule 3 looks
    activity_threshold: int = 10           # attempts needed (rule 4)
    activity_window_minutes: float = 1.0   # window for rule 4

    def __post_init__(self) -> None:
        for name in ("failed_threshold", "user_threshold", "activity_threshold"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a whole number of at least 1.")
        for name in ("window_minutes", "user_window_minutes",
                     "success_lookback_minutes", "activity_window_minutes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
                raise ValueError(f"{name} must be a number greater than 0.")


# ----------------------------------------------------------------------
# The core time-window algorithm
# ----------------------------------------------------------------------
def find_clusters(
    seconds: list[float],
    usernames: list[str],
    window_seconds: float,
    min_events: int,
    min_distinct_users: int = 1,
) -> list[tuple[int, int]]:
    """Find bursts of events using a sliding window.

    `seconds` must be sorted. A window holds events whose first and last times
    are at most `window_seconds` apart (the boundary is included).
    A window "qualifies" when it has at least `min_events` events and at least
    `min_distinct_users` different usernames.

    Overlapping qualifying windows are merged, so one burst gives ONE cluster
    and no event is counted twice. Returns (first_index, last_index) pairs.
    Each event is added and removed at most once, so this is O(n).
    """
    clusters: list[tuple[int, int]] = []
    in_window: Counter = Counter()
    start = 0
    current: tuple[int, int] | None = None

    for end in range(len(seconds)):
        in_window[usernames[end]] += 1
        while seconds[end] - seconds[start] > window_seconds:
            in_window[usernames[start]] -= 1
            if in_window[usernames[start]] == 0:
                del in_window[usernames[start]]
            start += 1

        if end - start + 1 >= min_events and len(in_window) >= min_distinct_users:
            if current is not None and start <= current[1]:
                current = (current[0], end)   # overlaps: extend the same burst
            else:
                if current is not None:
                    clusters.append(current)
                current = (start, end)        # a new burst begins
    if current is not None:
        clusters.append(current)
    return clusters


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def _fmt_time(value) -> str:
    return f"{value:%Y-%m-%d %H:%M:%S}"


def _fmt_number(value: float) -> str:
    return f"{value:g}"


def _username_text(names, limit: int = 5) -> str:
    unique = list(dict.fromkeys(names))
    text = ", ".join(unique[:limit])
    if len(unique) > limit:
        text += f" (+{len(unique) - limit} more)"
    return text


def _make_alert(rule, ip, severity, first_seen, last_seen, event_count,
                usernames, description, indicator, now, id_key) -> dict:
    digest = hashlib.sha256(f"{rule}|{ip}|{id_key}".encode("utf-8")).hexdigest()[:10].upper()
    return {
        "alert_id": f"ALR-{digest}",
        "detected_at": now,
        "source_ip": ip,
        "rule": rule,
        "severity": severity,
        "description": description,
        "indicator": indicator,
        "event_count": int(event_count),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "usernames": usernames,
        "status": STATUS_NEW,
    }


# ----------------------------------------------------------------------
# Rule 1: repeated failed logins from one IP
# ----------------------------------------------------------------------
def detect_repeated_failures(failed: pd.DataFrame, config: DetectionConfig, now) -> list[dict]:
    alerts = []
    window = config.window_minutes * 60
    for ip, group in failed.groupby("ip_address", sort=True):
        seconds = group["elapsed_s"].tolist()
        names = group["username"].tolist()
        stamps = group["timestamp"].tolist()
        for lo, hi in find_clusters(seconds, names, window, config.failed_threshold):
            count = hi - lo + 1
            if count >= 4 * config.failed_threshold:
                severity = "CRITICAL"
            elif count >= 2 * config.failed_threshold:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            alerts.append(_make_alert(
                RULE_REPEATED_FAILURES, ip, severity, stamps[lo], stamps[hi], count,
                _username_text(names[lo:hi + 1]),
                f"{count} failed logins from {ip} between {_fmt_time(stamps[lo])} and "
                f"{_fmt_time(stamps[hi])} UTC. Rule: at least {config.failed_threshold} "
                f"failures within {_fmt_number(config.window_minutes)} minutes.",
                "Possible password-guessing (brute-force) attempt. This is a heuristic and "
                "does not prove malicious intent: a forgotten password or a misconfigured "
                "application can look the same.",
                now, id_key=stamps[lo].isoformat(),
            ))
    return alerts


# ----------------------------------------------------------------------
# Rule 2: many different usernames from one IP
# ----------------------------------------------------------------------
def detect_multiple_usernames(failed: pd.DataFrame, config: DetectionConfig, now) -> list[dict]:
    alerts = []
    window = config.user_window_minutes * 60
    for ip, group in failed.groupby("ip_address", sort=True):
        seconds = group["elapsed_s"].tolist()
        names = group["username"].tolist()
        stamps = group["timestamp"].tolist()
        clusters = find_clusters(seconds, names, window,
                                 min_events=config.user_threshold,
                                 min_distinct_users=config.user_threshold)
        for lo, hi in clusters:
            distinct = len(set(names[lo:hi + 1]))
            severity = "HIGH" if distinct >= 2 * config.user_threshold else "MEDIUM"
            alerts.append(_make_alert(
                RULE_MULTIPLE_USERNAMES, ip, severity, stamps[lo], stamps[hi], hi - lo + 1,
                _username_text(names[lo:hi + 1]),
                f"{ip} failed to log in as {distinct} different usernames between "
                f"{_fmt_time(stamps[lo])} and {_fmt_time(stamps[hi])} UTC. Rule: at least "
                f"{config.user_threshold} usernames within "
                f"{_fmt_number(config.user_window_minutes)} minutes.",
                "Possible password-spraying or credential-stuffing attempt. This is a "
                "heuristic: a shared network address used by many people can look similar.",
                now, id_key=stamps[lo].isoformat(),
            ))
    return alerts


# ----------------------------------------------------------------------
# Rule 3: a successful login shortly after repeated failures
# ----------------------------------------------------------------------
def detect_success_after_failures(frame: pd.DataFrame, config: DetectionConfig, now) -> list[dict]:
    alerts = []
    lookback = config.success_lookback_minutes * 60
    for ip, group in frame.groupby("ip_address", sort=True):
        failures = group[group["status"] == "Failed"]
        successes = group[group["status"] == "Success"]
        if failures.empty or successes.empty:
            continue
        fail_seconds = failures["elapsed_s"].to_numpy()
        last_reported_end = None  # avoids one alert per success after the same failures

        for success in successes.itertuples():
            hi = int(np.searchsorted(fail_seconds, success.elapsed_s, side="right"))
            lo = int(np.searchsorted(fail_seconds, success.elapsed_s - lookback, side="left"))
            count = hi - lo
            if count < config.failed_threshold or hi == last_reported_end:
                continue
            last_reported_end = hi

            recent = failures.iloc[lo:hi]
            failed_users = recent["username"].tolist()
            same_user = success.username in failed_users
            if same_user and count >= 2 * config.failed_threshold:
                severity = "CRITICAL"
            elif same_user:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            who = ("The successful username was one of the usernames that had just failed."
                   if same_user else
                   "The successful username was different from the usernames that failed.")
            alerts.append(_make_alert(
                RULE_SUCCESS_AFTER_FAILURES, ip, severity,
                recent["timestamp"].iloc[0], success.timestamp, count + 1,
                _username_text(failed_users + [success.username]),
                f"{count} failed logins from {ip} were followed by a successful login as "
                f"'{success.username}' at {_fmt_time(success.timestamp)} UTC. {who} "
                f"Rule: at least {config.failed_threshold} failures in the previous "
                f"{_fmt_number(config.success_lookback_minutes)} minutes.",
                "Possible account compromise, or a real user who finally typed the right "
                "password. Confirm with the account owner before drawing conclusions.",
                now, id_key=recent["timestamp"].iloc[0].isoformat(),
            ))
    return alerts


# ----------------------------------------------------------------------
# Rule 4: unusually high activity from one IP
# ----------------------------------------------------------------------
def detect_high_activity(frame: pd.DataFrame, config: DetectionConfig, now) -> list[dict]:
    alerts = []
    window = config.activity_window_minutes * 60
    for ip, group in frame.groupby("ip_address", sort=True):
        seconds = group["elapsed_s"].tolist()
        names = group["username"].tolist()
        stamps = group["timestamp"].tolist()
        for lo, hi in find_clusters(seconds, names, window, config.activity_threshold):
            count = hi - lo + 1
            if count >= 4 * config.activity_threshold:
                severity = "HIGH"
            elif count >= 2 * config.activity_threshold:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            alerts.append(_make_alert(
                RULE_HIGH_ACTIVITY, ip, severity, stamps[lo], stamps[hi], count,
                _username_text(names[lo:hi + 1]),
                f"{count} login attempts (any result) from {ip} between {_fmt_time(stamps[lo])} "
                f"and {_fmt_time(stamps[hi])} UTC. Rule: at least {config.activity_threshold} "
                f"attempts within {_fmt_number(config.activity_window_minutes)} minute(s).",
                "Unusually fast activity. It can be automation (scripts, monitoring, shared "
                "office network) as well as an attack, so check what the address belongs to.",
                now, id_key=stamps[lo].isoformat(),
            ))
    return alerts


# ----------------------------------------------------------------------
# Rule 5: malformed records
# ----------------------------------------------------------------------
def detect_malformed_records(rejected: pd.DataFrame, total_rows: int, now) -> list[dict]:
    count = len(rejected)
    share = count / total_rows if total_rows else 1.0
    if share >= 0.5:
        severity = "HIGH"
    elif share >= 0.1:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    return [_make_alert(
        RULE_MALFORMED_RECORDS, NOT_APPLICABLE, severity, pd.NaT, pd.NaT, count, "",
        f"{count} of {total_rows} records ({share:.0%}) could not be validated and were "
        f"rejected (see the rejected-records table).",
        "Malformed records can come from logging bugs, a wrong export format, or someone "
        "tampering with the data. They are excluded from all other detections.",
        now, id_key=f"count={count}",
    )]


# ----------------------------------------------------------------------
# Run everything
# ----------------------------------------------------------------------
def _alerts_to_frame(rows: list[dict]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    alerts = pd.DataFrame(rows, columns=ALERT_COLUMNS)
    alerts["_rank"] = alerts["severity"].map(SEVERITY_ORDER)
    alerts = alerts.sort_values(["_rank", "first_seen"], ascending=[False, True],
                                na_position="last", kind="stable")
    return alerts.drop(columns="_rank").reset_index(drop=True)


def detect_all(events, rejected=None, total_rows=None, config=None, now=None) -> pd.DataFrame:
    """Run all five rules and return one table of alerts.

    events   : valid events from data_processor (sorted or not)
    rejected : rejected rows from data_processor (for the malformed-records rule)
    now      : the "detection time". Pass a fixed value in tests.
    """
    config = config or DetectionConfig()
    if now is None:
        now = pd.Timestamp.now("UTC").tz_localize(None).floor("s")
    now = pd.Timestamp(now)

    rows: list[dict] = []
    event_count = 0 if events is None else len(events)

    if event_count:
        frame = events.sort_values("timestamp", kind="stable").reset_index(drop=True)
        frame = frame.assign(
            elapsed_s=(frame["timestamp"] - frame["timestamp"].min()).dt.total_seconds()
        )
        failed = frame[frame["status"] == "Failed"]
        rows += detect_repeated_failures(failed, config, now)
        rows += detect_multiple_usernames(failed, config, now)
        rows += detect_success_after_failures(frame, config, now)
        rows += detect_high_activity(frame, config, now)

    if rejected is not None and len(rejected):
        total = total_rows if total_rows is not None else event_count + len(rejected)
        rows += detect_malformed_records(rejected, total, now)

    return _alerts_to_frame(rows)


# ----------------------------------------------------------------------
# Helpers used by the dashboard
# ----------------------------------------------------------------------
def alert_metrics(alerts: pd.DataFrame) -> dict:
    """Alert-based numbers for the summary cards."""
    if alerts.empty:
        return {"incidents": 0, "suspicious_ips": 0, "high_severity": 0}
    ips = alerts.loc[alerts["source_ip"] != NOT_APPLICABLE, "source_ip"].nunique()
    is_open = (alerts["status"] != STATUS_REVIEWED) if "status" in alerts.columns else True
    high = alerts["severity"].isin(["HIGH", "CRITICAL"]) & is_open
    return {"incidents": int(len(alerts)), "suspicious_ips": int(ips), "high_severity": int(high.sum())}


def filter_alerts(alerts: pd.DataFrame, severities=None, ip_text: str = "", statuses=None) -> pd.DataFrame:
    """Filter alerts by severity, part of an IP address, and status."""
    result = alerts
    if severities:
        result = result[result["severity"].isin(severities)]
    if ip_text and ip_text.strip():
        result = result[result["source_ip"].str.contains(ip_text.strip(), case=False, regex=False)]
    if statuses:
        result = result[result["status"].isin(statuses)]
    return result.reset_index(drop=True)
