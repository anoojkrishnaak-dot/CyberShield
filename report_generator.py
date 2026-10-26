"""
report_generator.py
-------------------
Builds the downloadable incident report (Markdown) and safe CSV exports.

Wording rule: the report talks about "indicators" and "heuristic alerts".
It never calls an event a confirmed attack, because the rules only spot patterns.
"""
from __future__ import annotations

import html

import pandas as pd

import data_processor as dp
import detector as d

CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
MAX_ALERTS_IN_REPORT = 50

RECOMMENDATIONS = {
    d.RULE_REPEATED_FAILURES: [
        "Check whether the targeted account(s) belong to real users and whether they were locked out.",
        "Find out who owns the source IP address (known user, office network, service, or unknown).",
        "Consider rate limiting, temporary lockouts and multi-factor authentication.",
    ],
    d.RULE_MULTIPLE_USERNAMES: [
        "Look at which usernames were tried. Do they exist? Are they all from one department?",
        "Check whether the IP address is a shared gateway used by many people.",
        "Consider blocking or throttling the address if it is not recognised.",
    ],
    d.RULE_SUCCESS_AFTER_FAILURES: [
        "Contact the account owner and ask whether they really logged in at that time.",
        "If they did not, treat the account as possibly compromised: reset the password and review recent activity.",
        "Check what the account did after the successful login.",
    ],
    d.RULE_HIGH_ACTIVITY: [
        "Check whether the address is a known script, monitoring tool or shared network.",
        "If it is unknown, review what the attempts targeted and consider throttling.",
    ],
    d.RULE_MALFORMED_RECORDS: [
        "Open the rejected-records table and look at the reasons.",
        "Check the logging system or export for bugs. Repeated bad records can also mean tampering.",
    ],
}

GENERAL_RECOMMENDATIONS = [
    "Treat every alert as a lead to investigate, not as proof of an attack.",
    "Record what you checked and the outcome, then mark the alert as reviewed.",
    "Compare with other data sources (firewall, VPN, application logs) before acting.",
    "Tune the thresholds if the same harmless pattern keeps producing alerts.",
]


# ----------------------------------------------------------------------
# CSV export (protected against spreadsheet formula injection)
# ----------------------------------------------------------------------
def _safe_cell(value):
    """A cell starting with = + - @ can run as a formula when opened in Excel.
    A leading apostrophe makes the spreadsheet treat it as plain text."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def to_csv_bytes(frame: pd.DataFrame) -> bytes:
    """Turn a table into CSV bytes, neutralising formula-like text."""
    safe = frame.copy()
    for column in safe.columns:
        if pd.api.types.is_string_dtype(safe[column]) or pd.api.types.is_object_dtype(safe[column]):
            safe[column] = safe[column].map(_safe_cell)
    return safe.to_csv(index=False).encode("utf-8")


# ----------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------
def _md(value) -> str:
    """Make any text safe to put in a Markdown table cell."""
    if value is None or (not isinstance(value, str) and pd.isna(value)):
        return ""
    text = html.escape(str(value), quote=False)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _time(value) -> str:
    return "" if pd.isna(value) else f"{value:%Y-%m-%d %H:%M:%S}"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines


def build_report(events, alerts, rejected, config, dataset_name: str,
                 simulated: bool = False, generated_at=None) -> str:
    """Return the full incident report as Markdown text."""
    stamp = pd.Timestamp(generated_at) if generated_at is not None else \
        pd.Timestamp.now("UTC").tz_localize(None).floor("s")
    summary = dp.summarize_events(events)
    rejected_count = 0 if rejected is None else len(rejected)
    failure_rate = f"{summary['failed'] / summary['total']:.1%}" if summary["total"] else "n/a"
    metrics = d.alert_metrics(alerts)

    lines = [
        "# CyberShield Incident Report",
        "",
        f"**Report generated:** {stamp:%Y-%m-%d %H:%M:%S} UTC",
        "",
        "> **Please read:** the alerts below come from simple heuristic rules. They are "
        "*indicators* that deserve a human look. They do not prove an attack or any "
        "person's intent.",
        "",
        "## 1. Dataset summary",
        "",
        f"- **Dataset:** {_md(dataset_name)}",
        f"- **Data type:** {'Simulated (fictional) data' if simulated else 'User-provided data'}",
        f"- **Valid records analysed:** {summary['total']:,}",
        f"- **Rejected records:** {rejected_count:,}",
        f"- **Time range (UTC):** "
        + (f"{_time(summary['start'])} to {_time(summary['end'])}" if summary["total"] else "no data"),
        f"- **Unique IP addresses:** {summary['unique_ips']:,}",
        f"- **Unique usernames:** {summary['unique_users']:,}",
        "",
        "## 2. Login statistics",
        "",
    ]
    lines += _table(["Measure", "Value"], [
        ["Total login attempts", f"{summary['total']:,}"],
        ["Successful logins", f"{summary['success']:,}"],
        ["Failed logins", f"{summary['failed']:,}"],
        ["Failure rate", failure_rate],
        ["IP addresses with at least one alert", f"{metrics['suspicious_ips']:,}"],
    ])

    lines += ["", "## 3. Detected incidents (heuristic alerts)", ""]
    if alerts.empty:
        lines.append("No alerts were generated for this dataset with the current settings.")
    else:
        lines.append(f"{len(alerts)} alert(s) were generated; {metrics['high_severity']} open alert(s) "
                     f"are HIGH or CRITICAL.")
        lines.append("")
        shown = alerts.head(MAX_ALERTS_IN_REPORT)
        lines += _table(
            ["ID", "Severity", "Rule", "Source IP", "Events", "First seen", "Last seen", "Status"],
            [[_md(r.alert_id), _md(r.severity), _md(r.rule), _md(r.source_ip), str(int(r.event_count)),
              _time(r.first_seen), _time(r.last_seen), _md(r.status)] for r in shown.itertuples()],
        )
        if len(alerts) > len(shown):
            lines.append("")
            lines.append(f"(Only the first {len(shown)} alerts are listed.)")
        serious = alerts[alerts["severity"].isin(["HIGH", "CRITICAL"])].head(10)
        if not serious.empty:
            lines += ["", "### Details for the most serious alerts", ""]
            for r in serious.itertuples():
                lines += [
                    f"**{_md(r.alert_id)} - {_md(r.severity)} - {_md(r.rule)} - {_md(r.source_ip)}**",
                    "",
                    f"- *What the data shows:* {_md(r.description)}",
                    f"- *What it might mean (suspicion, not proof):* {_md(r.indicator)}",
                    "",
                ]

    lines += ["", "## 4. Severity breakdown", ""]
    counts = alerts["severity"].value_counts() if not alerts.empty else pd.Series(dtype=int)
    lines += _table(["Severity", "Alerts"],
                    [[level, str(int(counts.get(level, 0)))] for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")])

    lines += ["", "## 5. Detection rules used", ""]
    for rule, text in d.RULE_DOCS.items():
        lines += [f"**{rule}**", "", f"- What it checks: {text['what']}", f"- Severity: {text['severity']}", ""]
    lines += [
        "Settings used for this report:",
        "",
        f"- Failed logins needed: {config.failed_threshold} within {config.window_minutes:g} minutes",
        f"- Different usernames needed: {config.user_threshold} within {config.user_window_minutes:g} minutes",
        f"- Success-after-failures look-back: {config.success_lookback_minutes:g} minutes",
        f"- High activity: {config.activity_threshold} attempts within {config.activity_window_minutes:g} minute(s)",
    ]

    lines += ["", "## 6. Investigation recommendations", ""]
    fired = [rule for rule in d.RULE_DOCS if not alerts.empty and (alerts["rule"] == rule).any()]
    for rule in fired:
        lines.append(f"**{rule}**")
        lines += [f"- {tip}" for tip in RECOMMENDATIONS[rule]]
        lines.append("")
    lines.append("**In general**")
    lines += [f"- {tip}" for tip in GENERAL_RECOMMENDATIONS]

    lines += [
        "", "## 7. Limitations", "",
        "- Rules are simple heuristics. They produce false positives (harmless activity flagged) "
        "and false negatives (real attacks missed).",
        "- An IP address is an indicator, not proof of who did something.",
        "- This is a learning and demonstration project, not a production security monitoring system.",
        "",
    ]
    return "\n".join(lines)
