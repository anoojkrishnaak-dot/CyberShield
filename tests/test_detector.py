"""Tests for detector.py (the rules are checked one at a time)."""
import pandas as pd

import data_processor as dp
import detector as d

NOW = "2026-10-25 13:00:00"
BASE = pd.Timestamp("2026-10-25 10:00:00")


def make_events(rows):
    """rows: list of (timestamp, username, ip_address, status)."""
    df = pd.DataFrame(rows, columns=["timestamp", "username", "ip_address", "status"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def failures(ip, count, gap_seconds, start=BASE, user="victim", status="Failed"):
    """`count` events from one IP, `gap_seconds` apart."""
    return [(start + pd.Timedelta(seconds=i * gap_seconds), user, ip, status) for i in range(count)]


def run(rows, config=None, rejected=None, total_rows=None):
    return d.detect_all(make_events(rows), rejected, total_rows, config, now=NOW)


def rule_alerts(alerts, rule):
    return alerts[alerts["rule"] == rule].reset_index(drop=True)


# ---------------------------------------------------------------- rule 1
def test_five_failures_within_five_minutes_creates_alert():
    alerts = run(failures("203.0.113.5", 5, 60))  # 0,1,2,3,4 minutes
    found = rule_alerts(alerts, d.RULE_REPEATED_FAILURES)
    assert len(found) == 1
    row = found.iloc[0]
    assert row["source_ip"] == "203.0.113.5"
    assert row["event_count"] == 5
    assert row["severity"] == "MEDIUM"
    assert row["first_seen"] == BASE
    assert row["last_seen"] == BASE + pd.Timedelta(minutes=4)
    assert row["status"] == d.STATUS_NEW


def test_four_failures_within_five_minutes_creates_no_alert():
    assert run(failures("203.0.113.5", 4, 60)).empty


def test_boundary_exactly_five_minutes_apart_is_inside_the_window():
    # first and last failure exactly 300 seconds apart
    alerts = run(failures("203.0.113.5", 5, 75))
    assert len(rule_alerts(alerts, d.RULE_REPEATED_FAILURES)) == 1


def test_boundary_one_second_over_the_window_is_outside():
    # first and last failure 301 seconds apart: 0, 75, 150, 225, 301
    rows = failures("203.0.113.5", 4, 75) + failures("203.0.113.5", 1, 0, start=BASE + pd.Timedelta(seconds=301))
    assert run(rows).empty


def test_failures_spread_outside_the_window_create_no_alert():
    assert run(failures("203.0.113.5", 6, 600)).empty  # one every 10 minutes


def test_events_from_different_ips_are_not_combined():
    rows = failures("203.0.113.5", 3, 30) + failures("203.0.113.6", 3, 30)
    assert run(rows).empty  # 6 failures in total, but only 3 per IP


def test_two_ips_each_over_threshold_give_two_alerts():
    rows = failures("203.0.113.5", 5, 30) + failures("203.0.113.6", 6, 30)
    found = rule_alerts(run(rows), d.RULE_REPEATED_FAILURES)
    assert sorted(found["source_ip"]) == ["203.0.113.5", "203.0.113.6"]


def test_only_the_bad_ip_is_flagged_when_mixed_with_normal_traffic():
    rows = failures("203.0.113.5", 5, 30) + failures("192.168.1.10", 2, 30)
    found = rule_alerts(run(rows), d.RULE_REPEATED_FAILURES)
    assert list(found["source_ip"]) == ["203.0.113.5"]


def test_successful_logins_are_never_counted_as_failures():
    alerts = run(failures("203.0.113.5", 8, 40, status="Success"))
    assert rule_alerts(alerts, d.RULE_REPEATED_FAILURES).empty


def test_successes_in_between_do_not_count_toward_the_threshold():
    rows = failures("203.0.113.5", 4, 30)
    rows += failures("203.0.113.5", 3, 30, start=BASE + pd.Timedelta(seconds=15), status="Success")
    assert rule_alerts(run(rows), d.RULE_REPEATED_FAILURES).empty


def test_one_long_burst_gives_one_alert_and_events_are_not_counted_twice():
    found = rule_alerts(run(failures("203.0.113.5", 12, 15)), d.RULE_REPEATED_FAILURES)
    assert len(found) == 1
    assert found.iloc[0]["event_count"] == 12


def test_two_separate_bursts_give_two_alerts():
    later = BASE + pd.Timedelta(hours=3)
    rows = failures("203.0.113.5", 5, 20) + failures("203.0.113.5", 5, 20, start=later)
    found = rule_alerts(run(rows), d.RULE_REPEATED_FAILURES)
    assert len(found) == 2
    assert list(found["event_count"]) == [5, 5]


def test_unsorted_input_gives_the_same_result():
    rows = failures("203.0.113.5", 5, 30)
    assert len(run(list(reversed(rows)))) == len(run(rows)) == 1


def test_severity_levels_for_repeated_failures():
    assert run(failures("203.0.113.5", 5, 5)).iloc[0]["severity"] == "MEDIUM"
    assert run(failures("203.0.113.5", 9, 5)).iloc[0]["severity"] == "MEDIUM"
    assert run(failures("203.0.113.5", 10, 5)).iloc[0]["severity"] == "HIGH"
    assert run(failures("203.0.113.5", 19, 5)).iloc[0]["severity"] == "HIGH"
    brute = rule_alerts(run(failures("203.0.113.5", 20, 5)), d.RULE_REPEATED_FAILURES)
    assert brute.iloc[0]["severity"] == "CRITICAL"


def test_threshold_and_window_are_configurable():
    config = d.DetectionConfig(failed_threshold=3, window_minutes=1)
    assert len(rule_alerts(run(failures("203.0.113.5", 3, 30), config), d.RULE_REPEATED_FAILURES)) == 1
    assert rule_alerts(run(failures("203.0.113.5", 3, 31), config), d.RULE_REPEATED_FAILURES).empty
    strict = d.DetectionConfig(failed_threshold=10)
    assert run(failures("203.0.113.5", 9, 10), strict).empty


def test_invalid_configuration_is_rejected():
    for bad in [dict(failed_threshold=0), dict(failed_threshold=2.5), dict(window_minutes=0),
                dict(window_minutes=-1), dict(window_minutes=float("nan")), dict(user_threshold=True)]:
        try:
            d.DetectionConfig(**bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad} should have been rejected")


def test_alert_explains_itself_and_separates_facts_from_suspicion():
    row = run(failures("203.0.113.5", 5, 30)).iloc[0]
    assert "203.0.113.5" in row["description"]
    assert "5 failed logins" in row["description"]
    assert "at least 5 failures within 5 minutes" in row["description"]
    assert "does not prove malicious intent" in row["indicator"]
    assert row["description"] != row["indicator"]


def test_detection_time_is_recorded():
    assert run(failures("203.0.113.5", 5, 30)).iloc[0]["detected_at"] == pd.Timestamp(NOW)


def test_alert_ids_are_stable_and_unique():
    rows = failures("203.0.113.5", 5, 30) + failures("203.0.113.6", 5, 30)
    first, second = run(rows), run(rows)
    assert list(first["alert_id"]) == list(second["alert_id"])
    assert first["alert_id"].is_unique
    assert all(a.startswith("ALR-") for a in first["alert_id"])


# ---------------------------------------------------------------- empty / odd data
def test_empty_dataset_gives_empty_alerts_with_correct_columns():
    for events in (dp.empty_events(), None):
        alerts = d.detect_all(events, now=NOW)
        assert alerts.empty
        assert list(alerts.columns) == d.ALERT_COLUMNS


def test_normal_successful_logins_give_no_alerts():
    assert run(failures("192.168.1.10", 30, 20, status="Success")).empty


def test_bad_rows_are_rejected_before_detection_and_reported_by_rule_5():
    csv = (
        "timestamp,username,ip_address,status\n"
        + "".join(f"2026-10-25 10:00:{i:02d},u,203.0.113.5,Failed\n" for i in range(0, 50, 10))
        + "not-a-time,u,203.0.113.5,Failed\n"
        + "2026-10-25 10:00:05,u,,Failed\n"
        + "2026-10-25 10:00:06,u,999.1.1.1,Failed\n"
    ).encode()
    loaded = dp.load_csv_bytes(csv)
    alerts = d.detect_all(loaded.events, loaded.rejected, loaded.total_rows, now=NOW)
    brute = rule_alerts(alerts, d.RULE_REPEATED_FAILURES)
    assert brute.iloc[0]["event_count"] == 5          # bad rows were not counted
    malformed = rule_alerts(alerts, d.RULE_MALFORMED_RECORDS)
    assert malformed.iloc[0]["event_count"] == 3


# ---------------------------------------------------------------- rule 2
def usernames_rows(count, gap_seconds, ip="192.0.2.9"):
    return [(BASE + pd.Timedelta(seconds=i * gap_seconds), f"user{i:02d}", ip, "Failed") for i in range(count)]


def test_five_usernames_from_one_ip_creates_alert():
    found = rule_alerts(run(usernames_rows(5, 100)), d.RULE_MULTIPLE_USERNAMES)
    assert len(found) == 1
    assert found.iloc[0]["severity"] == "MEDIUM"


def test_four_usernames_do_not_create_alert():
    assert rule_alerts(run(usernames_rows(4, 100)), d.RULE_MULTIPLE_USERNAMES).empty


def test_same_username_repeated_is_not_multiple_usernames():
    found = run(failures("192.0.2.9", 8, 20))
    assert rule_alerts(found, d.RULE_MULTIPLE_USERNAMES).empty


def test_usernames_spread_beyond_the_window_do_not_count():
    assert rule_alerts(run(usernames_rows(5, 300)), d.RULE_MULTIPLE_USERNAMES).empty  # 20 minutes in total


def test_ten_usernames_is_high_severity():
    found = rule_alerts(run(usernames_rows(10, 30)), d.RULE_MULTIPLE_USERNAMES)
    assert found.iloc[0]["severity"] == "HIGH"


# ---------------------------------------------------------------- rule 3
def success_case(failure_count, success_user="victim", gap_to_success=60, failure_gap=10):
    rows = failures("198.51.100.9", failure_count, failure_gap)
    last = rows[-1][0]
    rows.append((last + pd.Timedelta(seconds=gap_to_success), success_user, "198.51.100.9", "Success"))
    return rows


def test_success_after_failures_same_user_is_high():
    found = rule_alerts(run(success_case(5)), d.RULE_SUCCESS_AFTER_FAILURES)
    assert len(found) == 1
    assert found.iloc[0]["severity"] == "HIGH"
    assert found.iloc[0]["event_count"] == 6


def test_success_after_failures_different_user_is_medium():
    found = rule_alerts(run(success_case(5, success_user="someone_else")), d.RULE_SUCCESS_AFTER_FAILURES)
    assert found.iloc[0]["severity"] == "MEDIUM"


def test_success_after_many_failures_same_user_is_critical():
    found = rule_alerts(run(success_case(10)), d.RULE_SUCCESS_AFTER_FAILURES)
    assert found.iloc[0]["severity"] == "CRITICAL"


def test_success_after_too_few_failures_creates_no_alert():
    assert rule_alerts(run(success_case(4)), d.RULE_SUCCESS_AFTER_FAILURES).empty


def test_success_long_after_failures_is_outside_the_lookback():
    rows = success_case(6, gap_to_success=11 * 60)  # 11 minutes later; lookback is 10
    assert rule_alerts(run(rows), d.RULE_SUCCESS_AFTER_FAILURES).empty


def test_success_exactly_at_the_lookback_limit_counts_but_one_second_later_does_not():
    five_failures = failures("198.51.100.9", 5, 0)
    at_limit = five_failures + [(BASE + pd.Timedelta(minutes=10), "victim", "198.51.100.9", "Success")]
    too_late = five_failures + [(BASE + pd.Timedelta(minutes=10, seconds=1), "victim", "198.51.100.9", "Success")]
    assert len(rule_alerts(run(at_limit), d.RULE_SUCCESS_AFTER_FAILURES)) == 1
    assert rule_alerts(run(too_late), d.RULE_SUCCESS_AFTER_FAILURES).empty


def test_success_in_the_same_second_as_the_failures_still_counts():
    rows = failures("198.51.100.9", 5, 0) + [(BASE, "victim", "198.51.100.9", "Success")]
    assert len(rule_alerts(run(rows), d.RULE_SUCCESS_AFTER_FAILURES)) == 1


def test_several_successes_after_the_same_failures_give_one_alert():
    rows = success_case(6)
    rows.append((rows[-1][0] + pd.Timedelta(seconds=30), "victim", "198.51.100.9", "Success"))
    rows.append((rows[-1][0] + pd.Timedelta(seconds=60), "victim", "198.51.100.9", "Success"))
    assert len(rule_alerts(run(rows), d.RULE_SUCCESS_AFTER_FAILURES)) == 1


def test_success_from_a_different_ip_is_not_linked_to_failures():
    rows = failures("198.51.100.9", 8, 10)
    rows.append((BASE + pd.Timedelta(minutes=3), "victim", "192.168.1.10", "Success"))
    assert rule_alerts(run(rows), d.RULE_SUCCESS_AFTER_FAILURES).empty


# ---------------------------------------------------------------- rule 4
def test_ten_attempts_in_one_minute_is_low_activity_alert():
    found = rule_alerts(run(failures("10.0.0.250", 10, 5, status="Success")), d.RULE_HIGH_ACTIVITY)
    assert len(found) == 1
    assert found.iloc[0]["severity"] == "LOW"


def test_nine_attempts_in_one_minute_is_not_an_alert():
    assert rule_alerts(run(failures("10.0.0.250", 9, 5, status="Success")), d.RULE_HIGH_ACTIVITY).empty


def test_activity_severity_levels():
    assert rule_alerts(run(failures("10.0.0.250", 20, 2, status="Success")), d.RULE_HIGH_ACTIVITY).iloc[0]["severity"] == "MEDIUM"
    assert rule_alerts(run(failures("10.0.0.250", 40, 1, status="Success")), d.RULE_HIGH_ACTIVITY).iloc[0]["severity"] == "HIGH"


# ---------------------------------------------------------------- rule 5
def rejected_frame(count):
    return pd.DataFrame({"row": range(1, count + 1), "reason": ["x"] * count})


def test_malformed_record_severity_depends_on_share():
    ok = failures("192.168.1.10", 1, 1)
    assert run(ok, rejected=rejected_frame(1), total_rows=100).iloc[0]["severity"] == "LOW"
    assert run(ok, rejected=rejected_frame(10), total_rows=100).iloc[0]["severity"] == "MEDIUM"
    assert run(ok, rejected=rejected_frame(50), total_rows=100).iloc[0]["severity"] == "HIGH"


def test_no_malformed_records_means_no_alert():
    assert run(failures("192.168.1.10", 1, 1), rejected=rejected_frame(0)).empty


def test_malformed_alert_has_no_source_ip():
    row = run(failures("192.168.1.10", 1, 1), rejected=rejected_frame(2), total_rows=10).iloc[0]
    assert row["source_ip"] == d.NOT_APPLICABLE


# ---------------------------------------------------------------- find_clusters
def test_find_clusters_directly():
    assert d.find_clusters([], [], 300, 5) == []
    secs = [0, 10, 20, 30, 40, 5000, 5010, 5020, 5030, 5040]
    users = ["u"] * 10
    assert d.find_clusters(secs, users, 300, 5) == [(0, 4), (5, 9)]


def test_large_dataset_runs():
    rows = []
    for ip_number in range(200):
        rows += failures(f"10.1.{ip_number // 250}.{ip_number % 250}", 100, 7)
    alerts = run(rows)
    assert len(rule_alerts(alerts, d.RULE_REPEATED_FAILURES)) >= 200


# ---------------------------------------------------------------- dashboard helpers
def test_alert_metrics_and_review_status():
    alerts = run(success_case(10))
    metrics = d.alert_metrics(alerts)
    assert metrics["incidents"] == len(alerts) >= 2
    assert metrics["suspicious_ips"] == 1
    assert metrics["high_severity"] >= 2
    alerts["status"] = d.STATUS_REVIEWED
    assert d.alert_metrics(alerts)["high_severity"] == 0


def test_alert_metrics_on_empty_alerts():
    assert d.alert_metrics(d.detect_all(None, now=NOW)) == {"incidents": 0, "suspicious_ips": 0, "high_severity": 0}


def test_filter_alerts():
    rows = failures("203.0.113.5", 5, 30) + failures("198.51.100.9", 10, 5)
    alerts = run(rows)
    assert set(d.filter_alerts(alerts, severities=["HIGH"])["source_ip"]) == {"198.51.100.9"}
    assert set(d.filter_alerts(alerts, ip_text="203.0")["source_ip"]) == {"203.0.113.5"}
    assert d.filter_alerts(alerts, statuses=[d.STATUS_REVIEWED]).empty
    assert len(d.filter_alerts(alerts)) == len(alerts)


# ---------------------------------------------------------------- the real sample file
def test_sample_file_produces_the_documented_alerts():
    loaded = dp.load_csv_path("data/sample_logs.csv")
    assert loaded.ok
    assert len(loaded.events) + len(loaded.rejected) >= 50
    assert len(loaded.rejected) == 3
    assert all(str(i).startswith("SIM-") for i in loaded.events["event_id"])
    alerts = d.detect_all(loaded.events, loaded.rejected, loaded.total_rows, now=NOW)
    found = {(r.source_ip, r.rule, r.severity) for r in alerts.itertuples()}
    assert found == {
        ("198.51.100.23", d.RULE_SUCCESS_AFTER_FAILURES, "CRITICAL"),
        ("198.51.100.23", d.RULE_REPEATED_FAILURES, "HIGH"),
        ("203.0.113.45", d.RULE_REPEATED_FAILURES, "MEDIUM"),
        ("192.0.2.77", d.RULE_MULTIPLE_USERNAMES, "MEDIUM"),
        ("10.0.0.250", d.RULE_HIGH_ACTIVITY, "LOW"),
        (d.NOT_APPLICABLE, d.RULE_MALFORMED_RECORDS, "LOW"),
  }
