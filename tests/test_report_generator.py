"""Tests for report_generator.py"""
import pandas as pd

import data_processor as dp
import detector as d
import report_generator as rg

STAMP = "2026-10-25 14:00:00"


def sample_parts():
    loaded = dp.load_csv_path("data/sample_logs.csv")
    alerts = d.detect_all(loaded.events, loaded.rejected, loaded.total_rows, now="2026-10-25 13:00:00")
    return loaded, alerts


def make_report(simulated=True):
    loaded, alerts = sample_parts()
    return rg.build_report(loaded.events, alerts, loaded.rejected, d.DetectionConfig(),
                           "sample_logs.csv", simulated=simulated, generated_at=STAMP)


def test_report_has_timestamp_and_all_sections():
    report = make_report()
    assert "**Report generated:** 2026-10-25 14:00:00 UTC" in report
    for heading in ["## 1. Dataset summary", "## 2. Login statistics", "## 3. Detected incidents",
                    "## 4. Severity breakdown", "## 5. Detection rules used",
                    "## 6. Investigation recommendations", "## 7. Limitations"]:
        assert heading in report


def test_report_numbers_match_the_data():
    loaded, alerts = sample_parts()
    report = make_report()
    summary = dp.summarize_events(loaded.events)
    assert f"| Total login attempts | {summary['total']:,} |" in report
    assert f"| Failed logins | {summary['failed']:,} |" in report
    assert "Simulated (fictional) data" in report
    assert "| CRITICAL | 1 |" in report
    assert "| HIGH | 1 |" in report
    assert f"{len(alerts)} alert(s) were generated" in report


def test_report_uses_careful_wording():
    report = make_report().lower()
    assert "heuristic" in report
    assert "do not prove an attack" in report
    assert "not proof" in report
    assert "confirmed attack" not in report
    assert "was hacked" not in report


def test_report_lists_every_detection_rule_and_the_settings():
    report = make_report()
    for rule in d.RULE_DOCS:
        assert rule in report
    assert "Failed logins needed: 5 within 5 minutes" in report


def test_user_provided_data_is_labelled():
    assert "User-provided data" in make_report(simulated=False)


def test_empty_dataset_gives_a_valid_report():
    report = rg.build_report(dp.empty_events(), d.detect_all(None), None, d.DetectionConfig(),
                             "nothing.csv", generated_at=STAMP)
    assert "No alerts were generated" in report
    assert "| Total login attempts | 0 |" in report
    assert "no data" in report


def test_report_text_from_the_file_cannot_break_the_table_or_inject_html():
    evil = "a|b<script>x</script>"
    rows = "".join(f"2026-10-25 10:00:0{i},\"{evil}\",203.0.113.5,Failed\n" for i in range(5))
    rows += f"2026-10-25 10:01:00,\"{evil}\",203.0.113.5,Success\n"
    loaded = dp.load_csv_bytes(("timestamp,username,ip_address,status\n" + rows).encode())
    alerts = d.detect_all(loaded.events, loaded.rejected, loaded.total_rows, now=STAMP)
    assert (alerts["severity"] == "HIGH").any()  # so the username appears in the detail section
    report = rg.build_report(loaded.events, alerts, loaded.rejected, d.DetectionConfig(),
                             "evil|name<b>.csv", generated_at=STAMP)
    assert "<script>" not in report
    assert "<b>" not in report
    assert "a\\|b&lt;script&gt;" in report


def test_csv_export_neutralises_formulas():
    frame = pd.DataFrame({"username": ["=CMD(1)", "+1", "-2", "@x", "normal"], "n": [1, 2, 3, 4, 5]})
    text = rg.to_csv_bytes(frame).decode()
    for dangerous in ["'=CMD(1)", "'+1", "'-2", "'@x"]:
        assert dangerous in text
    assert "normal" in text and "'normal" not in text


def test_csv_export_of_events_and_empty_tables():
    loaded, alerts = sample_parts()
    text = rg.to_csv_bytes(loaded.events[["event_id", "timestamp", "username"]]).decode()
    assert text.splitlines()[0] == "event_id,timestamp,username"
    assert len(text.splitlines()) == len(loaded.events) + 1
    empty = rg.to_csv_bytes(pd.DataFrame(columns=d.ALERT_COLUMNS)).decode()
    assert empty.strip() == ",".join(d.ALERT_COLUMNS)
    assert rg.to_csv_bytes(alerts).decode().count("ALR-") >= len(alerts)
