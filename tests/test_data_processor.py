"""Tests for data_processor.py"""
import pandas as pd

import data_processor as dp

HEADER = "timestamp,username,ip_address,status\n"


def csv_bytes(*rows: str) -> bytes:
    return (HEADER + "\n".join(rows) + "\n").encode("utf-8")


def test_valid_csv_loads_and_normalizes_status():
    data = csv_bytes(
        "2026-10-25 10:00:00,user01,192.168.1.10,SUCCESS",
        "2026-10-25 10:01:00,user02,192.168.1.20,failure",
        "2026-10-25 10:02:00,user03,192.168.1.30,Denied",
    )
    result = dp.load_csv_bytes(data)
    assert result.ok
    assert len(result.events) == 3
    assert list(result.events["status"]) == ["Success", "Failed", "Failed"]
    assert list(result.events.columns) == dp.EVENT_COLUMNS


def test_events_are_sorted_by_time():
    data = csv_bytes(
        "2026-10-25 10:05:00,a,10.0.0.1,Failed",
        "2026-10-25 10:01:00,b,10.0.0.2,Failed",
    )
    result = dp.load_csv_bytes(data)
    assert list(result.events["username"]) == ["b", "a"]


def test_empty_file_is_rejected():
    assert not dp.load_csv_bytes(b"").ok
    assert not dp.load_csv_bytes(b"   \n  \n").ok


def test_header_only_file_is_rejected():
    result = dp.load_csv_bytes(HEADER.encode())
    assert not result.ok
    assert "no data rows" in result.errors[0]


def test_missing_required_column():
    data = b"timestamp,username,status\n2026-10-25 10:00:00,u1,Success\n"
    result = dp.load_csv_bytes(data)
    assert not result.ok
    assert "ip_address" in result.errors[0]


def test_column_names_are_case_and_space_tolerant():
    data = b" Timestamp , USERNAME ,IP_Address,Status\n2026-10-25 10:00:00,u1,10.0.0.1,Success\n"
    assert dp.load_csv_bytes(data).ok


def test_invalid_timestamp_is_rejected_with_reason():
    data = csv_bytes(
        "not-a-time,user01,10.0.0.1,Failed",
        "2026-10-25 10:00:00,user02,10.0.0.2,Failed",
    )
    result = dp.load_csv_bytes(data)
    assert len(result.events) == 1
    assert len(result.rejected) == 1
    assert "invalid timestamp" in result.rejected.iloc[0]["reason"]
    assert result.rejected.iloc[0]["row"] == 1


def test_missing_timestamp_is_rejected():
    result = dp.load_csv_bytes(csv_bytes(",user01,10.0.0.1,Failed", "2026-10-25 10:00:00,u,10.0.0.2,Failed"))
    assert "missing timestamp" in result.rejected.iloc[0]["reason"]


def test_date_only_and_impossible_dates_are_rejected():
    result = dp.load_csv_bytes(csv_bytes(
        "2026-10-25,user01,10.0.0.1,Failed",
        "2026-13-45 10:00:00,user02,10.0.0.2,Failed",
        "2026-10-25 10:00:00,user03,10.0.0.3,Failed",
    ))
    assert len(result.events) == 1
    assert len(result.rejected) == 2


def test_missing_ip_is_rejected():
    result = dp.load_csv_bytes(csv_bytes(
        "2026-10-25 10:00:00,user01,,Failed",
        "2026-10-25 10:00:01,user02,10.0.0.2,Failed",
    ))
    assert len(result.events) == 1
    assert "missing IP address" in result.rejected.iloc[0]["reason"]


def test_invalid_ip_is_rejected():
    bad_ips = ["999.1.1.1", "abc", "192.168.1", "192.168.001.001", "1.2.3.4.5"]
    rows = [f"2026-10-25 10:00:00,user01,{ip},Failed" for ip in bad_ips]
    result = dp.load_csv_bytes(csv_bytes(*rows, "2026-10-25 10:00:01,user02,10.0.0.2,Failed"))
    assert len(result.events) == 1
    assert len(result.rejected) == len(bad_ips)
    assert all("invalid IP address" in r for r in result.rejected["reason"])


def test_ipv6_is_accepted_and_normalized():
    result = dp.load_csv_bytes(csv_bytes("2026-10-25 10:00:00,user01,2001:0db8:0000:0000:0000:0000:0000:0001,Failed"))
    assert result.events.iloc[0]["ip_address"] == "2001:db8::1"


def test_invalid_status_is_rejected():
    result = dp.load_csv_bytes(csv_bytes(
        "2026-10-25 10:00:00,user01,10.0.0.1,maybe",
        "2026-10-25 10:00:01,user02,10.0.0.2,",
        "2026-10-25 10:00:02,user03,10.0.0.3,Success",
    ))
    assert len(result.events) == 1
    reasons = list(result.rejected["reason"])
    assert "unrecognized status" in reasons[0]
    assert "missing status" in reasons[1]


def test_missing_username_is_rejected():
    result = dp.load_csv_bytes(csv_bytes(
        "2026-10-25 10:00:00,,10.0.0.1,Failed",
        "2026-10-25 10:00:01,user02,10.0.0.2,Failed",
    ))
    assert len(result.events) == 1
    assert "missing username" in result.rejected.iloc[0]["reason"]


def test_one_row_can_have_several_problems():
    result = dp.load_csv_bytes(csv_bytes(
        "bad,,999.9.9.9,nope",
        "2026-10-25 10:00:01,user02,10.0.0.2,Failed",
    ))
    reason = result.rejected.iloc[0]["reason"]
    for text in ["invalid timestamp", "invalid IP address", "unrecognized status", "missing username"]:
        assert text in reason


def test_all_rows_invalid_gives_error_but_keeps_rejected_table():
    result = dp.load_csv_bytes(csv_bytes("bad,u,10.0.0.1,Failed", "bad2,u,10.0.0.1,Failed"))
    assert not result.ok
    assert len(result.rejected) == 2
    assert result.events.empty


def test_duplicate_rows_are_removed_once():
    row = "2026-10-25 10:00:00,user01,10.0.0.1,Failed"
    result = dp.load_csv_bytes(csv_bytes(row, row, row, "2026-10-25 10:00:01,user01,10.0.0.1,Failed"))
    assert len(result.events) == 2
    assert any("duplicate" in w for w in result.warnings)


def test_event_hash_is_stable_between_loads():
    data = csv_bytes("2026-10-25 10:00:00,user01,10.0.0.1,Failed")
    first = dp.load_csv_bytes(data).events.iloc[0]["event_hash"]
    second = dp.load_csv_bytes(data).events.iloc[0]["event_hash"]
    assert first == second


def test_event_id_is_kept_or_generated():
    data = (
        b"timestamp,username,ip_address,status,event_id\n"
        b"2026-10-25 10:00:00,u1,10.0.0.1,Failed,MY-1\n"
        b"2026-10-25 10:00:01,u2,10.0.0.2,Failed,\n"
    )
    events = dp.load_csv_bytes(data).events
    assert events.iloc[0]["event_id"] == "MY-1"
    assert events.iloc[1]["event_id"].startswith("EV-")


def test_timezone_offsets_are_converted_to_utc():
    result = dp.load_csv_bytes(csv_bytes(
        "2026-10-25 10:00:00+05:30,user01,10.0.0.1,Failed",
        "2026-10-25T10:00:00Z,user02,10.0.0.2,Failed",
        "2026-10-25 10:00:00,user03,10.0.0.3,Failed",
    ))
    assert len(result.events) == 3
    by_user = result.events.set_index("username")["timestamp"]
    assert by_user["user01"] == pd.Timestamp("2026-10-25 04:30:00")
    assert by_user["user02"] == pd.Timestamp("2026-10-25 10:00:00")
    assert by_user["user03"] == pd.Timestamp("2026-10-25 10:00:00")


def test_file_that_is_too_large_is_rejected():
    result = dp.load_csv_bytes(b"a" * (dp.MAX_FILE_BYTES + 1))
    assert not result.ok
    assert "MB" in result.errors[0]


def test_non_utf8_file_is_rejected_without_crashing():
    result = dp.load_csv_bytes(b"\xff\xfe\x00\x01 not text \x80\x81")
    assert not result.ok


def test_binary_file_with_null_bytes_is_rejected():
    assert not dp.load_csv_bytes(b"timestamp,username\x00,ip_address,status\n").ok


def test_malformed_lines_are_skipped_with_warning():
    data = (
        "timestamp,username,ip_address,status\n"
        "2026-10-25 10:00:00,user01,10.0.0.1,Failed\n"
        "2026-10-25 10:00:01,user02,10.0.0.2,Failed,EXTRA,FIELDS\n"
        "2026-10-25 10:00:02,user03,10.0.0.3,Success\n"
    ).encode()
    result = dp.load_csv_bytes(data)
    assert result.ok
    assert len(result.events) == 2
    assert any("malformed" in w for w in result.warnings)


def test_formula_text_in_username_is_kept_as_plain_text():
    result = dp.load_csv_bytes(csv_bytes("2026-10-25 10:00:00,=CMD(1),10.0.0.1,Failed"))
    assert result.events.iloc[0]["username"] == "=CMD(1)"  # exports escape it later


def test_very_long_username_is_rejected():
    result = dp.load_csv_bytes(csv_bytes("2026-10-25 10:00:00," + "a" * 65 + ",10.0.0.1,Failed"))
    assert "username too long" in result.rejected.iloc[0]["reason"]


def test_summarize_events_counts_match_data():
    result = dp.load_csv_bytes(csv_bytes(
        "2026-10-25 10:00:00,a,10.0.0.1,Success",
        "2026-10-25 10:00:01,b,10.0.0.2,Failed",
        "2026-10-25 10:00:02,b,10.0.0.2,Failed",
    ))
    summary = dp.summarize_events(result.events)
    assert summary["total"] == 3
    assert summary["success"] == 1
    assert summary["failed"] == 2
    assert summary["unique_ips"] == 2
    assert summary["unique_users"] == 2


def test_summarize_empty_dataset_does_not_crash():
    summary = dp.summarize_events(dp.empty_events())
    assert summary["total"] == 0
    assert summary["start"] is None


def test_sanitize_filename_removes_paths_and_unsafe_characters():
    assert dp.sanitize_filename("../../etc/passwd") == "passwd"
    assert dp.sanitize_filename("my logs (1).csv") == "my_logs__1_.csv"
    assert dp.sanitize_filename("") == "uploaded_file.csv"
    assert dp.sanitize_filename("<script>.csv") == "_script_.csv"


def test_is_csv_filename():
    assert dp.is_csv_filename("logs.CSV")
    assert not dp.is_csv_filename("logs.exe")


def test_load_csv_path_reads_a_file(tmp_path):
    path = tmp_path / "logs.csv"
    path.write_bytes(csv_bytes("2026-10-25 10:00:00,user01,10.0.0.1,Failed"))
    assert dp.load_csv_path(path).ok


def test_load_csv_path_missing_file_is_a_clean_error(tmp_path):
    result = dp.load_csv_path(tmp_path / "does_not_exist.csv")
    assert not result.ok


def test_all_status_spellings():
    expected = {
        "success": "Success", "Successful": "Success", "OK": "Success", "succeeded": "Success",
        "failed": "Failed", "FAILURE": "Failed", "fail": "Failed", "denied": "Failed",
    }
    for spelling, standard in expected.items():
        assert dp.normalize_status(spelling) == standard
    assert dp.normalize_status("maybe") is None
