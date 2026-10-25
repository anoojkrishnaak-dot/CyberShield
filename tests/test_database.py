"""Tests for database.py (every test uses its own temporary database file)."""
import os
import sqlite3

import pandas as pd

import data_processor as dp
import database as db
import detector as d

NOW = "2026-10-25 13:00:00"


def sample_events():
    loaded = dp.load_csv_path("data/sample_logs.csv")
    return loaded


def sample_alerts():
    loaded = sample_events()
    return d.detect_all(loaded.events, loaded.rejected, loaded.total_rows, now=NOW)


def new_db(tmp_path, name="test.db"):
    return db.Database(tmp_path / name)


def test_database_is_created_automatically_with_all_tables(tmp_path):
    database = new_db(tmp_path / "nested" / "folder")
    assert database.available
    assert (tmp_path / "nested" / "folder" / "test.db").exists()
    with sqlite3.connect(database.path) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"events", "alerts", "alert_reviews"} <= tables


def test_no_table_has_a_password_or_secret_column(tmp_path):
    database = new_db(tmp_path)
    with sqlite3.connect(database.path) as conn:
        for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            columns = [row[1].lower() for row in conn.execute(f"PRAGMA table_info({table})")]
            assert not any(word in col for col in columns for word in ("password", "secret", "token"))


def test_import_and_load_round_trip(tmp_path):
    database = new_db(tmp_path)
    events = sample_events().events
    summary = database.import_events(events, "sample_logs.csv")
    assert summary.saved
    assert summary.inserted == len(events)
    assert summary.duplicates == 0
    loaded = database.load_events()
    assert len(loaded) == len(events)
    assert list(loaded.columns) == dp.EVENT_COLUMNS
    assert list(loaded["event_id"]) == list(events["event_id"])
    assert list(loaded["timestamp"]) == list(events["timestamp"])
    assert loaded["timestamp"].is_monotonic_increasing


def test_importing_the_same_file_twice_does_not_create_duplicates(tmp_path):
    database = new_db(tmp_path)
    events = sample_events().events
    database.import_events(events, "sample_logs.csv")
    second = database.import_events(events, "sample_logs.csv")
    assert second.inserted == 0
    assert second.duplicates == len(events)
    assert database.stats()["events"] == len(events)


def test_partially_overlapping_import_only_adds_new_events(tmp_path):
    database = new_db(tmp_path)
    events = sample_events().events
    database.import_events(events.iloc[:40], "a.csv")
    summary = database.import_events(events.iloc[30:], "b.csv")
    assert summary.duplicates == 10
    assert summary.inserted == len(events) - 40
    assert database.stats()["events"] == len(events)


def test_importing_an_empty_table_is_harmless(tmp_path):
    database = new_db(tmp_path)
    summary = database.import_events(dp.empty_events(), "empty.csv")
    assert summary.inserted == 0
    assert database.load_events().empty


def test_import_rejects_tables_with_missing_columns_or_bad_status(tmp_path):
    database = new_db(tmp_path)
    events = sample_events().events
    for broken in (events.drop(columns=["event_hash"]), events.assign(status="Maybe")):
        try:
            database.import_events(broken, "x.csv")
        except ValueError:
            continue
        raise AssertionError("bad input should raise ValueError")
    assert database.stats()["events"] == 0


def test_sql_injection_text_is_stored_as_plain_text(tmp_path):
    database = new_db(tmp_path)
    evil = "x'); DROP TABLE events; --"
    csv = f"timestamp,username,ip_address,status\n2026-10-25 10:00:00,\"{evil}\",10.0.0.1,Failed\n".encode()
    events = dp.load_csv_bytes(csv).events
    database.import_events(events, "evil.csv")
    loaded = database.load_events()
    assert list(loaded["username"]) == [evil]
    assert database.stats()["events"] == 1  # the table still exists


def test_source_name_is_sanitized(tmp_path):
    database = new_db(tmp_path)
    database.import_events(sample_events().events.iloc[:1], "../../etc/passwd")
    with sqlite3.connect(database.path) as conn:
        assert conn.execute("SELECT source FROM events").fetchone()[0] == "passwd"


def test_alerts_round_trip_and_saving_twice_does_not_duplicate(tmp_path):
    database = new_db(tmp_path)
    alerts = sample_alerts()
    assert database.save_alerts(alerts)
    assert database.save_alerts(alerts)
    stored = database.load_alerts()
    assert len(stored) == len(alerts)
    assert set(stored["alert_id"]) == set(alerts["alert_id"])
    assert list(stored.columns) == d.ALERT_COLUMNS
    malformed = stored[stored["rule"] == d.RULE_MALFORMED_RECORDS].iloc[0]
    assert pd.isna(malformed["first_seen"])  # missing times stay missing


def test_saving_an_updated_alert_changes_it_instead_of_adding_a_second_copy(tmp_path):
    database = new_db(tmp_path)
    alerts = sample_alerts()
    database.save_alerts(alerts)
    changed = alerts.copy()
    changed.loc[0, "event_count"] = 99
    database.save_alerts(changed)
    stored = database.load_alerts()
    assert len(stored) == len(alerts)
    assert 99 in set(stored["event_count"])


def test_saving_empty_alerts_is_fine(tmp_path):
    assert new_db(tmp_path).save_alerts(pd.DataFrame(columns=d.ALERT_COLUMNS))


def test_review_status_persists_after_restarting_the_database(tmp_path):
    first = new_db(tmp_path)
    alerts = sample_alerts()
    target = alerts.iloc[0]["alert_id"]
    assert first.set_alert_status(target, d.STATUS_REVIEWED)

    second = new_db(tmp_path)  # a brand-new object on the same file = an app restart
    assert second.load_review_statuses() == {target: d.STATUS_REVIEWED}
    applied = second.apply_review_status(alerts)
    assert applied.loc[applied["alert_id"] == target, "status"].iloc[0] == d.STATUS_REVIEWED
    assert (applied["status"] == d.STATUS_NEW).sum() == len(alerts) - 1
    assert (alerts["status"] == d.STATUS_NEW).all()  # the original table was not changed


def test_review_can_be_undone(tmp_path):
    database = new_db(tmp_path)
    alert_id = sample_alerts().iloc[0]["alert_id"]
    database.set_alert_status(alert_id, d.STATUS_REVIEWED)
    database.set_alert_status(alert_id, d.STATUS_NEW)
    assert database.load_review_statuses()[alert_id] == d.STATUS_NEW
    assert database.stats()["reviewed"] == 0


def test_review_survives_running_detection_and_saving_alerts_again(tmp_path):
    database = new_db(tmp_path)
    alerts = sample_alerts()
    alert_id = alerts.iloc[0]["alert_id"]
    database.save_alerts(alerts)
    database.set_alert_status(alert_id, d.STATUS_REVIEWED)
    database.save_alerts(sample_alerts())
    stored = database.load_alerts()
    assert stored.loc[stored["alert_id"] == alert_id, "status"].iloc[0] == d.STATUS_REVIEWED


def test_invalid_alert_id_or_status_is_rejected(tmp_path):
    database = new_db(tmp_path)
    for alert_id, status in [("hello", "Reviewed"), ("ALR-123'; DROP TABLE alerts;--", "Reviewed"),
                             ("ALR-ABCDEF0123", "Done"), ("", "New")]:
        try:
            database.set_alert_status(alert_id, status)
        except ValueError:
            continue
        raise AssertionError(f"{alert_id!r}/{status!r} should be rejected")
    assert database.load_review_statuses() == {}


def test_apply_review_status_on_empty_alerts(tmp_path):
    empty = pd.DataFrame(columns=d.ALERT_COLUMNS)
    assert new_db(tmp_path).apply_review_status(empty).empty


def test_app_stays_usable_when_the_database_cannot_be_opened(tmp_path):
    blocker = tmp_path / "i_am_a_file.txt"
    blocker.write_text("not a folder")
    broken = db.Database(blocker / "cybershield.db")  # a folder can't be created inside a file
    assert not broken.available
    assert broken.error
    assert str(tmp_path) not in broken.error           # no internal paths shown to users
    events = sample_events().events
    summary = broken.import_events(events, "x.csv")
    assert not summary.saved and summary.inserted == 0
    assert broken.load_events().empty
    assert broken.load_alerts().empty
    assert broken.save_alerts(sample_alerts()) is False
    assert broken.set_alert_status("ALR-ABCDEF0123", d.STATUS_REVIEWED) is False
    assert broken.load_review_statuses() == {}
    assert broken.stats() == {"events": 0, "alerts": 0, "reviewed": 0}
    alerts = sample_alerts()
    assert broken.apply_review_status(alerts)["status"].eq(d.STATUS_NEW).all()


def test_database_path_can_be_set_with_an_environment_variable(tmp_path):
    wanted = tmp_path / "custom.db"
    old = os.environ.get(db.DB_PATH_ENV_VAR)
    os.environ[db.DB_PATH_ENV_VAR] = str(wanted)
    try:
        assert db.default_db_path() == wanted
        assert db.Database().path == wanted
    finally:
        if old is None:
            del os.environ[db.DB_PATH_ENV_VAR]
        else:
            os.environ[db.DB_PATH_ENV_VAR] = old
    assert db.default_db_path().name == "cybershield.db"


def test_stats_counts(tmp_path):
    database = new_db(tmp_path)
    loaded = sample_events()
    database.import_events(loaded.events, "s.csv")
    alerts = sample_alerts()
    database.save_alerts(alerts)
    database.set_alert_status(alerts.iloc[0]["alert_id"], d.STATUS_REVIEWED)
    assert database.stats() == {"events": len(loaded.events), "alerts": len(alerts), "reviewed": 1}
