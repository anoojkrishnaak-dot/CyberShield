"""
database.py
-----------
All SQLite code lives here. Nothing else in the project writes SQL.

What is stored (and what is NOT):
  * events         - imported login events (time, username, IP, result)
  * alerts         - detection results
  * alert_reviews  - which alerts a person marked as reviewed
  * Passwords, tokens and other secrets are never stored.

Safety rules used in this file:
  * Every query uses "?" placeholders, so user text can never become SQL.
  * One short-lived connection per operation (safe with Streamlit's threads).
  * If the database cannot be opened, `available` is False and the app keeps
    working without saving anything.

Hosting note: on free hosting the disk is usually temporary and shared by all
visitors of the app. Use fictional data only.
"""
from __future__ import annotations

import os
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from data_processor import EVENT_COLUMNS, empty_events, sanitize_filename
from detector import ALERT_COLUMNS, STATUS_NEW, STATUS_REVIEWED

SCHEMA_VERSION = 1
DB_PATH_ENV_VAR = "CYBERSHIELD_DB_PATH"
_ALERT_ID_PATTERN = re.compile(r"^ALR-[0-9A-F]{10}$")
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash  TEXT NOT NULL UNIQUE,   -- fingerprint of time+user+IP+result (blocks duplicates)
    event_id    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,          -- UTC, "YYYY-MM-DD HH:MM:SS.ffffff"
    username    TEXT NOT NULL,
    ip_address  TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('Success', 'Failed')),
    source      TEXT NOT NULL,          -- where it came from (file name or 'sample')
    imported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (ip_address);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source_ip   TEXT NOT NULL,
    description TEXT NOT NULL,
    indicator   TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    first_seen  TEXT,
    last_seen   TEXT,
    usernames   TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_reviews (
    alert_id    TEXT PRIMARY KEY,       -- kept separate so re-running detection never erases reviews
    status      TEXT NOT NULL CHECK (status IN ('New', 'Reviewed')),
    reviewed_at TEXT
);
"""


@dataclass
class ImportSummary:
    inserted: int = 0
    duplicates: int = 0
    saved: bool = True
    message: str = ""


def default_db_path() -> Path:
    """Use the CYBERSHIELD_DB_PATH environment variable if set, else data/cybershield.db."""
    custom = os.environ.get(DB_PATH_ENV_VAR, "").strip()
    if custom:
        return Path(custom)
    return Path(__file__).resolve().parent / "data" / "cybershield.db"


def _time_text(value) -> str | None:
    """Timestamp -> text for storing. Missing values become NULL."""
    if value is None or pd.isna(value):
        return None
    return pd.Timestamp(value).strftime(_TIME_FORMAT)


def _now_text() -> str:
    return pd.Timestamp.now("UTC").tz_localize(None).strftime(_TIME_FORMAT)


class Database:
    """Small wrapper around one SQLite file."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_db_path()
        self.available = False
        self.error = ""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as conn:
                conn.executescript(SCHEMA)
                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                conn.commit()
            self.available = True
        except (sqlite3.Error, OSError):
            # Keep the message generic: no paths or internals shown to users.
            self.error = "The database could not be opened, so nothing will be saved."

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    # ------------------------------------------------------------ events
    def import_events(self, events: pd.DataFrame, source: str) -> ImportSummary:
        """Save validated events. Events that are already stored are skipped."""
        if not self.available:
            return ImportSummary(saved=False, message=self.error)
        missing = [c for c in EVENT_COLUMNS if c not in events.columns]
        if missing:
            raise ValueError("Events table is missing column(s): " + ", ".join(missing))
        if events.empty:
            return ImportSummary()
        if not events["status"].isin(["Success", "Failed"]).all():
            raise ValueError("Events contain a status other than 'Success' or 'Failed'.")

        source_label = sanitize_filename(source)
        imported_at = _now_text()
        rows = [
            (str(r.event_hash), str(r.event_id), _time_text(r.timestamp), str(r.username),
             str(r.ip_address), str(r.status), source_label, imported_at)
            for r in events.itertuples(index=False)
        ]
        try:
            with closing(self._connect()) as conn:
                before = conn.total_changes
                conn.executemany(
                    "INSERT OR IGNORE INTO events (event_hash, event_id, timestamp, username, "
                    "ip_address, status, source, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
                conn.commit()
                inserted = conn.total_changes - before
        except sqlite3.Error:
            return ImportSummary(saved=False, message="Saving to the database failed.")
        return ImportSummary(inserted=inserted, duplicates=len(rows) - inserted)

    def load_events(self) -> pd.DataFrame:
        """All stored events, oldest first, in the same shape data_processor produces."""
        if not self.available:
            return empty_events()
        try:
            with closing(self._connect()) as conn:
                frame = pd.read_sql_query(
                    "SELECT event_id, timestamp, username, ip_address, status, event_hash "
                    "FROM events ORDER BY timestamp, id",
                    conn,
                )
        except (sqlite3.Error, pd.errors.DatabaseError):
            return empty_events()
        if frame.empty:
            return empty_events()
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], format="ISO8601")
        return frame[EVENT_COLUMNS]

    # ------------------------------------------------------------ alerts
    def save_alerts(self, alerts: pd.DataFrame) -> bool:
        """Store detection results. Saving the same alert again updates it (no duplicates)."""
        if not self.available:
            return False
        if alerts.empty:
            return True
        rows = [
            (r.alert_id, r.rule, r.severity, r.source_ip, r.description, r.indicator,
             int(r.event_count), _time_text(r.first_seen), _time_text(r.last_seen),
             r.usernames or "", _time_text(r.detected_at))
            for r in alerts.itertuples(index=False)
        ]
        try:
            with closing(self._connect()) as conn:
                conn.executemany(
                    "INSERT INTO alerts (alert_id, rule, severity, source_ip, description, indicator, "
                    "event_count, first_seen, last_seen, usernames, detected_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(alert_id) DO UPDATE SET "
                    "rule=excluded.rule, severity=excluded.severity, source_ip=excluded.source_ip, "
                    "description=excluded.description, indicator=excluded.indicator, "
                    "event_count=excluded.event_count, first_seen=excluded.first_seen, "
                    "last_seen=excluded.last_seen, usernames=excluded.usernames, "
                    "detected_at=excluded.detected_at",
                    rows,
                )
                conn.commit()
            return True
        except sqlite3.Error:
            return False

    def load_alerts(self) -> pd.DataFrame:
        """All stored alerts, with their review status."""
        empty = pd.DataFrame(columns=ALERT_COLUMNS)
        if not self.available:
            return empty
        try:
            with closing(self._connect()) as conn:
                frame = pd.read_sql_query(
                    "SELECT a.alert_id, a.detected_at, a.source_ip, a.rule, a.severity, a.description, "
                    "a.indicator, a.event_count, a.first_seen, a.last_seen, a.usernames, "
                    "COALESCE(r.status, 'New') AS status "
                    "FROM alerts a LEFT JOIN alert_reviews r ON r.alert_id = a.alert_id "
                    "ORDER BY a.detected_at, a.alert_id",
                    conn,
                )
        except (sqlite3.Error, pd.errors.DatabaseError):
            return empty
        for col in ("detected_at", "first_seen", "last_seen"):
            frame[col] = pd.to_datetime(frame[col], format="ISO8601")
        return frame[ALERT_COLUMNS]

    # ------------------------------------------------------------ reviews
    def set_alert_status(self, alert_id: str, status: str) -> bool:
        """Mark an alert 'Reviewed' or put it back to 'New'. Returns True if saved."""
        if not _ALERT_ID_PATTERN.match(str(alert_id)):
            raise ValueError("Invalid alert ID.")
        if status not in (STATUS_NEW, STATUS_REVIEWED):
            raise ValueError("Status must be 'New' or 'Reviewed'.")
        if not self.available:
            return False
        reviewed_at = _now_text() if status == STATUS_REVIEWED else None
        try:
            with closing(self._connect()) as conn:
                conn.execute(
                    "INSERT INTO alert_reviews (alert_id, status, reviewed_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status, "
                    "reviewed_at=excluded.reviewed_at",
                    (alert_id, status, reviewed_at),
                )
                conn.commit()
            return True
        except sqlite3.Error:
            return False

    def load_review_statuses(self) -> dict[str, str]:
        """alert_id -> status for every alert that has been reviewed before."""
        if not self.available:
            return {}
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute("SELECT alert_id, status FROM alert_reviews").fetchall()
        except sqlite3.Error:
            return {}
        return {alert_id: status for alert_id, status in rows}

    def apply_review_status(self, alerts: pd.DataFrame) -> pd.DataFrame:
        """Return a copy of `alerts` whose 'status' column reflects saved reviews."""
        result = alerts.copy()
        if result.empty:
            return result
        saved = self.load_review_statuses()
        result["status"] = [saved.get(a, STATUS_NEW) for a in result["alert_id"]]
        return result

    # ------------------------------------------------------------ info
    def stats(self) -> dict:
        """Row counts for the 'database' panel."""
        if not self.available:
            return {"events": 0, "alerts": 0, "reviewed": 0}
        try:
            with closing(self._connect()) as conn:
                return {
                    "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                    "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                    "reviewed": conn.execute(
                        "SELECT COUNT(*) FROM alert_reviews WHERE status = 'Reviewed'").fetchone()[0],
                }
        except sqlite3.Error:
            return {"events": 0, "alerts": 0, "reviewed": 0}
