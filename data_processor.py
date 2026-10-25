"""
data_processor.py
-----------------
Loads, validates and cleans authentication-log CSV files.

This file is plain data processing. It does not use Streamlit or the
database, which makes it easy to test.

Timestamp rule:
  * Accepted: YYYY-MM-DD HH:MM[:SS[.ffffff]]  (a "T" instead of a space is fine)
  * Times without a timezone are treated as UTC.
  * Times with an offset (for example +05:30 or Z) are converted to UTC.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
REQUIRED_COLUMNS = ["timestamp", "username", "ip_address", "status"]
OPTIONAL_COLUMNS = ["event_id"]
EVENT_COLUMNS = ["event_id", "timestamp", "username", "ip_address", "status", "event_hash"]
REJECTED_COLUMNS = ["row", "reason", "timestamp", "username", "ip_address", "status"]

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_ROWS = 50_000
MAX_USERNAME_LENGTH = 64
MAX_DISPLAY_LENGTH = 100  # long values are shortened in the rejected-rows table

# Every accepted spelling of a login result -> one standard value.
STATUS_MAP = {
    "success": "Success",
    "successful": "Success",
    "succeeded": "Success",
    "ok": "Success",
    "failed": "Failed",
    "failure": "Failed",
    "fail": "Failed",
    "denied": "Failed",
}

_TIMESTAMP_SHAPE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})?$"
)
_CONTROL_CHARS = r"[\x00-\x1f\x7f]"


# ----------------------------------------------------------------------
# Empty tables (used for "no data" states)
# ----------------------------------------------------------------------
def empty_events() -> pd.DataFrame:
    """An events table with the right columns and no rows."""
    return pd.DataFrame(
        {
            "event_id": pd.Series(dtype="object"),
            "timestamp": pd.Series(dtype="datetime64[ns]"),
            "username": pd.Series(dtype="object"),
            "ip_address": pd.Series(dtype="object"),
            "status": pd.Series(dtype="object"),
            "event_hash": pd.Series(dtype="object"),
        }
    )


def empty_rejected() -> pd.DataFrame:
    """A rejected-rows table with the right columns and no rows."""
    return pd.DataFrame({col: pd.Series(dtype="object") for col in REJECTED_COLUMNS})


# ----------------------------------------------------------------------
# Result object returned by the loading functions
# ----------------------------------------------------------------------
@dataclass
class ValidationResult:
    events: pd.DataFrame = field(default_factory=empty_events)
    rejected: pd.DataFrame = field(default_factory=empty_rejected)
    errors: list[str] = field(default_factory=list)    # problems that stop the import
    warnings: list[str] = field(default_factory=list)  # things the user should know
    total_rows: int = 0

    @property
    def ok(self) -> bool:
        """True when there is no blocking error."""
        return not self.errors

    @classmethod
    def failure(cls, message: str) -> "ValidationResult":
        return cls(errors=[message])


# ----------------------------------------------------------------------
# Small helper functions (each one is easy to test on its own)
# ----------------------------------------------------------------------
def sanitize_filename(name: str) -> str:
    """Keep only safe characters so a file name can be shown or stored safely."""
    base = re.split(r"[\\/]", str(name))[-1]       # drop any folder part
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)   # replace unsafe characters
    base = base.lstrip(".")[:100]
    return base or "uploaded_file.csv"


def is_csv_filename(name: str) -> bool:
    return str(name).lower().endswith(".csv")


def normalize_ip(value) -> str | None:
    """Return the standard text form of a valid IPv4/IPv6 address, else None."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def normalize_status(value) -> str | None:
    """Return 'Success' or 'Failed' for known spellings, else None."""
    return STATUS_MAP.get(str(value).strip().lower())


def parse_timestamps(values: pd.Series) -> pd.Series:
    """Parse text timestamps safely. Anything invalid becomes NaT (not a crash)."""
    text = values.fillna("").astype(str).str.strip()
    shape_ok = text.str.match(_TIMESTAMP_SHAPE)
    parsed = pd.to_datetime(text.where(shape_ok), format="ISO8601", utc=True, errors="coerce")
    return parsed.dt.tz_localize(None)  # UTC, without the timezone label


def _hash_events(events: pd.DataFrame) -> pd.Series:
    """A fingerprint of (time, user, IP, status). Used to spot duplicate events."""
    key = (
        events["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        + "|" + events["username"]
        + "|" + events["ip_address"]
        + "|" + events["status"]
    )
    return key.map(lambda text: hashlib.sha256(text.encode("utf-8")).hexdigest()[:32])


# ----------------------------------------------------------------------
# Main validation
# ----------------------------------------------------------------------
def validate_and_normalize(raw: pd.DataFrame) -> ValidationResult:
    """Check every row of a loaded CSV and split it into valid and rejected rows."""
    df = raw.copy().reset_index(drop=True)
    df.columns = [str(col).strip().lower() for col in df.columns]

    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        return ValidationResult.failure(
            "Missing required column(s): " + ", ".join(missing)
            + ". Required columns are: " + ", ".join(REQUIRED_COLUMNS) + "."
        )
    if df.empty:
        return ValidationResult.failure("The file has a header but no data rows.")

    for col in REQUIRED_COLUMNS + OPTIONAL_COLUMNS:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()

    timestamps = parse_timestamps(df["timestamp"])
    ips = df["ip_address"].map(normalize_ip)
    statuses = df["status"].map(normalize_status)
    usernames = df["username"]

    # (which rows have the problem, message to show)
    checks = [
        (df["timestamp"] == "", "missing timestamp"),
        ((df["timestamp"] != "") & timestamps.isna(), "invalid timestamp (use YYYY-MM-DD HH:MM:SS)"),
        (df["ip_address"] == "", "missing IP address"),
        ((df["ip_address"] != "") & ips.isna(), "invalid IP address"),
        (df["status"] == "", "missing status"),
        ((df["status"] != "") & statuses.isna(), "unrecognized status"),
        (usernames == "", "missing username"),
        (usernames.str.len() > MAX_USERNAME_LENGTH, "username too long"),
        (usernames.str.contains(_CONTROL_CHARS, regex=True), "username has control characters"),
    ]
    reasons = pd.Series("", index=df.index)
    for mask, message in checks:
        reasons = reasons.mask(mask, reasons + message + "; ")
    reasons = reasons.str.rstrip("; ")
    bad = (reasons != "").to_numpy()
    good = ~bad

    # ---- rejected rows (kept so the user can see why) ----
    rejected = pd.DataFrame(
        {
            "row": df.index[bad] + 1,  # 1 = first data row
            "reason": reasons[bad].to_numpy(),
            "timestamp": df.loc[bad, "timestamp"].str.slice(0, MAX_DISPLAY_LENGTH).to_numpy(),
            "username": df.loc[bad, "username"].str.slice(0, MAX_DISPLAY_LENGTH).to_numpy(),
            "ip_address": df.loc[bad, "ip_address"].str.slice(0, MAX_DISPLAY_LENGTH).to_numpy(),
            "status": df.loc[bad, "status"].str.slice(0, MAX_DISPLAY_LENGTH).to_numpy(),
        }
    ).reset_index(drop=True)

    # ---- accepted rows ----
    event_ids = df.loc[good, "event_id"] if "event_id" in df.columns else ""
    events = pd.DataFrame(
        {
            "event_id": event_ids,
            "timestamp": timestamps[good],
            "username": usernames[good],
            "ip_address": ips[good],
            "status": statuses[good],
        }
    ).reset_index(drop=True)
    events["event_hash"] = _hash_events(events)

    # Remove exact duplicates so the same event is never counted twice.
    before = len(events)
    events = events.drop_duplicates(subset="event_hash", keep="first")
    duplicates = before - len(events)

    # Create an ID for rows that did not have one.
    no_id = events["event_id"] == ""
    events["event_id"] = events["event_id"].where(~no_id, "EV-" + events["event_hash"].str.slice(0, 10))

    events = (
        events[EVENT_COLUMNS]
        .sort_values("timestamp", kind="stable")
        .reset_index(drop=True)
    )

    result = ValidationResult(events=events, rejected=rejected, total_rows=len(df))
    if len(rejected):
        result.warnings.append(f"{len(rejected)} row(s) were rejected. See the details below.")
    if duplicates:
        result.warnings.append(f"{duplicates} duplicate row(s) were removed.")
    if events.empty:
        result.errors.append("None of the rows in the file were valid.")
    return result


# ----------------------------------------------------------------------
# Loading from bytes / from a file path
# ----------------------------------------------------------------------
def load_csv_bytes(data: bytes) -> ValidationResult:
    """Validate raw CSV bytes (for example an uploaded file). The content is
    only ever read as data. It is never run as code."""
    if not data or not data.strip():
        return ValidationResult.failure("The file is empty.")
    if len(data) > MAX_FILE_BYTES:
        return ValidationResult.failure(
            f"The file is larger than the {MAX_FILE_BYTES // (1024 * 1024)} MB limit."
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ValidationResult.failure("The file is not UTF-8 text. Save it as a UTF-8 CSV file.")
    if "\x00" in text:
        return ValidationResult.failure("The file looks like a binary file, not a CSV text file.")

    skipped = {"count": 0}

    def skip_bad_line(_line):
        skipped["count"] += 1
        return None  # None = skip this line

    try:
        raw = pd.read_csv(
            io.StringIO(text),
            dtype=str,
            keep_default_na=False,
            engine="python",
            on_bad_lines=skip_bad_line,
        )
    except pd.errors.EmptyDataError:
        return ValidationResult.failure("The file is empty.")
    except (pd.errors.ParserError, csv.Error):
        return ValidationResult.failure("The file could not be read as a CSV file.")
    except Exception:  # noqa: BLE001 - never show internal details to the user
        return ValidationResult.failure("Something went wrong while reading the file.")

    if len(raw) > MAX_ROWS:
        return ValidationResult.failure(f"The file has more than {MAX_ROWS:,} rows.")

    result = validate_and_normalize(raw)
    if skipped["count"]:
        result.warnings.append(
            f"{skipped['count']} malformed line(s) with the wrong number of columns were skipped."
        )
    return result


def load_csv_path(path: str | Path) -> ValidationResult:
    """Validate a CSV file stored on disk (used for the built-in sample data)."""
    try:
        return load_csv_bytes(Path(path).read_bytes())
    except OSError:
        return ValidationResult.failure("The file could not be opened.")


# ----------------------------------------------------------------------
# Simple statistics for the dashboard
# ----------------------------------------------------------------------
def summarize_events(events: pd.DataFrame) -> dict:
    """Counts calculated from whatever data is currently loaded."""
    if events.empty:
        return {"total": 0, "success": 0, "failed": 0, "unique_ips": 0,
                "unique_users": 0, "start": None, "end": None}
    return {
        "total": int(len(events)),
        "success": int((events["status"] == "Success").sum()),
        "failed": int((events["status"] == "Failed").sum()),
        "unique_ips": int(events["ip_address"].nunique()),
        "unique_users": int(events["username"].nunique()),
        "start": events["timestamp"].min(),
        "end": events["timestamp"].max(),
  }
