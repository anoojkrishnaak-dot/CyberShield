"""
app.py - CyberShield dashboard (Streamlit).

This file only builds the screen. The real work is done in:
  data_processor.py (loading + validation), detector.py (rules),
  database.py (SQLite), report_generator.py (reports + CSV export).

Run it with:  streamlit run app.py
"""
from __future__ import annotations

import html
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

import data_processor as dp
import detector as d
import report_generator as rg
from database import Database

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_PATH = BASE_DIR / "data" / "sample_logs.csv"

PAGES = ["Overview", "Alerts", "Events", "Data & Validation", "Reports", "Rules & About"]
SOURCES = ["Sample data (simulated)", "Upload CSV", "Saved in database"]
SEVERITY_COLORS = {"LOW": "#58A6FF", "MEDIUM": "#D29922", "HIGH": "#F0883E", "CRITICAL": "#F85149"}
STATUS_COLORS = {"Success": "#3FB950", "Failed": "#F85149"}
MAX_TABLE_ROWS = 1000
EVENT_VIEW_COLUMNS = ["event_id", "timestamp", "username", "ip_address", "status"]
TEMPLATE_CSV = (
    "timestamp,username,ip_address,status,event_id\n"
    "2026-10-25 10:00:00,user01,192.168.1.10,Success,EX-001\n"
    "2026-10-25 10:01:00,user02,192.168.1.20,Failed,EX-002\n"
).encode("utf-8")

LOGO_SVG = (
    '<svg width="34" height="34" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" fill="#00D4AA" fill-opacity="0.15" '
    'stroke="#00D4AA" stroke-width="1.6"/>'
    '<path d="M8.5 12l2.5 2.5 4.5-5" stroke="#00D4AA" stroke-width="1.8" stroke-linecap="round" '
    'stroke-linejoin="round"/></svg>'
)

CSS = """
<style>
.block-container {padding-top: 1.5rem; padding-bottom: 3rem; max-width: 1200px;}
[data-testid="stMetric"] {background:#131C2E; border:1px solid #243049; border-radius:10px; padding:12px 14px;}
.cs-header {display:flex; align-items:center; gap:10px; margin-bottom:2px;}
.cs-title {font-size:1.6rem; font-weight:700; color:#E6EDF3; line-height:1.1;}
.cs-badge {display:inline-block; padding:2px 8px; border-radius:10px; font-size:0.72rem;
           font-weight:700; color:#0B1220;}
.cs-timeline-item {border-left:3px solid #243049; padding:4px 0 12px 12px; margin-left:4px; color:#E6EDF3;}
.cs-muted {color:#9AA7B8; font-size:0.85rem;}
</style>
"""


# ----------------------------------------------------------------------
# Loading data
# ----------------------------------------------------------------------
@dataclass
class Dataset:
    name: str
    simulated: bool
    result: dp.ValidationResult


@st.cache_resource
def get_database() -> Database:
    """One Database object for the whole app (it opens short connections itself)."""
    return Database()


def load_dataset(source: str, uploaded, db: Database) -> Dataset | None:
    if source == SOURCES[0]:
        return Dataset("sample_logs.csv", True, dp.load_csv_path(SAMPLE_PATH))
    if source == SOURCES[1]:
        if uploaded is None:
            return None
        name = dp.sanitize_filename(uploaded.name)
        if not dp.is_csv_filename(name):
            return Dataset(name, False, dp.ValidationResult.failure("Please upload a file that ends in .csv."))
        return Dataset(name, False, dp.load_csv_bytes(uploaded.getvalue()))
    events = db.load_events()
    if events.empty:
        message = "The database has no saved events yet. Save the sample data or an upload first."
        return Dataset("saved events", False, dp.ValidationResult.failure(message))
    return Dataset("saved events (database)", False, dp.ValidationResult(events=events, total_rows=len(events)))


def detection_settings() -> d.DetectionConfig | None:
    with st.sidebar.expander("Detection settings"):
        failed = st.slider("Failed logins to flag", 2, 20, 5)
        window = st.slider("Failed logins: window (minutes)", 1, 30, 5)
        users = st.slider("Different usernames to flag", 2, 20, 5)
        user_window = st.slider("Usernames: window (minutes)", 1, 60, 10)
        lookback = st.slider("Success-after-failures look-back (minutes)", 1, 60, 10)
        activity = st.slider("Attempts per window = high activity", 5, 100, 10)
        activity_window = st.slider("High-activity window (minutes)", 1, 10, 1)
    try:
        return d.DetectionConfig(failed, window, users, user_window, lookback, activity, activity_window)
    except ValueError:
        st.sidebar.error("These detection settings are not valid.")
        return None


# ----------------------------------------------------------------------
# Review status (database if available, otherwise this browser session)
# ----------------------------------------------------------------------
def apply_status(db: Database, alerts: pd.DataFrame) -> pd.DataFrame:
    if db.available:
        return db.apply_review_status(alerts)
    reviewed = st.session_state.get("reviewed_ids", set())
    result = alerts.copy()
    if not result.empty:
        result["status"] = [d.STATUS_REVIEWED if a in reviewed else d.STATUS_NEW for a in result["alert_id"]]
    return result


def set_status(db: Database, alert_id: str, status: str) -> None:
    if db.available:
        if not db.set_alert_status(alert_id, status):
            st.warning("The review status could not be saved.")
        return
    reviewed = st.session_state.setdefault("reviewed_ids", set())
    if status == d.STATUS_REVIEWED:
        reviewed.add(alert_id)
    else:
        reviewed.discard(alert_id)


# ----------------------------------------------------------------------
# Charts
# ----------------------------------------------------------------------
def _plain(frame: pd.DataFrame) -> pd.DataFrame:
    """Use plain text columns so every Plotly version handles them."""
    return frame.astype({c: object for c in frame.columns if pd.api.types.is_string_dtype(frame[c])})


def _style(fig, height: int = 310):
    fig.update_layout(
        template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=8, r=8, t=48, b=8), height=height, legend_title_text="",
    )
    return fig


def fig_status_split(events: pd.DataFrame):
    if events.empty:
        return None
    counts = events["status"].value_counts().reset_index()
    counts.columns = ["status", "logins"]
    fig = px.pie(_plain(counts), names="status", values="logins", hole=0.55, color="status",
                 color_discrete_map=STATUS_COLORS, title="Successful vs failed logins")
    return _style(fig)


def fig_activity(events: pd.DataFrame):
    if events.empty:
        return None
    span = events["timestamp"].max() - events["timestamp"].min()
    freq = "5min" if span <= pd.Timedelta(hours=12) else ("1h" if span <= pd.Timedelta(days=7) else "1D")
    grouped = (events.assign(time=events["timestamp"].dt.floor(freq))
               .groupby(["time", "status"]).size().reset_index(name="logins"))
    fig = px.bar(_plain(grouped), x="time", y="logins", color="status", color_discrete_map=STATUS_COLORS,
                 title=f"Login activity over time (per {freq})")
    return _style(fig)


def fig_failed_by_ip(events: pd.DataFrame):
    failed = events[events["status"] == "Failed"]
    if failed.empty:
        return None
    top = failed.groupby("ip_address").size().reset_index(name="failed_logins")
    top = top.sort_values("failed_logins", ascending=False).head(10)
    fig = px.bar(_plain(top), x="failed_logins", y="ip_address", orientation="h",
                 title="Failed attempts by IP address (top 10)")
    fig.update_traces(marker_color=STATUS_COLORS["Failed"])
    fig.update_yaxes(categoryorder="total ascending")
    return _style(fig)


def fig_alerts_by_severity(alerts: pd.DataFrame):
    if alerts.empty:
        return None
    counts = alerts["severity"].value_counts().reindex(list(SEVERITY_COLORS), fill_value=0).reset_index()
    counts.columns = ["severity", "alerts"]
    fig = px.bar(_plain(counts), x="severity", y="alerts", color="severity",
                 color_discrete_map=SEVERITY_COLORS, title="Alerts by severity")
    fig.update_layout(showlegend=False)
    return _style(fig)


def fig_targeted_usernames(events: pd.DataFrame):
    failed = events[events["status"] == "Failed"]
    if failed.empty:
        return None
    top = failed.groupby("username").size().reset_index(name="failed_logins")
    top = top.sort_values("failed_logins", ascending=False).head(10)
    fig = px.bar(_plain(top), x="failed_logins", y="username", orientation="h",
                 title="Most frequently targeted usernames (failed logins)")
    fig.update_traces(marker_color="#D29922")
    fig.update_yaxes(categoryorder="total ascending")
    return _style(fig)


def fig_incident_trend(alerts: pd.DataFrame):
    dated = alerts.dropna(subset=["first_seen"]) if not alerts.empty else alerts
    if dated.empty:
        return None
    grouped = (dated.assign(time=dated["first_seen"].dt.floor("1h"))
               .groupby(["time", "severity"]).size().reset_index(name="alerts"))
    fig = px.bar(_plain(grouped), x="time", y="alerts", color="severity", color_discrete_map=SEVERITY_COLORS,
                 title="Security incidents over time (by first activity, per hour)")
    return _style(fig)


def show_chart(fig, empty_message: str) -> None:
    if fig is None:
        st.info(empty_message)
    else:
        st.plotly_chart(fig)


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def search_events(events: pd.DataFrame, query: str, results: list[str]) -> pd.DataFrame:
    view = events[events["status"].isin(results)] if results else events.iloc[0:0]
    query = (query or "").strip()
    if query:
        mask = pd.Series(False, index=view.index)
        for column in ("event_id", "username", "ip_address"):
            mask |= view[column].str.contains(query, case=False, regex=False)
        view = view[mask]
    return view


def render_timeline(alerts: pd.DataFrame) -> None:
    dated = alerts.dropna(subset=["first_seen"]) if not alerts.empty else alerts
    if dated.empty:
        st.info("No incidents to show yet.")
        return
    items = []
    for row in dated.sort_values("first_seen", ascending=False).head(8).itertuples():
        color = SEVERITY_COLORS.get(row.severity, "#9AA7B8")
        items.append(
            f'<div class="cs-timeline-item" style="border-left-color:{color}">'
            f'<span class="cs-badge" style="background:{color}">{html.escape(row.severity)}</span> '
            f"<b>{html.escape(row.rule)}</b> &middot; {html.escape(row.source_ip)}"
            f'<div class="cs-muted">{row.first_seen:%Y-%m-%d %H:%M:%S} UTC &middot; '
            f"{int(row.event_count)} events &middot; {html.escape(row.status)}</div></div>"
        )
    st.markdown("".join(items), unsafe_allow_html=True)


def render_database_panel(db: Database, dataset: Dataset | None, alerts: pd.DataFrame | None) -> None:
    with st.sidebar.expander("Database"):
        if not db.available:
            st.warning(db.error + " Review marks will only last for this session.")
            return
        stats = db.stats()
        st.caption(f"Stored: {stats['events']} events, {stats['alerts']} alerts, {stats['reviewed']} reviewed.")
        can_save = dataset is not None and dataset.result.ok and alerts is not None
        if st.button("Save current data and alerts", disabled=not can_save):
            summary = db.import_events(dataset.result.events, dataset.name)
            saved_alerts = db.save_alerts(alerts)
            if summary.saved and saved_alerts:
                st.success(f"Saved {summary.inserted} new events ({summary.duplicates} were already stored).")
            else:
                st.error("Saving failed. Nothing was changed.")
        st.caption("Free hosting storage can be temporary and shared by all visitors. Use fictional data only.")


# ----------------------------------------------------------------------
# Pages
# ----------------------------------------------------------------------
def page_overview(dataset: Dataset, events: pd.DataFrame, alerts: pd.DataFrame) -> None:
    if dataset.simulated:
        st.info("Simulated data: every record in this dataset is fictional.")
    st.success(f"Loaded {len(events):,} valid events from {dataset.name}.")
    for warning in dataset.result.warnings:
        st.warning(warning)

    summary = dp.summarize_events(events)
    metrics = d.alert_metrics(alerts)
    top = st.columns(3)
    top[0].metric("Total login attempts", f"{summary['total']:,}")
    top[1].metric("Successful logins", f"{summary['success']:,}")
    top[2].metric("Failed logins", f"{summary['failed']:,}")
    bottom = st.columns(3)
    bottom[0].metric("Suspicious IP addresses", f"{metrics['suspicious_ips']:,}")
    bottom[1].metric("Detected security incidents", f"{metrics['incidents']:,}")
    bottom[2].metric("High-severity alerts (open)", f"{metrics['high_severity']:,}")

    if metrics["high_severity"]:
        st.error(f"{metrics['high_severity']} open HIGH or CRITICAL alert(s) need a human review. See the Alerts page.")
    elif metrics["incidents"]:
        st.warning("There are alerts to look at, but none are open HIGH or CRITICAL.")
    else:
        st.success("No alerts with the current settings. That does not prove nothing happened.")

    left, right = st.columns(2)
    with left:
        show_chart(fig_status_split(events), "No login data to chart.")
    with right:
        show_chart(fig_activity(events), "No login data to chart.")
    left, right = st.columns(2)
    with left:
        show_chart(fig_failed_by_ip(events), "No failed logins in this dataset.")
    with right:
        show_chart(fig_targeted_usernames(events), "No failed logins in this dataset.")
    left, right = st.columns(2)
    with left:
        show_chart(fig_alerts_by_severity(alerts), "No alerts to chart.")
    with right:
        show_chart(fig_incident_trend(alerts), "No incidents to chart.")

    st.subheader("Recent incident timeline")
    render_timeline(alerts)


def page_alerts(db: Database, alerts: pd.DataFrame) -> None:
    st.subheader("Security alerts")
    st.caption("Each alert separates what the data shows from what it might mean. "
               "Alerts are heuristic indicators, not proof of an attack.")
    if alerts.empty:
        st.info("No alerts were generated for this dataset.")
        return

    severities = st.multiselect("Severity", list(SEVERITY_COLORS), default=list(SEVERITY_COLORS))
    ip_text = st.text_input("Source IP contains")
    statuses = st.multiselect("Status", [d.STATUS_NEW, d.STATUS_REVIEWED], default=[d.STATUS_NEW, d.STATUS_REVIEWED])
    view = d.filter_alerts(alerts, severities=severities, ip_text=ip_text, statuses=statuses)
    if view.empty:
        st.warning("No alerts match these filters.")
        return

    st.caption(f"Showing {len(view)} of {len(alerts)} alerts.")
    table_columns = ["alert_id", "detected_at", "source_ip", "rule", "severity", "event_count", "status"]
    st.dataframe(view[table_columns], hide_index=True)
    st.download_button("Download alerts (CSV)", data=rg.to_csv_bytes(view), file_name="cybershield_alerts.csv",
                       mime="text/csv")

    for row in view.head(50).itertuples():
        with st.expander(f"{row.severity} | {row.rule} | {row.source_ip} | {row.status}"):
            st.markdown("**What the data shows (observed facts)**")
            st.text(row.description)
            st.markdown("**What it might mean (suspicion, not proof)**")
            st.text(row.indicator)
            st.text(f"Alert ID: {row.alert_id} | Events: {int(row.event_count)} | Usernames: {row.usernames or 'n/a'}")
            if row.status == d.STATUS_REVIEWED:
                if st.button("Mark as new again", key=f"toggle_{row.alert_id}"):
                    set_status(db, row.alert_id, d.STATUS_NEW)
                    st.rerun()
            elif st.button("Mark as reviewed", key=f"toggle_{row.alert_id}"):
                set_status(db, row.alert_id, d.STATUS_REVIEWED)
                st.rerun()
    if len(view) > 50:
        st.caption("Only the first 50 alerts are shown as cards. Use the filters or the CSV download for the rest.")


def page_events(events: pd.DataFrame) -> None:
    st.subheader("Security events")
    query = st.text_input("Search (username, IP address or event ID)")
    results = st.multiselect("Result", ["Success", "Failed"], default=["Success", "Failed"])
    view = search_events(events, query, results)
    if view.empty:
        st.info("No events match your search.")
        return
    st.caption(f"{len(view):,} matching events" + (f" (showing the first {MAX_TABLE_ROWS:,})"
                                                   if len(view) > MAX_TABLE_ROWS else ""))
    st.dataframe(view[EVENT_VIEW_COLUMNS].head(MAX_TABLE_ROWS), hide_index=True)
    st.download_button("Download filtered events (CSV)", data=rg.to_csv_bytes(view[EVENT_VIEW_COLUMNS]),
                       file_name="cybershield_events.csv", mime="text/csv")


def page_validation(dataset: Dataset) -> None:
    result = dataset.result
    st.subheader("Data and validation")
    st.markdown(
        "**Required columns:** `timestamp`, `username`, `ip_address`, `status`. Optional: `event_id`.\n\n"
        "**Timestamps:** `YYYY-MM-DD HH:MM:SS` (UTC unless you add an offset such as `+05:30`).\n\n"
        "**Status:** success / successful / ok or failed / failure / fail / denied.\n\n"
        "**Limits:** `.csv` only, up to 5 MB and 50,000 rows. Files are read as plain data and never run."
    )
    st.download_button("Download a CSV template", data=TEMPLATE_CSV, file_name="cybershield_template.csv",
                       mime="text/csv")
    for error in result.errors:
        st.error(error)
    for warning in result.warnings:
        st.warning(warning)
    if result.ok:
        st.success(f"{len(result.events):,} valid events accepted from {result.total_rows:,} rows.")
    if not result.rejected.empty:
        st.markdown("**Rejected rows (not used in any analysis):**")
        st.dataframe(result.rejected.head(MAX_TABLE_ROWS), hide_index=True)
    elif result.ok:
        st.info("No rows were rejected.")


def page_reports(dataset: Dataset, events: pd.DataFrame, alerts: pd.DataFrame, config: d.DetectionConfig) -> None:
    st.subheader("Incident report and exports")
    report = rg.build_report(events, alerts, dataset.result.rejected, config, dataset.name,
                             simulated=dataset.simulated)
    st.download_button("Download incident report (Markdown)", data=report.encode("utf-8"),
                       file_name="cybershield_incident_report.md", mime="text/markdown")
    st.download_button("Download all alerts (CSV)", data=rg.to_csv_bytes(alerts),
                       file_name="cybershield_alerts.csv", mime="text/csv")
    st.download_button("Download all events (CSV)", data=rg.to_csv_bytes(events[EVENT_VIEW_COLUMNS]),
                       file_name="cybershield_events.csv", mime="text/csv")
    with st.expander("Preview the report"):
        st.markdown(report)


def page_rules() -> None:
    st.subheader("Detection rules")
    st.caption("All rules are heuristics. A rule firing means a pattern deserves a human look.")
    for rule, text in d.RULE_DOCS.items():
        with st.expander(rule):
            st.markdown(f"**What it checks:** {text['what']}")
            st.markdown(f"**Severity:** {text['severity']}")
    st.subheader("About this project")
    st.markdown(
        "- **CyberShield** is a SIEM-inspired learning and demonstration project.\n"
        "- It is **not** a production security monitoring system: no real-time collection, no user "
        "accounts, no tamper protection, and no tuning for a real environment.\n"
        "- The sample data is simulated. Real logs are noisier and larger.\n"
        "- An IP address is an indicator, not proof of who did something. A private or unfamiliar "
        "address is never treated as malicious by itself.\n"
        "- Rules produce **false positives** (harmless activity flagged, like the backup script in the "
        "sample data) and **false negatives** (real attacks missed)."
    )


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main() -> None:
    st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    db = get_database()

    st.sidebar.markdown(f'<div class="cs-header">{LOGO_SVG}<span class="cs-title">CyberShield</span></div>',
                        unsafe_allow_html=True)
    page = st.sidebar.radio("Navigation", PAGES, label_visibility="collapsed")
    source = st.sidebar.radio("Data source", SOURCES)
    st.sidebar.button("Reload data", help="Reads the selected data source again.")
    config = detection_settings()

    st.markdown(f'<div class="cs-header">{LOGO_SVG}<span class="cs-title">CyberShield</span></div>',
                unsafe_allow_html=True)
    st.caption("Intelligent threat detection and security monitoring dashboard. "
               "A SIEM-inspired project that analyses authentication logs. All times are UTC.")

    if page == "Rules & About":
        render_database_panel(db, None, None)
        page_rules()
        return

    uploaded = None
    if source == SOURCES[1]:
        uploaded = st.file_uploader("Upload an authentication log (.csv, up to 5 MB)", type=["csv"])
    dataset = load_dataset(source, uploaded, db)
    if dataset is None:
        render_database_panel(db, None, None)
        st.info("Choose a CSV file to begin. Open 'Data & Validation' to see the required format and get a template.")
        return

    if page == "Data & Validation":
        render_database_panel(db, dataset, None)
        page_validation(dataset)
        return

    if not dataset.result.ok:
        render_database_panel(db, None, None)
        for error in dataset.result.errors:
            st.error(error)
        st.info("Open 'Data & Validation' to see what went wrong and what the file should look like.")
        return
    if config is None:
        st.error("Please fix the detection settings in the sidebar.")
        return

    events = dataset.result.events
    alerts = d.detect_all(events, dataset.result.rejected, dataset.result.total_rows, config)
    alerts = apply_status(db, alerts)
    render_database_panel(db, dataset, alerts)

    if page == "Overview":
        page_overview(dataset, events, alerts)
    elif page == "Alerts":
        page_alerts(db, alerts)
    elif page == "Events":
        page_events(events)
    elif page == "Reports":
        page_reports(dataset, events, alerts, config)


main()
