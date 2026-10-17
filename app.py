from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import altair as alt
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from src.filesentinel.database import (
    DEFAULT_DB_PATH,
    initialize_database,
    list_events,
    list_folders,
)
from src.filesentinel.monitoring import (
    check_folder,
    initialize_folder,
    rebaseline_folder,
)
from src.filesentinel.watcher import (
    start_watching,
    stop_watching,
    is_watching,
    get_watcher_error,
)


# -------------------- Page setup and styling --------------------
st.set_page_config(
    page_title="FileSentinel | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    dedent(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
        :root {
            --bg:#080e19; --sidebar:#0b1422; --panel:#101b2c; --panel2:#142338;
            --border:#26374d; --cyan:#32d7ee; --blue:#7dc7ff; --green:#38d99a;
            --red:#ff657a; --muted:#91a4bc; --text:#eaf2fc;
        }
        html, body, [class*="css"] { font-family:'Inter',sans-serif; }
        .stApp { background:radial-gradient(ellipse at 74% 0%,rgba(30,91,132,.18),transparent 36%),var(--bg); color:var(--text); }
        [data-testid="stHeader"] { background:rgba(8,14,25,.94); }
        [data-testid="stSidebar"] { background:var(--sidebar); border-right:1px solid var(--border); }
        [data-testid="stSidebar"] > div:first-child { padding-top:1.6rem; }
        .block-container { max-width:1540px; padding-top:1.35rem; padding-bottom:2.8rem; }
        h1,h2,h3,h4 { color:var(--text)!important; letter-spacing:-.035em; }
        p, label, [data-testid="stCaptionContainer"] { color:var(--muted); }
        [data-testid="stMetric"] { background:linear-gradient(145deg,#132238,#0e1828); border:1px solid var(--border); border-radius:13px; padding:17px 19px; min-height:108px; }
        [data-testid="stMetricLabel"] { color:#9db2cb; font-size:.82rem; }
        [data-testid="stMetricValue"] { color:#eaf2fc; font-weight:800; font-size:2rem; }
        div.stButton > button { border-radius:8px; min-height:41px; font-weight:600; border:1px solid var(--border); background:#111c2c; color:#a9c3df; transition:all .15s ease; }
        div.stButton > button[kind="primary"] { background:var(--cyan); color:#07131e; border:0; }
        div.stButton > button:hover { border-color:var(--cyan); color:#eafaff; }
        div[data-testid="stTextInput"] input, div[data-testid="stSelectbox"] > div, div[data-testid="stMultiSelect"] > div { background:#0e1929; border-color:var(--border); border-radius:8px; }
        div[data-testid="stDataFrame"] { border:1px solid var(--border); border-radius:10px; overflow:hidden; }
        [data-testid="stTabs"] button { color:#9bb0c9; }
        hr { border-color:var(--border); margin:1.5rem 0; }
        .brand { font-size:1.42rem; font-weight:800; color:#eef7ff; letter-spacing:-.055em; }
        .brand span { color:var(--cyan); }
        .eyebrow { font-size:.68rem; text-transform:uppercase; letter-spacing:.19em; color:var(--cyan); font-weight:800; }
        .hero { background:linear-gradient(112deg,rgba(24,51,76,.98),rgba(15,25,42,.97)); border:1px solid #29435b; border-radius:17px; padding:26px 28px 24px; margin:0 0 25px; box-shadow:0 12px 35px rgba(0,0,0,.08); }
        .hero h1 { margin:12px 0 11px; font-size:clamp(1.8rem,2.7vw,2.45rem); line-height:1.18; }
        .hero p { margin:0; max-width:760px; line-height:1.75; color:#9cb9d7; font-size:.94rem; }
        .panel { background:linear-gradient(145deg,#111f32,#0e1929); border:1px solid var(--border); border-radius:12px; padding:18px 20px; margin-bottom:12px; overflow-wrap:anywhere; }
        .muted { color:var(--muted); font-size:.84rem; line-height:1.6; }
        .status-dot { display:inline-block; width:7px; height:7px; background:var(--green); border-radius:50%; margin-right:8px; box-shadow:0 0 11px rgba(56,217,154,.55); }
        .footer { text-align:center; color:#72869e; font-size:.74rem; padding-top:18px; line-height:1.8; }
        </style>
        """
    ),
    unsafe_allow_html=True,
)

initialize_database(DEFAULT_DB_PATH)


# -------------------- Helpers --------------------
def display_error(error: Exception) -> None:
    st.error(f"{type(error).__name__}: {error}")


def normalize_type(value) -> str:
    return str(value or "").strip().lower()


def folder_path_of(folder: dict) -> str:
    for key in ("folder_path", "path", "root_path"):
        if folder.get(key):
            return str(folder[key])
    return ""


def load_dashboard_data():
    return list_folders(DEFAULT_DB_PATH), list_events(DEFAULT_DB_PATH, limit=500)


def navigate_to(page_name: str) -> None:
    # Streamlit executes callbacks before it instantiates the radio widget again.
    st.session_state["navigation_page"] = page_name


def show_events(events: list[dict], key: str, limit: int | None = None) -> None:
    rows = events[:limit] if limit else events
    if not rows:
        st.info("No events match this view.")
        return
    frame = pd.DataFrame(rows)
    rename = {
        "event_type": "Change", "type": "Change", "file_path": "File path",
        "path": "File path", "folder_path": "Monitored folder", "old_hash": "Previous SHA-256",
        "new_hash": "Current SHA-256", "detected_at": "Detected at (UTC)", "id": "Event ID",
    }
    frame = frame.rename(columns=rename)
    preferred = ["Change", "File path", "Monitored folder", "Detected at (UTC)", "Previous SHA-256", "Current SHA-256", "Event ID"]
    frame = frame[[c for c in preferred if c in frame.columns] or list(frame.columns)]
    st.dataframe(frame, use_container_width=True, hide_index=True, key=key)


def validate_selected_folder(raw_path: str) -> Path:
    if not raw_path.strip():
        raise ValueError("Enter a folder path in the sidebar first.")
    folder = Path(raw_path.strip()).expanduser().resolve(strict=True)
    if not folder.is_dir():
        raise NotADirectoryError(f"Not a directory: {folder}")
    return folder


def render_event_distribution(events: list[dict]) -> None:
    """Render a donut chart from actual recorded event types."""
    kinds = [normalize_type(e.get("event_type", e.get("type"))) for e in events]
    chart_data = pd.DataFrame({
        "Change Type": ["Added", "Deleted", "Modified"],
        "Count": [kinds.count("added"), kinds.count("deleted"), kinds.count("modified")],
    })
    chart_data = chart_data[chart_data["Count"] > 0]
    if chart_data.empty:
        st.info("Event distribution will appear after changes are detected.")
        return

    chart = (
        alt.Chart(chart_data)
        .mark_arc(innerRadius=66, outerRadius=104, cornerRadius=5, padAngle=0.025)
        .encode(
            theta=alt.Theta("Count:Q", stack=True),
            color=alt.Color(
                "Change Type:N",
                scale=alt.Scale(domain=["Added", "Deleted", "Modified"], range=["#2DD4BF", "#FB7185", "#FBBF24"]),
                legend=alt.Legend(orient="bottom", title=None, labelColor="#B8C7D9", labelFontSize=11),
            ),
            tooltip=[alt.Tooltip("Change Type:N", title="Change"), alt.Tooltip("Count:Q", title="Events")],
        )
        .properties(height=260, background="transparent")
        .configure_view(strokeOpacity=0)
    )
    st.altair_chart(chart, use_container_width=True)


def render_event_timeline(events: list[dict]) -> None:
    """Plot recorded event volume over time; timestamps are taken from the audit log."""
    if not events:
        st.info("The activity timeline will appear when audit events are recorded.")
        return

    frame = pd.DataFrame(events)
    time_col = "detected_at" if "detected_at" in frame.columns else None
    type_col = "event_type" if "event_type" in frame.columns else ("type" if "type" in frame.columns else None)
    if time_col is None:
        st.info("No timestamps are available for the event timeline yet.")
        return

    frame["Timestamp"] = pd.to_datetime(frame[time_col], errors="coerce", utc=True)
    frame = frame.dropna(subset=["Timestamp"])
    if frame.empty:
        st.info("No valid event timestamps are available to chart.")
        return

    frame["Time"] = frame["Timestamp"].dt.floor("h")
    if type_col:
        frame["Change Type"] = frame[type_col].astype(str).str.lower().map({
            "added": "Added", "deleted": "Deleted", "modified": "Modified"
        }).fillna("Other")
        grouped = frame.groupby(["Time", "Change Type"], as_index=False).size().rename(columns={"size": "Events"})
        color = alt.Color(
            "Change Type:N",
            scale=alt.Scale(domain=["Added", "Deleted", "Modified", "Other"], range=["#2DD4BF", "#FB7185", "#FBBF24", "#A1A1AA"]),
            legend=alt.Legend(orient="bottom", title=None, labelColor="#B8C7D9"),
        )
        chart = alt.Chart(grouped).mark_line(point=alt.OverlayMarkDef(filled=True, size=45), strokeWidth=2.5).encode(
            x=alt.X("Time:T", title=None, axis=alt.Axis(labelColor="#9FB1C7", grid=False, format="%d %b %H:%M", labelAngle=-25)),
            y=alt.Y("Events:Q", title="Events", scale=alt.Scale(domainMin=0), axis=alt.Axis(labelColor="#9FB1C7", gridColor="#26374D", titleColor="#9FB1C7")),
            color=color,
            tooltip=[alt.Tooltip("Time:T", title="Time"), alt.Tooltip("Change Type:N", title="Change"), alt.Tooltip("Events:Q", title="Events")],
        )
    else:
        grouped = frame.groupby("Time", as_index=False).size().rename(columns={"size": "Events"})
        chart = alt.Chart(grouped).mark_line(point=True, color="#7DC7FF", strokeWidth=2.5).encode(
            x=alt.X("Time:T", title=None, axis=alt.Axis(labelColor="#9FB1C7", grid=False, labelAngle=-25)),
            y=alt.Y("Events:Q", title="Events", scale=alt.Scale(domainMin=0), axis=alt.Axis(labelColor="#9FB1C7", gridColor="#26374D")),
            tooltip=[alt.Tooltip("Time:T", title="Time"), alt.Tooltip("Events:Q", title="Events")],
        )
    chart = chart.properties(height=250, background="transparent").configure_view(strokeOpacity=0).configure_axis(labelFont="Inter", labelFontSize=10, titleFont="Inter", gridOpacity=.75)
    st.altair_chart(chart, use_container_width=True)


# -------------------- Sidebar --------------------
with st.sidebar:
    st.markdown('<div class="brand">◈ File<span>Sentinel</span></div>', unsafe_allow_html=True)
    st.caption("FILE INTEGRITY • SECURITY MONITORING")
    st.divider()
    st.markdown("##### NAVIGATION")
    page = st.radio(
        "Navigation",
        ["Overview", "Integrity Monitor", "Audit History", "Monitored Folders"],
        label_visibility="collapsed",
        key="navigation_page",
    )
    st.divider()
    st.markdown("##### MONITORING TARGET")
    folder_path = st.text_input(
        "Folder path", placeholder=r"C:\Users\You\Documents\Protected",
        help="Enter the full path of an existing folder.", key="selected_folder_path",
    )
    st.markdown('<div class="muted">A baseline is a trusted snapshot. Scans report changes; they do not approve them.</div>', unsafe_allow_html=True)
    st.divider()
    st.markdown("##### SYSTEM")
    st.markdown('<span class="status-dot"></span>Local database configured', unsafe_allow_html=True)
    st.caption("SQLite  ·  SHA-256  ·  Watchdog")

try:
    folders, events = load_dashboard_data()
except (OSError, ValueError, RuntimeError) as exc:
    display_error(exc)
    folders, events = [], []

kinds = [normalize_type(e.get("event_type", e.get("type"))) for e in events]
modified_count = kinds.count("modified")
added_count = kinds.count("added")
deleted_count = kinds.count("deleted")
active_paths = [folder_path_of(f) for f in folders if folder_path_of(f) and is_watching(folder_path_of(f))]
active_count = len(active_paths)

# The hero is intentionally HTML, but dedent prevents Markdown from rendering it as a code block.
st.markdown(
    dedent("""
    <div class="hero">
      <div class="eyebrow">SECURITY OPERATIONS CENTER</div>
      <h1>File integrity at a glance.</h1>
      <p>Monitor protected directories, identify unexpected file changes, and inspect SHA-256 evidence from one central workspace.</p>
    </div>
    """),
    unsafe_allow_html=True,
)


# -------------------- Overview --------------------
if page == "Overview":
    st.subheader("Security Overview")
    st.caption("Recent recorded activity across registered folders.")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Monitored Folders", len(folders))
    c2.metric("Recent Events", len(events))
    c3.metric("Modified Files", modified_count)
    c4.metric("Deleted Files", deleted_count)
    st.caption("Event counts use the latest 500 database records. They are not lifetime totals.")

    chart_left, chart_right = st.columns([1.1, 1.5])
    with chart_left:
        st.markdown("#### Event Distribution")
        st.markdown('<div class="muted">Share of added, deleted, and modified files</div>', unsafe_allow_html=True)
        render_event_distribution(events)
    with chart_right:
        st.markdown("#### Activity Timeline")
        st.markdown('<div class="muted">Recorded event volume by hour (UTC)</div>', unsafe_allow_html=True)
        render_event_timeline(events)

    st.divider()
    event_col, status_col = st.columns([1.65, 1])
    with event_col:
        st.markdown("#### Recent Integrity Events")
        show_events(events, "overview_recent_events", limit=8)
    with status_col:
        st.markdown("#### Monitoring Status")
        st.metric("Currently active watchers", active_count)
        if active_count:
            st.success("At least one registered folder has an active watcher.")
        else:
            st.info("No registered folder watcher is currently active.")
        st.markdown("#### Event breakdown")
        st.markdown(f'<div class="panel"><span style="color:#2DD4BF">● Added</span><h3>{added_count}</h3><span class="muted">New files detected</span><hr><span style="color:#FB7185">● Deleted</span><h3>{deleted_count}</h3><span class="muted">Missing files detected</span><hr><span style="color:#FBBF24">● Modified</span><h3>{modified_count}</h3><span class="muted">Content changes detected</span></div>', unsafe_allow_html=True)

    st.divider()
    st.markdown("#### Quick Actions")
    qa, qb = st.columns(2)
    with qa:
        st.button("Open Integrity Monitor", use_container_width=True, on_click=navigate_to, args=("Integrity Monitor",), key="quick_open_monitor")
    with qb:
        st.button("Open Audit History", use_container_width=True, on_click=navigate_to, args=("Audit History",), key="quick_open_audit")


# -------------------- Integrity Monitor --------------------
elif page == "Integrity Monitor":
    st.subheader("Integrity Monitor")
    st.caption("Create a baseline, run scans, or manage continuous monitoring.")

    selected_folder = None
    try:
        if folder_path.strip():
            selected_folder = validate_selected_folder(folder_path)
            is_active = is_watching(str(selected_folder))
            st.markdown(
                f'<div class="panel"><div class="eyebrow">SELECTED DIRECTORY</div><b>{str(selected_folder)}</b><p class="muted">Watcher status: {"ACTIVE" if is_active else "STOPPED"}</p></div>',
                unsafe_allow_html=True,
            )
        else:
            st.info("Enter an existing folder path in the sidebar to begin.")
    except (OSError, ValueError, RuntimeError) as exc:
        display_error(exc)

    baseline_col, scan_col = st.columns(2)
    with baseline_col:
        st.markdown("#### Trusted Baseline")
        st.write("Create an initial snapshot or load an existing baseline. Existing baselines are not overwritten by this action.")
        if st.button("Create / Load Baseline", use_container_width=True, key="create_load_baseline"):
            try:
                target = validate_selected_folder(folder_path)
                result = initialize_folder(target, DEFAULT_DB_PATH)
                if result.get("baseline_created"):
                    st.success(f"Baseline created. {result.get('file_count', 0)} file(s) recorded.")
                else:
                    st.info(f"Existing baseline loaded. {result.get('file_count', 0)} file(s); trusted snapshot was not overwritten.")
            except (OSError, ValueError, RuntimeError) as exc:
                display_error(exc)
    with scan_col:
        st.markdown("#### Integrity Scan")
        st.write("Compare current files against the latest observed state and record detected changes.")
        if st.button("Scan for Changes", type="primary", use_container_width=True, key="scan_for_changes"):
            try:
                target = validate_selected_folder(folder_path)
                result = check_folder(target, DEFAULT_DB_PATH)
                st.session_state["last_scan_result"] = result
                if result["changes_detected"]:
                    st.warning(f"{result['changes_detected']} change(s) detected.")
                    show_events(result["events"], "scan_result_events")
                else:
                    st.success(f"No changes detected. {result['files_scanned']} file(s) scanned.")
            except (OSError, ValueError, RuntimeError) as exc:
                display_error(exc)

    st.divider()
    st.markdown("#### Continuous Monitoring")
    if selected_folder is not None:
        selected = str(selected_folder)
        running = is_watching(selected)
        if running:
            st.success("Continuous monitoring is active.")
            watcher_error = get_watcher_error(selected)
            if watcher_error:
                st.error(f"Latest monitoring error: {watcher_error}")
        else:
            st.info("Continuous monitoring is currently stopped.")
        start_col, stop_col = st.columns(2)
        with start_col:
            if st.button("▶ Start Monitoring", disabled=running, use_container_width=True, key="start_monitoring"):
                try:
                    start_watching(selected, DEFAULT_DB_PATH)
                    st.success("Continuous monitoring started.")
                    st.rerun()
                except (OSError, ValueError, RuntimeError) as exc:
                    display_error(exc)
        with stop_col:
            if st.button("■ Stop Monitoring", disabled=not running, use_container_width=True, key="stop_monitoring"):
                stop_watching(selected)
                st.success("Monitoring stopped.")
                st.rerun()
        auto_refresh = st.checkbox("Automatically refresh every 3 seconds while monitoring", value=running, key="monitor_auto_refresh")
        if running and auto_refresh:
            st_autorefresh(interval=3000, limit=None, key="filesentinel_monitor_refresh")

    st.divider()
    st.markdown("#### Explicit Rebaseline")
    st.warning("Rebaselining approves the current file state as the new trusted baseline. Verify the directory before continuing.")
    approved = st.checkbox("I have verified this folder and intentionally approve its current state.", key="confirm_rebaseline")
    if st.button("Approve Current State as New Baseline", disabled=not approved, use_container_width=True, key="approve_rebaseline"):
        try:
            target = validate_selected_folder(folder_path)
            result = rebaseline_folder(target, DEFAULT_DB_PATH)
            st.success(f"New baseline approved. {result.get('file_count', 0)} file(s) recorded.")
        except (OSError, ValueError, RuntimeError) as exc:
            display_error(exc)


# -------------------- Audit History --------------------
elif page == "Audit History":
    st.subheader("Audit History")
    st.caption("Review recorded file changes and their SHA-256 evidence.")
    filter_col, search_col = st.columns([1, 2])
    with filter_col:
        type_filter = st.selectbox("Filter by change type", ["All", "Added", "Deleted", "Modified"], key="audit_type_filter")
    with search_col:
        path_query = st.text_input("Search file or folder path", placeholder="Enter part of a path...", key="audit_path_search")

    filtered = []
    for event in events:
        event_type = normalize_type(event.get("event_type", event.get("type")))
        path_text = f"{event.get('file_path', event.get('path', ''))} {event.get('folder_path', '')}".lower()
        if type_filter != "All" and event_type != type_filter.lower():
            continue
        if path_query.strip().lower() not in path_text:
            continue
        filtered.append(event)
    st.caption(f"{len(filtered)} matching event(s) in the latest 500 records.")
    show_events(filtered, "audit_history_table")

    if filtered:
        st.divider()
        st.markdown("#### Inspect SHA-256 Evidence")
        labels = []
        for i, event in enumerate(filtered):
            event_type = normalize_type(event.get("event_type", event.get("type")))
            path = event.get("file_path", event.get("path", "Unknown path"))
            event_id = event.get("id", i + 1)
            labels.append(f"{event_id} — {event_type} — {path}")
        chosen_index = st.selectbox("Select event", range(len(filtered)), format_func=lambda i: labels[i], key="selected_audit_event")
        chosen = filtered[chosen_index]
        prev_hash = chosen.get("old_hash")
        curr_hash = chosen.get("new_hash")
        a, b = st.columns(2)
        with a:
            st.markdown("**Previous SHA-256**")
            st.code(str(prev_hash) if prev_hash else "None (file did not previously exist)", language=None)
        with b:
            st.markdown("**Current SHA-256**")
            st.code(str(curr_hash) if curr_hash else "None (file is no longer present)", language=None)
        st.markdown("**Complete event record**")
        st.json(chosen)


# -------------------- Monitored Folders --------------------
elif page == "Monitored Folders":
    st.subheader("Monitored Folders")
    st.caption("Review registered directories and the status of their live watchers.")
    if folders:
        rows = []
        for folder in folders:
            path = folder_path_of(folder)
            rows.append({
                "Folder path": path or "Unknown",
                "Watcher status": "ACTIVE" if path and is_watching(path) else "STOPPED",
                **{k: v for k, v in folder.items() if k not in {"folder_path", "path", "root_path"}},
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        st.metric("Registered folders", len(folders))
        st.metric("Active watchers", active_count)
    else:
        st.info("No folders have been registered yet. Open Integrity Monitor and create or load a baseline for a folder.")

    st.divider()
    st.markdown("#### Quick navigation")
    a, b = st.columns(2)
    with a:
        st.button("Open Integrity Monitor", use_container_width=True, on_click=navigate_to, args=("Integrity Monitor",), key="folders_open_monitor")
    with b:
        st.button("Open Audit History", use_container_width=True, on_click=navigate_to, args=("Audit History",), key="folders_open_audit")


st.markdown('<div class="footer">FileSentinel · SHA-256 integrity monitoring · Local SQLite audit log<br>Integrity detection is not the same as prevention.</div>', unsafe_allow_html=True)
