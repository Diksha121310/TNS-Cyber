
from pathlib import Path

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from src.filesentinel.database import (
    DEFAULT_DB_PATH,
    initialize_database,
    list_events,
    list_folders,
)
from src.filesentinel.monitoring import check_folder, initialize_folder
from src.filesentinel.watcher import (
    start_watching,
    stop_watching,
    is_watching,
    get_watcher_error,
)


# -------------------- Page setup --------------------

st.set_page_config(
    page_title="FileSentinel | File Integrity Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    div[data-testid="stMetric"] {
        background: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(128, 128, 128, 0.2);
        padding: 16px;
        border-radius: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

initialize_database(DEFAULT_DB_PATH)

st.title("🛡️ FileSentinel")
st.caption("Automated File Integrity Monitoring & Tampering Detection")


# -------------------- Helpers --------------------

def display_error(error: Exception) -> None:
    st.error(f"{type(error).__name__}: {error}")


def event_dataframe(events: list[dict]) -> pd.DataFrame:
    if not events:
        return pd.DataFrame(
            columns=["type", "path", "old_hash", "new_hash"]
        )
    return pd.DataFrame(events)


# -------------------- Sidebar --------------------

st.sidebar.title("Control Center")
st.sidebar.caption("Monitor files. Detect changes. Review evidence.")

folder_path = st.sidebar.text_input(
    "Folder to monitor",
    placeholder=r"C:\Users\YourName\Documents\Protected",
    help="Enter the full path of an existing folder on this computer.",
)

st.sidebar.info(
    "The first scan creates a baseline. Later scans compare current "
    "SHA-256 hashes against that saved snapshot."
)


# -------------------- Main actions --------------------

left, right = st.columns(2)

with left:
    st.subheader("Baseline")
    st.write("Save a trusted snapshot of the selected folder.")

    if st.button("Create / Load Baseline", use_container_width=True):
        if not folder_path.strip():
            st.warning("Enter a folder path in the sidebar first.")
        else:
            try:
                result = initialize_folder(
                    folder_path.strip(),
                    DEFAULT_DB_PATH,
                )

                if result["baseline_created"]:
                    st.success("Baseline created successfully.")
                else:
                    st.info(
                        "An existing baseline was loaded. "
                        "It was not overwritten."
                    )

                st.write(f"**Folder:** `{result['folder_path']}`")
                st.metric("Files in baseline", result["file_count"])

            except (OSError, ValueError, RuntimeError) as exc:
                display_error(exc)


with right:
    st.subheader("Integrity Check")
    st.write("Compare the selected folder against its saved baseline.")

    if st.button(
        "Scan for Changes",
        type="primary",
        use_container_width=True,
    ):
        if not folder_path.strip():
            st.warning("Enter a folder path in the sidebar first.")
        else:
            try:
                result = check_folder(
                    folder_path.strip(),
                    DEFAULT_DB_PATH,
                )
                st.session_state["last_scan"] = result

                if result["changes_detected"] == 0:
                    st.success("No changes detected.")
                else:
                    st.warning(
                        f"{result['changes_detected']} change(s) detected."
                    )

                a, b = st.columns(2)
                a.metric("Files scanned", result["files_scanned"])
                b.metric("Changes detected", result["changes_detected"])

                if result["events"]:
                    st.dataframe(
                        event_dataframe(result["events"]),
                        use_container_width=True,
                        hide_index=True,
                    )

            except (OSError, ValueError, RuntimeError) as exc:
                display_error(exc)


st.divider()


# -------------------- Continuous monitoring --------------------

st.subheader("Continuous Monitoring")

if not folder_path.strip():
    st.info("Enter a folder path in the sidebar to manage monitoring.")
else:
    try:
        selected_folder = str(
            Path(folder_path.strip()).expanduser().resolve(strict=True)
        )

        if not Path(selected_folder).is_dir():
            raise NotADirectoryError(
                f"Not a directory: {selected_folder}"
            )

        running = is_watching(selected_folder)

        if running:
            st.success("Monitoring is active for the selected folder.")
        else:
            st.info("Monitoring is currently stopped for this folder.")

        start_col, stop_col = st.columns(2)

        with start_col:
            if st.button(
                "▶ Start Monitoring",
                disabled=running,
                use_container_width=True,
            ):
                try:
                    start_watching(selected_folder, DEFAULT_DB_PATH)
                    st.success("Continuous monitoring started.")
                    st.rerun()
                except (OSError, ValueError, RuntimeError) as exc:
                    display_error(exc)

        with stop_col:
            if st.button(
                "■ Stop Monitoring",
                disabled=not running,
                use_container_width=True,
            ):
                stop_watching(selected_folder)
                st.success("Monitoring stopped.")
                st.rerun()

        if running:
            watcher_error = get_watcher_error(selected_folder)

            if watcher_error:
                st.error(f"Latest monitoring error: {watcher_error}")

            auto_refresh = st.checkbox(
                "Automatically refresh dashboard every 3 seconds",
                value=True,
                key="watcher_auto_refresh",
            )

            if auto_refresh:
                st_autorefresh(
                    interval=3000,
                    limit=None,
                    key="filesentinel_refresh",
                )

    except (OSError, ValueError, RuntimeError) as exc:
        display_error(exc)


st.divider()


# -------------------- Dashboard metrics --------------------

st.subheader("Monitoring Overview")

try:
    folders = list_folders(DEFAULT_DB_PATH)
    events = list_events(DEFAULT_DB_PATH, limit=500)

    total_events = len(events)
    modified_count = sum(
        event["event_type"] == "modified" for event in events
    )
    deleted_count = sum(
        event["event_type"] == "deleted" for event in events
    )
    added_count = sum(
        event["event_type"] == "added" for event in events
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Registered Folders", len(folders))
    m2.metric("Recent Events", total_events)
    m3.metric("Modified Files", modified_count)
    m4.metric("Deleted Files", deleted_count)

    st.caption(
        "Event counts are based on the latest 500 recorded events, "
        "not necessarily lifetime totals."
    )

    tab_events, tab_folders = st.tabs(
        ["Audit History", "Monitored Folders"]
    )

    with tab_events:
        if events:
            history = pd.DataFrame(events).rename(
                columns={
                    "event_type": "Change Type",
                    "folder_path": "Monitored Folder",
                    "file_path": "File Path",
                    "old_hash": "Previous SHA-256",
                    "new_hash": "Current SHA-256",
                    "detected_at": "Detected At (UTC)",
                    "id": "Event ID",
                }
            )

            st.dataframe(
                history,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No audit events have been recorded yet.")

    with tab_folders:
        if folders:
            st.dataframe(
                pd.DataFrame(folders),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No folders registered yet.")

except (OSError, ValueError, RuntimeError) as exc:
    display_error(exc)


st.divider()
st.caption(
    "FileSentinel • SHA-256 integrity checks • Local SQLite audit database"
)
