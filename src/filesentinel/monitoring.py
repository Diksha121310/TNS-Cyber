
from pathlib import Path

from src.filesentinel.scanner import scan_folder
from src.filesentinel.integrity import create_baseline, detect_changes
from src.filesentinel.database import (
    DEFAULT_DB_PATH,
    initialize_database,
    register_folder,
    has_baseline,
    load_baseline,
    save_baseline,
    load_observed_state,
    has_observed_state,
    record_events_and_update_observed,
)


def initialize_folder(
    folder_path: str | Path,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict:
    """
    Establish the initial baseline for a folder.

    An existing baseline is never silently replaced.
    """
    initialize_database(db_path)

    folder_id = register_folder(folder_path, db_path)
    folder = Path(folder_path).expanduser().resolve(strict=True)

    if has_baseline(folder_id, db_path):
        return {
            "folder_id": folder_id,
            "folder_path": str(folder),
            "baseline_created": False,
            "file_count": len(load_baseline(folder_id, db_path)),
        }

    # scan_folder raises on scan failure. If that happens, the baseline
    # is not marked initialized.
    fingerprints = scan_folder(folder)

    baseline = create_baseline(fingerprints)
    save_baseline(folder_id, baseline, db_path)

    return {
        "folder_id": folder_id,
        "folder_path": str(folder),
        "baseline_created": True,
        "file_count": len(baseline),
    }




def check_folder(
    folder_path: str | Path,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict:
    """
    Compare the current scan with the latest observed state.
    Record events and update observed state after a successful scan.
    """
    initialize_database(db_path)

    folder = Path(folder_path).expanduser().resolve(strict=True)

    if not folder.is_dir():
        raise NotADirectoryError(f"Not a directory: {folder}")

    folder_id = register_folder(folder, db_path)

    if not has_baseline(folder_id, db_path):
        raise RuntimeError(
            "No baseline exists. Initialize this folder before checking it."
        )

    # Do not record changes from an incomplete or failed scan.
    current = scan_folder(folder)

    observed = load_observed_state(folder_id, db_path)

    if has_observed_state(folder_id, db_path):
        # Compare against the latest successfully observed state.
        events = detect_changes(observed, current)
    else:
        # First check for databases created before observed-state tracking.
        baseline = load_baseline(folder_id, db_path)
        events = detect_changes(baseline, current)

    # IMPORTANT: Save events and observed state on EVERY successful check.
    record_events_and_update_observed(
        folder_id,
        events,
        current,
        db_path,
    )

    return {
        "folder_id": folder_id,
        "folder_path": str(folder),
        "files_scanned": len(current),
        "changes_detected": len(events),
        "events": events,
    }


def rebaseline_folder(
    folder_path: str | Path,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict:
    """
    Explicitly accept the current state as the new baseline.

    Call this only after reviewing and approving the changes.
    """
    initialize_database(db_path)

    folder = Path(folder_path).expanduser().resolve(strict=True)

    if not folder.is_dir():
        raise NotADirectoryError(f"Not a directory: {folder}")

    folder_id = register_folder(folder, db_path)

    # Do not alter the baseline until a complete scan succeeds.
    fingerprints = scan_folder(folder)

    save_baseline(
        folder_id,
        create_baseline(fingerprints),
        db_path,
    )

    return {
        "folder_id": folder_id,
        "folder_path": str(folder),
        "file_count": len(fingerprints),
        "baseline_updated": True,
    }
