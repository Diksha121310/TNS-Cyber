
from pathlib import Path
from typing import Literal


ChangeType = Literal["modified", "deleted", "added"]


def create_baseline(
    fingerprints: dict[str, str],
) -> dict[str, str]:
    """
    Create an independent snapshot of the current file fingerprints.

    The caller is responsible for ensuring the initial scan completed
    successfully and the baseline is stored in a trusted location.
    """
    return dict(fingerprints)


def detect_changes(
    baseline: dict[str, str],
    current: dict[str, str],
) -> list[dict[str, str | None]]:
    """
    Compare a trusted baseline with a complete current scan.

    Each event contains:
        type: modified, deleted, or added
        path: absolute file path
        old_hash: baseline hash, if available
        new_hash: current hash, if available
    """
    events: list[dict[str, str | None]] = []

    baseline_paths = set(baseline)
    current_paths = set(current)

    # Files that existed in both snapshots may have changed content.
    for path in sorted(baseline_paths & current_paths):
        old_hash = baseline[path]
        new_hash = current[path]

        if old_hash != new_hash:
            events.append({
                "type": "modified",
                "path": path,
                "old_hash": old_hash,
                "new_hash": new_hash,
            })

    # Files present before but absent in the current scan.
    for path in sorted(baseline_paths - current_paths):
        events.append({
            "type": "deleted",
            "path": path,
            "old_hash": baseline[path],
            "new_hash": None,
        })

    # Files absent before but present in the current scan.
    for path in sorted(current_paths - baseline_paths):
        events.append({
            "type": "added",
            "path": path,
            "old_hash": None,
            "new_hash": current[path],
        })

    return events
