
from pathlib import Path

import pytest

from src.filesentinel.database import (
    initialize_database,
    register_folder,
    save_baseline,
    load_baseline,
    record_events,
    list_folders,
    list_events,
)


def test_database_initializes(tmp_path: Path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    assert db_path.exists()


def test_register_folder_and_save_baseline(tmp_path: Path):
    folder = tmp_path / "protected"
    folder.mkdir()

    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    folder_id = register_folder(folder, db_path)
    fingerprints = {str(folder / "a.txt"): "abc123"}

    save_baseline(folder_id, fingerprints, db_path)

    assert load_baseline(folder_id, db_path) == fingerprints
    assert len(list_folders(db_path)) == 1


def test_record_and_retrieve_audit_event(tmp_path: Path):
    folder = tmp_path / "protected"
    folder.mkdir()

    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    folder_id = register_folder(folder, db_path)

    record_events(
        folder_id,
        [{
            "type": "modified",
            "path": str(folder / "a.txt"),
            "old_hash": "old_hash",
            "new_hash": "new_hash",
        }],
        db_path,
    )

    events = list_events(db_path)

    assert len(events) == 1
    assert events[0]["event_type"] == "modified"
    assert events[0]["old_hash"] == "old_hash"
    assert events[0]["new_hash"] == "new_hash"
    assert events[0]["detected_at"]


def test_duplicate_folder_registration_is_idempotent(tmp_path: Path):
    folder = tmp_path / "protected"
    folder.mkdir()

    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    first_id = register_folder(folder, db_path)
    second_id = register_folder(folder, db_path)

    assert first_id == second_id
    assert len(list_folders(db_path)) == 1


def test_empty_event_list_is_accepted(tmp_path: Path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    folder = tmp_path / "protected"
    folder.mkdir()
    folder_id = register_folder(folder, db_path)

    record_events(folder_id, [], db_path)

    assert list_events(db_path) == []


def test_duplicate_audit_event_is_recorded_only_once(tmp_path: Path):
    folder = tmp_path / "protected"
    folder.mkdir()

    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    folder_id = register_folder(folder, db_path)

    event = {
        "type": "modified",
        "path": str(folder / "a.txt"),
        "old_hash": "old_hash",
        "new_hash": "new_hash",
    }

    # Record the same detected state twice.
    record_events(folder_id, [event], db_path)
    record_events(folder_id, [event], db_path)

    events = list_events(db_path)

    assert len(events) == 1
    assert events[0]["event_type"] == "modified"
    assert events[0]["file_path"] == str(folder / "a.txt")
    assert events[0]["old_hash"] == "old_hash"
    assert events[0]["new_hash"] == "new_hash"
