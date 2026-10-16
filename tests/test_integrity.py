
from src.filesentinel.integrity import create_baseline, detect_changes


def test_detects_modified_file():
    baseline = {"employee.csv": "hash_A"}
    current = {"employee.csv": "hash_B"}

    events = detect_changes(baseline, current)

    assert len(events) == 1
    assert events[0]["type"] == "modified"
    assert events[0]["path"] == "employee.csv"
    assert events[0]["old_hash"] == "hash_A"
    assert events[0]["new_hash"] == "hash_B"


def test_detects_deleted_file():
    baseline = {"config.json": "hash_A"}
    current = {}

    events = detect_changes(baseline, current)

    assert len(events) == 1
    assert events[0]["type"] == "deleted"
    assert events[0]["old_hash"] == "hash_A"
    assert events[0]["new_hash"] is None


def test_detects_added_file():
    baseline = {}
    current = {"notes.txt": "hash_A"}

    events = detect_changes(baseline, current)

    assert len(events) == 1
    assert events[0]["type"] == "added"
    assert events[0]["old_hash"] is None
    assert events[0]["new_hash"] == "hash_A"


def test_unchanged_files_produce_no_events():
    baseline = {
        "employee.csv": "hash_A",
        "config.json": "hash_B",
    }
    current = baseline.copy()

    assert detect_changes(baseline, current) == []


def test_detects_multiple_change_types():
    baseline = {
        "employee.csv": "hash_A",
        "config.json": "hash_B",
        "old.txt": "hash_C",
    }
    current = {
        "employee.csv": "hash_CHANGED",
        "config.json": "hash_B",
        "new.txt": "hash_D",
    }

    events = detect_changes(baseline, current)

    event_types = {event["type"] for event in events}

    assert len(events) == 3
    assert event_types == {"modified", "deleted", "added"}


def test_baseline_is_an_independent_copy():
    original = {"employee.csv": "hash_A"}

    baseline = create_baseline(original)
    original["employee.csv"] = "hash_B"

    assert baseline["employee.csv"] == "hash_A"
