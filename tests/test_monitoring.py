
from pathlib import Path

import pytest

import src.filesentinel.monitoring as monitoring
from src.filesentinel.database import load_baseline, list_events


def test_initialization_creates_baseline(tmp_path: Path):
    folder = tmp_path / "protected"
    folder.mkdir()
    (folder / "a.txt").write_text("original", encoding="utf-8")

    db = tmp_path / "test.db"

    result = monitoring.initialize_folder(folder, db)

    assert result["baseline_created"] is True
    assert result["file_count"] == 1
    assert len(load_baseline(result["folder_id"], db)) == 1


def test_check_detects_modification(tmp_path: Path):
    folder = tmp_path / "protected"
    folder.mkdir()

    file_path = folder / "a.txt"
    file_path.write_text("original", encoding="utf-8")
    db = tmp_path / "test.db"

    monitoring.initialize_folder(folder, db)

    file_path.write_text("changed", encoding="utf-8")
    result = monitoring.check_folder(folder, db)

    assert result["changes_detected"] == 1
    assert result["events"][0]["type"] == "modified"
    assert len(list_events(db)) == 1


def test_repeated_initialization_does_not_replace_baseline(
    tmp_path: Path,
):
    folder = tmp_path / "protected"
    folder.mkdir()

    file_path = folder / "a.txt"
    file_path.write_text("original", encoding="utf-8")
    db = tmp_path / "test.db"

    first = monitoring.initialize_folder(folder, db)
    baseline_before = load_baseline(first["folder_id"], db)

    file_path.write_text("changed", encoding="utf-8")
    second = monitoring.initialize_folder(folder, db)
    baseline_after = load_baseline(first["folder_id"], db)

    assert second["baseline_created"] is False
    assert baseline_after == baseline_before


def test_failed_scan_does_not_change_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    folder = tmp_path / "protected"
    folder.mkdir()

    file_path = folder / "a.txt"
    file_path.write_text("original", encoding="utf-8")
    db = tmp_path / "test.db"

    result = monitoring.initialize_folder(folder, db)
    baseline_before = load_baseline(result["folder_id"], db)

    def failed_scan(_folder):
        raise OSError("Simulated incomplete scan")

    monkeypatch.setattr(monitoring, "scan_folder", failed_scan)

    with pytest.raises(OSError, match="Simulated incomplete scan"):
        monitoring.check_folder(folder, db)

    assert load_baseline(result["folder_id"], db) == baseline_before
    assert list_events(db) == []


def test_empty_folder_can_have_a_baseline(tmp_path: Path):
    folder = tmp_path / "empty"
    folder.mkdir()
    db = tmp_path / "test.db"

    result = monitoring.initialize_folder(folder, db)

    assert result["baseline_created"] is True
    assert result["file_count"] == 0

    # A second initialization must recognize the empty baseline.
    second = monitoring.initialize_folder(folder, db)
    assert second["baseline_created"] is False
