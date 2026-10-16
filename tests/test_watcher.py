
from pathlib import Path

import pytest

from src.filesentinel.monitoring import initialize_folder
from src.filesentinel.watcher import (
    is_watching,
    start_watching,
    stop_watching,
)


def test_watcher_requires_existing_baseline(tmp_path: Path):
    folder = tmp_path / "protected"
    folder.mkdir()

    with pytest.raises(RuntimeError, match="baseline"):
        start_watching(folder, tmp_path / "test.db")


def test_watcher_starts_and_stops(tmp_path: Path):
    folder = tmp_path / "protected"
    folder.mkdir()
    (folder / "sample.txt").write_text("original", encoding="utf-8")

    db = tmp_path / "test.db"
    initialize_folder(folder, db)

    start_watching(folder, db)
    try:
        assert is_watching(folder)
    finally:
        stop_watching(folder)

    assert not is_watching(folder)