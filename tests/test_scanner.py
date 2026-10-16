
from pathlib import Path

import pytest

from src.filesentinel.scanner import calculate_sha256, scan_folder


def test_same_content_produces_same_hash(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("FileSentinel test", encoding="utf-8")

    assert calculate_sha256(file_path) == calculate_sha256(file_path)


def test_modified_content_changes_hash(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("original", encoding="utf-8")
    original_hash = calculate_sha256(file_path)

    file_path.write_text("modified", encoding="utf-8")

    assert calculate_sha256(file_path) != original_hash


def test_scan_includes_nested_files(tmp_path: Path):
    nested = tmp_path / "nested"
    nested.mkdir()

    (tmp_path / "root.txt").write_text("root", encoding="utf-8")
    (nested / "child.txt").write_text("child", encoding="utf-8")

    result = scan_folder(tmp_path)

    assert len(result) == 2
    assert str((tmp_path / "root.txt").resolve()) in result
    assert str((nested / "child.txt").resolve()) in result


def test_scan_rejects_file_instead_of_folder(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("test", encoding="utf-8")

    with pytest.raises(NotADirectoryError):
        scan_folder(file_path)


def test_scan_fails_when_directory_traversal_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import os

    folder = tmp_path / "protected"
    folder.mkdir()

    def fail_walk(*args, **kwargs):
        raise PermissionError("Access denied")

    monkeypatch.setattr(os, "walk", fail_walk)

    with pytest.raises(PermissionError, match="Access denied"):
        scan_folder(folder)


def test_hash_fails_if_file_changes_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import os

    file_path = tmp_path / "changing.txt"
    file_path.write_text("original", encoding="utf-8")

    original_fstat = os.fstat
    calls = 0

    def changing_fstat(fd):
        nonlocal calls
        calls += 1
        result = original_fstat(fd)

        if calls == 2:
            # Simulate changed metadata after reading.
            class ChangedStat:
                st_mode = result.st_mode
                st_size = result.st_size + 1
                st_mtime_ns = result.st_mtime_ns

            return ChangedStat()

        return result

    monkeypatch.setattr(os, "fstat", changing_fstat)

    with pytest.raises(OSError, match="changed while being hashed"):
        calculate_sha256(file_path)
