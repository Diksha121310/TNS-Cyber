
import hashlib
import os
import stat
from pathlib import Path


CHUNK_SIZE = 65536


def calculate_sha256(file_path: Path) -> str:
    """Calculate a file's SHA-256 hash and detect changes during reading."""
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        before = os.fstat(file.fileno())

        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"Not a regular file: {file_path}")

        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            sha256.update(chunk)

        after = os.fstat(file.fileno())

    # Detect ordinary concurrent writes while hashing.
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise OSError(
            f"File changed while being hashed; retry the scan: {file_path}"
        )

    return sha256.hexdigest()


def _raise_walk_error(error: OSError) -> None:
    """Make os.walk traversal failures visible to the caller."""
    raise error


def scan_folder(folder_path: str | Path) -> dict[str, str]:
    """
    Recursively hash regular files.

    Raises OSError if traversal or file reading fails. Callers must discard
    the scan result on failure and must not infer deletions from a partial scan.
    """
    root = Path(folder_path).expanduser().resolve(strict=True)

    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    fingerprints: dict[str, str] = {}

    for current_root, directories, filenames in os.walk(
        root,
        topdown=True,
        onerror=_raise_walk_error,
        followlinks=False,
    ):
        current = Path(current_root)

        # Do not traverse symbolic-link directories.
        directories[:] = [
            name
            for name in directories
            if not (current / name).is_symlink()
        ]

        for filename in filenames:
            file_path = current / filename

            try:
                if file_path.is_symlink():
                    continue

                if not file_path.is_file():
                    continue

                resolved_path = str(file_path.resolve(strict=True))
                fingerprints[resolved_path] = calculate_sha256(file_path)

            except OSError as exc:
                raise OSError(
                    f"Could not complete scan for {file_path}: {exc}"
                ) from exc

    return fingerprints
