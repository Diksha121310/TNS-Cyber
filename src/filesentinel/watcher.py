
from pathlib import Path
from threading import Lock, Timer

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from src.filesentinel.database import (
    DEFAULT_DB_PATH,
    has_baseline,
    initialize_database,
    register_folder,
)
from src.filesentinel.monitoring import check_folder


# Keep observers alive across Streamlit reruns.
_observers: dict[str, Observer] = {}
_timers: dict[str, Timer] = {}
_locks: dict[str, Lock] = {}
_errors: dict[str, str] = {}
_guard = Lock()

DEBOUNCE_SECONDS = 1.0


def _check_after_event(folder: str, db_path: str) -> None:
    """Run one integrity check after a burst of filesystem events."""
    with _guard:
        lock = _locks.setdefault(folder, Lock())

    try:
        with lock:
            check_folder(folder, db_path)
            with _guard:
                _errors.pop(folder, None)
    except Exception as exc:
        with _guard:
            _errors[folder] = f"{type(exc).__name__}: {exc}"


class _ChangeHandler(FileSystemEventHandler):
    def __init__(self, folder: str, db_path: str):
        self.folder = folder
        self.db_path = db_path

    def on_any_event(self, event: FileSystemEvent) -> None:
        # Ignore directory changes only when they are irrelevant?
        # Directory events are retained because they may affect many files.
        with _guard:
            previous = _timers.get(self.folder)

            if previous is not None:
                previous.cancel()

            timer = Timer(
                DEBOUNCE_SECONDS,
                _check_after_event,
                args=(self.folder, self.db_path),
            )
            timer.daemon = True
            _timers[self.folder] = timer
            timer.start()


def start_watching(
    folder_path: str | Path,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> str:
    """Start recursive monitoring for a folder with an existing baseline."""
    initialize_database(db_path)

    folder = str(Path(folder_path).expanduser().resolve(strict=True))
    if not Path(folder).is_dir():
        raise NotADirectoryError(f"Not a directory: {folder}")

    folder_id = register_folder(folder, db_path)
    if not has_baseline(folder_id, db_path):
        raise RuntimeError(
            "Create a baseline for this folder before starting monitoring."
        )

    with _guard:
        existing = _observers.get(folder)
        if existing is not None and existing.is_alive():
            return folder

        observer = Observer()
        observer.schedule(
            _ChangeHandler(folder, str(Path(db_path).resolve())),
            folder,
            recursive=True,
        )
        observer.start()
        _observers[folder] = observer
        _locks.setdefault(folder, Lock())
        _errors.pop(folder, None)

    return folder


def stop_watching(folder_path: str | Path) -> bool:
    """Stop monitoring a folder. Return True if it was running."""
    folder = str(Path(folder_path).expanduser().resolve())

    with _guard:
        observer = _observers.pop(folder, None)
        timer = _timers.pop(folder, None)

    if timer is not None:
        timer.cancel()

    if observer is None:
        return False

    observer.stop()
    observer.join(timeout=5)
    return True


def is_watching(folder_path: str | Path) -> bool:
    folder = str(Path(folder_path).expanduser().resolve())

    with _guard:
        observer = _observers.get(folder)
        return observer is not None and observer.is_alive()


def get_watcher_error(folder_path: str | Path) -> str | None:
    folder = str(Path(folder_path).expanduser().resolve())

    with _guard:
        return _errors.get(folder)
