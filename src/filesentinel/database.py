
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "filesentinel.db"


def get_connection(db_path: str | Path = DEFAULT_DB_PATH):
    """Open a SQLite connection and enable foreign-key enforcement."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """Create the tables required by FileSentinel."""
    with get_connection(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitored_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_path TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_baselines (
                folder_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (folder_id, file_path),
                FOREIGN KEY (folder_id)
                    REFERENCES monitored_folders(id)
                    ON DELETE CASCADE
            );

            
            CREATE TABLE IF NOT EXISTS observed_files (
                folder_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                PRIMARY KEY (folder_id, file_path),
                FOREIGN KEY (folder_id)
                    REFERENCES monitored_folders(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS observed_state (
                folder_id INTEGER PRIMARY KEY,
                initialized_at TEXT NOT NULL,
                FOREIGN KEY (folder_id)
                    REFERENCES monitored_folders(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_id INTEGER NOT NULL,
                event_type TEXT NOT NULL
                    CHECK (event_type IN ('modified', 'deleted', 'added')),
                file_path TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (folder_id)
                    REFERENCES monitored_folders(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_events_detected_at
            ON audit_events(detected_at);

            CREATE INDEX IF NOT EXISTS idx_events_folder
            ON audit_events(folder_id);

            CREATE TABLE IF NOT EXISTS baseline_state (
                folder_id INTEGER PRIMARY KEY,
                initialized_at TEXT NOT NULL,
                FOREIGN KEY (folder_id)
                    REFERENCES monitored_folders(id)
                    ON DELETE CASCADE
            );
            """
        )

def has_baseline(
    folder_id: int,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> bool:
    """Check whether a baseline has been initialized, even if it is empty."""
    with get_connection(db_path) as connection:
        row = connection.execute(
            "SELECT 1 FROM baseline_state WHERE folder_id = ?",
            (folder_id,),
        ).fetchone()

        return row is not None
    
def register_folder(
    folder_path: str | Path,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    """Register a folder and return its database ID."""
    path = Path(folder_path).expanduser().resolve(strict=True)

    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")

    with get_connection(db_path) as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO monitored_folders
                (folder_path, created_at)
            VALUES (?, ?)
            """,
            (str(path), datetime.now(timezone.utc).isoformat()),
        )

        row = connection.execute(
            "SELECT id FROM monitored_folders WHERE folder_path = ?",
            (str(path),),
        ).fetchone()

        return row["id"]



def save_baseline(
    folder_id: int,
    fingerprints: dict[str, str],
    db_path: str | Path = DEFAULT_DB_PATH,
) -> None:
    """Save a trusted baseline and synchronize the observed state atomically."""
    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection(db_path) as connection:
        # Replace the trusted baseline.
        connection.execute(
            "DELETE FROM file_baselines WHERE folder_id = ?",
            (folder_id,),
        )

        connection.executemany(
            """
            INSERT INTO file_baselines
                (folder_id, file_path, sha256, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            [
                (folder_id, path, digest, timestamp)
                for path, digest in fingerprints.items()
            ],
        )

        connection.execute(
            """
            INSERT INTO baseline_state (folder_id, initialized_at)
            VALUES (?, ?)
            ON CONFLICT(folder_id) DO UPDATE SET
                initialized_at = excluded.initialized_at
            """,
            (folder_id, timestamp),
        )

        # A newly accepted baseline is also the latest observed state.
        connection.execute(
            "DELETE FROM observed_files WHERE folder_id = ?",
            (folder_id,),
        )

        connection.executemany(
            """
            INSERT INTO observed_files (folder_id, file_path, sha256)
            VALUES (?, ?, ?)
            """,
            [
                (folder_id, path, digest)
                for path, digest in fingerprints.items()
            ],
        )

        # Mark the state initialized even if fingerprints is empty.
        connection.execute(
            """
            INSERT INTO observed_state (folder_id, initialized_at)
            VALUES (?, ?)
            ON CONFLICT(folder_id) DO UPDATE SET
                initialized_at = excluded.initialized_at
            """,
            (folder_id, timestamp),
        )


def load_baseline(
    folder_id: int,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, str]:
    """Load the stored fingerprints for a registered folder."""
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT file_path, sha256
            FROM file_baselines
            WHERE folder_id = ?
            """,
            (folder_id,),
        ).fetchall()

        return {row["file_path"]: row["sha256"] for row in rows}



def record_events(
    folder_id: int,
    events: list[dict[str, str | None]],
    db_path: str | Path = DEFAULT_DB_PATH,
) -> None:
    """Persist newly observed event states with UTC timestamps."""
    if not events:
        return

    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection(db_path) as connection:
        for event in events:
            event_type = event["type"]
            file_path = event["path"]
            old_hash = event["old_hash"]
            new_hash = event["new_hash"]

            # Skip only if this exact event state has already been logged
            # for this folder and path.
            existing = connection.execute(
                """
                SELECT 1
                FROM audit_events
                WHERE folder_id = ?
                  AND file_path = ?
                  AND event_type = ?
                  AND old_hash IS ?
                  AND new_hash IS ?
                LIMIT 1
                """,
                (
                    folder_id,
                    file_path,
                    event_type,
                    old_hash,
                    new_hash,
                ),
            ).fetchone()

            if existing is not None:
                continue

            connection.execute(
                """
                INSERT INTO audit_events (
                    folder_id, event_type, file_path,
                    old_hash, new_hash, detected_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    folder_id,
                    event_type,
                    file_path,
                    old_hash,
                    new_hash,
                    timestamp,
                ),
            )


def list_folders(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict]:
    """Return all registered folders."""
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, folder_path, created_at
            FROM monitored_folders
            ORDER BY id
            """
        ).fetchall()

        return [dict(row) for row in rows]


def list_events(
    db_path: str | Path = DEFAULT_DB_PATH,
    limit: int = 100,
) -> list[dict]:
    """Return recent audit events, newest first."""
    if limit < 1:
        raise ValueError("limit must be positive")

    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                e.id, f.folder_path, e.event_type, e.file_path,
                e.old_hash, e.new_hash, e.detected_at
            FROM audit_events e
            JOIN monitored_folders f ON f.id = e.folder_id
            ORDER BY e.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]


def load_observed_state(
    folder_id: int,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, str]:
    """Load the most recently observed file fingerprints."""
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT file_path, sha256
            FROM observed_files
            WHERE folder_id = ?
            """,
            (folder_id,),
        ).fetchall()

        return {row["file_path"]: row["sha256"] for row in rows}


def record_events_and_update_observed(
    folder_id: int,
    events: list[dict[str, str | None]],
    current: dict[str, str],
    db_path: str | Path = DEFAULT_DB_PATH,
) -> None:
    """Record detected transitions and atomically save the latest state."""
    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection(db_path) as connection:
        connection.executemany(
            """
            INSERT INTO audit_events (
                folder_id, event_type, file_path,
                old_hash, new_hash, detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    folder_id,
                    event["type"],
                    event["path"],
                    event["old_hash"],
                    event["new_hash"],
                    timestamp,
                )
                for event in events
            ],
        )
        connection.execute(
            """
            INSERT INTO observed_state (folder_id, initialized_at)
            VALUES (?, ?)
            ON CONFLICT(folder_id) DO UPDATE SET
                initialized_at = excluded.initialized_at
            """,
            (folder_id, timestamp),
        )
        connection.execute(
            "DELETE FROM observed_files WHERE folder_id = ?",
            (folder_id,),
        )

        connection.executemany(
            """
            INSERT INTO observed_files (folder_id, file_path, sha256)
            VALUES (?, ?, ?)
            """,
            [
                (folder_id, path, digest)
                for path, digest in current.items()
            ],
        )

def has_observed_state(
    folder_id: int,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> bool:
    """Return whether observed-state tracking has been initialized."""
    with get_connection(db_path) as connection:
        row = connection.execute(
            "SELECT 1 FROM observed_state WHERE folder_id = ?",
            (folder_id,),
        ).fetchone()

        return row is not None