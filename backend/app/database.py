import json
import sqlite3
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).resolve().parents[2] / "securescope.db"


def init_db(db_path: Path = DB_PATH) -> None:
    """Create the scan history table if it does not exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                findings TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def save_scan(
    target: str,
    findings: list[dict[str, Any]],
    db_path: Path = DB_PATH,
) -> int:
    """Save scan findings and return the new scan ID."""
    init_db(db_path)

    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO scans (target, findings) VALUES (?, ?)",
            (target, json.dumps(findings)),
        )
        return int(cursor.lastrowid)


def get_scans(db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    """Return saved scans, newest first."""
    init_db(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, target, findings, created_at
            FROM scans
            ORDER BY id DESC
            """
        ).fetchall()

    return [
        {
            "id": row["id"],
            "target": row["target"],
            "findings": json.loads(row["findings"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]