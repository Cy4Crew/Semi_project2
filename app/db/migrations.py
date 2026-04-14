from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Lock

from app.core.config import settings

DB_PATH = Path(settings.report_db_path)
_LOCK = Lock()
_LATEST_SCHEMA_VERSION = 3
_INITIALIZED = False


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=max(1.0, float(settings.report_db_busy_timeout_ms) / 1000.0))
    conn.execute(f"PRAGMA busy_timeout={int(settings.report_db_busy_timeout_ms)}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
        (table_name,),
    ).fetchone()
    return bool(row)


def _column_names(conn: sqlite3.Connection, table_name: str) -> set[str]:
    if not _table_exists(conn, table_name):
        return set()
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def _ensure_schema_version(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    row = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version(version) VALUES (0)")


def _current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
    return int(row[0]) if row else 0


def _set_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version(version) VALUES (?)", (int(version),))


def _migrate_v1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            status TEXT,
            filename TEXT,
            verdict TEXT,
            risk_score INTEGER,
            sample_sha256 TEXT,
            updated_at TEXT,
            created_at TEXT,
            payload_json TEXT NOT NULL
        )
        """
    )
    columns = _column_names(conn, 'reports')
    if 'sample_sha256' not in columns:
        conn.execute("ALTER TABLE reports ADD COLUMN sample_sha256 TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_updated_at ON reports(updated_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_sha256 ON reports(sample_sha256)")


def _migrate_v2(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT,
            stage TEXT,
            status TEXT,
            duration_ms INTEGER,
            reason TEXT,
            created_at TEXT,
            payload_json TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_metrics_created_at ON analysis_metrics(created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_metrics_stage ON analysis_metrics(stage)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_metrics_status ON analysis_metrics(status)")


def _migrate_v3(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT,
            event_type TEXT,
            message TEXT,
            created_at TEXT,
            payload_json TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_app_events_created_at ON app_events(created_at DESC)")


def initialize_database() -> None:
    global _INITIALIZED
    if _INITIALIZED:
        return
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        if _INITIALIZED:
            return
        with _connect() as conn:
            _ensure_schema_version(conn)
            version = _current_version(conn)
            if version < 1:
                _migrate_v1(conn)
                _set_version(conn, 1)
                version = 1
            if version < 2:
                _migrate_v2(conn)
                _set_version(conn, 2)
                version = 2
            if version < 3:
                _migrate_v3(conn)
                _set_version(conn, 3)
            conn.commit()
        _INITIALIZED = True


def ensure_database_ready() -> None:
    initialize_database()
