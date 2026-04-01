
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from app.core.config import settings

REPORT_DIR = Path(settings.artifacts_dir) / "reports"
DB_PATH = Path(settings.report_db_path)
_REPORT_LOCK = Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_report_store() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(f"PRAGMA busy_timeout={int(settings.report_db_busy_timeout_ms)}")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                status TEXT,
                filename TEXT,
                verdict TEXT,
                risk_score INTEGER,
                updated_at TEXT,
                created_at TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_updated_at ON reports(updated_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")
        conn.commit()


ensure_report_store()

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=max(1.0, float(settings.report_db_busy_timeout_ms) / 1000.0))
    conn.execute(f"PRAGMA busy_timeout={int(settings.report_db_busy_timeout_ms)}")
    return conn


def _normalize_payload(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    current = dict(existing or {})
    current.update(payload)
    timestamps = dict(existing.get("timestamps", {}) if isinstance(existing, dict) else {})
    timestamps.update(current.get("timestamps") or {})
    if "created_at" not in timestamps:
        timestamps["created_at"] = timestamps.get("queued_at") or _utc_now()
    timestamps["updated_at"] = _utc_now()
    current["timestamps"] = timestamps
    return current


def _upsert_payload(conn: sqlite3.Connection, payload: dict[str, Any]) -> None:
    ts = payload.get("timestamps") or {}
    conn.execute(
        """
        INSERT INTO reports(report_id, status, filename, verdict, risk_score, updated_at, created_at, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(report_id) DO UPDATE SET
            status=excluded.status,
            filename=excluded.filename,
            verdict=excluded.verdict,
            risk_score=excluded.risk_score,
            updated_at=excluded.updated_at,
            created_at=excluded.created_at,
            payload_json=excluded.payload_json
        """,
        (
            str(payload["report_id"]),
            str(payload.get("status") or ""),
            str(payload.get("filename") or ""),
            str(payload.get("verdict") or ""),
            int(payload.get("risk_score") or 0),
            str(ts.get("updated_at") or ""),
            str(ts.get("created_at") or ""),
            json.dumps(payload, ensure_ascii=False),
        ),
    )


def save_report(payload: dict[str, Any]) -> str:
    ensure_report_store()
    report_id = str(payload["report_id"])
    with _REPORT_LOCK, _connect() as conn:
        row = conn.execute("SELECT payload_json FROM reports WHERE report_id = ?", (report_id,)).fetchone()
        existing = json.loads(row[0]) if row and row[0] else None
        normalized = _normalize_payload(payload, existing)
        _upsert_payload(conn, normalized)
        conn.commit()
    return report_id


def update_report(report_id: str, **updates: Any) -> str:
    ensure_report_store()
    with _REPORT_LOCK, _connect() as conn:
        row = conn.execute("SELECT payload_json FROM reports WHERE report_id = ?", (report_id,)).fetchone()
        current = json.loads(row[0]) if row and row[0] else {"report_id": report_id}
        current.update(updates)
        normalized = _normalize_payload(current)
        _upsert_payload(conn, normalized)
        conn.commit()
    return report_id


def get_report(report_id: str) -> dict[str, Any] | None:
    ensure_report_store()
    with _REPORT_LOCK, _connect() as conn:
        row = conn.execute("SELECT payload_json FROM reports WHERE report_id = ?", (report_id,)).fetchone()
    if not row or not row[0]:
        return None
    return json.loads(row[0])


def list_reports(limit: int = 30) -> list[dict[str, Any]]:
    ensure_report_store()
    with _REPORT_LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT payload_json FROM reports ORDER BY updated_at DESC, report_id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        try:
            items.append(json.loads(row[0]))
        except Exception:
            continue
    return items[:limit]
