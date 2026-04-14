from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from app.core.config import settings
from app.db.migrations import ensure_database_ready

DB_PATH = Path(settings.report_db_path)
_LOCK = Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    ensure_database_ready()
    conn = sqlite3.connect(DB_PATH, timeout=max(1.0, float(settings.report_db_busy_timeout_ms) / 1000.0))
    conn.execute(f"PRAGMA busy_timeout={int(settings.report_db_busy_timeout_ms)}")
    return conn


def ensure_metrics_store() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    ensure_database_ready()


def record_stage_metric(report_id: str | None, stage: str, status: str, duration_ms: int | None = None, reason: str | None = None, payload: dict[str, Any] | None = None) -> None:
    ensure_metrics_store()
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO analysis_metrics(report_id, stage, status, duration_ms, reason, created_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(report_id or ""),
                str(stage or "unknown"),
                str(status or "unknown"),
                None if duration_ms is None else int(duration_ms),
                str(reason or "")[:500],
                _utc_now(),
                json.dumps(payload or {}, ensure_ascii=False),
            ),
        )
        conn.commit()


def record_event(event_type: str, message: str, report_id: str | None = None, payload: dict[str, Any] | None = None) -> None:
    ensure_metrics_store()
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO app_events(report_id, event_type, message, created_at, payload_json) VALUES (?, ?, ?, ?, ?)",
            (
                str(report_id or ""),
                str(event_type or "info"),
                str(message or "")[:1000],
                _utc_now(),
                json.dumps(payload or {}, ensure_ascii=False),
            ),
        )
        conn.commit()


def stage_summary(limit: int = 2000) -> dict[str, dict[str, Any]]:
    ensure_metrics_store()
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT stage, status, duration_ms, reason FROM analysis_metrics ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for stage, status, duration_ms, reason in rows:
        bucket = out.setdefault(str(stage or 'unknown'), {
            'count': 0,
            'ok': 0,
            'failed': 0,
            'avg_duration_ms': 0,
            '_dur_total': 0,
            '_dur_count': 0,
            'top_reasons': {},
        })
        bucket['count'] += 1
        if str(status).lower() in {'ok', 'done', 'success', 'queued'}:
            bucket['ok'] += 1
        else:
            bucket['failed'] += 1
        if duration_ms is not None:
            bucket['_dur_total'] += int(duration_ms)
            bucket['_dur_count'] += 1
        if reason:
            bucket['top_reasons'][str(reason)] = bucket['top_reasons'].get(str(reason), 0) + 1
    for bucket in out.values():
        if bucket['_dur_count']:
            bucket['avg_duration_ms'] = int(bucket['_dur_total'] / bucket['_dur_count'])
        bucket['top_reasons'] = sorted(bucket['top_reasons'].items(), key=lambda x: (-x[1], x[0]))[:5]
        bucket.pop('_dur_total', None)
        bucket.pop('_dur_count', None)
    return out


def top_failure_reasons(limit: int = 10) -> list[dict[str, Any]]:
    ensure_metrics_store()
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT reason, COUNT(*) AS cnt FROM analysis_metrics WHERE status NOT IN ('ok','done','success','queued') AND COALESCE(reason,'') != '' GROUP BY reason ORDER BY cnt DESC, reason ASC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [{'reason': str(reason), 'count': int(cnt)} for reason, cnt in rows]


def recent_events(limit: int = 20) -> list[dict[str, Any]]:
    ensure_metrics_store()
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT report_id, event_type, message, created_at FROM app_events ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [
        {'report_id': str(report_id or ''), 'event_type': str(event_type), 'message': str(message), 'created_at': str(created_at)}
        for report_id, event_type, message, created_at in rows
    ]
