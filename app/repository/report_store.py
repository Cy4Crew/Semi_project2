from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.config import settings

REPORT_DIR = Path(settings.artifacts_dir) / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _path(report_id: str) -> Path:
    return REPORT_DIR / f"{report_id}.json"


def save_report(payload: dict[str, Any]) -> str:
    report_id = payload["report_id"]
    path = _path(report_id)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return report_id


def update_report(report_id: str, **updates: Any) -> str:
    current = get_report(report_id) or {"report_id": report_id}
    current.update(updates)
    return save_report(current)


def get_report(report_id: str) -> dict[str, Any] | None:
    path = _path(report_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_reports(limit: int = 30) -> list[dict[str, Any]]:
    items = []
    for path in sorted(REPORT_DIR.glob("*.json"), reverse=True):
        try:
            items.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            continue
        if len(items) >= limit:
            break
    return items
