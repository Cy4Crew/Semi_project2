
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import settings


def _load_data() -> dict[str, Any]:
    path = Path(settings.benign_whitelist_path)
    if not settings.benign_whitelist_enabled or not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


@lru_cache(maxsize=1)
def get_whitelist() -> dict[str, Any]:
    return _load_data()


def refresh_whitelist() -> dict[str, Any]:
    get_whitelist.cache_clear()
    return get_whitelist()


def evaluate_benign_indicators(item: dict[str, Any]) -> dict[str, Any]:
    rules = get_whitelist()
    file_path = str(item.get("file") or "").lower()
    name = Path(file_path).name.lower()
    suffix = Path(file_path).suffix.lower()
    texts = "\n".join(str(x) for x in (item.get("decoded_texts") or [])[:20]).lower()
    hits: list[str] = []

    for marker in rules.get("path_contains", []) or []:
        if str(marker).lower() in file_path:
            hits.append(f"path:{marker}")
    for marker in rules.get("file_names", []) or []:
        if name == str(marker).lower():
            hits.append(f"name:{marker}")
    for marker in rules.get("suffixes", []) or []:
        if suffix == str(marker).lower():
            hits.append(f"suffix:{marker}")
    for marker in rules.get("text_markers", []) or []:
        if str(marker).lower() in texts:
            hits.append(f"text:{marker}")

    strength = 0
    if hits:
        strength = min(3, max(1, len(hits) // 2 + (1 if any(h.startswith("name:") for h in hits) else 0)))
    return {
        "benign_hits": hits[:10],
        "benign_strength": strength,
        "is_likely_benign": strength >= 2,
    }
