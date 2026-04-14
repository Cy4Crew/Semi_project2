from __future__ import annotations

from pathlib import Path
import hashlib

def _file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return ""

def snapshot_tree(root: str) -> dict[str, str]:
    root_path = Path(root)
    snap = {}
    if not root_path.exists():
        return snap
    for p in root_path.rglob("*"):
        if p.is_file():
            snap[str(p)] = _file_hash(p)
    return snap

def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> dict:
    created = sorted([p for p in after if p not in before])
    changed = sorted([p for p in after if p in before and before[p] != after[p]])
    deleted = sorted([p for p in before if p not in after])
    return {"created": created[:100], "changed": changed[:100], "deleted": deleted[:100]}
