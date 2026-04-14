
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services.whitelist_service import refresh_whitelist


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def build_rule_manifest(refresh: bool = False) -> dict[str, Any]:
    if refresh:
        refresh_whitelist()
    root = Path(settings.yara_rules_dir)
    files = []
    for path in sorted(root.glob('*')):
        if path.is_file():
            files.append({
                'name': path.name,
                'size_bytes': path.stat().st_size,
                'sha256': _sha256(path),
                'updated_at': path.stat().st_mtime,
                'category': 'whitelist' if path.name.endswith('benign_whitelist.json') else ('suricata' if path.suffix == '.rules' else 'yara'),
            })
    return {'rule_root': str(root), 'total_files': len(files), 'files': files}
