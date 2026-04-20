"""
fs_monitor.py
위치: app/sandbox/fs_monitor.py
실행 환경: Docker 컨테이너

역할:
  - Docker 컨테이너 내부 artifact 디렉토리 스냅샷 비교 (로컬 백엔드 전용)
  - diff 결과에 sha256 해시 포함 (4번 수정: 기존에는 경로만 반환, 해시 유실됨)
  - VMware 백엔드 사용 시 실제 파일 탐지는 guest_tools/file_diff.py 에서 수행
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def _file_hash(path: Path) -> str:
    """SHA-256 해시 반환. 실패 시 빈 문자열."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def snapshot_tree(root: str) -> dict[str, str]:
    """
    디렉토리를 재귀 스캔해 {절대경로: sha256} 딕셔너리 반환.
    동일 함수 시그니처 유지 — dynamic_analysis_service.py 호환.
    """
    root_path = Path(root)
    snap: dict[str, str] = {}
    if not root_path.exists():
        return snap
    for p in root_path.rglob("*"):
        if p.is_file():
            snap[str(p)] = _file_hash(p)
    return snap


def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> dict:
    """
    before/after 스냅샷 비교.

    반환 형태 (4번 수정: 기존에는 경로 문자열 리스트만 반환, sha256 유실):
      created: [{"path": str, "sha256": str}, ...]
      changed: [{"path": str, "sha256": str}, ...]   ← after 기준 해시
      deleted: [{"path": str, "sha256": str}, ...]   ← before 기준 해시
    """
    created_paths = sorted(p for p in after if p not in before)
    changed_paths = sorted(p for p in after if p in before and before[p] != after[p])
    deleted_paths = sorted(p for p in before if p not in after)

    return {
        "created": [{"path": p, "sha256": after[p]}  for p in created_paths[:100]],
        "changed": [{"path": p, "sha256": after[p]}  for p in changed_paths[:100]],
        "deleted": [{"path": p, "sha256": before[p]} for p in deleted_paths[:100]],
    }