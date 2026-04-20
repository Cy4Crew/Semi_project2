"""
file_diff.py
위치: guest_tools/file_diff.py
실행 환경: VMware Guest (Windows 10 VM)

역할:
  - 샘플 실행 전/후 파일시스템 스냅샷 비교
  - TEMP, APPDATA, Startup 등 실제 Windows 경로 스캔
  - 신규 exe/dll/lnk/txt 등 분류 및 해시 기록
  - dropped_files.json 생성 (outbox로 저장)
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

# ──────────────────────────────────────────────
# 스캔 대상 Windows 경로 (환경변수 우선, 없으면 기본값)
# ──────────────────────────────────────────────
def _get_scan_roots() -> list[Path]:
    user_profile = os.environ.get("USERPROFILE", r"C:\Users\sandbox")
    appdata      = os.environ.get("APPDATA",      rf"{user_profile}\AppData\Roaming")
    localappdata = os.environ.get("LOCALAPPDATA", rf"{user_profile}\AppData\Local")
    temp         = os.environ.get("TEMP",         rf"{localappdata}\Temp")

    roots = [
        Path(temp),                                                                        # %TEMP%
        Path(appdata),                                                                     # %APPDATA%
        Path(localappdata),                                                                # %LOCALAPPDATA%
        Path(appdata)  / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup", # 사용자 Startup
        Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),             # 공용 Startup
        Path(r"C:\Windows\Temp"),                                                          # Windows Temp
        Path(r"C:\Windows\System32"),                                                      # System32 (신규 dll 감지)
        Path(r"C:\Windows\SysWOW64"),                                                      # 32bit dll
        Path(user_profile) / "Desktop",                                                   # 바탕화면 (랜섬노트 자주 여기)
        Path(user_profile) / "Documents",                                                  # 문서
        Path(user_profile) / "Downloads",
    ]
    # 존재하는 경로만 반환
    return [r for r in roots if r.exists()]


# ──────────────────────────────────────────────
# 탐지 대상 파일 분류 기준
# ──────────────────────────────────────────────
BINARY_SUFFIXES   = {".exe", ".dll", ".com", ".scr", ".sys"}
SCRIPT_SUFFIXES   = {".ps1", ".bat", ".cmd", ".js", ".vbs", ".py", ".hta"}
DOCUMENT_SUFFIXES = {".docm", ".xlsm", ".doc", ".docx", ".xls", ".xlsx"}
SHORTCUT_SUFFIXES = {".lnk"}
TEXT_SUFFIXES     = {".txt", ".html", ".htm"}

RANSOM_NOTE_STEMS = {
    "readme", "decrypt", "how_to", "restore", "recover",
    "your_files", "files_encrypted", "read_me", "help_decrypt",
    "attention", "important", "instructions",
}

STARTUP_MARKERS = {
    "start menu\\programs\\startup",
    "startmenu\\programs\\startup",
}

# System32/SysWOW64 안 노이즈 제외 (윈도우 자체 업데이트 파일)
NOISE_SUFFIXES = {".mui", ".cat", ".manifest", ".log", ".etl", ".tmp"}


# ──────────────────────────────────────────────
# 핵심 유틸
# ──────────────────────────────────────────────
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


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except Exception:
        return -1


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ──────────────────────────────────────────────
# 분류 함수
# ──────────────────────────────────────────────
def is_ransom_note(path_str: str) -> bool:
    """파일명/경로 기준으로 랜섬노트 여부 판별."""
    p = Path(path_str)
    suffix = p.suffix.lower()
    stem   = p.stem.lower().replace(" ", "_").replace("-", "_")

    if suffix not in TEXT_SUFFIXES and suffix not in {".bmp", ".png"}:
        return False
    return any(keyword in stem for keyword in RANSOM_NOTE_STEMS)


def classify_file(path_str: str) -> str:
    """
    파일 경로를 받아 카테고리 문자열 반환.
    우선순위: ransom_note > startup_drop > binary_drop > script_drop
              > document_drop > shortcut_drop > other_drop
    """
    p      = Path(path_str)
    suffix = p.suffix.lower()
    lower  = path_str.lower().replace("/", "\\")

    if is_ransom_note(path_str):
        return "ransom_note"
    if any(marker in lower for marker in STARTUP_MARKERS):
        return "startup_drop"
    if suffix in BINARY_SUFFIXES:
        return "binary_drop"
    if suffix in SCRIPT_SUFFIXES:
        return "script_drop"
    if suffix in DOCUMENT_SUFFIXES:
        return "document_drop"
    if suffix in SHORTCUT_SUFFIXES:
        return "shortcut_drop"
    return "other_drop"


def _is_noise(path: Path) -> bool:
    """스냅샷 비교에서 제외할 노이즈 파일 여부."""
    name   = path.name.lower()
    suffix = path.suffix.lower()
    # 내부 분석 로그 등 제외
    if name.endswith("_stdout.txt") or name.endswith("_stderr.txt"):
        return True
    if name in {"stdout.txt", "stderr.txt", "result.json", "job.json"}:
        return True
    if suffix in NOISE_SUFFIXES:
        return True
    return False


# ──────────────────────────────────────────────
# 스냅샷 / Diff 핵심 함수
# ──────────────────────────────────────────────
def take_snapshot(roots: list[Path] | None = None) -> dict[str, str]:
    """
    여러 경로를 재귀 스캔해 {절대경로: sha256} 딕셔너리 반환.
    roots=None 이면 SCAN_ROOTS 기본값 사용.
    """
    if roots is None:
        roots = _get_scan_roots()

    snap: dict[str, str] = {}
    for root in roots:
        try:
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                if _is_noise(p):
                    continue
                key = str(p)
                if key not in snap:          # 중복 경로 방지
                    snap[key] = _file_hash(p)
        except PermissionError:
            pass
        except Exception:
            pass
    return snap


def compare_snapshots(before: dict[str, str], after: dict[str, str]) -> dict:
    """
    before/after 스냅샷을 비교해 created/changed/deleted 분류.
    각 항목에 sha256, category, is_ransom_note, size_bytes 포함.
    """
    created_paths = [p for p in after if p not in before]
    changed_paths = [p for p in after if p in before and before[p] != after[p]]
    deleted_paths = [p for p in before if p not in after]

    def _enrich(path_str: str, sha256: str) -> dict:
        p = Path(path_str)
        return {
            "path":           path_str,
            "sha256":         sha256,
            "category":       classify_file(path_str),
            "is_ransom_note": is_ransom_note(path_str),
            "size_bytes":     _file_size(p),
            "ext":            p.suffix.lower(),
            "created_time":   _get_created_time(p),
        }

    created = sorted(created_paths)[:200]
    changed = sorted(changed_paths)[:100]
    deleted = sorted(deleted_paths)[:100]

    return {
        "created": [_enrich(p, after[p])  for p in created],
        "changed": [_enrich(p, after[p])  for p in changed],
        "deleted": [{"path": p, "sha256": before[p]} for p in deleted],
    }


# ──────────────────────────────────────────────
# dropped_files.json 저장
# ──────────────────────────────────────────────
def save_dropped_files(diff: dict, output_path: Path, scan_roots: list[Path] | None = None) -> None:
    """
    compare_snapshots() 결과를 받아 dropped_files.json 으로 저장.
    output_path: outbox/{report_id}/dropped_files.json
    """
    if scan_roots is None:
        scan_roots = _get_scan_roots()

    all_files = diff.get("created", []) + diff.get("changed", [])

    # 카테고리별 집계
    summary: dict[str, int] = {}
    for item in all_files:
        cat = item.get("category", "other_drop")
        summary[cat] = summary.get(cat, 0) + 1

    payload = {
        "scan_time":    _utc_now(),
        "scan_roots":   [str(r) for r in scan_roots],
        "dropped_files": all_files,
        "summary": {
            "total":         len(all_files),
            "binary_drop":   summary.get("binary_drop",   0),
            "script_drop":   summary.get("script_drop",   0),
            "document_drop": summary.get("document_drop", 0),
            "shortcut_drop": summary.get("shortcut_drop", 0),
            "startup_drop":  summary.get("startup_drop",  0),
            "ransom_note":   summary.get("ransom_note",   0),
            "other_drop":    summary.get("other_drop",    0),
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )