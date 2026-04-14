from __future__ import annotations

import shutil
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
EXCLUDE_PARTS = {"__pycache__", ".pytest_cache", ".git", "dist"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}

def should_skip(path: Path) -> bool:
    if any(part in EXCLUDE_PARTS for part in path.parts):
        return True
    if path.suffix.lower() in EXCLUDE_SUFFIXES:
        return True
    return False

def main() -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    out = DIST / "Semi_project2-main_phase3_ui_cicd_refactor_FIXED.zip"
    if out.exists():
        out.unlink()
    with ZipFile(out, "w", compression=ZIP_DEFLATED) as zf:
        for path in sorted(ROOT.rglob("*")):
            if path.is_dir() or should_skip(path):
                continue
            zf.write(path, path.relative_to(ROOT))
    print(out)

if __name__ == "__main__":
    main()
