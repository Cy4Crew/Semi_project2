from __future__ import annotations

import re
import zipfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.config import settings
from app.models.report_models import UploadResponse
from app.services.job_service import submit_report
from app.services.report_service import create_report_job

router = APIRouter(prefix="/api/samples", tags=["samples"])

_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")
_DANGEROUS_ZIP_PARTS = {"..", ""}
_NESTED_ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".iso"}


def _safe_upload_name(name: str | None) -> str:
    candidate = Path(name or "sample.zip").name
    candidate = _FILENAME_SAFE_RE.sub("_", candidate).strip("._") or "sample.zip"
    if not candidate.lower().endswith(".zip"):
        candidate += ".zip"
    return candidate


def _allowed_content_types() -> set[str]:
    return {x.strip().lower() for x in settings.allowed_upload_content_types.split(",") if x.strip()}


def _content_type_allowed(content_type: str) -> bool:
    if not content_type:
        return True
    lowered = content_type.lower()
    if lowered in {"application/octet-stream", "binary/octet-stream"}:
        return True
    return lowered in _allowed_content_types()


def _unique_sample_path(safe_name: str) -> Path:
    sample_dir = Path(settings.samples_dir)
    sample_dir.mkdir(parents=True, exist_ok=True)
    path = sample_dir / safe_name
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    counter = 1
    while True:
        candidate = sample_dir / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def _validate_zip_archive(sample_path: Path) -> None:
    with zipfile.ZipFile(sample_path) as zf:
        infos = zf.infolist()
        file_count = 0
        total_uncompressed = 0
        nested_archive_count = 0

        for info in infos:
            name = info.filename or ""
            normalized_parts = Path(name.replace("\\", "/")).parts
            if Path(name).is_absolute() or any(part in _DANGEROUS_ZIP_PARTS for part in normalized_parts):
                raise HTTPException(status_code=400, detail=f"Unsafe ZIP path detected: {name}")

            if info.flag_bits & 0x1 and bool(settings.reject_encrypted_archives):
                raise HTTPException(status_code=400, detail="Encrypted ZIP entries are not supported.")

            if info.is_dir():
                continue

            file_count += 1
            entry_size = int(info.file_size)
            compressed_size = max(1, int(info.compress_size))
            total_uncompressed += entry_size
            ratio = entry_size / compressed_size

            if file_count > int(settings.max_archive_files):
                raise HTTPException(status_code=400, detail=f"ZIP contains too many files. Max {settings.max_archive_files}.")
            if total_uncompressed > int(settings.max_zip_total_uncompressed_bytes):
                raise HTTPException(status_code=400, detail=f"ZIP uncompressed size exceeds limit: {settings.max_zip_total_uncompressed_bytes} bytes.")
            if entry_size > int(settings.max_zip_entry_uncompressed_bytes):
                raise HTTPException(status_code=400, detail=f"ZIP entry too large: {name}")
            if ratio > float(settings.max_zip_compression_ratio):
                raise HTTPException(status_code=400, detail=f"ZIP entry compression ratio too high: {name}")

            suffix = Path(name).suffix.lower()
            if suffix in _NESTED_ARCHIVE_SUFFIXES:
                nested_archive_count += 1
                if nested_archive_count > int(settings.max_zip_depth_hint):
                    raise HTTPException(status_code=400, detail="Too many nested archives inside ZIP.")


@router.post("/upload", response_model=UploadResponse)
async def upload_sample(file: UploadFile = File(...)):
    safe_name = _safe_upload_name(file.filename)
    if Path(safe_name).suffix.lower() != ".zip":
        raise HTTPException(status_code=400, detail="Only .zip uploads are supported in this demo.")

    content_type = (file.content_type or "").lower()
    if not _content_type_allowed(content_type):
        raise HTTPException(status_code=400, detail=f"Unsupported content type: {content_type}")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty upload.")
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail=f"Upload too large. Max {settings.max_upload_bytes} bytes.")

    sample_path = _unique_sample_path(safe_name)
    sample_path.write_bytes(data)

    if not zipfile.is_zipfile(sample_path):
        sample_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive.")

    try:
        _validate_zip_archive(sample_path)
    except HTTPException:
        sample_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        sample_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Invalid ZIP archive: {exc}")

    try:
        report = create_report_job(str(sample_path), safe_name)
    except Exception:
        sample_path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    submit_report(report["report_id"])
    return UploadResponse(
        report_id=report["report_id"],
        filename=report["filename"],
        verdict=report["verdict"],
        risk_score=report["risk_score"],
        summary=report["summary"],
        status=report.get("status"),
    )
