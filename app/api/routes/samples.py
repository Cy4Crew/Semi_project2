from __future__ import annotations

import re
import zipfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.config import settings
from app.models.report_models import UploadResponse
from app.services.report_service import build_report

router = APIRouter(prefix="/api/samples", tags=["samples"])

_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_upload_name(name: str | None) -> str:
    candidate = Path(name or "sample.zip").name
    candidate = _FILENAME_SAFE_RE.sub("_", candidate).strip("._") or "sample.zip"
    if not candidate.lower().endswith(".zip"):
        candidate += ".zip"
    return candidate


def _allowed_content_types() -> set[str]:
    return {x.strip().lower() for x in settings.allowed_upload_content_types.split(",") if x.strip()}


@router.post("/upload", response_model=UploadResponse)
async def upload_sample(file: UploadFile = File(...)):
    safe_name = _safe_upload_name(file.filename)
    if Path(safe_name).suffix.lower() != ".zip":
        raise HTTPException(status_code=400, detail="Only .zip uploads are supported in this demo.")

    content_type = (file.content_type or "").lower()
    if content_type and content_type not in _allowed_content_types():
        raise HTTPException(status_code=400, detail=f"Unsupported content type: {content_type}")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty upload.")
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail=f"Upload too large. Max {settings.max_upload_bytes} bytes.")

    sample_dir = Path(settings.samples_dir)
    sample_dir.mkdir(parents=True, exist_ok=True)
    sample_path = sample_dir / safe_name
    sample_path.write_bytes(data)

    if not zipfile.is_zipfile(sample_path):
        sample_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive.")

    try:
        with zipfile.ZipFile(sample_path) as zf:
            file_count = sum(1 for info in zf.infolist() if not info.is_dir())
            total_uncompressed = sum(int(info.file_size) for info in zf.infolist())
            if file_count > settings.max_archive_files:
                raise HTTPException(status_code=400, detail=f"ZIP contains too many files. Max {settings.max_archive_files}.")
            if total_uncompressed > settings.max_zip_total_uncompressed_bytes:
                raise HTTPException(status_code=400, detail=f"ZIP uncompressed size exceeds limit: {settings.max_zip_total_uncompressed_bytes} bytes.")
    except HTTPException:
        sample_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        sample_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Invalid ZIP archive: {exc}")

    try:
        report = build_report(str(sample_path), safe_name)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"analysis_failed: {e}")

    return UploadResponse(
        report_id=report["report_id"],
        filename=report["filename"],
        verdict=report["verdict"],
        risk_score=report["risk_score"],
        summary=report["summary"],
        status=report.get("status"),
    )
