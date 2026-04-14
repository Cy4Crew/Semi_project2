from __future__ import annotations

import logging
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes.reports import router as reports_router
from app.api.routes.samples import router as samples_router
from app.core.config import settings
from app.db.migrations import initialize_database
from app.repository.report_store import ensure_report_store
from app.utils.logging_setup import request_id_var, setup_logging
from app.utils.metrics_store import ensure_metrics_store

logger = logging.getLogger(__name__)

app = FastAPI(title=settings.app_name)
BUILD_ID = "full-hardening-2026-04-12"
app.include_router(samples_router)
app.include_router(reports_router)

ui_root = Path(__file__).resolve().parents[1] / "ui"
static_dir = ui_root / "static"
templates = Jinja2Templates(directory=str(ui_root / "templates"))
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.on_event("startup")
def startup() -> None:
    setup_logging()
    Path(settings.samples_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.artifacts_dir).mkdir(parents=True, exist_ok=True)
    (Path(settings.artifacts_dir) / "reports").mkdir(parents=True, exist_ok=True)
    (Path(settings.artifacts_dir) / "logs").mkdir(parents=True, exist_ok=True)
    Path(getattr(settings, "dead_letter_dir", Path(settings.artifacts_dir) / "dead_letter")).mkdir(parents=True, exist_ok=True)
    Path(settings.yara_rules_dir).mkdir(parents=True, exist_ok=True)
    initialize_database()
    ensure_report_store()
    ensure_metrics_store()
    logger.info("application startup complete")


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid4().hex[:16]
    token = request_id_var.set(request_id)
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("unhandled request error")
        raise
    finally:
        request_id_var.reset(token)
    response.headers["x-request-id"] = request_id
    return response


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "app_name": settings.app_name,
            "build_id": BUILD_ID,
            "bridge_url": settings.sandbox_bridge_url,
        },
    )


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "app": settings.app_name, "build": BUILD_ID})
