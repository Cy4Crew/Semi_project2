from __future__ import annotations

import atexit
import json
import logging
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock

from app.core.config import settings
from app.utils.logging_setup import report_id_var
from app.utils.metrics_store import record_event, record_stage_metric
from app.repository.report_store import get_report, update_report
from app.services.report_service import process_report

logger = logging.getLogger(__name__)

_EXECUTOR = ThreadPoolExecutor(
    max_workers=max(1, int(settings.analysis_worker_count)),
    thread_name_prefix="analysis-worker",
)
_INFLIGHT: set[str] = set()
_LOCK = Lock()
_SHUTTING_DOWN = False
_DEAD_LETTER_DIR = Path(getattr(settings, "dead_letter_dir", Path(settings.artifacts_dir) / "dead_letter"))
_DEAD_LETTER_DIR.mkdir(parents=True, exist_ok=True)


def _set_shutdown(*_args) -> None:
    global _SHUTTING_DOWN
    _SHUTTING_DOWN = True
    logger.warning("worker shutdown requested")


for _sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
    if _sig is not None:
        try:
            signal.signal(_sig, _set_shutdown)
        except Exception:
            pass


@atexit.register
def _shutdown_executor() -> None:
    global _SHUTTING_DOWN
    _SHUTTING_DOWN = True
    _EXECUTOR.shutdown(wait=False, cancel_futures=True)


def get_queue_stats() -> dict:
    with _LOCK:
        return {"queued_or_running": len(_INFLIGHT), "inflight_ids": sorted(_INFLIGHT)[:50], "shutting_down": _SHUTTING_DOWN}


def submit_report(report_id: str) -> None:
    if _SHUTTING_DOWN:
        update_report(report_id, status="deferred", summary="Worker shutdown in progress. Job not accepted.")
        record_event("job_rejected_shutdown", "analysis job rejected during shutdown", report_id=report_id)
        return
    with _LOCK:
        if report_id in _INFLIGHT:
            return
        _INFLIGHT.add(report_id)
    record_event("job_submit", "analysis job queued", report_id=report_id)
    logger.info("Queued analysis job")
    _EXECUTOR.submit(_run_report, report_id)


def _write_dead_letter(report_id: str, reason: str, attempts: int) -> None:
    payload = {
        "report_id": report_id,
        "reason": reason,
        "attempts": attempts,
        "ts": time.time(),
    }
    (_DEAD_LETTER_DIR / f"{report_id}.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _run_report(report_id: str) -> None:
    token = report_id_var.set(report_id)
    max_attempts = max(1, int(getattr(settings, "analysis_max_retries", 2)) + 1)
    backoff = max(0.25, float(getattr(settings, "analysis_retry_backoff_seconds", 2.0)))
    try:
        logger.info("Starting analysis worker")
        current = get_report(report_id) or {}
        attempts = int(current.get("analysis_attempts") or 0)
        while attempts < max_attempts:
            if _SHUTTING_DOWN:
                update_report(report_id, status="deferred", summary="Worker shutdown interrupted analysis.", analysis_attempts=attempts)
                record_event("job_deferred_shutdown", "analysis interrupted due to shutdown", report_id=report_id)
                return
            attempts += 1
            update_report(report_id, analysis_attempts=attempts)
            try:
                process_report(report_id)
                record_stage_metric(report_id, "worker", "done", payload={"attempts": attempts})
                record_event("job_complete", "analysis job finished", report_id=report_id, payload={"attempts": attempts})
                logger.info("Finished analysis worker")
                return
            except Exception as exc:
                transient = any(x in str(exc).lower() for x in ["timeout", "bridge", "connection", "guest_not_ready", "vmware_bridge_failed"])
                update_report(report_id, status="retrying" if attempts < max_attempts and transient else "failed", failure_reason=str(exc), failed_stage="worker", error_type=type(exc).__name__, traceback=None, last_successful_step="worker", analysis_attempts=attempts)
                record_event("job_retry" if attempts < max_attempts and transient else "job_failed", "analysis job retry/fail", report_id=report_id, payload={"attempts": attempts, "transient": transient, "error": str(exc)})
                logger.exception("Worker failed on attempt %s/%s", attempts, max_attempts)
                if attempts < max_attempts and transient:
                    time.sleep(backoff * attempts)
                    continue
                record_stage_metric(report_id, "worker", "failed", payload={"attempts": attempts, "error": str(exc), "transient": transient})
                _write_dead_letter(report_id, str(exc), attempts)
                return
    finally:
        with _LOCK:
            _INFLIGHT.discard(report_id)
        report_id_var.reset(token)
