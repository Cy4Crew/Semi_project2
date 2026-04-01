from __future__ import annotations

import atexit
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

from app.core.config import settings
from app.repository.report_store import update_report
from app.services.report_service import process_report

_EXECUTOR = ThreadPoolExecutor(
    max_workers=max(1, int(settings.analysis_worker_count)),
    thread_name_prefix="analysis-worker",
)
_INFLIGHT: set[str] = set()
_LOCK = Lock()


@atexit.register
def _shutdown_executor() -> None:
    _EXECUTOR.shutdown(wait=False, cancel_futures=True)


def submit_report(report_id: str) -> None:
    with _LOCK:
        if report_id in _INFLIGHT:
            return
        _INFLIGHT.add(report_id)
    _EXECUTOR.submit(_run_report, report_id)


def _run_report(report_id: str) -> None:
    try:
        process_report(report_id)
    except Exception as exc:
        update_report(report_id, status="failed", summary=f"Analysis failed: {exc}", failure_reason=str(exc))
    finally:
        with _LOCK:
            _INFLIGHT.discard(report_id)
