from __future__ import annotations

import contextvars
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.core.config import settings

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
report_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("report_id", default="-")


class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get("-")
        record.report_id = report_id_var.get("-")
        return True


def setup_logging() -> None:
    root = logging.getLogger()
    if getattr(setup_logging, "_configured", False):
        return
    logs_dir = Path(settings.artifacts_dir) / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] request_id=%(request_id)s report_id=%(report_id)s %(message)s"
    )
    context_filter = ContextFilter()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    stream.addFilter(context_filter)
    root.addHandler(stream)

    file_handler = RotatingFileHandler(
        logs_dir / "app.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    file_handler.addFilter(context_filter)
    root.addHandler(file_handler)
    setup_logging._configured = True
