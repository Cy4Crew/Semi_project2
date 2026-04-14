
from __future__ import annotations

import json
import shutil
import subprocess
from app.utils.subprocess_helper import run_command
import threading
import time
from pathlib import Path
from typing import Any

import psutil

from app.core.config import settings


def reserve_pcap_path(path: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


def _snapshot_connections() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            laddr = ""
            raddr = ""
            if conn.laddr:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            if conn.raddr:
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
            items.append(
                {
                    "fd": conn.fd,
                    "family": int(conn.family),
                    "type": int(conn.type),
                    "pid": conn.pid,
                    "status": conn.status,
                    "laddr": laddr,
                    "raddr": raddr,
                }
            )
    except Exception:
        pass
    return items


def _ss_snapshot() -> str:
    ss_path = shutil.which("ss")
    if not ss_path:
        return ""
    try:
        result = subprocess.run([ss_path, "-tunap"], capture_output=True, text=True, timeout=3)
        return result.stdout or ""
    except Exception:
        return ""


def start_tcpdump(path: str):
    return None


def stop_tcpdump(proc):
    return None


class NetworkCapture:
    def __init__(self, path: str, interval_ms: int = 250):
        self.path = Path(path)
        self.interval = max(0.05, interval_ms / 1000.0)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.samples: list[dict[str, Any]] = []
        self.before = _snapshot_connections()
        self.before_ss = _ss_snapshot()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.samples.append({"ts": time.time(), "connections": _snapshot_connections()[:400]})
            time.sleep(self.interval)

    def start(self) -> "NetworkCapture":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(target=self._loop, name="network-capture", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.5)
        after = _snapshot_connections()
        after_ss = _ss_snapshot()
        created = _diff_connections(self.before, after)
        unique_remote = sorted({item["raddr"] for item in created if item.get("raddr")})
        payload = {
            "before_count": len(self.before),
            "after_count": len(after),
            "new_connections": created[:100],
            "unique_remote_addresses": unique_remote[:100],
            "sample_count": len(self.samples),
            "network_signal": bool(unique_remote or created),
            "ss_before": self.before_ss[:4000],
            "ss_after": after_ss[:4000],
        }
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return payload


def _diff_connections(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> list[dict[str, Any]]:
    key = lambda x: (x.get("pid"), x.get("laddr"), x.get("raddr"), x.get("status"))
    before_keys = {key(item) for item in before}
    return [item for item in after if key(item) not in before_keys]


def start_network_capture(path: str):
    if settings.sandbox_disable_network:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({
            "before_count": 0,
            "after_count": 0,
            "new_connections": [],
            "unique_remote_addresses": [],
            "sample_count": 0,
            "network_signal": False,
            "disabled": True,
            "reason": "sandbox_disable_network_enabled",
            "ss_before": "",
            "ss_after": "",
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return None
    return NetworkCapture(path, settings.sandbox_network_sample_interval_ms).start()


def stop_network_capture(capture) -> dict[str, Any]:
    if not capture:
        return {
            "before_count": 0,
            "after_count": 0,
            "new_connections": [],
            "unique_remote_addresses": [],
            "sample_count": 0,
            "network_signal": False,
            "disabled": bool(settings.sandbox_disable_network),
            "reason": "capture_not_started" if not settings.sandbox_disable_network else "sandbox_disable_network_enabled",
            "ss_before": "",
            "ss_after": "",
        }
    return capture.stop()
