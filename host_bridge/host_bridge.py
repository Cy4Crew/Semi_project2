from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, UploadFile

APP = FastAPI(title="VMware Host Bridge")

BASE_DIR = Path(__file__).resolve().parent
WORK_DIR = Path(os.environ.get("BRIDGE_WORK_DIR", str(BASE_DIR / "workspace"))).resolve()
SHARED_DIR = Path(os.environ.get("BRIDGE_SHARED_DIR", str(WORK_DIR / "shared"))).resolve()
VMX_PATH_ENV = os.environ.get("VMX_PATH", "").strip()
VMRUN_PATH_ENV = os.environ.get("VMRUN_PATH", "").strip()


def _autodetect_vmrun_path() -> Path:
    candidates = [
        VMRUN_PATH_ENV,
        r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
        r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
    ]
    for candidate in candidates:
        if candidate:
            p = Path(candidate)
            if p.exists():
                return p
    return Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")


def _autodetect_vmx_path() -> Path | None:
    if VMX_PATH_ENV:
        p = Path(VMX_PATH_ENV)
        return p if p.exists() else p

    roots = [
        Path.home() / "Documents" / "Virtual Machines",
        Path.home() / "문서" / "Virtual Machines",
        Path(r"C:/Users/Public/Documents/Shared Virtual Machines"),
        Path(r"C:/win10x64"),
    ]
    matches: list[Path] = []
    for root in roots:
        if root.exists():
            matches.extend(root.rglob("*.vmx"))
    if len(matches) == 1:
        return matches[0]
    return matches[0] if matches else None


VMRUN_PATH = _autodetect_vmrun_path()
VMX_PATH = _autodetect_vmx_path()

DEFAULT_VM_NAME = os.environ.get("DEFAULT_VM_NAME", "analysis-win10")
DEFAULT_SNAPSHOT = os.environ.get("DEFAULT_SNAPSHOT", "clean")
DEFAULT_TIMEOUT = int(os.environ.get("DEFAULT_TIMEOUT", "180"))
SOFT_STOP_WAIT_SECONDS = int(os.environ.get("SOFT_STOP_WAIT_SECONDS", "20"))

for p in [WORK_DIR, SHARED_DIR, SHARED_DIR / "inbox", SHARED_DIR / "outbox", WORK_DIR / "jobs", WORK_DIR / "logs"]:
    p.mkdir(parents=True, exist_ok=True)


def _run_vmrun(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    if not VMRUN_PATH.exists():
        raise RuntimeError(f"vmrun_not_found:{VMRUN_PATH}")
    cmd = [str(VMRUN_PATH), *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _vmx_for_request(vm_name: str) -> str:
    if VMX_PATH:
        return str(VMX_PATH)
    raise RuntimeError(f"VMX_PATH_not_configured_for:{vm_name}")


def _append_trace(log_path: Path, stage: str, **extra: Any) -> None:
    payload = {"ts": time.time(), "stage": stage}
    payload.update(extra)
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _ensure_guest_ready(vmx_path: str, log_path: Path) -> None:
    _append_trace(log_path, "vm_start_attempt", vmx_path=vmx_path)
    start = _run_vmrun("start", vmx_path, timeout=180)
    stderr = (start.stderr or "").strip().lower()
    if start.returncode != 0 and "already running" not in stderr:
        raise RuntimeError(f"vm_start_failed:{(start.stderr or start.stdout).strip()}")
    _append_trace(log_path, "vm_start_ok", stdout=start.stdout, stderr=start.stderr)
    time.sleep(15)


def _stop_vm(vmx_path: str, log_path: Path) -> None:
    try:
        _append_trace(log_path, "vm_stop_soft_attempt")
        soft = _run_vmrun("stop", vmx_path, "soft", timeout=120)
        _append_trace(log_path, "vm_stop_soft_result", returncode=soft.returncode, stdout=soft.stdout, stderr=soft.stderr)
        time.sleep(max(1, SOFT_STOP_WAIT_SECONDS))
        list_out = _run_vmrun("list", timeout=30)
        if vmx_path.lower() in (list_out.stdout or "").lower():
            _append_trace(log_path, "vm_stop_hard_attempt")
            hard = _run_vmrun("stop", vmx_path, "hard", timeout=120)
            _append_trace(log_path, "vm_stop_hard_result", returncode=hard.returncode, stdout=hard.stdout, stderr=hard.stderr)
    except Exception as exc:
        _append_trace(log_path, "vm_stop_error", error=str(exc))


def _revert_snapshot(vmx_path: str, snapshot_name: str, log_path: Path) -> None:
    _append_trace(log_path, "vm_revert_attempt", snapshot_name=snapshot_name)
    result = _run_vmrun("revertToSnapshot", vmx_path, snapshot_name, timeout=120)
    _append_trace(log_path, "vm_revert_result", returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"revert_snapshot_failed:{(result.stderr or result.stdout).strip()}")


def _wait_for_result(result_path: Path, timeout_seconds: int, log_path: Path) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if result_path.exists():
            _append_trace(log_path, "result_detected", result_path=str(result_path), size=result_path.stat().st_size)
            return json.loads(result_path.read_text(encoding="utf-8"))
        time.sleep(2)
    raise TimeoutError(f"result_timeout:{result_path}")


def _cleanup_job_paths(job_dir: Path, inbox_dir: Path, outbox_dir: Path, log_path: Path) -> None:
    for p in [job_dir, inbox_dir, outbox_dir]:
        try:
            if p.exists():
                shutil.rmtree(p, ignore_errors=True)
                _append_trace(log_path, "cleanup_path", path=str(p))
        except Exception as exc:
            _append_trace(log_path, "cleanup_error", path=str(p), error=str(exc))


@APP.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "vmrun_exists": VMRUN_PATH.exists(),
        "shared_dir": str(SHARED_DIR),
        "vmx_path": str(VMX_PATH) if VMX_PATH else None,
        "vmrun_path": str(VMRUN_PATH),
    }


@APP.post("/submit")
async def submit(
    sample: UploadFile = File(...),
    report_id: str = Form(...),
    vm_name: str = Form(default=DEFAULT_VM_NAME),
    snapshot_name: str = Form(default=DEFAULT_SNAPSHOT),
    timeout_seconds: int = Form(default=DEFAULT_TIMEOUT),
) -> dict[str, Any]:
    vmx_path = _vmx_for_request(vm_name)
    job_dir = WORK_DIR / "jobs" / report_id
    inbox_dir = SHARED_DIR / "inbox" / report_id
    outbox_dir = SHARED_DIR / "outbox" / report_id
    log_path = WORK_DIR / "logs" / f"{report_id}.jsonl"

    for p in [job_dir, inbox_dir, outbox_dir]:
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
        p.mkdir(parents=True, exist_ok=True)

    sample_path = job_dir / (sample.filename or f"{report_id}.zip")
    sample_bytes = await sample.read()
    sample_path.write_bytes(sample_bytes)
    await sample.close()

    inbox_sample = inbox_dir / sample_path.name
    shutil.copy2(sample_path, inbox_sample)
    job_payload = {
        "report_id": report_id,
        "sample_name": sample_path.name,
        "timeout_seconds": int(timeout_seconds),
        "submitted_at": time.time(),
    }
    (inbox_dir / "job.json").write_text(json.dumps(job_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    result_path = outbox_dir / "result.json"

    try:
        _revert_snapshot(vmx_path, snapshot_name, log_path)
        _ensure_guest_ready(vmx_path, log_path)
        result = _wait_for_result(result_path, int(timeout_seconds), log_path)
        bridge_payload = {
            "ok": True,
            "result": result,
            "bridge_trace_path": str(log_path),
        }
        _append_trace(log_path, "submit_complete", ok=True)
        return bridge_payload
    finally:
        try:
            _stop_vm(vmx_path, log_path)
        finally:
            try:
                _revert_snapshot(vmx_path, snapshot_name, log_path)
            finally:
                _cleanup_job_paths(job_dir, inbox_dir, outbox_dir, log_path)
