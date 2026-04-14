from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile

APP = FastAPI(title="VMware Host Bridge")

BASE_DIR = Path(__file__).resolve().parent
WORK_DIR = Path(os.environ.get("BRIDGE_WORK_DIR", str(BASE_DIR / "workspace"))).resolve()
SHARED_DIR = Path(os.environ.get("BRIDGE_SHARED_DIR", str(WORK_DIR / "shared"))).resolve()
VMX_PATH_ENV = os.environ.get("VMX_PATH", "").strip()
VMRUN_PATH_ENV = os.environ.get("VMRUN_PATH", "").strip()
GUEST_HEARTBEAT_TTL_SECONDS = int(os.environ.get("GUEST_HEARTBEAT_TTL_SECONDS", "45"))
GUEST_READY_TIMEOUT_SECONDS = int(os.environ.get("GUEST_READY_TIMEOUT_SECONDS", "120"))
SNAPSHOT_PROBE_TIMEOUT_SECONDS = int(os.environ.get("SNAPSHOT_PROBE_TIMEOUT_SECONDS", "60"))
VM_START_GRACE_SECONDS = int(os.environ.get("VM_START_GRACE_SECONDS", "20"))
BRIDGE_AUTH_TOKEN = os.getenv("BRIDGE_AUTH_TOKEN", "")


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

DEFAULT_VM_NAME = os.environ.get("DEFAULT_VM_NAME", "win10x64")
DEFAULT_SNAPSHOT = os.environ.get("DEFAULT_SNAPSHOT", "clean")
DEFAULT_TIMEOUT = int(os.environ.get("DEFAULT_TIMEOUT", "180"))
SOFT_STOP_WAIT_SECONDS = int(os.environ.get("SOFT_STOP_WAIT_SECONDS", "20"))

for p in [WORK_DIR, SHARED_DIR, SHARED_DIR / "inbox", SHARED_DIR / "outbox", WORK_DIR / "jobs", WORK_DIR / "logs", WORK_DIR / "state"]:
    p.mkdir(parents=True, exist_ok=True)


def _run_vmrun(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    if not VMRUN_PATH.exists():
        raise RuntimeError(f"vmrun_not_found:{VMRUN_PATH}")
    cmd = [str(VMRUN_PATH), *args]
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def _vmx_for_request(vm_name: str) -> str:
    if VMX_PATH:
        return str(VMX_PATH)
    raise RuntimeError(f"VMX_PATH_not_configured_for:{vm_name}")


def _append_trace(log_path: Path, stage: str, **extra: Any) -> None:
    payload = {"ts": time.time(), "stage": stage}
    payload.update(extra)
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _heartbeat_path() -> Path:
    return SHARED_DIR / "agent_heartbeat.json"


def _read_guest_heartbeat() -> dict[str, Any]:
    path = _heartbeat_path()
    if not path.exists():
        return {"exists": False, "guest_ready": False, "reason": "heartbeat_missing"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"exists": True, "guest_ready": False, "reason": f"heartbeat_invalid:{exc}"}
    ts = float(payload.get("ts") or 0)
    age = max(0.0, time.time() - ts) if ts else 999999.0
    payload["exists"] = True
    payload["age_seconds"] = age
    payload["fresh"] = age <= GUEST_HEARTBEAT_TTL_SECONDS
    payload["guest_ready"] = bool(payload.get("fresh")) and bool(payload.get("shared_dir_ready")) and bool(payload.get("inbox_ready")) and bool(payload.get("outbox_ready"))
    if not payload.get("fresh"):
        payload["reason"] = payload.get("reason") or "heartbeat_stale"
    elif not payload.get("shared_dir_ready"):
        payload["reason"] = payload.get("reason") or "guest_shared_dir_not_ready"
    elif not payload.get("inbox_ready") or not payload.get("outbox_ready"):
        payload["reason"] = payload.get("reason") or "guest_shared_subdirs_not_ready"
    return payload


def _list_snapshots(vmx_path: str) -> dict[str, Any]:
    try:
        proc = _run_vmrun("listSnapshots", vmx_path, timeout=SNAPSHOT_PROBE_TIMEOUT_SECONDS)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        snapshots = [line for line in lines if not line.lower().startswith("total snapshots")]
        return {"ok": proc.returncode == 0, "snapshots": snapshots, "raw": output.strip()[:2000]}
    except Exception as exc:
        return {"ok": False, "snapshots": [], "raw": str(exc)}


def _probe_vm_running(vmx_path: str) -> bool:
    try:
        proc = _run_vmrun("list", timeout=30)
        return vmx_path.lower() in (proc.stdout or "").lower()
    except Exception:
        return False


def _probe_readiness(vmx_path: str, snapshot_name: str) -> dict[str, Any]:
    hb = _read_guest_heartbeat()
    snap = _list_snapshots(vmx_path)
    snapshot_exists = snapshot_name in set(snap.get("snapshots") or [])
    host_inbox = SHARED_DIR / "inbox"
    host_outbox = SHARED_DIR / "outbox"
    shared_ok = SHARED_DIR.exists() and host_inbox.exists() and host_outbox.exists()
    host_shared_name = SHARED_DIR.name.lower()
    guest_shared_name = str(hb.get("resolved_shared_dir_name") or "").strip().lower()
    guest_matches_host = not guest_shared_name or guest_shared_name == host_shared_name
    guest_shared_ready = bool(hb.get("shared_dir_ready")) and bool(hb.get("inbox_ready")) and bool(hb.get("outbox_ready"))
    guest_ready = bool(hb.get("guest_ready")) and guest_matches_host
    vm_running = _probe_vm_running(vmx_path)
    slot_startable = bool(VMRUN_PATH.exists()) and bool(vmx_path) and bool(snapshot_exists) and bool(shared_ok)
    slot_healthy = (slot_startable and not vm_running) or (slot_startable and vm_running and guest_ready)

    reason = None
    if not VMRUN_PATH.exists():
        reason = "vmrun_missing"
    elif not vmx_path:
        reason = "vmx_missing"
    elif not snapshot_exists:
        reason = "snapshot_missing"
    elif not shared_ok:
        reason = "shared_dir_not_ready"
    elif vm_running and not guest_ready:
        reason = hb.get("reason") or "guest_not_ready"
    elif not vm_running and slot_startable:
        reason = "vm_powered_off_but_startable"

    return {
        "vmrun_exists": VMRUN_PATH.exists(),
        "vmx_path": vmx_path,
        "vm_running": vm_running,
        "shared_dir": str(SHARED_DIR),
        "shared_dir_name": SHARED_DIR.name,
        "shared_dir_ready": shared_ok,
        "snapshot_name": snapshot_name,
        "snapshot_exists": snapshot_exists,
        "snapshot_probe": snap,
        "guest_heartbeat": hb,
        "guest_shared_dir_ready": guest_shared_ready,
        "guest_shared_dir_matches_host": guest_matches_host,
        "guest_ready": guest_ready,
        "slot_startable": slot_startable,
        "slot_healthy": slot_healthy,
        "reason": reason,
    }


def _ensure_guest_ready(vmx_path: str, snapshot_name: str, log_path: Path) -> dict[str, Any]:
    _append_trace(log_path, "vm_start_attempt", vmx_path=vmx_path)
    try:
        start = _run_vmrun("start", vmx_path, "nogui", timeout=45)
        stderr = (start.stderr or "").strip().lower()
        if start.returncode != 0 and "already running" not in stderr:
            raise RuntimeError(f"vm_start_failed:{(start.stderr or start.stdout).strip()}")
        _append_trace(log_path, "vm_start_ok", stdout=start.stdout, stderr=start.stderr)
    except subprocess.TimeoutExpired as exc:
        _append_trace(log_path, "vm_start_timeout", timeout_seconds=45, stdout=(exc.stdout or ""), stderr=(exc.stderr or ""))
        if not _probe_vm_running(vmx_path):
            raise RuntimeError("vm_start_timeout_before_power_on") from exc
        _append_trace(log_path, "vm_start_timeout_but_running", vmx_path=vmx_path)

    if VM_START_GRACE_SECONDS > 0:
        _append_trace(log_path, "vm_start_grace_sleep", seconds=VM_START_GRACE_SECONDS)
        time.sleep(VM_START_GRACE_SECONDS)

    deadline = time.time() + max(10, GUEST_READY_TIMEOUT_SECONDS)
    last_probe: dict[str, Any] = {}
    while time.time() < deadline:
        last_probe = _probe_readiness(vmx_path, snapshot_name)
        _append_trace(log_path, "guest_ready_probe", probe=last_probe)
        if (
            last_probe.get("guest_ready")
            and last_probe.get("snapshot_exists")
            and last_probe.get("shared_dir_ready")
            and last_probe.get("guest_shared_dir_ready")
            and last_probe.get("guest_shared_dir_matches_host")
        ):
            return last_probe
        time.sleep(3)
    raise RuntimeError(f"guest_not_ready:{json.dumps(last_probe, ensure_ascii=False)[:1500]}")


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
    probe = _probe_readiness(vmx_path, snapshot_name)
    _append_trace(log_path, "vm_snapshot_probe", probe=probe)
    if not probe.get("snapshot_exists"):
        raise RuntimeError(f"snapshot_not_found:{snapshot_name}")
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


def _require_bridge_token(received_token: str | None) -> None:
    expected = str(BRIDGE_AUTH_TOKEN or "").strip()
    if not expected:
        return
    if str(received_token or "").strip() != expected:
        raise HTTPException(status_code=403, detail="invalid bridge token")


@APP.get("/health")
def health(snapshot_name: str = DEFAULT_SNAPSHOT, vm_name: str = DEFAULT_VM_NAME, x_bridge_token: str | None = Header(default=None)) -> dict[str, Any]:
    _require_bridge_token(x_bridge_token)
    vmx_path = _vmx_for_request(vm_name)
    probe = _probe_readiness(vmx_path, snapshot_name)
    return {
        "status": "ok" if probe.get("vmrun_exists") else "degraded",
        "vmrun_exists": probe.get("vmrun_exists"),
        "shared_dir": probe.get("shared_dir"),
        "shared_dir_ready": probe.get("shared_dir_ready"),
        "vmx_path": probe.get("vmx_path"),
        "vmrun_path": str(VMRUN_PATH),
        "vm_running": probe.get("vm_running"),
        "snapshot_name": snapshot_name,
        "snapshot_exists": probe.get("snapshot_exists"),
        "guest_ready": probe.get("guest_ready"),
        "guest_heartbeat": probe.get("guest_heartbeat"),
        "snapshot_probe": probe.get("snapshot_probe"),
        "slot_startable": probe.get("slot_startable"),
        "slot_healthy": probe.get("slot_healthy"),
        "reason": probe.get("reason"),
    }


@APP.post("/submit")
async def submit(
    sample: UploadFile = File(...),
    report_id: str = Form(...),
    vm_name: str = Form(default=DEFAULT_VM_NAME),
    snapshot_name: str = Form(default=DEFAULT_SNAPSHOT),
    timeout_seconds: int = Form(default=DEFAULT_TIMEOUT),
    x_bridge_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_bridge_token(x_bridge_token)
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
        readiness = _ensure_guest_ready(vmx_path, snapshot_name, log_path)
        result = _wait_for_result(result_path, int(timeout_seconds), log_path)
        bridge_payload = {
            "ok": True,
            "result": result,
            "bridge_trace_path": str(log_path),
            "readiness": readiness,
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
