from __future__ import annotations

import json
import os
import pwd
import resource
import shlex
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from app.core.config import settings
from app.sandbox.fs_monitor import diff_snapshots, snapshot_tree
from app.sandbox.network_monitor import reserve_pcap_path, start_network_capture, start_tcpdump, stop_network_capture, stop_tcpdump
from app.sandbox.vmware_bridge_backend import run_vmware_bridge_analysis
from app.utils.subprocess_helper import run_command

EXECUTABLE_SUFFIXES = {".py", ".sh", ".js", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".com", ".scr", ".vbs"}
STRINGS_ONLY_SUFFIXES = {".exe", ".dll", ".com", ".scr"}
SKIP_PARTS = {"__pycache__", ".git", ".idea", ".vscode", "node_modules", ".pytest_cache"}
ANALYSIS_ARTIFACT_NAMES = {"stdout.txt", "stderr.txt", "analysis_log.jsonl", "network_trace.jsonl", "capture.pcap"}
ANALYSIS_ARTIFACT_DIRS = {"analysis", "artifacts", "evidence", "logs", "network", "results", "sandbox", "trace"}

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _append_stage(log_path: Path, stage: str, **extra) -> None:
    payload = {"ts": _utc_now(), "stage": stage}
    payload.update(extra)
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, ensure_ascii=False) + "\n")

def _is_analysis_artifact_path(path_value: str | None) -> bool:
    if not path_value:
        return False
    normalized = str(path_value).replace("\\", "/").strip("/")
    parts = [part.lower() for part in normalized.split("/") if part]
    if not parts:
        return False
    filename = parts[-1]
    if filename in ANALYSIS_ARTIFACT_NAMES:
        return True
    if filename.endswith("_stdout.txt") or filename.endswith("_stderr.txt"):
        return True
    if filename.startswith("report") and filename.endswith(".json"):
        return True
    return any(part in ANALYSIS_ARTIFACT_DIRS for part in parts[:-1])

def _filter_filesystem_delta(fs_delta: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key in ("created", "changed", "deleted"):
        values = fs_delta.get(key) or []
        out[key] = [v for v in values if not _is_analysis_artifact_path(v)]
    return out

def _summarize_exec_activity(exec_results: list[dict[str, Any]]) -> dict[str, Any]:
    attempted = executed = successful = 0
    for r in exec_results:
        was_attempted = bool(r.get("attempted")) or str(r.get("strategy") or "").lower() in {"native", "guest_native", "strings_only"}
        was_executed = was_attempted and not bool(r.get("skipped"))
        was_success = bool(r.get("succeeded")) or (was_executed and int(r.get("returncode", 0) or 0) == 0 and not bool(r.get("timed_out")))
        if was_attempted:
            attempted += 1
        if was_executed:
            executed += 1
        if was_success:
            successful += 1
    return {"attempted_count": attempted, "executed_count": executed, "successful_count": successful}

def _process_snapshot() -> list[dict[str, Any]]:
    out = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline"]):
        try:
            out.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out[:500]

def _estimate_process_delta(proc_before: list[dict[str, Any]], proc_after: list[dict[str, Any]], exec_results: list[dict[str, Any]]) -> dict[str, Any]:
    executed_names = {Path(str(r.get("path") or r.get("member_path") or "")).name.lower() for r in exec_results if not bool(r.get("skipped"))}
    before_keys = {(p.get("pid"), p.get("ppid"), p.get("name"), tuple(p.get("cmdline") or [])) for p in proc_before}
    new_processes = []
    for proc in proc_after:
        key = (proc.get("pid"), proc.get("ppid"), proc.get("name"), tuple(proc.get("cmdline") or []))
        if key in before_keys:
            continue
        name = str(proc.get("name") or "").lower()
        cmd = " ".join(proc.get("cmdline") or []).lower()
        if any(n and (n == name or n in cmd) for n in executed_names):
            new_processes.append({"pid": proc.get("pid"), "ppid": proc.get("ppid"), "name": proc.get("name"), "cmdline": proc.get("cmdline") or []})
    return {"before_count": len(proc_before), "after_count": len(proc_after), "new_processes_estimate": len(new_processes), "new_process_tree": new_processes[:20]}

def _filter_network_trace(trace: dict[str, Any], exec_results: list[dict[str, Any]]) -> dict[str, Any]:
    out = dict(trace or {})
    conns = out.get("connections") or []
    executed_names = {Path(str(r.get("path") or r.get("member_path") or "")).name.lower() for r in exec_results if not bool(r.get("skipped"))}
    if not executed_names:
        out["connections"] = []
        out["connection_count"] = 0
        out["noise_filtered"] = True
        out["noise_reason"] = "no_executed_member"
        return out
    filtered = []
    for row in conns:
        cmd = str(row.get("cmdline") or "").lower()
        image = str(row.get("process") or row.get("image") or "").lower()
        if any(n and (n in cmd or image.endswith(n)) for n in executed_names):
            filtered.append(row)
    out["connections"] = filtered
    out["connection_count"] = len(filtered)
    out["noise_filtered"] = True
    if conns and not filtered:
        out["noise_reason"] = "sandbox_background_traffic"
    return out

def _strings_command(sample_path: str, limit: int) -> list[str]:
    quoted = shlex.quote(sample_path)
    return ["sh", "-lc", f"strings {quoted} | head -n {int(limit)}"]

def _build_command(sample_path: str) -> tuple[list[str], str]:
    suffix = Path(sample_path).suffix.lower()
    if suffix == ".py":
        return ["python", sample_path], "native"
    if suffix == ".sh":
        return ["sh", sample_path], "native"
    if suffix == ".js":
        return ["node", sample_path], "native"
    if suffix == ".ps1":
        return ["pwsh", "-File", sample_path], "native"
    if suffix in {".bat", ".cmd"}:
        return _strings_command(sample_path, 100), "strings_only"
    if suffix in STRINGS_ONLY_SUFFIXES:
        return _strings_command(sample_path, 140), "guest_native"
    return _strings_command(sample_path, 100), "strings_only"

def _get_nobody_ids() -> tuple[int, int] | None:
    try:
        pw = pwd.getpwnam("nobody")
        return pw.pw_uid, pw.pw_gid
    except Exception:
        return None

def _sandbox_preexec() -> None:
    try:
        os.setsid()
    except Exception:
        pass
    try:
        limit_mb = max(1, int(settings.sandbox_memory_limit_mb))
        resource.setrlimit(resource.RLIMIT_AS, (limit_mb * 1024 * 1024, limit_mb * 1024 * 1024))
    except Exception:
        pass
    if bool(settings.sandbox_drop_privileges):
        ids = _get_nobody_ids()
        if ids:
            uid, gid = ids
            try:
                os.setgid(gid)
                os.setuid(uid)
            except Exception:
                pass

def _sandbox_env(work_dir: Path) -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(work_dir), "TMPDIR": str(work_dir), "TEMP": str(work_dir), "TMP": str(work_dir), "PYTHONUNBUFFERED": "1"}

def _stage_target_for_execution(sample_path: str, work_dir: Path) -> Path:
    src = Path(sample_path)
    work_dir.mkdir(parents=True, exist_ok=True)
    dst = work_dir / src.name
    shutil.copy2(src, dst)
    try:
        dst.chmod(0o700)
    except Exception:
        pass
    return dst

def _execute_one(sample_path: str, timeout_seconds: int, analysis_log_path: Path, role: str, work_dir: Path) -> dict[str, Any]:
    command, strategy = _build_command(sample_path)
    skipped = False
    skip_reason = None
    if strategy == "native":
        try:
            staged = _stage_target_for_execution(sample_path, work_dir)
            command, strategy = _build_command(str(staged))
        except Exception as exc:
            skipped = True
            skip_reason = f"staging failed: {exc}"
            command = _strings_command(sample_path, 140)
            strategy = "strings_only"
    _append_stage(analysis_log_path, "execute_start", role=role, command=command, strategy=strategy, sample_path=sample_path)
    try:
        proc = run_command(command, timeout=timeout_seconds, cwd=str(work_dir), env=_sandbox_env(work_dir), preexec_fn=_sandbox_preexec)
        result = {"command": command, "returncode": int(proc.returncode), "timed_out": False, "stdout": proc.stdout or "", "stderr": proc.stderr or "", "strategy": strategy, "skipped": skipped, "skip_reason": skip_reason, "attempted": True, "succeeded": not skipped and int(proc.returncode) == 0, "failed": not skipped and int(proc.returncode) != 0}
    except subprocess.TimeoutExpired as exc:
        result = {"command": command, "returncode": -1, "timed_out": True, "stdout": exc.stdout or "", "stderr": exc.stderr or "", "strategy": strategy, "skipped": skipped, "skip_reason": skip_reason, "attempted": True, "succeeded": False, "failed": True}
    _append_stage(analysis_log_path, "execute_end", role=role, returncode=result["returncode"], timed_out=result["timed_out"], strategy=result["strategy"], skipped=result["skipped"])
    return result

def _safe_extract(zip_path: Path, extract_dir: Path) -> None:
    root = extract_dir.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            if any(part in SKIP_PARTS for part in Path(member.filename).parts):
                continue
            target = (extract_dir / member.filename).resolve()
            if os.path.commonpath([str(target), str(root)]) != str(root):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)

def _list_exec_candidates(root: Path) -> list[Path]:
    members = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() in EXECUTABLE_SUFFIXES:
            members.append(path)
    members.sort(key=lambda p: str(p).lower())
    return members[: int(settings.max_archive_exec_members)]

def _write_preview(path: Path, text: str) -> None:
    path.write_text((text or "")[:4000], encoding="utf-8", errors="ignore")

def _runtime_root() -> Path:
    root = Path(settings.sandbox_runtime_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root

def run_dynamic_analysis(sample_path: str, report_id: str, artifact_root: str) -> dict[str, Any]:
    backend = str(settings.sandbox_backend).lower()
    if backend in {"vmware-bridge", "auto"}:
        try:
            return run_vmware_bridge_analysis(sample_path, report_id, artifact_root)
        except Exception:
            if backend == "vmware-bridge":
                raise

    artifact_root_path = Path(artifact_root)
    artifact_root_path.mkdir(parents=True, exist_ok=True)
    analysis_log_path = artifact_root_path / "analysis_log.jsonl"
    stdout_path = artifact_root_path / "stdout.txt"
    stderr_path = artifact_root_path / "stderr.txt"
    extract_dir = artifact_root_path / "extract"
    work_dir = Path(tempfile.mkdtemp(prefix=f"sandbox_{report_id}_", dir=str(_runtime_root())))

    pre_tree = snapshot_tree(artifact_root_path)
    proc_before = _process_snapshot()
    trace_path = artifact_root_path / "network_trace.jsonl"
    capture = start_network_capture(str(trace_path))
    tcpdump_proc = None
    pcap_path = None
    if bool(settings.enable_pcap):
        pcap_path = reserve_pcap_path(artifact_root)
        tcpdump_proc = start_tcpdump(pcap_path)

    exec_results: list[dict[str, Any]] = []
    sample = Path(sample_path)
    try:
        _append_stage(analysis_log_path, "dynamic_begin", report_id=report_id, sample_path=sample_path)
        if sample.suffix.lower() == ".zip":
            _safe_extract(sample, extract_dir)
            for target in _list_exec_candidates(extract_dir):
                result = _execute_one(str(target), int(settings.sample_timeout_seconds), analysis_log_path, "archive_member", work_dir)
                result["path"] = str(target.relative_to(extract_dir)).replace("\\", "/")
                result["member_path"] = result["path"]
                exec_results.append(result)
        else:
            result = _execute_one(sample_path, int(settings.sample_timeout_seconds), analysis_log_path, "sample", work_dir)
            result["path"] = sample.name
            result["member_path"] = sample.name
            exec_results.append(result)
    finally:
        trace = stop_network_capture(capture)
        if tcpdump_proc is not None:
            stop_tcpdump(tcpdump_proc)

    proc_after = _process_snapshot()
    raw_fs_delta = diff_snapshots(pre_tree, snapshot_tree(artifact_root_path))
    fs_delta = _filter_filesystem_delta(raw_fs_delta)
    exec_activity = _summarize_exec_activity(exec_results)
    archive_success_count = int(exec_activity.get("successful_count", 0))
    process_delta = _estimate_process_delta(proc_before, proc_after, exec_results)
    filtered_trace = _filter_network_trace(trace, exec_results)

    combined_stdout = "\n\n".join((r.get("stdout") or "") for r in exec_results).strip()
    combined_stderr = "\n\n".join((r.get("stderr") or "") for r in exec_results).strip()
    _write_preview(stdout_path, combined_stdout)
    _write_preview(stderr_path, combined_stderr)

    result = {
        "returncode": max((int(r.get("returncode", 0)) for r in exec_results), default=0),
        "timed_out": any(bool(r.get("timed_out")) for r in exec_results),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "analysis_log_path": str(analysis_log_path),
        "trace_path": trace.get("trace_path"),
        "pcap_path": pcap_path,
        "filesystem_delta": fs_delta,
        "process_delta": process_delta,
        "network_trace": filtered_trace,
        "network_signal": bool(filtered_trace.get("connections")),
        "exec_signal": archive_success_count > 0,
        "persistence_signal": False,
        "file_signal": bool(fs_delta.get("created") or fs_delta.get("changed") or fs_delta.get("deleted")) and archive_success_count > 0,
        "ransomware_signal": False,
        "archive_file_count": sum(1 for p in extract_dir.rglob("*") if p.is_file()) if extract_dir.exists() else 1,
        "archive_member_exec_count": int(exec_activity.get("executed_count", 0)),
        "archive_member_skipped_count": sum(1 for r in exec_results if bool(r.get("skipped"))),
        "archive_member_attempted_count": int(exec_activity.get("attempted_count", 0)),
        "archive_member_success_count": archive_success_count,
        "archive_member_results": [{
            "path": r.get("path"),
            "member_path": r.get("member_path"),
            "command": r.get("command"),
            "returncode": r.get("returncode"),
            "timed_out": r.get("timed_out"),
            "stdout_preview": (r.get("stdout") or "")[:1200],
            "stderr_preview": (r.get("stderr") or "")[:1200],
            "strategy": r.get("strategy"),
            "skipped": r.get("skipped"),
            "attempted": bool(r.get("attempted")),
            "succeeded": bool(r.get("succeeded")),
            "failed": bool(r.get("failed")),
            "skip_reason": r.get("skip_reason"),
            "runtime_ms": r.get("runtime_ms", 0),
            "behavior": r.get("behavior") or {"execution_signal": bool(r.get("succeeded"))},
            "process_tree_live": [],
            "network_endpoints_live": [],
        } for r in exec_results],
        "combined_output_preview": (combined_stdout + "\n" + combined_stderr).strip()[:4000],
        "score": 0,
        "analysis_state": "partial" if exec_results else "complete",
        "dynamic_status": "executed" if archive_success_count > 0 else ("attempted" if int(exec_activity.get("attempted_count", 0)) > 0 else "not_executed"),
        "dynamic_reason": None if archive_success_count > 0 else ("members_attempted_but_no_successful_execution" if int(exec_activity.get("attempted_count", 0)) > 0 else "no_member_executed"),
        "sandbox_profile": {"backend": "local", "runtime_root": str(work_dir)},
    }
    shutil.rmtree(work_dir, ignore_errors=True)
    return result
