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

import psutil

from app.core.config import settings
from app.sandbox.fs_monitor import diff_snapshots, snapshot_tree
from app.sandbox.network_monitor import (
    reserve_pcap_path,
    start_network_capture,
    start_tcpdump,
    stop_network_capture,
    stop_tcpdump,
)
from app.sandbox.vmware_bridge_backend import run_vmware_bridge_analysis
from app.utils.subprocess_helper import run_command

EXECUTABLE_SUFFIXES = {".py", ".sh", ".js", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".com", ".scr", ".vbs"}
NATIVE_EXEC_SUFFIXES = {".py", ".sh", ".js", ".ps1", ".bat", ".cmd", ".vbs"}
STRINGS_ONLY_SUFFIXES = {".exe", ".dll", ".com", ".scr"}
SKIP_PARTS = {"__pycache__", ".git", ".idea", ".vscode", "node_modules", ".pytest_cache"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _process_snapshot() -> list[dict]:
    processes = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline"]):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes[:500]


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
        return _strings_command(sample_path, 140), "strings_only"
    return _strings_command(sample_path, 100), "strings_only"


def _append_stage(log_path: Path, stage: str, **extra) -> None:
    payload = {"ts": _utc_now(), "stage": stage}
    payload.update(extra)
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, ensure_ascii=False) + "\n")


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

    try:
        limit_mb = max(1, int(settings.sandbox_file_size_limit_mb))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit_mb * 1024 * 1024, limit_mb * 1024 * 1024))
    except Exception:
        pass

    try:
        max_proc = max(16, int(settings.sandbox_max_processes))
        resource.setrlimit(resource.RLIMIT_NPROC, (max_proc, max_proc))
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
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(work_dir),
        "TMPDIR": str(work_dir),
        "TEMP": str(work_dir),
        "TMP": str(work_dir),
        "PYTHONUNBUFFERED": "1",
    }


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


def _maybe_wrap_with_network_namespace(command: list[str]) -> list[str]:
    if not bool(settings.sandbox_disable_network):
        return command
    if shutil.which("unshare"):
        return ["unshare", "-n", "--"] + command
    return command


def _runtime_root() -> Path:
    root = Path(settings.sandbox_runtime_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _unsupported_member_reason(sample_path: str) -> str | None:
    suffix = Path(sample_path).suffix.lower()
    if suffix in {".exe", ".dll", ".com", ".scr"}:
        return f"dynamic execution skipped for {suffix} on Linux sandbox; strings inspection used instead"
    return None


def _execute_one(sample_path: str, timeout_seconds: int, analysis_log_path: Path, role: str, work_dir: Path) -> dict:
    command, strategy = _build_command(sample_path)
    runtime_path = sample_path
    skipped = False
    skip_reason = None

    if strategy == "native":
        try:
            staged = _stage_target_for_execution(sample_path, work_dir)
            runtime_path = str(staged)
            command, strategy = _build_command(runtime_path)
        except Exception as exc:
            skip_reason = f"staging skipped: {exc}"
            skipped = True
            command = []
            strategy = "skipped"

    unsupported = _unsupported_member_reason(sample_path)
    if unsupported and strategy == "native":
        skip_reason = unsupported
        skipped = True
        command, strategy = _build_command(sample_path)
        strategy = "strings_only"

    if strategy == "native":
        command = _maybe_wrap_with_network_namespace(command)

    _append_stage(analysis_log_path, "execute_start", role=role, command=command, strategy=strategy, sample_path=sample_path)

    if not command:
        return {
            "command": command,
            "returncode": 0,
            "timed_out": False,
            "stdout": "",
            "stderr": f"stage_error:{skip_reason}",
            "strategy": strategy,
            "skipped": True,
            "skip_reason": skip_reason,
        }

    try:
        proc = run_command(
            command,
            timeout=timeout_seconds,
            cwd=str(work_dir),
            env=_sandbox_env(work_dir),
            preexec_fn=_sandbox_preexec,
        )
        result = {
            "command": command,
            "returncode": proc.returncode,
            "timed_out": False,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "strategy": strategy,
            "skipped": skipped,
            "skip_reason": skip_reason,
        }
    except subprocess.TimeoutExpired as exc:
        result = {
            "command": command,
            "returncode": -1,
            "timed_out": True,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "strategy": strategy,
            "skipped": skipped,
            "skip_reason": skip_reason,
        }
    except FileNotFoundError as exc:
        fallback_command = _strings_command(sample_path, 140)
        result = {
            "command": fallback_command,
            "returncode": 0,
            "timed_out": False,
            "stdout": "",
            "stderr": f"runner_missing:{exc}",
            "strategy": "strings_only",
            "skipped": True,
            "skip_reason": str(exc),
        }
    _append_stage(
        analysis_log_path,
        "execute_end",
        role=role,
        returncode=result["returncode"],
        timed_out=result["timed_out"],
        strategy=result["strategy"],
        skipped=result.get("skipped", False),
    )
    return result


def _safe_extract(zip_path: Path, extract_dir: Path) -> None:
    extract_root = extract_dir.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            if member.flag_bits & 0x1:
                continue
            if any(part in SKIP_PARTS for part in Path(member.filename).parts):
                continue
            if int(member.file_size) > int(settings.max_zip_entry_uncompressed_bytes):
                continue
            try:
                target = (extract_dir / member.filename).resolve()
                if os.path.commonpath([str(target), str(extract_root)]) != str(extract_root):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
            except Exception:
                continue


def _list_exec_candidates(root: Path) -> list[Path]:
    members = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() in EXECUTABLE_SUFFIXES:
            members.append(path)
    priority = {".exe": 0, ".ps1": 1, ".bat": 2, ".cmd": 3, ".vbs": 4, ".js": 5, ".py": 6, ".sh": 7}
    members.sort(key=lambda p: (priority.get(p.suffix.lower(), 20), str(p).lower()))
    return members[: int(settings.max_archive_exec_members)]


def _write_preview(path: Path, text: str) -> None:
    path.write_text(text[:4000], encoding="utf-8", errors="ignore")


def run_dynamic_analysis(sample_path: str, report_id: str, artifact_root: str) -> dict:
    backend = str(settings.sandbox_backend).lower()
    if backend in {"vmware-bridge", "auto"}:
        try:
            return run_vmware_bridge_analysis(sample_path, report_id, artifact_root)
        except Exception as exc:
            if backend == "vmware-bridge":
                raise
            artifact_root_path = Path(artifact_root)
            artifact_root_path.mkdir(parents=True, exist_ok=True)
            fallback_note = artifact_root_path / "vmware_bridge_fallback.txt"
            fallback_note.write_text(f"vmware_bridge_failed:{exc}\nlocal_sandbox_fallback_enabled", encoding="utf-8")

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

    _append_stage(analysis_log_path, "dynamic_begin", report_id=report_id, sample_path=sample_path)

    sample = Path(sample_path)
    exec_results: list[dict] = []

    try:
        if sample.suffix.lower() == ".zip":
            _safe_extract(sample, extract_dir)
            for target in _list_exec_candidates(extract_dir):
                result = _execute_one(str(target), int(settings.sample_timeout_seconds), analysis_log_path, "archive_member", work_dir)
                result["path"] = str(target.relative_to(extract_dir))
                exec_results.append(result)
        else:
            result = _execute_one(sample_path, int(settings.sample_timeout_seconds), analysis_log_path, "sample", work_dir)
            result["path"] = sample.name
            exec_results.append(result)
    finally:
        trace = stop_network_capture(capture)
        if tcpdump_proc is not None:
            stop_tcpdump(tcpdump_proc)

    proc_after = _process_snapshot()
    post_tree = snapshot_tree(artifact_root_path)
    fs_delta = diff_snapshots(pre_tree, post_tree)

    combined_stdout = "\n\n".join((r.get("stdout") or "") for r in exec_results).strip()
    combined_stderr = "\n\n".join((r.get("stderr") or "") for r in exec_results).strip()
    _write_preview(stdout_path, combined_stdout)
    _write_preview(stderr_path, combined_stderr)

    combined_preview = (combined_stdout + "\n" + combined_stderr).strip()[:4000]
    archive_exec_count = len(exec_results)
    archive_skipped_count = sum(1 for r in exec_results if r.get("skipped"))
    exec_signal = any(not r.get("skipped") for r in exec_results)
    persistence_signal = any("run" in (r.get("stderr") or "").lower() or "schtasks" in (r.get("stdout") or "").lower() for r in exec_results)
    file_signal = bool(fs_delta.get("created") or fs_delta.get("changed") or fs_delta.get("deleted"))
    network_signal = bool(trace.get("connections"))

    result = {
        "returncode": max((int(r.get("returncode", 0)) for r in exec_results), default=0),
        "timed_out": any(bool(r.get("timed_out")) for r in exec_results),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "analysis_log_path": str(analysis_log_path),
        "trace_path": trace.get("trace_path"),
        "pcap_path": pcap_path,
        "filesystem_delta": fs_delta,
        "process_delta": {
            "before_count": len(proc_before),
            "after_count": len(proc_after),
            "new_processes_estimate": max(0, len(proc_after) - len(proc_before)),
        },
        "network_trace": trace,
        "network_signal": network_signal,
        "exec_signal": exec_signal,
        "persistence_signal": persistence_signal,
        "file_signal": file_signal,
        "archive_file_count": sum(1 for p in extract_dir.rglob("*") if p.is_file()) if extract_dir.exists() else 1,
        "archive_member_exec_count": archive_exec_count,
        "archive_member_skipped_count": archive_skipped_count,
        "archive_member_results": [{
            "path": r.get("path"),
            "command": r.get("command"),
            "returncode": r.get("returncode"),
            "timed_out": r.get("timed_out"),
            "stdout_preview": (r.get("stdout") or "")[:1200],
            "stderr_preview": (r.get("stderr") or "")[:1200],
            "strategy": r.get("strategy"),
            "skipped": r.get("skipped"),
            "skip_reason": r.get("skip_reason"),
        } for r in exec_results],
        "combined_output_preview": combined_preview,
        "score": 0,
        "analysis_state": "partial" if archive_skipped_count else "complete",
        "sandbox_profile": {
            "backend": "local",
            "network_disabled": bool(settings.sandbox_disable_network),
            "drop_privileges": bool(settings.sandbox_drop_privileges),
            "runtime_root": str(work_dir),
        },
    }

    shutil.rmtree(work_dir, ignore_errors=True)
    return result
