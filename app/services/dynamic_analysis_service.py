from __future__ import annotations

import json
import os
import pwd
import resource
import shlex
import shutil
import subprocess
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
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(work_dir),
        "TMPDIR": str(work_dir),
        "TEMP": str(work_dir),
        "TMP": str(work_dir),
        "PYTHONUNBUFFERED": "1",
    }
    return env


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


def _unsupported_member_reason(sample_path: str) -> str | None:
    suffix = Path(sample_path).suffix.lower()
    if suffix in {".exe", ".dll", ".com", ".scr"}:
        return f"dynamic execution skipped for {suffix} on Linux sandbox; strings inspection used instead"
    return None


def _execute_one(sample_path: str, timeout_seconds: int, analysis_log_path: Path, role: str, work_dir: Path) -> dict:
    command, strategy = _build_command(sample_path)
    suffix = Path(sample_path).suffix.lower()
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
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
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
            "skip_reason": f"runner missing: {exc}",
        }
        try:
            proc = subprocess.run(
                fallback_command,
                capture_output=True,
                text=True,
                timeout=max(5, min(timeout_seconds, 15)),
                cwd=str(work_dir),
                env=_sandbox_env(work_dir),
                preexec_fn=_sandbox_preexec,
            )
            result["stdout"] = proc.stdout or ""
            result["stderr"] = ((result["stderr"] + "\n\n") if result["stderr"] else "") + (proc.stderr or "")
        except Exception as fallback_exc:
            result["stderr"] = ((result["stderr"] + "\n\n") if result["stderr"] else "") + f"strings_fallback_error:{fallback_exc}"
    except Exception as exc:
        result = {
            "command": command,
            "returncode": -1,
            "timed_out": False,
            "stdout": "",
            "stderr": str(exc),
            "strategy": strategy,
            "skipped": True,
            "skip_reason": str(exc),
        }

    _append_stage(
        analysis_log_path,
        "execute_done",
        role=role,
        strategy=result["strategy"],
        returncode=result["returncode"],
        timed_out=result["timed_out"],
        skipped=result["skipped"],
    )
    return result


def _score_runtime_output(stdout: str, stderr: str, fs_delta: dict, network_result: dict) -> dict:
    combined = f"{stdout}\n{stderr}".lower()
    exec_keywords = ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript", "bash", "sh "]
    persistence_keywords = ["currentversion\\run", "schtasks", "startup", "reg add", "autorun"]
    score = 0

    exec_signal = any(k in combined for k in exec_keywords)
    persistence_signal = any(k in combined for k in persistence_keywords)
    file_signal = bool(fs_delta.get("created") or fs_delta.get("changed") or fs_delta.get("deleted"))
    network_signal = bool(network_result.get("network_signal"))

    if exec_signal:
        score += 4
    if persistence_signal:
        score += 4
    if file_signal:
        score += 2
    if network_signal:
        score += 4

    preview = (stdout[:2000] + "\n\n" + stderr[:2000]).strip()
    return {
        "exec_signal": exec_signal,
        "persistence_signal": persistence_signal,
        "file_signal": file_signal,
        "network_signal": network_signal,
        "score": score,
        "combined_output_preview": preview[:4000],
    }


def _should_skip_member(name: str) -> bool:
    parts = set(Path(name).parts)
    return bool(parts & SKIP_PARTS)


def _safe_extract_zip(zf: zipfile.ZipFile, extract_root: Path) -> None:
    extract_root = extract_root.resolve()
    for member in zf.infolist():
        member_path = (extract_root / member.filename).resolve()
        if not str(member_path).startswith(str(extract_root)):
            raise ValueError(f"unsafe archive member path: {member.filename}")
        if member.is_dir():
            member_path.mkdir(parents=True, exist_ok=True)
            continue
        member_path.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, open(member_path, "wb") as dst:
            shutil.copyfileobj(src, dst)


def _collect_archive_targets(sample_path: str, extract_root: Path) -> tuple[list[Path], int]:
    targets: list[Path] = []
    file_count = 0
    with zipfile.ZipFile(sample_path, "r") as zf:
        _safe_extract_zip(zf, extract_root)

    for path in extract_root.rglob("*"):
        if path.is_dir():
            continue
        if _should_skip_member(str(path.relative_to(extract_root))):
            continue
        file_count += 1
        if path.suffix.lower() in EXECUTABLE_SUFFIXES:
            targets.append(path)
    return targets[: int(settings.max_archive_exec_members)], file_count


def run_dynamic_analysis(sample_path: str, job_id: str, artifact_root: str) -> dict:
    artifact_root = Path(artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)

    stdout_path = artifact_root / f"job_{job_id}_stdout.txt"
    stderr_path = artifact_root / f"job_{job_id}_stderr.txt"
    proc_path = artifact_root / f"job_{job_id}_processes.json"
    analysis_log_path = artifact_root / f"job_{job_id}_analysis.log"
    network_trace_path = artifact_root / f"job_{job_id}_network_trace.json"
    pcap_path = reserve_pcap_path(str(artifact_root), job_id) if settings.enable_pcap else None

    before_fs = snapshot_tree(artifact_root)
    before_proc = _process_snapshot()

    extract_root = artifact_root / "archive_exec" / f"job_{job_id}"
    extract_root.mkdir(parents=True, exist_ok=True)
    member_results = []
    total_stdout_parts: list[str] = []
    total_stderr_parts: list[str] = []
    returncode = 0
    timed_out = False
    archive_file_count = 0
    skipped_count = 0

    targets, archive_file_count = _collect_archive_targets(sample_path, extract_root)

    tcpdump_proc = None
    net_capture = start_network_capture(str(network_trace_path))
    if settings.enable_pcap and pcap_path:
        tcpdump_proc = start_tcpdump(pcap_path)

    try:
        timeout_seconds = max(5, int(settings.sandbox_timeout_seconds))
        sandbox_root = artifact_root / "sandbox" / f"job_{job_id}"
        sandbox_root.mkdir(parents=True, exist_ok=True)

        if not targets:
            _append_stage(analysis_log_path, "dynamic_skip", reason="no executable members in archive")
        for idx, target in enumerate(targets, start=1):
            work_dir = sandbox_root / f"member_{idx}"
            work_dir.mkdir(parents=True, exist_ok=True)
            member_result = _execute_one(str(target), timeout_seconds, analysis_log_path, target.name, work_dir)
            member_results.append({
                "name": target.name,
                "command": member_result.get("command", []),
                "returncode": member_result.get("returncode", 0),
                "timed_out": member_result.get("timed_out", False),
                "stdout_preview": (member_result.get("stdout", "") or "")[:1200],
                "stderr_preview": (member_result.get("stderr", "") or "")[:1200],
                "strategy": member_result.get("strategy"),
                "skipped": member_result.get("skipped", False),
                "skip_reason": member_result.get("skip_reason"),
            })
            if member_result.get("timed_out"):
                timed_out = True
                returncode = -1
            elif member_result.get("returncode", 0) != 0 and returncode == 0:
                returncode = int(member_result.get("returncode", 0))
            if member_result.get("skipped"):
                skipped_count += 1
            total_stdout_parts.append(member_result.get("stdout", ""))
            total_stderr_parts.append(member_result.get("stderr", ""))
    finally:
        stop_tcpdump(tcpdump_proc)
        network_result = stop_network_capture(net_capture)
        _append_stage(analysis_log_path, "dynamic_stop", network_signal=network_result.get("network_signal", False))

    stdout = "\n\n".join([part for part in total_stdout_parts if part])
    stderr = "\n\n".join([part for part in total_stderr_parts if part])

    Path(stdout_path).write_text(stdout, encoding="utf-8", errors="ignore")
    Path(stderr_path).write_text(stderr, encoding="utf-8", errors="ignore")

    after_fs = snapshot_tree(artifact_root)
    after_proc = _process_snapshot()
    fs_delta = diff_snapshots(before_fs, after_fs)
    proc_delta = {
        "before_count": len(before_proc),
        "after_count": len(after_proc),
        "new_processes_estimate": max(0, len(after_proc) - len(before_proc)),
    }
    Path(proc_path).write_text(json.dumps(after_proc, ensure_ascii=False, indent=2), encoding="utf-8")

    runtime_result = _score_runtime_output(stdout, stderr, fs_delta, network_result)
    return {
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "analysis_log_path": str(analysis_log_path),
        "trace_path": str(network_trace_path),
        "pcap_path": pcap_path if settings.enable_pcap else None,
        "filesystem_delta": fs_delta,
        "process_delta": proc_delta,
        "network_trace": network_result,
        "network_signal": runtime_result["network_signal"],
        "exec_signal": runtime_result["exec_signal"],
        "persistence_signal": runtime_result["persistence_signal"],
        "file_signal": runtime_result["file_signal"],
        "archive_file_count": archive_file_count,
        "archive_member_exec_count": len(member_results),
        "archive_member_skipped_count": skipped_count,
        "archive_member_results": member_results,
        "combined_output_preview": runtime_result["combined_output_preview"],
        "score": runtime_result["score"],
        "analysis_state": "partial" if skipped_count else "complete",
        "sandbox_profile": {
            "memory_limit_mb": settings.sandbox_memory_limit_mb,
            "file_size_limit_mb": settings.sandbox_file_size_limit_mb,
            "max_processes": settings.sandbox_max_processes,
            "drop_privileges": settings.sandbox_drop_privileges,
            "disable_network": settings.sandbox_disable_network,
        },
    }
