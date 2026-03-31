from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import psutil

from app.core.config import settings
from app.sandbox.fs_monitor import diff_snapshots, snapshot_tree
from app.sandbox.network_monitor import reserve_pcap_path, start_tcpdump, stop_tcpdump

EXECUTABLE_SUFFIXES = {".py", ".sh", ".js", ".ps1", ".bat", ".cmd"}
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
    return processes[:300]


def _strings_command(sample_path: str, limit: int) -> list[str]:
    quoted = shlex.quote(sample_path)
    return ["sh", "-lc", f"strings {quoted} | head -n {int(limit)}"]


def _build_command(sample_path: str) -> list[str]:
    suffix = Path(sample_path).suffix.lower()
    if suffix == ".py":
        return ["python", sample_path]
    if suffix == ".sh":
        return ["sh", sample_path]
    if suffix == ".js":
        return ["node", sample_path]
    if suffix == ".ps1":
        return ["pwsh", "-File", sample_path]
    if suffix in {".bat", ".cmd"}:
        return _strings_command(sample_path, 100)
    if suffix in {".exe", ".dll", ".scr", ".com"}:
        return _strings_command(sample_path, 140)
    return _strings_command(sample_path, 100)


def _append_stage(log_path: Path, stage: str, **extra) -> None:
    payload = {"ts": _utc_now(), "stage": stage}
    payload.update(extra)
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _execute_one(sample_path: str, timeout_seconds: int, analysis_log_path: Path, role: str) -> tuple[str, str, int, bool, list[str]]:
    command = _build_command(sample_path)
    _append_stage(analysis_log_path, "exec_start", role=role, target=sample_path, command=command)
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(Path(sample_path).parent),
        )
        _append_stage(analysis_log_path, "exec_done", role=role, target=sample_path, returncode=int(result.returncode))
        return result.stdout or "", result.stderr or "", int(result.returncode), False, command
    except FileNotFoundError as exc:
        fallback_cmd = _strings_command(sample_path, 140)
        _append_stage(analysis_log_path, "exec_runner_missing", role=role, target=sample_path, missing=str(exc), fallback=fallback_cmd)
        fallback = subprocess.run(
            fallback_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(Path(sample_path).parent),
        )
        stderr = (fallback.stderr or "") + f"\nrunner_missing:{exc}"
        return fallback.stdout or "", stderr, int(fallback.returncode), False, fallback_cmd
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + "\ntimeout"
        _append_stage(analysis_log_path, "exec_timeout", role=role, target=sample_path)
        return stdout, stderr, 124, True, command
    except Exception as exc:
        _append_stage(analysis_log_path, "exec_error", role=role, target=sample_path, error=str(exc))
        return "", f"execution_error:{exc}", 1, False, command


def _score_runtime_output(stdout: str, stderr: str, fs_delta: dict) -> dict:
    combined_output = f"{stdout}\n{stderr}".lower()
    network_signal = any(k in combined_output for k in ["http://", "https://", "wget", "curl", "downloadstring", "invoke-webrequest", "bitsadmin"])
    exec_signal = any(k in combined_output for k in ["powershell", "cmd.exe", "wscript", "cscript", "start-process", "subprocess"])
    persistence_signal = any(k in combined_output for k in ["schtasks", "startup", "registry", "reg add", "autorun", "run key", "scheduled task"])
    file_signal = bool(fs_delta["created"] or fs_delta["changed"])

    score = 0
    if network_signal:
        score += 2
    if exec_signal:
        score += 1
    if persistence_signal:
        score += 3
    if file_signal:
        score += 1
    if persistence_signal and network_signal:
        score += 1

    return {
        "network_signal": network_signal,
        "exec_signal": exec_signal,
        "persistence_signal": persistence_signal,
        "file_signal": file_signal,
        "score": score,
        "combined_output_preview": combined_output[:1200],
    }


def _should_skip_member(name: str) -> bool:
    lowered = name.lower()
    return any(part in lowered for part in SKIP_PARTS)


def _safe_extract_zip(zf: zipfile.ZipFile, extract_root: Path) -> None:
    base = extract_root.resolve()
    extracted = 0
    total_uncompressed = 0
    for member in zf.infolist():
        if member.is_dir():
            continue
        extracted += 1
        total_uncompressed += int(member.file_size)
        if extracted > settings.max_archive_files:
            raise ValueError("archive_limit_exceeded:file_count")
        if total_uncompressed > settings.max_zip_total_uncompressed_bytes:
            raise ValueError("archive_limit_exceeded:uncompressed_size")
        target_path = (extract_root / member.filename).resolve()
        if os.path.commonpath([str(base), str(target_path)]) != str(base):
            raise ValueError(f"unsafe_zip_member:{member.filename}")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, open(target_path, "wb") as dst:
            shutil.copyfileobj(src, dst)


def _collect_archive_targets(sample_path: str, extract_root: Path) -> tuple[list[Path], int]:
    if not zipfile.is_zipfile(sample_path):
        return [], 0
    targets = []
    file_count = 0
    with zipfile.ZipFile(sample_path) as zf:
        _safe_extract_zip(zf, extract_root)
    for path in sorted(extract_root.rglob("*")):
        if not path.is_file():
            continue
        file_count += 1
        if _should_skip_member(str(path)):
            continue
        if path.suffix.lower() in EXECUTABLE_SUFFIXES:
            targets.append(path)
    return targets[: settings.max_archive_exec_members], file_count


def run_dynamic_analysis(sample_path: str, job_id: str, artifact_root: str) -> dict:
    logs_dir = Path(artifact_root) / "logs"
    pcaps_dir = Path(artifact_root) / "pcaps"
    extract_dir = Path(artifact_root) / "archive_exec" / f"job_{job_id}"
    logs_dir.mkdir(parents=True, exist_ok=True)
    pcaps_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    stdout_path = str(logs_dir / f"job_{job_id}_stdout.txt")
    stderr_path = str(logs_dir / f"job_{job_id}_stderr.txt")
    proc_path = str(logs_dir / f"job_{job_id}_processes.json")
    analysis_log_path = logs_dir / f"job_{job_id}_analysis.log"
    pcap_path = reserve_pcap_path(str(pcaps_dir / f"job_{job_id}.pcap"))

    before_fs = snapshot_tree(artifact_root)
    before_proc = _process_snapshot()
    tcpdump_proc = start_tcpdump(pcap_path) if settings.enable_pcap else None
    _append_stage(analysis_log_path, "dynamic_start", sample=sample_path)

    member_results = []
    total_stdout_parts = []
    total_stderr_parts = []
    returncode = 0
    timed_out = False
    archive_file_count = 0

    try:
        stdout, stderr, returncode, root_timed_out, root_command = _execute_one(sample_path, settings.sample_timeout_seconds, analysis_log_path, "archive")
        timed_out = timed_out or root_timed_out
        total_stdout_parts.append(stdout)
        total_stderr_parts.append(stderr)
        archive_targets, archive_file_count = _collect_archive_targets(sample_path, extract_dir)
        _append_stage(analysis_log_path, "archive_targets_ready", total_files=archive_file_count, executable_members=len(archive_targets), archive_command=root_command)
        for member in archive_targets:
            m_stdout, m_stderr, m_returncode, m_timed_out, member_command = _execute_one(str(member), settings.sample_timeout_seconds, analysis_log_path, "member")
            timed_out = timed_out or m_timed_out
            member_results.append({
                "name": str(member.relative_to(extract_dir)),
                "command": member_command,
                "returncode": m_returncode,
                "timed_out": m_timed_out,
                "stdout_preview": (m_stdout or "")[:400],
                "stderr_preview": (m_stderr or "")[:400],
            })
            total_stdout_parts.append(m_stdout)
            total_stderr_parts.append(m_stderr)
    finally:
        stop_tcpdump(tcpdump_proc)
        _append_stage(analysis_log_path, "dynamic_stop")

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

    runtime_result = _score_runtime_output(stdout, stderr, fs_delta)
    return {
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "analysis_log_path": str(analysis_log_path),
        "trace_path": None,
        "pcap_path": pcap_path if settings.enable_pcap else None,
        "filesystem_delta": fs_delta,
        "process_delta": proc_delta,
        "network_signal": runtime_result["network_signal"],
        "exec_signal": runtime_result["exec_signal"],
        "persistence_signal": runtime_result["persistence_signal"],
        "file_signal": runtime_result["file_signal"],
        "archive_file_count": archive_file_count,
        "archive_member_exec_count": len(member_results),
        "archive_member_results": member_results,
        "combined_output_preview": runtime_result["combined_output_preview"],
        "score": runtime_result["score"],
    }
