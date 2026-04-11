from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import traceback
import zipfile
from pathlib import Path

import psutil

WORK_DIR = Path(os.environ.get("VM_WORK_DIR", r"C:\sandbox_work")).resolve()
POLL_SECONDS = int(os.environ.get("VM_AGENT_POLL_SECONDS", "3"))


def resolve_shared_dir() -> Path:
    env_value = (os.environ.get("VM_SHARED_DIR") or "").strip()
    candidates = []
    if env_value:
        candidates.append(Path(env_value))
    candidates.extend([
        Path(r"C:\sandbox_shared"),
        Path(r"\\vmware-host\Shared Folders\sandbox_shared"),
        Path(r"\\vmware-host\Shared Folders\shared"),
        Path(r"Z:\sandbox_shared"),
        Path(r"Z:\shared"),
    ])

    for candidate in candidates:
        try:
            if candidate.exists():
                inbox = candidate / "inbox"
                outbox = candidate / "outbox"
                if inbox.exists() or outbox.exists():
                    return candidate.resolve()
        except Exception:
            continue

    for candidate in candidates:
        try:
            if candidate.exists():
                return candidate.resolve()
        except Exception:
            continue

    return Path(r"C:\sandbox_shared").resolve()


SHARED_DIR = Path(r"\\vmware-host\Shared Folders\shared")

EXEC_SUFFIXES = {".py", ".ps1", ".bat", ".cmd", ".exe", ".js", ".vbs"}
EXEC_PRIORITY = {".exe": 0, ".dll": 1, ".ps1": 2, ".bat": 3, ".cmd": 4, ".js": 5, ".vbs": 6, ".py": 7}
SUSPICIOUS_PROCESS_MARKERS = {
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
    "schtasks", "certutil", "bitsadmin", "wmic", "msbuild", "installutil", "python"
}
PERSISTENCE_DIR_MARKERS = {
    "appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
    "programdata\\microsoft\\windows\\start menu\\programs\\startup",
}
DOCUMENT_SUFFIXES = {".docm", ".xlsm", ".doc", ".docx", ".xls", ".xlsx"}
SCRIPT_SUFFIXES = {".ps1", ".bat", ".cmd", ".js", ".vbs", ".py"}
BINARY_SUFFIXES = {".exe", ".dll", ".com", ".scr"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def append_timeline(timeline: list[dict], event: str, **extra) -> None:
    payload = {"ts": utc_now(), "event": event}
    payload.update(extra)
    timeline.append(payload)


def process_snapshot() -> list[dict]:
    items = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "exe", "create_time"]):
        try:
            info = proc.info
            info["cmdline"] = info.get("cmdline") or []
            items.append(info)
        except Exception:
            continue
    return items[:800]


def process_map(snapshot: list[dict]) -> dict[tuple[int, float], dict]:
    mapped = {}
    for item in snapshot:
        key = (int(item.get("pid") or 0), float(item.get("create_time") or 0.0))
        mapped[key] = item
    return mapped


def net_snapshot() -> list[dict]:
    rows = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            raddr = getattr(conn, "raddr", None)
            if not raddr:
                continue
            remote_ip = getattr(raddr, "ip", None) or (raddr[0] if isinstance(raddr, tuple) and len(raddr) > 0 else None)
            remote_port = getattr(raddr, "port", None) or (raddr[1] if isinstance(raddr, tuple) and len(raddr) > 1 else None)
            if not remote_ip:
                continue
            rows.append({
                "pid": int(conn.pid or 0),
                "status": str(conn.status),
                "remote_ip": str(remote_ip),
                "remote_port": int(remote_port or 0),
            })
    except Exception:
        return []
    return rows[:300]


def safe_extract(zip_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            target = (dest / member.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)


def build_command(path: Path) -> list[str] | None:
    suf = path.suffix.lower()
    if suf == ".py":
        return ["python", str(path)]
    if suf == ".ps1":
        return ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(path)]
    if suf in {".bat", ".cmd"}:
        return ["cmd", "/c", str(path)]
    if suf == ".js":
        return ["wscript", "//B", str(path)]
    if suf == ".vbs":
        return ["cscript", "//B", str(path)]
    if suf == ".exe":
        return [str(path)]
    return None


def classify_created_file(path_str: str) -> str:
    suffix = Path(path_str).suffix.lower()
    lowered = path_str.lower()
    if suffix in BINARY_SUFFIXES:
        return "binary_drop"
    if suffix in SCRIPT_SUFFIXES:
        return "script_drop"
    if suffix in DOCUMENT_SUFFIXES:
        return "document_drop"
    if any(marker in lowered for marker in PERSISTENCE_DIR_MARKERS):
        return "startup_drop"
    return "other_drop"


def rank_targets(extract_dir: Path) -> list[Path]:
    targets = [p for p in extract_dir.rglob("*") if p.is_file() and p.suffix.lower() in EXEC_SUFFIXES]
    targets.sort(key=lambda p: (EXEC_PRIORITY.get(p.suffix.lower(), 20), str(p).lower()))
    return targets[:8]


def run_member(path: Path, timeout_seconds: int, out_dir: Path, timeline: list[dict], extract_dir: Path) -> dict:
    command = build_command(path)
    rel_path = str(path.relative_to(extract_dir)).replace("\\", "/")

    if not command:
        return {
            "name": path.name,
            "path": rel_path,
            "skipped": True,
            "skip_reason": "unsupported_extension",
            "fail_reason": "not_executable",
        }

    append_timeline(timeline, "member_start", member=str(path), command=command)
    started = time.time()

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(path.parent),
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        (out_dir / f"{path.stem}_stdout.txt").write_text(stdout, encoding="utf-8", errors="ignore")
        (out_dir / f"{path.stem}_stderr.txt").write_text(stderr, encoding="utf-8", errors="ignore")

        append_timeline(
            timeline,
            "member_end",
            member=str(path),
            returncode=proc.returncode,
            duration_ms=int((time.time() - started) * 1000),
        )

        text_l = (stdout + "\n" + stderr + "\n" + " ".join(command)).lower()
        behavior = {
            "network_signal": any(m in text_l for m in ["http://", "https://", "ftp://", "downloadstring", "invoke-webrequest", "urlmon", "bitsadmin", "certutil -urlcache"]),
            "persistence_signal": any(m in text_l for m in ["currentversion\\run", "runonce", "schtasks", "startup", "reg add"]),
            "ransomware_signal": any(m in text_l for m in ["vssadmin", "wbadmin", "bcdedit", "ransom", "decrypt"]),
            "execution_signal": any(m in text_l for m in ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript"]),
        }

        return {
            "name": path.name,
            "path": rel_path,
            "command": command,
            "returncode": proc.returncode,
            "timed_out": False,
            "stdout_preview": stdout[:1200],
            "stderr_preview": stderr[:1200],
            "strategy": "guest_native",
            "behavior": behavior,
            "skipped": False,
        }

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        append_timeline(timeline, "member_timeout", member=str(path), duration_ms=int((time.time() - started) * 1000))

        text_l = (stdout + "\n" + stderr + "\n" + " ".join(command)).lower()
        behavior = {
            "network_signal": any(m in text_l for m in ["http://", "https://", "ftp://", "downloadstring", "invoke-webrequest", "urlmon", "bitsadmin", "certutil -urlcache"]),
            "persistence_signal": any(m in text_l for m in ["currentversion\\run", "runonce", "schtasks", "startup", "reg add"]),
            "ransomware_signal": any(m in text_l for m in ["vssadmin", "wbadmin", "bcdedit", "ransom", "decrypt"]),
            "execution_signal": any(m in text_l for m in ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript"]),
        }

        return {
            "name": path.name,
            "path": rel_path,
            "command": command,
            "returncode": -1,
            "timed_out": True,
            "stdout_preview": stdout[:1200],
            "stderr_preview": stderr[:1200],
            "strategy": "guest_native",
            "behavior": behavior,
            "skipped": False,
            "fail_reason": "timeout",
        }

    except Exception as exc:
        append_timeline(timeline, "member_error", member=str(path), error=str(exc))
        return {
            "name": path.name,
            "path": rel_path,
            "skipped": True,
            "skip_reason": str(exc),
            "strategy": "guest_native",
            "fail_reason": "execution_failed",
        }


def summarize_process_delta(before_proc: list[dict], after_proc: list[dict]) -> dict:
    before_map = process_map(before_proc)
    after_map = process_map(after_proc)
    new_items = [v for k, v in after_map.items() if k not in before_map]

    suspicious = []
    tree = []

    for item in new_items[:60]:
        name = str(item.get("name") or "")
        cmdline = " ".join(item.get("cmdline") or [])
        lowered = f"{name} {cmdline}".lower()
        if any(marker in lowered for marker in SUSPICIOUS_PROCESS_MARKERS):
            suspicious.append({"pid": item.get("pid"), "name": name, "cmdline": cmdline[:300]})
        tree.append({"pid": item.get("pid"), "ppid": item.get("ppid"), "name": name, "cmdline": cmdline[:300]})

    return {
        "before_count": len(before_proc),
        "after_count": len(after_proc),
        "new_processes_estimate": max(0, len(after_proc) - len(before_proc)),
        "new_process_tree": tree[:40],
        "suspicious_processes": suspicious[:20],
    }


def summarize_network_delta(before_net: list[dict], after_net: list[dict]) -> dict:
    before_keys = {(r["pid"], r["remote_ip"], r["remote_port"]) for r in before_net}
    after_rows = [r for r in after_net if (r["pid"], r["remote_ip"], r["remote_port"]) not in before_keys]
    endpoints = []
    for row in after_rows[:40]:
        endpoints.append({
            "pid": row["pid"],
            "remote_ip": row["remote_ip"],
            "remote_port": row["remote_port"],
            "status": row["status"],
        })
    return {
        "endpoints": endpoints,
        "connection_count": len(endpoints),
        "disabled": False,
        "reason": None,
    }


def analyze_job(job_dir: Path) -> dict:
    report_id = job_dir.name
    outbox = SHARED_DIR / "outbox" / report_id
    outbox.mkdir(parents=True, exist_ok=True)

    meta_path = job_dir / "job.json"
    if not meta_path.exists():
        raise Exception(f"job.json not found: {meta_path}")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    sample_name = meta.get("sample_name")
    if not sample_name:
        raise Exception(f"sample_name missing in job.json: {meta}")

    timeout_seconds = int(meta.get("timeout_seconds", 180))
    sample_path = job_dir / sample_name

    if not sample_path.exists():
        raise Exception(f"sample file not found: {sample_path}")

    guest_job_root = WORK_DIR / report_id
    timeline: list[dict] = []
    append_timeline(timeline, "job_begin", report_id=report_id, sample_name=sample_name)

    if guest_job_root.exists():
        shutil.rmtree(guest_job_root, ignore_errors=True)
    guest_job_root.mkdir(parents=True, exist_ok=True)

    extract_dir = guest_job_root / "extract"
    artifact_dir = guest_job_root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    before_files = {str(p.relative_to(guest_job_root)) for p in guest_job_root.rglob("*") if p.is_file()}
    before_proc = process_snapshot()
    before_net = net_snapshot()

    if sample_path.suffix.lower() == ".zip":
        safe_extract(sample_path, extract_dir)
    else:
        extract_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sample_path, extract_dir / sample_path.name)

    append_timeline(timeline, "extract_complete", file_count=sum(1 for p in extract_dir.rglob("*") if p.is_file()))

    targets = rank_targets(extract_dir)
    append_timeline(timeline, "execution_plan", targets=[str(p.relative_to(extract_dir)) for p in targets])

    member_results = [run_member(p, timeout_seconds, artifact_dir, timeline, extract_dir) for p in targets]

    time.sleep(2)

    after_files = {str(p.relative_to(guest_job_root)) for p in guest_job_root.rglob("*") if p.is_file()}
    after_proc = process_snapshot()
    after_net = net_snapshot()

    created = sorted(after_files - before_files)
    created_details = [{"path": p, "category": classify_created_file(p)} for p in created[:200]]

    process_delta = summarize_process_delta(before_proc, after_proc)
    network_trace = summarize_network_delta(before_net, after_net)

    combined = "\n\n".join(
        (m.get("stdout_preview", "") + "\n" + m.get("stderr_preview", "")).strip()
        for m in member_results
        if not m.get("skipped")
    )
    combined_l = combined.lower()
    created_lower = "\n".join(c["path"].lower() for c in created_details)

    exec_signal = bool(process_delta["suspicious_processes"]) or any(k in combined_l for k in ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript"])
    persistence_signal = (
        any(k in combined_l for k in ["currentversion\\run", "runonce", "schtasks", "startup"])
        or any("startup_drop" == c["category"] for c in created_details)
        or "scheduledtasks" in created_lower
    )
    file_signal = bool(created_details)
    network_signal = bool(network_trace["endpoints"]) or any(k in combined_l for k in ["http://", "https://", "ftp://"])
    ransomware_signal = any(k in combined_l for k in ["vssadmin", "wbadmin", "bcdedit", "ransom", "decrypt"])
    note_signal = any(Path(c["path"]).suffix.lower() == ".txt" and ("readme" in c["path"].lower() or "decrypt" in c["path"].lower()) for c in created_details)

    score = 0
    if exec_signal:
        score += 20
    if persistence_signal:
        score += 25
    if file_signal:
        score += min(20, 4 + len(created_details) // 2)
    if network_signal:
        score += 20
    if process_delta["suspicious_processes"]:
        score += min(10, len(process_delta["suspicious_processes"]) * 2)
    if ransomware_signal or note_signal:
        score += 25
    score = min(score, 100)

    append_timeline(
        timeline,
        "job_end",
        created_files=len(created_details),
        suspicious_processes=len(process_delta["suspicious_processes"]),
        network_connections=len(network_trace["endpoints"]),
    )

    result = {
        "returncode": 0 if all(not m.get("timed_out") for m in member_results) else -1,
        "timed_out": any(m.get("timed_out") for m in member_results),
        "filesystem_delta": {
            "created": created[:200],
            "changed": [],
            "deleted": [],
            "created_details": created_details,
        },
        "process_delta": process_delta,
        "network_trace": network_trace,
        "network_signal": network_signal,
        "exec_signal": exec_signal,
        "persistence_signal": persistence_signal,
        "file_signal": file_signal,
        "ransomware_signal": ransomware_signal or note_signal,
        "archive_file_count": sum(1 for p in extract_dir.rglob("*") if p.is_file()),
        "archive_member_exec_count": sum(1 for m in member_results if not m.get("skipped")),
        "archive_member_skipped_count": sum(1 for m in member_results if m.get("skipped")),
        "archive_member_results": member_results,
        "combined_output_preview": combined[:4000],
        "score": score,
        "analysis_state": "complete" if member_results else "static_only",
        "timeline": timeline,
    }

    (outbox / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def write_failed_result(out_result: Path, exc: Exception) -> None:
    out_result.parent.mkdir(parents=True, exist_ok=True)
    error_detail = {
        "returncode": -1,
        "timed_out": False,
        "analysis_state": "failed",
        "error": str(exc),
        "traceback": traceback.format_exc(),
    }
    out_result.write_text(json.dumps(error_detail, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    (SHARED_DIR / "inbox").mkdir(parents=True, exist_ok=True)
    (SHARED_DIR / "outbox").mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    print(f"guest_agent watching {SHARED_DIR}")
    print(f"guest_agent inbox={(SHARED_DIR / 'inbox')}")
    print(f"guest_agent outbox={(SHARED_DIR / 'outbox')}")

    while True:
        for job_dir in (SHARED_DIR / "inbox").iterdir():
            if not job_dir.is_dir():
                continue
            if not (job_dir / "job.json").exists():
                continue

            out_result = SHARED_DIR / "outbox" / job_dir.name / "result.json"
            if out_result.exists():
                continue

            try:
                analyze_job(job_dir)
            except Exception as exc:
                write_failed_result(out_result, exc)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())