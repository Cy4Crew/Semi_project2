from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import traceback
import zipfile
from collections import deque

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
PE_DLL_CHARACTERISTIC = 0x2000
from pathlib import Path

import psutil

# ── 4번: file_diff 모듈 import (같은 guest_tools/ 디렉토리에 위치)
try:
    from file_diff import (
        take_snapshot,
        compare_snapshots,
        save_dropped_files,
        classify_file,
        is_ransom_note,
        _get_scan_roots,
    )
    _FILE_DIFF_AVAILABLE = True
except ImportError:
    _FILE_DIFF_AVAILABLE = False

WORK_DIR = Path(os.environ.get("VM_WORK_DIR", r"C:\sandbox_work")).resolve()
POLL_SECONDS = int(os.environ.get("VM_AGENT_POLL_SECONDS", "3"))
SHARED_DIR = Path(os.environ.get("VM_SHARED_DIR") or r"\\vmware-host\Shared Folders\shared")
try:
    from sysmon_collector import collect_sysmon_events, clear_sysmon_log, summarize_sysmon_events
    SYSMON_AVAILABLE = True
except ImportError:
    SYSMON_AVAILABLE = False

def _derive_candidate_paths(value: str) -> list[Path]:
    value = str(value or "").strip()
    if not value:
        return []
    paths: list[Path] = [Path(value)]
    try:
        leaf = Path(value).name
    except Exception:
        leaf = ""
    if leaf:
        paths.append(Path(rf"\\vmware-host\Shared Folders\{leaf}"))
        paths.append(Path(rf"Z:\{leaf}"))
    return paths


def resolve_shared_dir() -> Path:
    shared_name = (os.environ.get("VM_SHARED_DIR_NAME") or "").strip()
    env_values = [
        (os.environ.get("VM_SHARED_DIR") or "").strip(),
        (os.environ.get("SHARED_DIR") or "").strip(),
    ]
    candidates: list[Path] = []
    for value in env_values:
        candidates.extend(_derive_candidate_paths(value))
    if shared_name:
        candidates.extend([
            Path(rf"\\vmware-host\Shared Folders\{shared_name}"),
            Path(rf"Z:\{shared_name}"),
            Path(rf"C:\{shared_name}"),
        ])
    candidates.extend([
        Path(r"\\vmware-host\Shared Folders\shared"),
        Path(r"\\vmware-host\Shared Folders\sandbox_shared"),
        Path(r"Z:\shared"),
        Path(r"Z:\sandbox_shared"),
        Path(r"C:\sandbox_shared"),
    ])

    preferred: list[Path] = []
    fallback: list[Path] = []
    seen: set[str] = set()

    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        preferred.append(candidate)

    for candidate in preferred:
        try:
            if candidate.exists():
                inbox = candidate / "inbox"
                outbox = candidate / "outbox"
                if inbox.exists() and outbox.exists():
                    return candidate.resolve()
        except Exception:
            continue

    for candidate in preferred:
        try:
            if candidate.exists():
                fallback.append(candidate)
        except Exception:
            continue

    if fallback:
        try:
            return fallback[0].resolve()
        except Exception:
            return fallback[0]

    if preferred:
        return preferred[0]
    return Path(r"\\vmware-host\Shared Folders\shared")


MAX_RECURSIVE_EXEC_TARGETS = int(os.environ.get("MAX_RECURSIVE_EXEC_TARGETS", "8"))
ARCHIVE_PASSWORDS = [token.strip().encode("utf-8", errors="ignore") for token in os.environ.get("ARCHIVE_PASSWORDS", "infected,malware,infected!,virus").split(",") if token.strip()]
MAX_RECURSIVE_EXEC_DEPTH = int(os.environ.get("MAX_RECURSIVE_EXEC_DEPTH", "2"))

EXEC_SUFFIXES = {'.py', '.ps1', '.bat', '.cmd', '.exe', '.dll', '.js', '.vbs', '.docm', '.xlsm', '.doc', '.docx', '.xls', '.xlsx', '.lnk', '.pdf', '.zip'}
EXEC_PRIORITY = {'.exe': 0, '.dll': 1, '.ps1': 2, '.bat': 3, '.cmd': 4, '.js': 5, '.vbs': 6, '.docm': 7, '.xlsm': 8, '.doc': 9, '.docx': 10, '.xls': 11, '.xlsx': 12, '.lnk': 13, '.pdf': 14, '.zip': 15, '.py': 16}
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



POPUP_KILL_INTERVAL_SECONDS = float(os.environ.get("POPUP_KILL_INTERVAL_SECONDS", "1.0"))
POPUP_PROCESS_NAMES = tuple(
    name.strip().lower()
    for name in (os.environ.get("POPUP_PROCESS_NAMES") or "WerFault.exe,wermgr.exe,OpenWith.exe,rundll32.exe,regsvr32.exe,hh.exe,AcroRd32.exe,WINWORD.EXE,EXCEL.EXE").split(",")
    if name.strip()
)
COMMON_LAUNCH_ERROR_MARKERS = (
    "not a valid win32 application",
    "not a valid application",
    "error in starting program",
    "unable to load",
    "entry point",
    "not found",
    "is not recognized",
    "wrong format",
    "bad exe format",
    "올바른 win32 응용 프로그램이 아닙니다",
    "시작하는 동안 문제가 발생했습니다",
)

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


def _open_zip_member(zf: zipfile.ZipFile, member: zipfile.ZipInfo):
    encrypted = bool(getattr(member, "flag_bits", 0) & 0x1)
    if not encrypted:
        return zf.open(member)
    last_error = None
    for password in ARCHIVE_PASSWORDS:
        try:
            return zf.open(member, pwd=password)
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"encrypted_zip_unsupported_or_bad_password:{member.filename}:{last_error}")

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
            with _open_zip_member(zf, member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)


def detect_package(path: Path) -> str:
    suf = path.suffix.lower()
    if suf in {'.docm', '.xlsm'}:
        return 'office_macro'
    if suf in {'.doc', '.docx', '.xls', '.xlsx'}:
        return 'office_document'
    if suf == '.dll':
        return 'dll'
    if suf == '.lnk':
        return 'shortcut'
    if suf == '.pdf':
        return 'pdf'
    if suf == '.zip':
        return 'zip_recursive'
    if suf in {'.js', '.vbs', '.ps1', '.bat', '.cmd', '.py'}:
        return 'script'
    if suf == '.exe':
        return 'exe'
    return 'generic'






def _binary_contains_token(data: bytes, token: str) -> bool:
    needle = token.encode("ascii", errors="ignore")
    if needle and needle in data:
        return True
    try:
        wide = token.encode("utf-16le")
    except Exception:
        return False
    return bool(wide) and wide in data


def _dll_has_export_name(path: Path, export_name: str) -> bool:
    try:
        data = path.read_bytes()[: 2 * 1024 * 1024]
    except Exception:
        return False
    return _binary_contains_token(data, export_name)


def _terminate_process_tree(pid: int) -> None:
    if pid <= 0:
        return
    try:
        proc = psutil.Process(pid)
    except Exception:
        return
    children = []
    try:
        children = proc.children(recursive=True)
    except Exception:
        children = []
    for child in reversed(children):
        try:
            child.kill()
        except Exception:
            pass
    try:
        proc.kill()
    except Exception:
        pass


def _kill_popup_processes_once() -> list[str]:
    killed = []
    target_names = set(POPUP_PROCESS_NAMES)
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = str(proc.info.get("name") or "").strip().lower()
            if not name or name not in target_names:
                continue
            proc.kill()
            killed.append(f"{name}:{proc.pid}")
        except Exception:
            continue
    return killed


def _start_popup_guard(stop_event: threading.Event, timeline: list[dict]) -> threading.Thread:
    def _worker() -> None:
        while not stop_event.is_set():
            killed = _kill_popup_processes_once()
            if killed:
                append_timeline(timeline, "popup_guard_kill", killed=killed)
            stop_event.wait(max(0.2, POPUP_KILL_INTERVAL_SECONDS))

    thread = threading.Thread(target=_worker, name="popup_guard", daemon=True)
    thread.start()
    return thread


def _stdout_stderr_preview(stdout: str, stderr: str) -> tuple[str, str]:
    return (stdout or "")[:1200], (stderr or "")[:1200]


def _detect_launch_error(stdout: str, stderr: str, command: list[str]) -> str | None:
    lowered = "\n".join([stdout or "", stderr or "", " ".join(command or [])]).lower()
    for marker in COMMON_LAUNCH_ERROR_MARKERS:
        if marker in lowered:
            return marker
    return None


def _classify_execution_outcome(path: Path, command: list[str], returncode: int, timed_out: bool, runtime_ms: int, stdout: str, stderr: str) -> tuple[bool, str | None]:
    if timed_out:
        return False, "timeout"
    launch_error = _detect_launch_error(stdout, stderr, command)
    if launch_error:
        return False, f"launch_error:{launch_error}"
    suffix = path.suffix.lower()
    if suffix in SCRIPT_SUFFIXES:
        if returncode == 0:
            return True, None
        if runtime_ms >= 1500 and not launch_error:
            return True, None
        return False, f"returncode_{returncode}"
    if suffix == ".dll":
        if returncode == 0 and runtime_ms >= 500:
            return True, None
        return False, f"returncode_{returncode}"
    if suffix == ".exe":
        if returncode == 0:
            return True, None
        if runtime_ms >= 2000 and not launch_error:
            return True, None
        return False, f"returncode_{returncode}"
    if returncode == 0:
        return True, None
    return False, f"returncode_{returncode}"


def _read_pe_info(path: Path) -> dict:
    try:
        with path.open('rb') as fp:
            mz = fp.read(2)
            if mz != b'MZ':
                return {"is_pe": False, "is_dll": False, "machine": None}
            fp.seek(0x3C)
            pe_offset_bytes = fp.read(4)
            if len(pe_offset_bytes) != 4:
                return {"is_pe": False, "is_dll": False, "machine": None}
            pe_offset = int.from_bytes(pe_offset_bytes, 'little', signed=False)
            fp.seek(pe_offset)
            if fp.read(4) != b'PE\x00\x00':
                return {"is_pe": False, "is_dll": False, "machine": None}
            machine = int.from_bytes(fp.read(2), 'little', signed=False)
            fp.seek(18, 1)
            characteristics = int.from_bytes(fp.read(2), 'little', signed=False)
            return {
                "is_pe": True,
                "is_dll": bool(characteristics & PE_DLL_CHARACTERISTIC),
                "machine": machine,
                "characteristics": characteristics,
            }
    except Exception:
        return {"is_pe": False, "is_dll": False, "machine": None}


def preflight_execution(path: Path) -> tuple[bool, str | None, dict]:
    suf = path.suffix.lower()
    package = detect_package(path)
    info = {"package": package, "suffix": suf}
    if suf in {'.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.pdf', '.lnk'}:
        return False, 'gui_launch_skipped', info
    if suf == '.zip':
        return False, 'archive_exec_skipped', info
    if suf == '.exe':
        pe = _read_pe_info(path)
        info['pe'] = pe
        if not pe.get('is_pe'):
            return False, 'invalid_pe_exe', info
        if pe.get('is_dll'):
            return False, 'exe_is_dll_image', info
    if suf == '.dll':
        pe = _read_pe_info(path)
        info['pe'] = pe
        if not pe.get('is_pe'):
            return False, 'invalid_pe_dll', info
        if not pe.get('is_dll'):
            return False, 'not_a_dll_image', info
        has_entry = _dll_has_export_name(path, 'DllRegisterServer')
        info['dll_register_server_export'] = has_entry
        if not has_entry:
            return False, 'dll_entrypoint_missing', info
    return True, None, info


def build_command(path: Path) -> tuple[list[str] | None, str]:
    package = detect_package(path)
    suf = path.suffix.lower()
    if suf == '.py':
        return ["python", str(path)], package
    if suf == '.ps1':
        return ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(path)], package
    if suf in {'.bat', '.cmd'}:
        return ["cmd", "/c", str(path)], package
    if suf == '.js':
        return ["wscript", "//B", str(path)], package
    if suf == '.vbs':
        return ["cscript", "//B", str(path)], package
    if suf == '.exe':
        return [str(path)], package
    if suf == '.dll':
        return ["rundll32.exe", str(path) + ",DllRegisterServer"], package
    if suf in {'.docm', '.doc', '.docx'}:
        return None, package
    if suf in {'.xlsm', '.xls', '.xlsx'}:
        return None, package
    if suf == '.pdf':
        return None, package
    if suf == '.lnk':
        return None, package
    return None, package




def _sample_process_state(root_pid: int, path: Path) -> tuple[list[dict], list[dict]]:
    tree: list[dict] = []
    netrows: list[dict] = []
    if root_pid <= 0:
        return tree, netrows

    related_markers = {str(path).lower(), str(path.name).lower(), str(path.parent).lower()}
    procs: list[psutil.Process] = []
    try:
        root = psutil.Process(root_pid)
        procs.extend([root] + root.children(recursive=True))
    except Exception:
        pass

    now = time.time()
    for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
        try:
            info = proc.info
            cmdline_parts = info.get("cmdline") or []
            cmdline = " ".join(cmdline_parts).lower()
            create_time = float(info.get("create_time") or 0.0)
            recent = create_time > 0 and (now - create_time) <= max(20.0, float(POLL_SECONDS) * 8.0)
            related = any(marker and marker in cmdline for marker in related_markers)
            if related or recent and int(info.get("ppid") or 0) == root_pid:
                procs.append(proc)
        except Exception:
            continue

    seen = set()
    for proc in procs:
        try:
            if proc.pid in seen:
                continue
            seen.add(proc.pid)
            cmdline = ' '.join(proc.cmdline())[:300]
            tree.append({'pid': proc.pid, 'ppid': proc.ppid(), 'name': proc.name(), 'cmdline': cmdline})
            for conn in proc.net_connections(kind='inet'):
                raddr = getattr(conn, 'raddr', None)
                if not raddr:
                    continue
                remote_ip = getattr(raddr, 'ip', None) or (raddr[0] if isinstance(raddr, tuple) and len(raddr) > 0 else None)
                remote_port = getattr(raddr, 'port', None) or (raddr[1] if isinstance(raddr, tuple) and len(raddr) > 1 else None)
                if remote_ip:
                    netrows.append({'pid': proc.pid, 'remote_ip': str(remote_ip), 'remote_port': int(remote_port or 0), 'status': str(conn.status)})
        except Exception:
            continue

    tree.sort(key=lambda x: (int(x.get('ppid') or 0), int(x.get('pid') or 0), str(x.get('name') or '').lower()))
    return tree[:80], netrows[:80]


def _is_noise_created_path(path_str: str) -> bool:
    lower = str(path_str or '').replace('/', '\\').lower()
    name = lower.rsplit('\\', 1)[-1]
    return name.endswith('_stdout.txt') or name.endswith('_stderr.txt') or name in {'stdout.txt', 'stderr.txt'}
def classify_created_file(path_str: str) -> str:
    # ── 4번: file_diff 모듈이 있으면 위임, 없으면 기존 로직 폴백
    if _FILE_DIFF_AVAILABLE:
        return classify_file(path_str)
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


def expand_nested_archives(extract_dir: Path, depth_limit: int = 2) -> None:
    archives = [p for p in extract_dir.rglob('*.zip') if p.is_file()]
    seen = set()
    depth = 0
    while archives and depth < depth_limit:
        current = archives.pop(0)
        key = str(current.resolve())
        if key in seen:
            continue
        seen.add(key)
        nested_dir = current.parent / (current.stem + '_unzipped')
        try:
            safe_extract(current, nested_dir)
            for child in nested_dir.rglob('*.zip'):
                if child.is_file():
                    archives.append(child)
        except Exception:
            pass
        depth += 1


def rank_targets(extract_dir: Path) -> list[Path]:
    expand_nested_archives(extract_dir, depth_limit=2)
    targets = [p for p in extract_dir.rglob('*') if p.is_file() and p.suffix.lower() in EXEC_SUFFIXES]
    targets.sort(key=lambda p: (EXEC_PRIORITY.get(p.suffix.lower(), 20), str(p).lower()))
    return targets[:8]


def run_member(path: Path, timeout_seconds: int, out_dir: Path, timeline: list[dict], extract_dir: Path) -> dict:
    command, package = build_command(path)
    rel_path = str(path.relative_to(extract_dir)).replace("\\", "/")

    if not command:
        return {
            "name": path.name,
            "path": rel_path,
            "skipped": True,
            "skip_reason": "unsupported_extension",
            "fail_reason": "not_executable",
            "package": package,
            "attempted": False,
            "succeeded": False,
            "failed": False,
        }

    append_timeline(timeline, "member_start", member=str(path), command=command, package=package)
    started = time.time()
    proc = None
    stdout = ""
    stderr = ""
    timed_out = False
    process_tree_live: list[dict] = []
    network_endpoints_live: list[dict] = []

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(path.parent),
            creationflags=CREATE_NO_WINDOW,
        )
        deadline = time.time() + timeout_seconds
        seen_tree: set[tuple[int, int, str, str]] = set()
        seen_net: set[tuple[int, str, int, str]] = set()
        while True:
            sampled_tree, sampled_net = _sample_process_state(proc.pid, path)
            for row in sampled_tree:
                key = (int(row.get('pid') or 0), int(row.get('ppid') or 0), str(row.get('name') or ''), str(row.get('cmdline') or ''))
                if key in seen_tree:
                    continue
                seen_tree.add(key)
                process_tree_live.append(row)
            for row in sampled_net:
                key = (int(row.get('pid') or 0), str(row.get('remote_ip') or ''), int(row.get('remote_port') or 0), str(row.get('status') or ''))
                if key in seen_net:
                    continue
                seen_net.add(key)
                network_endpoints_live.append(row)
            if proc.poll() is not None:
                break
            if time.time() >= deadline:
                timed_out = True
                _terminate_process_tree(proc.pid)
                break
            time.sleep(0.5)
        out, err = proc.communicate(timeout=5)
        stdout = out or ""
        stderr = err or ""
    except subprocess.TimeoutExpired:
        timed_out = True
        if proc is not None:
            _terminate_process_tree(proc.pid)
            try:
                out, err = proc.communicate(timeout=5)
                stdout = out or ""
                stderr = err or ""
            except Exception:
                pass
    except Exception as exc:
        append_timeline(timeline, "member_error", member=str(path), error=str(exc))
        return {
            "name": path.name,
            "path": rel_path,
            "skipped": True,
            "skip_reason": str(exc),
            "strategy": "guest_native",
            "fail_reason": "execution_failed",
            "package": package,
            "attempted": True,
            "succeeded": False,
            "failed": True,
            "process_tree_live": process_tree_live,
            "network_endpoints_live": network_endpoints_live,
        }

    runtime_ms = int((time.time() - started) * 1000)
    (out_dir / f"{path.stem}_stdout.txt").write_text(stdout, encoding="utf-8", errors="ignore")
    (out_dir / f"{path.stem}_stderr.txt").write_text(stderr, encoding="utf-8", errors="ignore")

    rc = -1 if timed_out else int(proc.returncode if proc and proc.returncode is not None else -1)
    append_timeline(timeline, "member_end" if not timed_out else "member_timeout", member=str(path), returncode=rc, duration_ms=runtime_ms)

    text_l = (stdout + "\n" + stderr + "\n" + " ".join(command)).lower()
    launch_error = _detect_launch_error(stdout, stderr, command)
    behavior = {
        "network_signal": bool(network_endpoints_live) or any(m in text_l for m in ["http://", "https://", "ftp://", "downloadstring", "invoke-webrequest", "urlmon", "bitsadmin", "certutil -urlcache"]),
        "persistence_signal": any(m in text_l for m in ["currentversion\\run", "runonce", "schtasks", "startup", "reg add"]),
        "ransomware_signal": any(m in text_l for m in ["vssadmin", "wbadmin", "bcdedit", "ransom", "decrypt"]),
        "execution_signal": bool(process_tree_live) or (path.suffix.lower() in {".exe", ".ps1", ".bat", ".cmd", ".js", ".vbs"} and runtime_ms >= 1000),
    }
    succeeded, fail_reason = _classify_execution_outcome(path, command, rc, timed_out, runtime_ms, stdout, stderr)
    if launch_error and not fail_reason:
        fail_reason = f"launch_error:{launch_error}"

    return {
        "name": path.name,
        "path": rel_path,
        "command": command,
        "returncode": rc,
        "timed_out": timed_out,
        "stdout_preview": stdout[:1200],
        "stderr_preview": stderr[:1200],
        "strategy": "guest_native",
        "behavior": behavior,
        "skipped": False,
        "package": package,
        "attempted": True,
        "succeeded": bool(succeeded),
        "failed": not bool(succeeded),
        "fail_reason": fail_reason,
        "runtime_ms": runtime_ms,
        "process_tree_live": process_tree_live,
        "network_endpoints_live": network_endpoints_live,
    }


def maybe_capture_memory_dump(proc_items: list[dict], outbox: Path, timeline: list[dict]) -> list[dict]:
    procdump = os.environ.get("PROCDUMP_PATH", r"C:\Tools\Sysinternals\procdump64.exe")
    if not Path(procdump).exists():
        return []
    dumps = []
    for item in proc_items[:5]:
        pid = int(item.get("pid") or 0)
        name = str(item.get("name") or "")
        if pid <= 0:
            continue
        dump_path = outbox / f"{pid}_{name}.dmp"
        try:
            subprocess.run([procdump, "-accepteula", "-ma", str(pid), str(dump_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
            if dump_path.exists():
                dumps.append({"pid": pid, "name": name, "path": str(dump_path)})
                append_timeline(timeline, "memory_dump", pid=pid, path=str(dump_path))
        except Exception:
            continue
    return dumps


def collect_external_monitor_logs(outbox: Path, timeline: list[dict]) -> dict:
    monitor_dir = Path(os.environ.get("MONITOR_LOGS_DIR", r"C:\analysis\monitor"))
    if not monitor_dir.exists():
        return {"enabled": False, "reason": "monitor_dir_missing", "events": []}
    events = []
    for path in sorted(monitor_dir.glob("*.json"))[:10]:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            events.append({"file": str(path), "preview": raw[:2000]})
            shutil.copy2(path, outbox / path.name)
        except Exception:
            continue
    append_timeline(timeline, "external_monitor_logs", count=len(events))
    return {"enabled": True, "reason": None, "events": events[:20]}
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


def collect_registry_snapshot() -> dict[str, list[str]]:
    roots = {
        "run": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "runonce": r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "run_hklm": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    }
    result: dict[str, list[str]] = {}
    for key, reg_path in roots.items():
        try:
            proc = subprocess.run(["reg", "query", reg_path], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
            lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
            result[key] = lines[:200]
        except Exception:
            result[key] = []
    return result


def collect_scheduled_tasks() -> list[str]:
    try:
        proc = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        return [line.strip() for line in (proc.stdout or "").splitlines() if line.strip().startswith("TaskName:")][:300]
    except Exception:
        return []


def collect_services_snapshot() -> list[str]:
    try:
        proc = subprocess.run(["sc", "query", "state=", "all"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        return [line.strip() for line in (proc.stdout or "").splitlines() if line.strip().startswith("SERVICE_NAME:")][:400]
    except Exception:
        return []


def diff_named_items(before: list[str], after: list[str]) -> dict:
    before_set = set(before)
    after_set = set(after)
    return {"added": sorted(after_set - before_set)[:100], "removed": sorted(before_set - after_set)[:100]}


def diff_registry_snapshot(before: dict[str, list[str]], after: dict[str, list[str]]) -> dict:
    added = []
    removed = []
    for key in sorted(set(before) | set(after)):
        before_set = set(before.get(key) or [])
        after_set = set(after.get(key) or [])
        for item in sorted(after_set - before_set)[:50]:
            added.append({"hive": key, "entry": item})
        for item in sorted(before_set - after_set)[:50]:
            removed.append({"hive": key, "entry": item})
    return {"added": added[:100], "removed": removed[:100]}


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
    started_at = time.time()
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
    if SYSMON_AVAILABLE:
        clear_sysmon_log()
    before_registry = collect_registry_snapshot()
    before_tasks = collect_scheduled_tasks()
    before_services = collect_services_snapshot()

    # ── 4번: 실제 Windows 경로(TEMP/APPDATA/Startup 등) 사전 스냅샷
    if _FILE_DIFF_AVAILABLE:
        _scan_roots = _get_scan_roots()
        before_system_snap = take_snapshot(_scan_roots)
    else:
        _scan_roots = []
        before_system_snap = {}

    if sample_path.suffix.lower() == ".zip":
        safe_extract(sample_path, extract_dir)
    else:
        extract_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sample_path, extract_dir / sample_path.name)

    append_timeline(timeline, "extract_complete", file_count=sum(1 for p in extract_dir.rglob("*") if p.is_file()))

    queue: deque[tuple[Path, int, str | None]] = deque()
    seen_targets: set[str] = set()
    member_results: list[dict] = []

    for target in rank_targets(extract_dir):
        queue.append((target, 0, None))

    append_timeline(
        timeline,
        "execution_plan",
        targets=[str(p.relative_to(extract_dir)) for p, _, _ in list(queue)],
        packages=[detect_package(p) for p, _, _ in list(queue)],
    )

    while queue and len(member_results) < MAX_RECURSIVE_EXEC_TARGETS:
        target, depth, parent_path = queue.popleft()
        key = str(target.resolve())
        if key in seen_targets:
            continue
        seen_targets.add(key)

        result = run_member(target, timeout_seconds, artifact_dir, timeline, extract_dir)
        result["recursive_depth"] = depth
        result["parent_path"] = parent_path
        member_results.append(result)

        time.sleep(1)
        current_files = {str(p.relative_to(guest_job_root)) for p in guest_job_root.rglob("*") if p.is_file()}
        created_now = sorted(current_files - before_files)
        new_exec_candidates = []
        for rel in created_now:
            abs_path = guest_job_root / rel
            if not abs_path.exists() or not abs_path.is_file():
                continue
            if abs_path.suffix.lower() not in EXEC_SUFFIXES:
                continue
            if str(abs_path.resolve()) in seen_targets:
                continue
            new_exec_candidates.append(abs_path)
        if depth < MAX_RECURSIVE_EXEC_DEPTH:
            for child in new_exec_candidates[:4]:
                queue.append((child, depth + 1, str(target)))
                append_timeline(timeline, "recursive_enqueue", child=str(child), parent=str(target), depth=depth + 1)

    time.sleep(2)

    after_files = {str(p.relative_to(guest_job_root)) for p in guest_job_root.rglob("*") if p.is_file()}
    after_proc = process_snapshot()
    after_net = net_snapshot()
    after_registry = collect_registry_snapshot()
    after_tasks = collect_scheduled_tasks()
    after_services = collect_services_snapshot()

    created = sorted(after_files - before_files)
    created_details = [{\"path\": p, \"category\": classify_created_file(p)} for p in created[:200] if not _is_noise_created_path(p)]
    dropped_exec_candidates = [c for c in created_details if Path(c[\"path\"]).suffix.lower() in EXEC_SUFFIXES and not str(c[\"path\"]).lower().startswith(\"extract\\\\\")]

    # ── 4번: 실제 Windows 경로 사후 스냅샷 + Diff
    system_diff: dict = {"created": [], "changed": [], "deleted": []}
    if _FILE_DIFF_AVAILABLE and before_system_snap is not None:
        after_system_snap = take_snapshot(_scan_roots)
        system_diff = compare_snapshots(before_system_snap, after_system_snap)
        # 시스템 경로에서 발견된 dropped 파일도 created_details에 병합 (중복 제거)
        existing_paths = {c[\"path\"] for c in created_details}
        for item in system_diff[\"created\"]:
            if item[\"path\"] not in existing_paths:
                created_details.append({
                    \"path\":     item[\"path\"],
                    \"category\": item[\"category\"],
                    \"sha256\":   item[\"sha256\"],
                    \"size_bytes\": item[\"size_bytes\"],
                })
                existing_paths.add(item[\"path\"])

    process_delta = summarize_process_delta(before_proc, after_proc)
    live_processes = []
    live_endpoints = []
    for member in member_results:
        live_processes.extend(member.get("process_tree_live") or [])
        live_endpoints.extend(member.get("network_endpoints_live") or [])
    if live_processes:
        existing = {(x.get("pid"), x.get("name"), x.get("cmdline")) for x in process_delta.get("new_process_tree", [])}
        for row in live_processes:
            key = (row.get("pid"), row.get("name"), row.get("cmdline"))
            if key not in existing:
                process_delta.setdefault("new_process_tree", []).append(row)
        process_delta["suspicious_processes"] = [x for x in process_delta.get("new_process_tree", []) if any(marker in (((x.get("name") or "") + " " + (x.get("cmdline") or "")).lower()) for marker in SUSPICIOUS_PROCESS_MARKERS)][:20]
    network_trace = summarize_network_delta(before_net, after_net)
    if live_endpoints:
        existing = {(x.get("pid"), x.get("remote_ip"), x.get("remote_port"), x.get("status")) for x in network_trace.get("endpoints", [])}
        for row in live_endpoints:
            key = (row.get("pid"), row.get("remote_ip"), row.get("remote_port"), row.get("status"))
            if key not in existing:
                network_trace.setdefault("endpoints", []).append(row)
        network_trace["connection_count"] = len(network_trace.get("endpoints", []))
    memory_dumps = maybe_capture_memory_dump(process_delta.get("suspicious_processes", []), outbox, timeline)
    external_monitor = collect_external_monitor_logs(outbox, timeline)

    registry_diff = diff_registry_snapshot(before_registry, after_registry)
    sysmon_events = collect_sysmon_events(after_ts=started_at, max_events=160) if SYSMON_AVAILABLE else []
    sysmon_summary = summarize_sysmon_events(sysmon_events, [m.get("path") for m in member_results]) if SYSMON_AVAILABLE else {
        "event_count": 0,
        "matched_event_count": 0,
        "execution_observed": False,
        "process_tree": [],
        "registry_changes": [],
        "network_endpoints": [],
        "dns_queries": [],
        "anti_analysis_signals": [],
        "image_loads": [],
    }
    scheduled_task_diff = diff_named_items(before_tasks, after_tasks)
    service_diff = diff_named_items(before_services, after_services)

    if sysmon_summary.get("process_tree"):
        existing = {(x.get("pid"), x.get("name"), x.get("cmdline")) for x in process_delta.get("new_process_tree", [])}
        for row in sysmon_summary.get("process_tree", []):
            key = (row.get("pid"), row.get("name"), row.get("cmdline"))
            if key not in existing:
                process_delta.setdefault("new_process_tree", []).append({
                    "pid": row.get("pid"),
                    "ppid": None,
                    "name": row.get("name"),
                    "cmdline": row.get("cmdline"),
                })
    if sysmon_summary.get("anti_analysis_signals"):
        for signal in sysmon_summary.get("anti_analysis_signals", []):
            cmdline = str(signal.get("command_line") or signal.get("image") or "")[:300]
            marker = {
                "pid": None,
                "name": Path(str(signal.get("image") or "taskkill.exe")).name,
                "cmdline": cmdline,
            }
            if marker not in process_delta.get("suspicious_processes", []):
                process_delta.setdefault("suspicious_processes", []).append(marker)
    if sysmon_summary.get("network_endpoints"):
        existing = {(x.get("pid"), x.get("remote_ip"), x.get("remote_port"), x.get("status")) for x in network_trace.get("endpoints", [])}
        for row in sysmon_summary.get("network_endpoints", []):
            key = (row.get("pid"), row.get("remote_ip"), row.get("remote_port"), row.get("status"))
            if key not in existing:
                network_trace.setdefault("endpoints", []).append(row)
        network_trace["connection_count"] = len(network_trace.get("endpoints", []))
    network_trace["dns_queries"] = sysmon_summary.get("dns_queries", [])[:40]
    network_trace["anti_analysis_signals"] = sysmon_summary.get("anti_analysis_signals", [])[:20]

    combined = "\n\n".join(
        (m.get("stdout_preview", "") + "\n" + m.get("stderr_preview", "")).strip()
        for m in member_results
        if not m.get("skipped")
    )
    combined_l = combined.lower()
    created_lower = "\n".join(c["path"].lower() for c in created_details)

    successful_members = [m for m in member_results if m.get("succeeded")]
    anti_analysis_signal = bool(sysmon_summary.get("anti_analysis_signals")) or "taskkill /f /im taskmgr.exe" in combined_l
    execution_observed = bool(successful_members) or bool(process_delta["suspicious_processes"]) or bool(sysmon_summary.get("execution_observed"))
    exec_signal = execution_observed or any(k in combined_l for k in ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript"])
    persistence_signal = (
        any(k in combined_l for k in [r"currentversion\run", "runonce", "schtasks", "startup"])
        or any("startup_drop" == c["category"] for c in created_details)
        or bool(scheduled_task_diff.get("added"))
        or bool(service_diff.get("added"))
        or bool(registry_diff.get("added"))
        or bool(sysmon_summary.get("registry_changes"))
        or "scheduledtasks" in created_lower
    )
    file_signal = bool([c for c in created_details if c.get("category") not in {"other_drop"}])
    network_signal = bool([x for x in network_trace["endpoints"] if int(x.get("pid", 0) or 0) > 0]) or any(k in combined_l for k in ["http://", "https://", "ftp://"])
    ransomware_signal = any(k in combined_l for k in ["vssadmin", "wbadmin", "bcdedit", "ransom", "decrypt"])
    # ── 4번: ransom_note 탐지를 file_diff.is_ransom_note()로 강화
    if _FILE_DIFF_AVAILABLE:
        note_signal = any(
            is_ransom_note(c["path"]) or c.get("category") == "ransom_note"
            for c in created_details
        )
    else:
        note_signal = any(Path(c["path"]).suffix.lower() == ".txt" and ("readme" in c["path"].lower() or "decrypt" in c["path"].lower()) for c in created_details)

    score = 0
    if exec_signal:
        score += 20
    if any(Path(str(m.get("path") or "")).suffix.lower() == ".exe" and m.get("succeeded") for m in member_results):
        score += 10
    if any(int(m.get("runtime_ms", 0) or 0) >= 10000 for m in successful_members):
        score += 8
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
    if dropped_exec_candidates:
        score += min(10, len(dropped_exec_candidates) * 2)
    if anti_analysis_signal:
        score += 30
    score = min(score, 100)

    append_timeline(
        timeline,
        "job_end",
        created_files=len(created_details),
        suspicious_processes=len(process_delta["suspicious_processes"]),
        network_connections=len(network_trace["endpoints"]),
        recursive_targets=sum(1 for m in member_results if int(m.get("recursive_depth") or 0) > 0),
    )

    package_counts = {}
    for item in member_results:
        pkg = str(item.get('package') or 'generic')
        package_counts[pkg] = package_counts.get(pkg, 0) + 1
        item["execution_observed"] = bool(item.get("succeeded")) or bool(sysmon_summary.get("execution_observed"))
        item["anti_analysis"] = anti_analysis_signal
        item["sysmon_summary"] = {
            "matched_event_count": sysmon_summary.get("matched_event_count", 0),
            "anti_analysis_count": len(sysmon_summary.get("anti_analysis_signals", [])),
            "registry_change_count": len(sysmon_summary.get("registry_changes", [])),
            "network_endpoint_count": len(sysmon_summary.get("network_endpoints", [])),
        }

    dynamic_status = "executed" if execution_observed else ("attempted" if any(m.get("attempted") for m in member_results) else "not_executed")
    dynamic_reason = None
    if not execution_observed:
        dynamic_reason = "members_attempted_but_no_observed_behavior" if any(m.get("attempted") for m in member_results) else "no_member_executed"
    elif anti_analysis_signal:
        dynamic_reason = "anti_analysis_behavior_observed"

    result = {
        "returncode": 0 if all(not m.get("timed_out") for m in member_results) else -1,
        "timed_out": any(m.get("timed_out") for m in member_results if m.get("attempted")),
        "filesystem_delta": {
            "created": created[:200],
            "changed": [],
            "deleted": [],
            "created_details": created_details,
        },
        # ── 4번: TEMP/APPDATA/Startup 등 실제 Windows 경로 Diff
        "system_diff": system_diff,
        "process_delta": process_delta,
        "network_trace": network_trace,
        "network_signal": network_signal,
        "exec_signal": exec_signal,
        "execution_observed": execution_observed,
        "dynamic_status": dynamic_status,
        "dynamic_reason": dynamic_reason,
        "sysmon_summary": sysmon_summary,
        "anti_analysis_signal": anti_analysis_signal,
        "persistence_signal": persistence_signal,
        "file_signal": file_signal,
        "ransomware_signal": ransomware_signal or note_signal,
        "archive_file_count": sum(1 for p in extract_dir.rglob("*") if p.is_file()),
        "archive_member_attempted_count": sum(1 for m in member_results if m.get("attempted")),
        "archive_member_exec_count": sum(1 for m in member_results if m.get("succeeded")),
        "archive_member_failed_count": sum(1 for m in member_results if m.get("failed")),
        "archive_member_skipped_count": sum(1 for m in member_results if m.get("skipped")),
        "archive_member_results": member_results,
        "combined_output_preview": combined[:4000],
        "score": score,
        "analysis_state": "complete" if member_results else "static_only",
        "timeline": timeline,
        "memory_dumps": memory_dumps,
        "api_activity": external_monitor,
        "package_counts": package_counts,
        "registry_diff": registry_diff,
        "scheduled_tasks": scheduled_task_diff,
        "services": service_diff,
        "sysmon_events": sysmon_events,
        "recursive_exec": {
            "enabled": True,
            "max_depth": MAX_RECURSIVE_EXEC_DEPTH,
            "attempted_count": sum(1 for m in member_results if m.get("attempted")),
        "executed_count": sum(1 for m in member_results if m.get("succeeded")),
        "failed_count": sum(1 for m in member_results if m.get("failed")),
            "recursive_executed_count": sum(1 for m in member_results if int(m.get("recursive_depth") or 0) > 0),
            "dropped_exec_candidates": dropped_exec_candidates[:50],
        },
    }

    (outbox / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    # ── 4번: dropped_files.json 별도 저장 (host_bridge가 outbox를 통해 Docker로 전달)
    if _FILE_DIFF_AVAILABLE:
        try:
            save_dropped_files(
                diff=system_diff,
                output_path=outbox / "dropped_files.json",
                scan_roots=_scan_roots,
            )
        except Exception:
            pass

    return result




def ensure_shared_layout(shared_dir: Path) -> None:
    if not shared_dir.exists():
        raise FileNotFoundError(f"shared dir not found: {shared_dir}")
    if not shared_dir.is_dir():
        raise NotADirectoryError(f"shared dir is not a directory: {shared_dir}")
    (shared_dir / "inbox").mkdir(exist_ok=True)
    (shared_dir / "outbox").mkdir(exist_ok=True)


def build_heartbeat(shared_dir: Path, status: str, report_id: str | None = None, error: str | None = None) -> dict:
    inbox = shared_dir / "inbox"
    outbox = shared_dir / "outbox"
    payload = {
        "ts": time.time(),
        "status": status,
        "hostname": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "guest",
        "resolved_shared_dir": str(shared_dir),
        "resolved_shared_dir_name": shared_dir.name,
        "shared_dir_exists": shared_dir.exists(),
        "shared_dir_ready": shared_dir.exists() and shared_dir.is_dir(),
        "inbox_ready": inbox.exists(),
        "outbox_ready": outbox.exists(),
    }
    if report_id:
        payload["report_id"] = report_id
    if error:
        payload["error"] = error
    return payload


def write_heartbeat(shared_dir: Path, status: str, report_id: str | None = None, error: str | None = None) -> None:
    heartbeat_path = shared_dir / "agent_heartbeat.json"
    heartbeat_path.parent.mkdir(parents=True, exist_ok=True)
    heartbeat_path.write_text(json.dumps(build_heartbeat(shared_dir, status, report_id=report_id, error=error), ensure_ascii=False), encoding="utf-8")


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
    global SHARED_DIR

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    last_shared_dir: str | None = None
    last_wait_error: str | None = None

    while True:
        try:
            SHARED_DIR = resolve_shared_dir()
            ensure_shared_layout(SHARED_DIR)
            current_shared_dir = str(SHARED_DIR)
            if current_shared_dir != last_shared_dir:
                print(f"guest_agent watching {SHARED_DIR}")
                print(f"guest_agent inbox={(SHARED_DIR / 'inbox')}")
                print(f"guest_agent outbox={(SHARED_DIR / 'outbox')}")
                print(f"guest_agent VM_SHARED_DIR={os.environ.get('VM_SHARED_DIR', '')}")
                print(f"guest_agent VM_SHARED_DIR_NAME={os.environ.get('VM_SHARED_DIR_NAME', '')}")
                print(f"guest_agent SHARED_DIR={os.environ.get('SHARED_DIR', '')}")
                last_shared_dir = current_shared_dir
            write_heartbeat(SHARED_DIR, "idle")
            last_wait_error = None
        except Exception as exc:
            message = str(exc)
            if message != last_wait_error:
                print(f"guest_agent shared folder wait: {message}")
                last_wait_error = message
            time.sleep(POLL_SECONDS)
            continue

        for job_dir in (SHARED_DIR / "inbox").iterdir():
            if not job_dir.is_dir():
                continue
            if not (job_dir / "job.json").exists():
                continue

            out_result = SHARED_DIR / "outbox" / job_dir.name / "result.json"
            if out_result.exists():
                continue

            try:
                write_heartbeat(SHARED_DIR, "busy", report_id=job_dir.name)
                analyze_job(job_dir)
                write_heartbeat(SHARED_DIR, "idle", report_id=job_dir.name)
            except Exception as exc:
                write_failed_result(out_result, exc)
                try:
                    write_heartbeat(SHARED_DIR, "idle", report_id=job_dir.name, error=str(exc))
                except Exception:
                    pass

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())