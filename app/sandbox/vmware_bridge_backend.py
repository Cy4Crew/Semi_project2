from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests

from app.core.config import settings
from app.services.memory_analysis_service import analyze_memory_artifacts
from app.services.multi_vm_scheduler import MultiVMScheduler
from app.services.suricata_service import run_suricata_on_pcap

_SCHEDULER = MultiVMScheduler()

_ANALYSIS_ARTIFACT_NAMES = {
    "done.txt",
    "events.jsonl",
    "stdout.txt",
    "stderr.txt",
    "analysis_log.jsonl",
    "network_trace.jsonl",
    "report.json",
}

_ANALYSIS_ARTIFACT_DIR_MARKERS = {
    "analysis",
    "artifacts",
    "evidence",
    "log",
    "logs",
    "network",
    "output",
    "results",
    "sandbox",
    "trace",
}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default



def _lower_str(value: Any) -> str:
    return str(value or "").strip().lower()



def _is_analysis_artifact_path(path_value: Any) -> bool:
    text = _lower_str(path_value).replace("\\", "/")
    if not text:
        return False
    if any(part in _ANALYSIS_ARTIFACT_DIR_MARKERS for part in text.split("/")):
        return True
    name = text.rsplit("/", 1)[-1]
    if name in _ANALYSIS_ARTIFACT_NAMES:
        return True
    if name.startswith("report_") and name.endswith(".json"):
        return True
    if name.endswith("_stdout.txt") or name.endswith("_stderr.txt"):
        return True
    return False



def _member_path(member: dict[str, Any]) -> str:
    for key in ("member_path", "path", "name", "file", "filename"):
        value = member.get(key)
        if value:
            return str(value)
    return ""



def _member_was_attempted(member: dict[str, Any]) -> bool:
    status = _lower_str(member.get("execution_status") or member.get("status"))
    attempted = member.get("attempted")
    attempted_bool = bool(attempted) if attempted is not None else False
    return attempted_bool or status in {
        "attempted",
        "executed",
        "success",
        "failed",
        "timeout",
        "timed_out",
        "error",
    }



def _member_was_successful(member: dict[str, Any]) -> bool:
    status = _lower_str(member.get("execution_status") or member.get("status"))
    if member.get("executed") is True or member.get("success") is True:
        return True
    return status in {"executed", "success", "completed", "ok"}



def _normalize_member_results(raw_members: Any) -> tuple[list[dict[str, Any]], set[str], set[str]]:
    normalized: list[dict[str, Any]] = []
    attempted_paths: set[str] = set()
    successful_paths: set[str] = set()
    for item in raw_members or []:
        if not isinstance(item, dict):
            continue
        member = dict(item)
        path = _member_path(member)
        if path:
            member["member_path"] = path
        if _is_analysis_artifact_path(path):
            continue
        normalized.append(member)
        normalized_path = _lower_str(path)
        if _member_was_attempted(member) and normalized_path:
            attempted_paths.add(normalized_path)
        if _member_was_successful(member) and normalized_path:
            successful_paths.add(normalized_path)
    return normalized, attempted_paths, successful_paths



def _normalize_filesystem_delta(raw_delta: Any) -> tuple[dict[str, list[str]], bool]:
    delta = raw_delta if isinstance(raw_delta, dict) else {}
    normalized: dict[str, list[str]] = {"created": [], "changed": [], "deleted": []}
    file_signal = False
    for key in normalized:
        seen: set[str] = set()
        for item in delta.get(key) or []:
            path = str(item or "").strip()
            if not path or _is_analysis_artifact_path(path):
                continue
            lowered = _lower_str(path)
            if lowered in seen:
                continue
            seen.add(lowered)
            normalized[key].append(path)
        if normalized[key]:
            file_signal = True
    return normalized, file_signal



def _normalize_process_delta(raw_delta: Any, success_count: int) -> tuple[dict[str, Any], bool]:
    delta = raw_delta if isinstance(raw_delta, dict) else {}
    tree = [proc for proc in (delta.get("new_process_tree") or []) if isinstance(proc, dict)]
    estimate = _safe_int(delta.get("new_processes_estimate"), len(tree))
    if success_count <= 0:
        tree = []
        estimate = 0
    normalized = {
        "before_count": _safe_int(delta.get("before_count")),
        "after_count": _safe_int(delta.get("after_count")),
        "new_processes_estimate": estimate,
        "new_process_tree": tree,
    }
    return normalized, estimate > 0 or bool(tree)



def _event_matches_member(event: dict[str, Any], member_paths: set[str]) -> bool:
    haystacks = [
        _lower_str(event.get("path")),
        _lower_str(event.get("target")),
        _lower_str(event.get("process_path")),
        _lower_str(event.get("image")),
        _lower_str(event.get("command_line")),
        _lower_str(event.get("detail")),
        _lower_str(event.get("description")),
    ]
    for member_path in member_paths:
        if not member_path:
            continue
        if any(member_path in hay for hay in haystacks if hay):
            return True
    return False



def _normalize_network_trace(raw_trace: Any, member_paths: set[str], success_count: int) -> tuple[dict[str, Any], bool]:
    trace = raw_trace if isinstance(raw_trace, dict) else {}
    disabled = bool(trace.get("disabled", False))
    base_reason = trace.get("reason") or ("vmware_guest_agent" if disabled else "")
    connections = [item for item in (trace.get("connections") or []) if isinstance(item, dict)]
    if success_count <= 0:
        return {
            "disabled": disabled,
            "reason": base_reason or "no_member_executed",
            "connections": [],
            "dns_queries": [],
            "http_requests": [],
            "unique_remote": [],
            "connection_count": 0,
        }, False
    filtered_connections = [item for item in connections if _event_matches_member(item, member_paths)]
    unique_remote = sorted({str(item.get("remote") or item.get("dst") or "").strip() for item in filtered_connections if str(item.get("remote") or item.get("dst") or "").strip()})
    reason = trace.get("reason") or ("member_correlated" if filtered_connections else "noise_filtered")
    return {
        "disabled": disabled,
        "reason": reason,
        "connections": filtered_connections,
        "dns_queries": [],
        "http_requests": [],
        "unique_remote": unique_remote,
        "connection_count": len(filtered_connections),
    }, bool(filtered_connections)



def _normalize_timeline(raw_timeline: Any, member_paths: set[str], success_count: int) -> list[dict[str, Any]]:
    timeline = [item for item in (raw_timeline or []) if isinstance(item, dict)]
    if success_count <= 0 or not member_paths:
        return []
    filtered = [item for item in timeline if _event_matches_member(item, member_paths)]
    return filtered[:500]



def _normalize_bridge_result(result: dict[str, Any]) -> dict[str, Any]:
    archive_member_results, attempted_paths, successful_paths = _normalize_member_results(result.get("archive_member_results", []))
    attempted_count = len(attempted_paths)
    success_count = len(successful_paths)

    filesystem_delta, file_signal = _normalize_filesystem_delta(result.get("filesystem_delta"))
    if success_count <= 0:
        file_signal = False

    process_delta, process_signal = _normalize_process_delta(result.get("process_delta"), success_count)
    network_trace, network_signal = _normalize_network_trace(result.get("network_trace"), attempted_paths | successful_paths, success_count)
    timeline = _normalize_timeline(result.get("timeline"), attempted_paths | successful_paths, success_count)

    exec_signal = bool(result.get("exec_signal", False)) and success_count > 0
    persistence_signal = bool(result.get("persistence_signal", False)) and success_count > 0
    ransomware_signal = bool(result.get("ransomware_signal", False)) and success_count > 0

    return {
        "filesystem_delta": filesystem_delta,
        "file_signal": file_signal,
        "process_delta": process_delta,
        "process_signal": process_signal,
        "network_trace": network_trace,
        "network_signal": network_signal,
        "timeline": timeline,
        "archive_member_results": archive_member_results,
        "archive_member_attempted_count": attempted_count,
        "archive_member_success_count": success_count,
        "archive_member_exec_count": success_count,
        "archive_member_skipped_count": max(0, _safe_int(result.get("archive_member_skipped_count"))),
        "archive_file_count": max(_safe_int(result.get("archive_file_count")), len(archive_member_results)),
        "exec_signal": exec_signal,
        "persistence_signal": persistence_signal,
        "ransomware_signal": ransomware_signal,
    }



def _submit_to_slot(slot, sample_path: str, report_id: str, artifact_root: str) -> dict:
    bridge_url = str(slot.bridge_url).rstrip('/')
    endpoint = f"{bridge_url}/submit"
    Path(artifact_root).mkdir(parents=True, exist_ok=True)
    with open(sample_path, 'rb') as fp:
        headers = {}
        if str(getattr(settings, "bridge_auth_token", "") or "").strip():
            headers["x-bridge-token"] = str(settings.bridge_auth_token).strip()
        response = requests.post(
            endpoint,
            data={
                'report_id': report_id,
                'vm_name': str(slot.name),
                'snapshot_name': str(slot.snapshot),
                'timeout_seconds': str(settings.sandbox_job_timeout_seconds),
            },
            files={'sample': (Path(sample_path).name, fp, 'application/octet-stream')},
            headers=headers,
            timeout=max(30, int(settings.sandbox_job_timeout_seconds) + 60),
        )
    response.raise_for_status()
    payload = response.json()
    raw_path = Path(artifact_root) / f"job_{report_id}_{slot.name}_vmware_bridge_result.json"
    raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    result = payload.get('result', {}) if isinstance(payload, dict) else {}
    normalized = _normalize_bridge_result(result if isinstance(result, dict) else {})
    base = {
        'returncode': _safe_int(result.get('returncode', 0)),
        'timed_out': bool(result.get('timed_out', False)),
        'stdout_path': str(raw_path),
        'stderr_path': str(raw_path),
        'analysis_log_path': str(raw_path),
        'trace_path': result.get('trace_path'),
        'pcap_path': result.get('pcap_path'),
        'filesystem_delta': normalized['filesystem_delta'],
        'process_delta': normalized['process_delta'],
        'network_trace': normalized['network_trace'],
        'timeline': normalized['timeline'],
        'network_signal': normalized['network_signal'],
        'exec_signal': normalized['exec_signal'],
        'persistence_signal': normalized['persistence_signal'],
        'file_signal': normalized['file_signal'],
        'ransomware_signal': normalized['ransomware_signal'],
        'archive_file_count': normalized['archive_file_count'],
        'archive_member_exec_count': normalized['archive_member_exec_count'],
        'archive_member_attempted_count': normalized['archive_member_attempted_count'],
        'archive_member_success_count': normalized['archive_member_success_count'],
        'archive_member_skipped_count': normalized['archive_member_skipped_count'],
        'archive_member_results': normalized['archive_member_results'],
        'combined_output_preview': result.get('combined_output_preview', ''),
        'score': _safe_int(result.get('score', 0)),
        'analysis_state': result.get('analysis_state', 'partial'),
        'sandbox_profile': {
            'backend': 'vmware-host-bridge',
            'bridge_url': bridge_url,
            'vm_name': str(slot.name),
            'snapshot_name': str(slot.snapshot),
            'health': slot.metadata,
            'readiness': payload.get('readiness') if isinstance(payload, dict) else {},
        },
        'bridge_payload_path': str(raw_path),
        'bridge_trace_path': payload.get('bridge_trace_path') if isinstance(payload, dict) else None,
    }
    base['suricata'] = run_suricata_on_pcap(base.get('pcap_path'), artifact_root)
    base['memory_analysis'] = analyze_memory_artifacts(base, artifact_root)
    return base



def run_vmware_bridge_analysis(sample_path: str, report_id: str, artifact_root: str) -> dict:
    attempts = max(1, int(getattr(settings, 'sandbox_bridge_submit_retries', 2)))
    errors: list[str] = []
    slot_count = max(1, len(list(_SCHEDULER.health(force=True))))
    for _ in range(attempts * slot_count):
        slot = _SCHEDULER.acquire_vm(report_id=report_id)
        if slot is None:
            errors.append('no_healthy_vm_slot')
            time.sleep(2)
            continue
        try:
            result = _submit_to_slot(slot, sample_path, report_id, artifact_root)
            _SCHEDULER.release_vm(report_id, success=True)
            return result
        except Exception as exc:
            _SCHEDULER.release_vm(report_id, success=False, reason=str(exc))
            errors.append(f"{slot.name}@{slot.bridge_url}:{exc}")
            time.sleep(max(0.25, float(getattr(settings, "sandbox_bridge_retry_backoff_seconds", 2.0))) * min(len(errors), 4))
            continue
    raise RuntimeError('vmware_bridge_failed:' + ' | '.join(errors[:6]))
