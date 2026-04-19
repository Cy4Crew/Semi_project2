from __future__ import annotations

import json
import time
from pathlib import Path

import requests

from app.core.config import settings
from app.services.suricata_service import run_suricata_on_pcap
from app.services.memory_analysis_service import analyze_memory_artifacts
from app.services.multi_vm_scheduler import MultiVMScheduler

_SCHEDULER = MultiVMScheduler()


def _merge_filesystem_delta(result: dict) -> dict:
    """
    guest_agent result.json 의 filesystem_delta 와
    system_diff(TEMP/APPDATA/Startup 스캔) 를 합쳐 반환.

    filesystem_delta.created 는 두 가지 포맷이 섞일 수 있음:
      - 구 포맷: str (경로 문자열)
      - 신 포맷: {"path": str, "sha256": str, "category": str, ...}
    → 신 포맷으로 통일.
    """
    base_delta = result.get("filesystem_delta") or {}

    def _normalize(items: list) -> list:
        out = []
        for item in items:
            if isinstance(item, str):
                out.append({"path": item, "sha256": "", "category": "other_drop"})
            elif isinstance(item, dict):
                out.append(item)
        return out

    created = _normalize(base_delta.get("created", []))
    changed = _normalize(base_delta.get("changed", []))
    deleted = _normalize(base_delta.get("deleted", []))

    # system_diff 병합 (TEMP/APPDATA/Startup 스캔 결과)
    system_diff = result.get("system_diff") or {}
    existing_paths = {c["path"] for c in created}
    for item in _normalize(system_diff.get("created", [])):
        if item["path"] not in existing_paths:
            created.append(item)
            existing_paths.add(item["path"])
    for item in _normalize(system_diff.get("changed", [])):
        changed.append(item)
    for item in _normalize(system_diff.get("deleted", [])):
        deleted.append(item)

    return {"created": created[:200], "changed": changed[:100], "deleted": deleted[:100]}


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
    result = payload.get('result', {})
    base = {
        'returncode': int(result.get('returncode', 0)),
        'timed_out': bool(result.get('timed_out', False)),
        'stdout_path': str(raw_path),
        'stderr_path': str(raw_path),
        'analysis_log_path': str(raw_path),
        'trace_path': result.get('trace_path'),
        'pcap_path': result.get('pcap_path'),
        # ── 4번: TEMP/APPDATA/Startup 스캔 결과 병합 + 포맷 통일
        'filesystem_delta': _merge_filesystem_delta(result),
        # ── 4번: guest_agent가 outbox에 저장한 dropped_files.json 내용 전달
        'dropped_files': result.get('dropped_files', []),
        'process_delta': result.get('process_delta', {'before_count': 0, 'after_count': 0, 'new_processes_estimate': 0}),
        'network_trace': result.get('network_trace', {'disabled': True, 'reason': 'vmware_guest_agent'}),
        'timeline': result.get('timeline', []),
        'network_signal': bool(result.get('network_signal', False)),
        'exec_signal': bool(result.get('exec_signal', False)),
        'persistence_signal': bool(result.get('persistence_signal', False)),
        'file_signal': bool(result.get('file_signal', False)),
        'ransomware_signal': bool(result.get('ransomware_signal', False)),
        'archive_file_count': int(result.get('archive_file_count', 0)),
        'archive_member_exec_count': int(result.get('archive_member_exec_count', 0)),
        'archive_member_skipped_count': int(result.get('archive_member_skipped_count', 0)),
        'archive_member_results': result.get('archive_member_results', []),
        'combined_output_preview': result.get('combined_output_preview', ''),
        'score': int(result.get('score', 0)),
        'analysis_state': result.get('analysis_state', 'partial'),
        'sandbox_profile': {
            'backend': 'vmware-host-bridge',
            'bridge_url': bridge_url,
            'vm_name': str(slot.name),
            'snapshot_name': str(slot.snapshot),
            'health': slot.metadata,
            'readiness': payload.get('readiness') or {},
        },
        'bridge_payload_path': str(raw_path),
        'bridge_trace_path': payload.get('bridge_trace_path'),
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