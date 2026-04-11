from __future__ import annotations

import json
from pathlib import Path

import requests

from app.core.config import settings


def run_vmware_bridge_analysis(sample_path: str, report_id: str, artifact_root: str) -> dict:
    bridge_url = str(settings.sandbox_bridge_url).rstrip('/')
    endpoint = f"{bridge_url}/submit"
    health_endpoint = f"{bridge_url}/health"
    Path(artifact_root).mkdir(parents=True, exist_ok=True)

    health = requests.get(health_endpoint, timeout=5)
    health.raise_for_status()
    health_payload = health.json()
    if not bool(health_payload.get("vmrun_exists")):
        raise RuntimeError("vmware_bridge_unhealthy:vmrun_missing")
    if not health_payload.get("vmx_path"):
        raise RuntimeError("vmware_bridge_unhealthy:vmx_path_missing")

    with open(sample_path, 'rb') as fp:
        response = requests.post(
            endpoint,
            data={
                "report_id": report_id,
                "vm_name": str(settings.sandbox_vm_name),
                "snapshot_name": str(settings.sandbox_vm_snapshot),
                "timeout_seconds": str(settings.sandbox_job_timeout_seconds),
            },
            files={"sample": (Path(sample_path).name, fp, "application/zip")},
            timeout=max(30, int(settings.sandbox_job_timeout_seconds) + 60),
        )

    response.raise_for_status()
    payload = response.json()

    raw_path = Path(artifact_root) / f"job_{report_id}_vmware_bridge_result.json"
    raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')

    result = payload.get('result', {})
    return {
        "returncode": int(result.get("returncode", 0)),
        "timed_out": bool(result.get("timed_out", False)),
        "stdout_path": str(raw_path),
        "stderr_path": str(raw_path),
        "analysis_log_path": str(raw_path),
        "trace_path": result.get("trace_path"),
        "pcap_path": result.get("pcap_path"),
        "filesystem_delta": result.get("filesystem_delta", {"created": [], "changed": [], "deleted": []}),
        "process_delta": result.get("process_delta", {"before_count": 0, "after_count": 0, "new_processes_estimate": 0}),
        "network_trace": result.get("network_trace", {"disabled": True, "reason": "vmware_guest_agent"}),
        "timeline": result.get("timeline", []),
        "network_signal": bool(result.get("network_signal", False)),
        "exec_signal": bool(result.get("exec_signal", False)),
        "persistence_signal": bool(result.get("persistence_signal", False)),
        "file_signal": bool(result.get("file_signal", False)),
        "ransomware_signal": bool(result.get("ransomware_signal", False)),
        "archive_file_count": int(result.get("archive_file_count", 0)),
        "archive_member_exec_count": int(result.get("archive_member_exec_count", 0)),
        "archive_member_skipped_count": int(result.get("archive_member_skipped_count", 0)),
        "archive_member_results": result.get("archive_member_results", []),
        "combined_output_preview": result.get("combined_output_preview", ""),
        "score": int(result.get("score", 0)),
        "analysis_state": result.get("analysis_state", "partial"),
        "sandbox_profile": {
            "backend": "vmware-host-bridge",
            "bridge_url": bridge_url,
            "vm_name": str(settings.sandbox_vm_name),
            "snapshot_name": str(settings.sandbox_vm_snapshot),
            "health": health_payload,
        },
        "bridge_payload_path": str(raw_path),
        "bridge_trace_path": payload.get('bridge_trace_path'),
    }
