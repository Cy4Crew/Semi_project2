from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.core.config import settings
from app.repository.report_store import get_report, save_report, update_report
from app.services.dynamic_analysis_service import run_dynamic_analysis
from app.services.scoring_service import calculate_score
from app.services.static_analysis_service import analyze_archive


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verdict_policy() -> dict:
    return {
        "clean": {"min": 0, "max": int(settings.verdict_clean_max)},
        "review": {"min": int(settings.verdict_clean_max) + 1, "max": int(settings.verdict_review_max)},
        "suspicious": {"min": int(settings.verdict_review_max) + 1, "max": int(settings.verdict_suspicious_max)},
        "malicious": {"min": int(settings.verdict_suspicious_max) + 1, "max": 100},
    }


def _hash_file(path: str) -> dict[str, str]:
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hashes.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashes.items()}


def _build_evidence_bundle(static_results: list[dict], dynamic_result: dict, verdict: dict, iocs: dict) -> dict:
    interesting_files = []
    for item in static_results:
        if item.get("severity") in {"high", "medium"} or item.get("yara_matches"):
            interesting_files.append({
                "file": item.get("file"),
                "severity": item.get("severity"),
                "score": item.get("score"),
                "summary_reasons": item.get("summary_reasons", [])[:5],
                "tags": item.get("tags", [])[:10],
                "yara_matches": [m for m in item.get("yara_matches", []) if not str(m).startswith("yara_error:")][:10],
            })
    return {
        "top_reasons": verdict.get("evidence_reasons", [])[:10],
        "interesting_files": interesting_files[:20],
        "archive_member_results": dynamic_result.get("archive_member_results", [])[:20],
        "filesystem_changes": dynamic_result.get("filesystem_delta", {}),
        "network_trace": dynamic_result.get("network_trace", {}),
        "iocs": iocs,
    }


def _base_payload(report_id: str, original_filename: str) -> dict:
    return {
        "report_id": report_id,
        "filename": original_filename,
        "status": "queued",
        "verdict": "review",
        "risk_score": 0,
        "raw_score": 0,
        "summary": "Queued for analysis.",
        "failure_reason": None,
        "score_breakdown": {},
        "evidence_reasons": [],
        "sample_hashes": {},
        "verdict_policy": _verdict_policy(),
        "timestamps": {"queued_at": _utc_now()},
        "static_result": {"files": [], "summary": {"file_count": 0, "high_confidence_files": 0, "high_severity_files": 0}},
        "dynamic_result": {},
        "iocs": {"urls": [], "emails": [], "domains": [], "ips": [], "yara_matches": [], "suspected_families": []},
    }


def create_report_job(sample_path: str, original_filename: str) -> dict:
    report_id = uuid4().hex[:12]
    payload = {
        **_base_payload(report_id, original_filename),
        "sample_path": sample_path,
        "sample_hashes": _hash_file(sample_path),
        "summary": "Queued for analysis.",
    }
    save_report(payload)
    return payload


def create_reanalysis_job(report_id: str) -> dict:
    current = get_report(report_id)
    if not current:
        raise ValueError(f"report_not_found:{report_id}")
    sample_path = str(current.get("sample_path") or "")
    if not sample_path or not Path(sample_path).exists():
        raise ValueError("sample_path_missing")
    return create_report_job(sample_path, str(current.get("filename") or Path(sample_path).name))


def process_report(report_id: str) -> dict:
    current = get_report(report_id)
    if not current:
        raise ValueError(f"report_not_found:{report_id}")

    sample_path = str(current.get("sample_path") or "")
    original_filename = str(current.get("filename") or Path(sample_path).name or "sample.zip")
    artifact_root = str(Path(settings.artifacts_dir) / report_id)
    Path(artifact_root).mkdir(parents=True, exist_ok=True)

    started_at = _utc_now()
    update_report(
        report_id,
        status="running",
        summary="Static and dynamic analysis in progress.",
        failure_reason=None,
        timestamps={**(current.get("timestamps") or {}), "started_at": started_at},
    )

    try:
        static_results = analyze_archive(sample_path)
        try:
            dynamic_result = run_dynamic_analysis(sample_path, report_id, artifact_root)
        except Exception as exc:
            dynamic_result = {
                "returncode": 0,
                "timed_out": False,
                "filesystem_delta": {"created": [], "changed": [], "deleted": []},
                "process_delta": {"before_count": 0, "after_count": 0, "new_processes_estimate": 0},
                "network_trace": {"disabled": True, "reason": f"dynamic_analysis_error:{exc}"},
                "network_signal": False,
                "exec_signal": False,
                "persistence_signal": False,
                "file_signal": False,
                "archive_file_count": 0,
                "archive_member_exec_count": 0,
                "archive_member_skipped_count": 0,
                "archive_member_results": [],
                "combined_output_preview": "",
                "score": 0,
                "analysis_state": "static_only",
                "dynamic_error": str(exc),
                "sandbox_profile": {},
            }
        verdict = calculate_score(static_results, dynamic_result)

        suspected_families = sorted({fam for item in static_results for fam in item.get("suspected_family", [])})
        iocs = {
            "urls": sorted({u for item in static_results for u in item.get("iocs", {}).get("urls", [])})[:100],
            "emails": sorted({e for item in static_results for e in item.get("iocs", {}).get("emails", [])})[:100],
            "domains": sorted({d for item in static_results for d in item.get("iocs", {}).get("domains", [])})[:100],
            "ips": sorted({ip for item in static_results for ip in item.get("iocs", {}).get("ips", [])})[:100],
            "yara_matches": sorted({m for item in static_results for m in item.get("yara_matches", []) if not str(m).startswith("yara_error:")}),
            "suspected_families": suspected_families,
        }

        final_status = "done"
        if dynamic_result.get("timed_out"):
            final_status = "timeout"
        elif int(dynamic_result.get("returncode", 0)) < 0:
            final_status = "killed"

        summary = (
            f"{original_filename} analyzed as {verdict['verdict'].upper()} with risk score {verdict['score']}/100 "
            f"(static={verdict.get('static_score', 0)}, dynamic={verdict.get('dynamic_score', 0)}). "
            f"Executed archive members: {dynamic_result.get('archive_member_exec_count', 0)}. "
            f"Skipped archive members: {dynamic_result.get('archive_member_skipped_count', 0)}."
            + (" Developer-heavy archive detected." if verdict.get("developer_heavy") else "")
            + (" Strong evidence override applied." if verdict.get("strong_override") else "")
            + (" Runtime timeout observed." if final_status == "timeout" else "")
            + (" Execution terminated by signal." if final_status == "killed" else "")
            + (" Dynamic execution partially skipped due to unsupported format or sandbox limits." if dynamic_result.get("analysis_state") in {"partial", "static_only"} else "")
        )

        evidence_bundle = _build_evidence_bundle(static_results, dynamic_result, verdict, iocs)

        payload = {
            "report_id": report_id,
            "filename": original_filename,
            "sample_path": sample_path,
            "status": final_status,
            "verdict": verdict.get("verdict", "review"),
            "risk_score": verdict.get("score", 0),
            "raw_score": verdict.get("raw_score", verdict.get("score", 0)),
            "score_breakdown": verdict.get("score_breakdown", {}),
            "evidence_reasons": verdict.get("evidence_reasons", []),
            "sample_hashes": current.get("sample_hashes") or _hash_file(sample_path),
            "verdict_policy": _verdict_policy(),
            "summary": summary,
            "failure_reason": None,
            "timestamps": {**(current.get("timestamps") or {}), "started_at": started_at, "finished_at": _utc_now()},
            "static_result": {
                "files": static_results,
                "summary": {
                    "file_count": len(static_results),
                    "high_confidence_files": verdict.get("high_confidence_files", 0),
                    "high_severity_files": verdict.get("high_severity_files", 0),
                },
            },
            "dynamic_result": dynamic_result,
            "iocs": iocs,
            "evidence_bundle": evidence_bundle,
        }
        save_report(payload)
        return get_report(report_id) or payload
    except Exception as exc:
        failed = {
            **_base_payload(report_id, original_filename),
            "sample_path": sample_path,
            "sample_hashes": current.get("sample_hashes") or (_hash_file(sample_path) if sample_path and Path(sample_path).exists() else {}),
            "status": "failed",
            "failure_reason": str(exc),
            "summary": f"Analysis failed: {exc}",
            "timestamps": {**(current.get("timestamps") or {}), "started_at": started_at, "finished_at": _utc_now()},
        }
        save_report(failed)
        raise
