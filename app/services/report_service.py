from __future__ import annotations

import hashlib
import logging
import time
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

logger = logging.getLogger(__name__)

from app.core.config import settings
from app.repository.report_store import get_report, save_report, update_report, find_cached_report_by_sha256
from app.services.dynamic_analysis_service import run_dynamic_analysis
from app.services.scoring_service import assess_files, calculate_score
from app.services.static_analysis_service import analyze_archive
from app.utils.logging_setup import report_id_var
from app.utils.metrics_store import record_event, record_stage_metric
from app.utils.report_enrichment import build_artifact_manifest, normalize_iocs


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




def _cached_statuses() -> list[str]:
    raw = str(getattr(settings, "sandbox_cache_reuse_statuses", "done,timeout,killed") or "")
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


def _clone_cached_report(current: dict, cached: dict, started_at: str) -> dict:
    payload = dict(cached)
    payload["report_id"] = str(current.get("report_id"))
    payload["filename"] = str(current.get("filename") or cached.get("filename") or "sample")
    payload["sample_path"] = str(current.get("sample_path") or cached.get("sample_path") or "")
    payload["sample_hashes"] = current.get("sample_hashes") or cached.get("sample_hashes") or {}
    payload["summary"] = f"Cache hit reused analysis from {cached.get('report_id')} ({cached.get('status')})."
    payload["timestamps"] = {**(current.get("timestamps") or {}), "started_at": started_at, "finished_at": _utc_now()}
    payload["cache_hit"] = True
    payload["cached_from_report_id"] = cached.get("report_id")
    payload["status"] = cached.get("status") or "done"
    return payload


def _top_created_files(dynamic_result: dict, limit: int = 20) -> list[dict]:
    created_details = ((dynamic_result.get("filesystem_delta") or {}).get("created_details") or [])
    return created_details[:limit]


def _top_process_tree(dynamic_result: dict, limit: int = 25) -> list[dict]:
    return ((dynamic_result.get("process_delta") or {}).get("new_process_tree") or [])[:limit]


def _top_registry_artifacts(dynamic_result: dict, limit: int = 30) -> dict:
    return {
        "registry_diff": ((dynamic_result.get("registry_diff") or {}).get("changes") or [])[:limit],
        "scheduled_tasks": ((dynamic_result.get("scheduled_tasks") or {}).get("created") or [])[:limit],
        "services": ((dynamic_result.get("services") or {}).get("created") or [])[:limit],
    }


def _failure_detail(item: dict, dynamic_result: dict | None = None, exc: Exception | None = None) -> dict:
    dynamic_result = dynamic_result or {}
    timeline = dynamic_result.get("timeline") or []
    last_stage = timeline[-1].get("stage") if timeline and isinstance(timeline[-1], dict) else None
    detail = {
        "failed_stage": item.get("failed_stage") or dynamic_result.get("failed_stage") or ("dynamic_analysis" if dynamic_result.get("analysis_state") == "failed" else None),
        "error_type": item.get("error_type") or dynamic_result.get("error_type") or (type(exc).__name__ if exc else None),
        "error_message": item.get("failure_reason") or dynamic_result.get("error") or (str(exc) if exc else None),
        "traceback": item.get("traceback") or dynamic_result.get("traceback"),
        "last_successful_step": item.get("last_successful_step") or last_stage,
        "analysis_state": dynamic_result.get("analysis_state"),
    }
    return {k: v for k, v in detail.items() if v not in (None, "", [], {})}


def _build_evidence_bundle(static_results: list[dict] | dict, dynamic_result: dict, verdict: dict, iocs: dict, normalized_iocs: dict, artifact_manifest: dict) -> dict:
    if isinstance(static_results, dict):
        static_items = static_results.get("files") or []
    elif isinstance(static_results, list):
        static_items = static_results
    else:
        static_items = []

    interesting_files = []
    for item in static_items:
        if not isinstance(item, dict):
            continue
        if item.get("severity") in {"high", "medium"} or item.get("yara_matches"):
            interesting_files.append({
                "file": item.get("file"),
                "severity": item.get("severity"),
                "score": item.get("final_score", item.get("score")),
                "verdict": item.get("final_verdict", item.get("severity")),
                "reverse_plan": item.get("reverse_plan", {}),
                "summary_reasons": item.get("summary_reasons", [])[:5],
                "tags": item.get("tags", [])[:10],
                "yara_matches": [m for m in item.get("yara_matches", []) if not str(m).startswith("yara_error:")][:10],
                "malware_type_tags": item.get("malware_type_tags", [])[:6],
                "primary_malware_type": item.get("primary_malware_type"),
                "evidence_items": item.get("evidence_items", [])[:8],
            })
    return {
        "top_reasons": verdict.get("evidence_reasons", [])[:10],
        "interesting_files": interesting_files[:20],
        "archive_member_results": dynamic_result.get("archive_member_results", [])[:20],
        "filesystem_changes": dynamic_result.get("filesystem_delta", {}),
        "network_trace": dynamic_result.get("network_trace", {}),
        "timeline": dynamic_result.get("timeline", [])[:50],
        "process_delta": dynamic_result.get("process_delta", {}),
        "iocs": iocs,
        "evidence_list": verdict.get("evidence_list", [])[:20],
        "archive_profile": verdict.get("archive_profile", {}),
        "process_tree": _top_process_tree(dynamic_result),
        "dropped_files": _top_created_files(dynamic_result),
        "registry_artifacts": _top_registry_artifacts(dynamic_result),
        "memory_dumps": (dynamic_result.get("memory_dumps") or [])[:10],
        "api_activity": dynamic_result.get("api_activity") or {},
        "failure_detail": _failure_detail({}, dynamic_result),
        "normalized_iocs": normalized_iocs,
        "artifact_manifest": artifact_manifest,
        "family_matches": verdict.get("family_matches", []),
        "primary_family": verdict.get("primary_family", "unknown"),
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
        "iocs": {"urls": [], "emails": [], "domains": [], "ips": [], "yara_matches": [], "suspected_families": [], "malware_types": []},
        "malware_type_tags": [],
        "primary_malware_type": None,
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
    token = report_id_var.set(report_id)
    overall_start = time.perf_counter()
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

    record_event("analysis_started", "analysis started", report_id=report_id, payload={"filename": original_filename})
    sample_hashes = current.get("sample_hashes") or (_hash_file(sample_path) if sample_path and Path(sample_path).exists() else {})
    if bool(getattr(settings, "sandbox_enable_result_cache", True)):
        cached = find_cached_report_by_sha256(str((sample_hashes or {}).get("sha256") or ""), _cached_statuses())
        if cached and str(cached.get("report_id")) != report_id:
            payload = _clone_cached_report({**current, "sample_hashes": sample_hashes}, cached, started_at)
            save_report(payload)
            return get_report(report_id) or payload

    try:
        stage_start = time.perf_counter()
        static_results = analyze_archive(sample_path)
        static_items = static_results.get("files", []) if isinstance(static_results, dict) else (static_results or [])
        record_stage_metric(report_id, "static_analysis", "done", duration_ms=int((time.perf_counter() - stage_start) * 1000), payload={"files": len(static_items)})
        stage_start = time.perf_counter()
        dynamic_result = run_dynamic_analysis(sample_path, report_id, artifact_root)
        record_stage_metric(report_id, "dynamic_analysis", "done", duration_ms=int((time.perf_counter() - stage_start) * 1000), payload={"analysis_state": dynamic_result.get("analysis_state"), "exec_count": dynamic_result.get("archive_member_exec_count", 0)})

        if bool(settings.sandbox_require_dynamic_success):
            exec_count = int(dynamic_result.get("archive_member_exec_count", 0) or 0)
            attempted_count = int(dynamic_result.get("archive_member_attempted_count", 0) or 0)
            failed_count = int(dynamic_result.get("archive_member_failed_count", 0) or 0)
            analysis_state = str(dynamic_result.get("analysis_state", "")).lower()
            if analysis_state == "static_only":
                dynamic_result["analysis_state"] = "partial"
                dynamic_result["dynamic_status"] = "not_executed"
                dynamic_result["dynamic_reason"] = "static_only"
            if exec_count <= 0 and not bool(dynamic_result.get("exec_signal")):
                dynamic_result["analysis_state"] = "partial"
                dynamic_result["dynamic_status"] = "not_executed"
                dynamic_result["dynamic_reason"] = "members_attempted_but_no_successful_execution" if (attempted_count > 0 or failed_count > 0) else "no_member_executed"

        scored_files = assess_files(static_results, dynamic_result)
        verdict = calculate_score(scored_files, dynamic_result)

        suspected_families = sorted({fam for item in scored_files for fam in item.get("suspected_family", [])})
        malware_types = sorted({m for item in scored_files for m in item.get("malware_type_tags", [])})
        iocs = {
            "urls": sorted({u for item in scored_files for u in item.get("iocs", {}).get("urls", [])})[:100],
            "emails": sorted({e for item in scored_files for e in item.get("iocs", {}).get("emails", [])})[:100],
            "domains": sorted({d for item in scored_files for d in item.get("iocs", {}).get("domains", [])})[:100],
            "ips": sorted({ip for item in scored_files for ip in item.get("iocs", {}).get("ips", [])})[:100],
            "yara_matches": sorted({m for item in scored_files for m in item.get("yara_matches", []) if not str(m).startswith("yara_error:")}),
            "suspected_families": suspected_families,
            "malware_types": malware_types,
        }

        normalized_iocs = normalize_iocs(iocs, dynamic_result, scored_files)
        artifact_manifest = build_artifact_manifest(report_id, artifact_root, dynamic_result, verdict.get("evidence_list", []))

        final_status = "done"
        if dynamic_result.get("timed_out"):
            final_status = "timeout"
        elif int(dynamic_result.get("returncode", 0)) < 0:
            final_status = "killed"

        summary = (
            f"{original_filename} analyzed as {verdict['verdict'].upper()} with risk score {verdict['score']}/100 "
            f"(static={verdict.get('static_score', 0)}, dynamic={verdict.get('dynamic_score', 0)}). "
            f"Executed archive members: {dynamic_result.get('archive_member_exec_count', 0)}. "
            f"Failed archive members: {dynamic_result.get('archive_member_failed_count', 0)}. "
            f"Skipped archive members: {dynamic_result.get('archive_member_skipped_count', 0)}."
            + (f" Dynamic note: {dynamic_result.get('dynamic_reason')}." if dynamic_result.get('dynamic_reason') else "")
            + (" Developer-heavy archive discount applied." if verdict.get("developer_heavy") else "")
            + (" Strong evidence override applied." if verdict.get("strong_override") else "")
            + (" Runtime timeout observed." if final_status == "timeout" else "")
            + (" Execution terminated by signal." if final_status == "killed" else "")
            + (" Dynamic execution partially skipped due to unsupported format or sandbox limits." if dynamic_result.get("analysis_state") in {"partial", "static_only"} else "")
        )

        evidence_bundle = _build_evidence_bundle(static_results.get("files", []) if isinstance(static_results, dict) else static_results, dynamic_result, verdict, iocs, normalized_iocs, artifact_manifest)

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
            "evidence_list": verdict.get("evidence_list", []),
            "family_confidence": verdict.get("family_confidence", "low"),
            "archive_profile": verdict.get("archive_profile", {}),
            "sample_hashes": sample_hashes or _hash_file(sample_path),
            "normalized_iocs": normalized_iocs,
            "artifact_manifest": artifact_manifest,
            "verdict_policy": _verdict_policy(),
            "summary": summary,
            "failure_reason": None,
            "timestamps": {**(current.get("timestamps") or {}), "started_at": started_at, "finished_at": _utc_now()},
            "static_result": {
                "files": scored_files,
                "summary": {
                    "file_count": len(scored_files),
                    "high_confidence_files": verdict.get("high_confidence_files", 0),
                    "high_severity_files": verdict.get("high_severity_files", 0),
                },
            },
            "dynamic_result": dynamic_result,
            "iocs": iocs,
            "malware_type_tags": verdict.get("malware_type_tags", []),
            "primary_malware_type": verdict.get("primary_malware_type"),
            "evidence_bundle": evidence_bundle,
            "failure_detail": _failure_detail(current, dynamic_result),
        }
        save_report(payload)
        record_stage_metric(report_id, "report_total", final_status if final_status in {"done", "timeout", "killed"} else "done", duration_ms=int((time.perf_counter() - overall_start) * 1000), payload={"verdict": payload.get("verdict"), "score": payload.get("risk_score")})
        record_event("analysis_finished", payload.get("summary", "analysis finished"), report_id=report_id, payload={"verdict": payload.get("verdict"), "status": final_status})
        return get_report(report_id) or payload
    except Exception as exc:
        logger.exception("process_report failed", exc_info=exc)
        record_stage_metric(report_id, "report_total", "failed", duration_ms=int((time.perf_counter() - overall_start) * 1000), reason=str(exc), payload={"error_type": type(exc).__name__})
        record_event("analysis_failed", str(exc), report_id=report_id, payload={"error_type": type(exc).__name__})
        failed = {
            **_base_payload(report_id, original_filename),
            "sample_path": sample_path,
            "sample_hashes": sample_hashes or (_hash_file(sample_path) if sample_path and Path(sample_path).exists() else {}),
            "status": "failed",
            "failure_reason": str(exc),
            "summary": f"Analysis failed: {exc}",
            "timestamps": {**(current.get("timestamps") or {}), "started_at": started_at, "finished_at": _utc_now()},
            "failure_detail": _failure_detail(current, {}, exc),
        }
        save_report(failed)
        raise
    finally:
        report_id_var.reset(token)
