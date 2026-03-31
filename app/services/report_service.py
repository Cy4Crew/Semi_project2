from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.core.config import settings
from app.repository.report_store import save_report, update_report
from app.services.dynamic_analysis_service import run_dynamic_analysis
from app.services.scoring_service import calculate_score
from app.services.static_analysis_service import analyze_archive


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_report(sample_path: str, original_filename: str) -> dict:
    report_id = uuid4().hex[:12]
    artifact_root = str(Path(settings.artifacts_dir) / report_id)
    Path(artifact_root).mkdir(parents=True, exist_ok=True)

    base_payload = {
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
        "timestamps": {"queued_at": _utc_now()},
        "static_result": {"files": [], "summary": {"file_count": 0, "high_confidence_files": 0, "high_severity_files": 0}},
        "dynamic_result": {},
        "iocs": {"urls": [], "emails": [], "domains": [], "ips": [], "yara_matches": [], "suspected_families": []},
    }
    save_report(base_payload)

    try:
        update_report(report_id, status="running", summary="Static and dynamic analysis in progress.", timestamps={**base_payload["timestamps"], "started_at": _utc_now()})
        static_results = analyze_archive(sample_path)
        dynamic_result = run_dynamic_analysis(sample_path, report_id, artifact_root)
        verdict = calculate_score(static_results, dynamic_result)

        summary = (
            f"{original_filename} analyzed as {verdict['verdict'].upper()} with risk score {verdict['score']}/100 "
            f"(static={verdict.get('static_score', 0)}, dynamic={verdict.get('dynamic_score', 0)}). "
            f"Executed archive members: {dynamic_result.get('archive_member_exec_count', 0)}."
            + (" Developer-heavy archive detected." if verdict.get("developer_heavy") else "")
            + (" Strong evidence override applied." if verdict.get("strong_override") else "")
        )

        suspected_families = sorted({fam for item in static_results for fam in item.get("suspected_family", [])})
        iocs = {
            "urls": sorted({u for item in static_results for u in item.get("iocs", {}).get("urls", [])})[:100],
            "emails": sorted({e for item in static_results for e in item.get("iocs", {}).get("emails", [])})[:100],
            "domains": sorted({d for item in static_results for d in item.get("iocs", {}).get("domains", [])})[:100],
            "ips": sorted({ip for item in static_results for ip in item.get("iocs", {}).get("ips", [])})[:100],
            "yara_matches": sorted({m for item in static_results for m in item.get("yara_matches", []) if not str(m).startswith("yara_error:")}),
            "suspected_families": suspected_families,
        }

        payload = {
            "report_id": report_id,
            "filename": original_filename,
            "status": "done",
            "verdict": verdict.get("verdict", "review"),
            "risk_score": verdict.get("score", 0),
            "raw_score": verdict.get("raw_score", verdict.get("score", 0)),
            "score_breakdown": verdict.get("score_breakdown", {}),
            "evidence_reasons": verdict.get("evidence_reasons", []),
            "summary": summary,
            "failure_reason": None,
            "timestamps": {**base_payload["timestamps"], "started_at": _utc_now(), "finished_at": _utc_now()},
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
        }
        save_report(payload)
        return payload
    except Exception as exc:
        failed = {
            **base_payload,
            "status": "failed",
            "failure_reason": str(exc),
            "summary": f"Analysis failed: {exc}",
            "timestamps": {**base_payload["timestamps"], "started_at": _utc_now(), "finished_at": _utc_now()},
        }
        save_report(failed)
        raise
