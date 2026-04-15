from __future__ import annotations

import json
from html import escape
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response

from app.core.config import settings

from app.models.report_models import ReportOut
from app.repository.report_store import count_reports, get_report, list_reports
from app.services.job_service import get_queue_stats, submit_report
from app.services.multi_vm_scheduler import MultiVMScheduler
from app.utils.metrics_store import recent_events, stage_summary, top_failure_reasons
from app.services.rules_service import build_rule_manifest
from app.services.report_service import create_reanalysis_job



def _is_artifact_noise_path(path: str) -> bool:
    lower = str(path or '').replace('/', '\\').lower()
    name = lower.rsplit('\\', 1)[-1]
    return name.endswith('_stdout.txt') or name.endswith('_stderr.txt') or name in {'stdout.txt', 'stderr.txt'}


def _is_extract_original_path(path: str) -> bool:
    lower = str(path or '').replace('/', '\\').lower()
    return lower.startswith('extract\\')


def _display_drop_rows(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        path = str(row.get('path') or '')
        if _is_artifact_noise_path(path) or _is_extract_original_path(path):
            continue
        out.append(row)
    return out
router = APIRouter(prefix="/api/reports", tags=["reports"])
_ops_scheduler = MultiVMScheduler()


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    return value if isinstance(value, list) else []


def _risk_level(score: int, verdict: str) -> str:
    verdict = (verdict or "").lower()
    if verdict == "malicious" or score >= 70:
        return "Critical"
    if verdict == "suspicious" or score >= 40:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def _level_class(level: str) -> str:
    return {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}.get(level, "low")


def _e(value: object) -> str:
    return escape(str(value if value is not None else ""))


def _artifact_access_allowed(token: str | None) -> bool:
    required = str(getattr(settings, "artifact_access_token", "") or "").strip()
    if not required:
        return True
    return str(token or "").strip() == required


def _filtered_reports(q: str | None = None, verdict: str | None = None, status: str | None = None, limit: int = 30, offset: int = 0):
    items = list_reports(limit=max(limit, 1), offset=max(offset, 0))
    qv = (q or "").strip().lower()
    vv = (verdict or "").strip().lower()
    sv = (status or "").strip().lower()
    filtered = []
    for item in items:
        if vv and str(item.get("verdict", "")).lower() != vv:
            continue
        if sv and str(item.get("status", "")).lower() != sv:
            continue
        if qv and qv not in json.dumps({
            "report_id": item.get("report_id"),
            "filename": item.get("filename"),
            "summary": item.get("summary"),
            "verdict": item.get("verdict"),
        }, ensure_ascii=False).lower():
            continue
        filtered.append(item)
        if len(filtered) >= limit:
            break
    return filtered



@router.get("/")
def reports(
    q: str | None = None,
    verdict: str | None = None,
    status: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=settings.reports_default_page_size, ge=1, le=settings.reports_max_page_size),
):
    offset = (int(page) - 1) * int(page_size)
    items = _filtered_reports(q=q, verdict=verdict, status=status, limit=page_size, offset=offset)
    return {
        "items": items,
        "page": int(page),
        "page_size": int(page_size),
        "total": count_reports(),
    }


@router.get("/stats")
def report_stats():
    items = list_reports(limit=200)
    verdicts = {}
    statuses = {}
    for item in items:
        verdicts[str(item.get("verdict") or "unknown")] = verdicts.get(str(item.get("verdict") or "unknown"), 0) + 1
        statuses[str(item.get("status") or "unknown")] = statuses.get(str(item.get("status") or "unknown"), 0) + 1
    return {"total": len(items), "verdicts": verdicts, "statuses": statuses}




@router.get("/ops/summary")
def ops_summary():
    vm_health = [
        {
            "name": slot.name,
            "healthy": bool(slot.healthy),
            "reason": slot.reason,
            "busy": bool(slot.busy),
            "inflight_jobs": int(slot.inflight_jobs),
        }
        for slot in _ops_scheduler.health(force=False)
    ]
    return {
        "queue": get_queue_stats(),
        "stage_metrics": stage_summary(limit=2000),
        "top_failure_reasons": top_failure_reasons(limit=8),
        "recent_events": recent_events(limit=12),
        "vm_health": vm_health,
    }



@router.get("/ops/rules")
def rules_manifest(refresh: bool = Query(default=False)):
    return build_rule_manifest(refresh=refresh)

@router.get("/ops/logs/app", response_class=PlainTextResponse)
def app_log_tail(lines: int = Query(default=200, ge=20, le=1000)):
    from pathlib import Path
    log_path = Path("artifacts") / "logs" / "app.log"
    if not log_path.exists():
        raise HTTPException(status_code=404, detail="app.log not found")
    content = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-int(lines):])

@router.get("/{report_id}", response_model=ReportOut)
def report_detail(report_id: str, token: str | None = Query(default=None), include_sections: bool = Query(default=True)):
    if not _artifact_access_allowed(token):
        raise HTTPException(status_code=403, detail="artifact access denied")
    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    if not include_sections:
        item = {k: v for k, v in item.items() if k not in {"static_result", "dynamic_result", "evidence_bundle", "artifact_manifest"}} | {"static_result": {}, "dynamic_result": {}, "iocs": item.get("iocs") or {}}
    return ReportOut(**item)


@router.post("/{report_id}/reanalyze")
def report_reanalyze(report_id: str):
    try:
        new_report = create_reanalysis_job(report_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    submit_report(new_report["report_id"])
    return {"queued_from": report_id, **new_report}


@router.get("/{report_id}/download")
def report_download(report_id: str, token: str | None = Query(default=None)):
    if not _artifact_access_allowed(token):
        raise HTTPException(status_code=403, detail="artifact access denied")
    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    return Response(
        content=json.dumps(item, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="report_{report_id}.json"'},
    )


@router.get("/{report_id}/evidence")
def report_evidence(report_id: str, token: str | None = Query(default=None)):
    if not _artifact_access_allowed(token):
        raise HTTPException(status_code=403, detail="artifact access denied")
    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    payload = item.get("evidence_bundle") or {
        "top_reasons": item.get("evidence_reasons", []),
        "network_trace": _as_dict(item.get("dynamic_result")).get("network_trace", {}),
    }
    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="evidence_{report_id}.json"'},
    )

@router.get("/{report_id}/artifacts")
def report_artifacts(report_id: str, token: str | None = Query(default=None), page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=200)):
    if not _artifact_access_allowed(token):
        raise HTTPException(status_code=403, detail="artifact access denied")
    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    manifest = item.get("artifact_manifest") or {"files": [], "quick_links": {}, "total_files": 0}
    files = manifest.get("files") or []
    offset = (int(page) - 1) * int(page_size)
    manifest["files"] = files[offset: offset + int(page_size)]
    manifest["page"] = int(page)
    manifest["page_size"] = int(page_size)
    return manifest


@router.get("/{report_id}/artifacts/file")
def report_artifact_file(report_id: str, path: str, token: str | None = Query(default=None)):
    if not _artifact_access_allowed(token):
        raise HTTPException(status_code=403, detail="artifact access denied")
    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    artifact_root = Path("artifacts") / report_id
    target = (artifact_root / str(path)).resolve()
    if artifact_root.resolve() not in target.parents and target != artifact_root.resolve():
        raise HTTPException(status_code=400, detail="invalid artifact path")
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(str(target), filename=target.name)



def _render_kv_table(data: dict, title_left: str = "Key", title_right: str = "Value") -> str:
    rows = "".join(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>" for k, v in data.items())
    if not rows:
        rows = f"<tr><td colspan='2' class='muted'>No data.</td></tr>"
    return f"<table><thead><tr><th>{_e(title_left)}</th><th>{_e(title_right)}</th></tr></thead><tbody>{rows}</tbody></table>"


@router.get("/{report_id}/view", response_class=HTMLResponse)
def report_view(report_id: str, token: str | None = Query(default=None)):
    if not _artifact_access_allowed(token):
        raise HTTPException(status_code=403, detail="artifact access denied")
    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")

    score = int(item.get("risk_score") or 0)
    verdict = str(item.get("verdict") or "unknown")
    risk_level = _risk_level(score, verdict)
    level_class = _level_class(risk_level)
    status = str(item.get("status") or "unknown")

    static_result = _as_dict(item.get("static_result"))
    dynamic_result = _as_dict(item.get("dynamic_result"))
    evidence_bundle = _as_dict(item.get("evidence_bundle"))
    iocs = _as_dict(item.get("iocs"))
    failure_detail = _as_dict(item.get("failure_detail"))
    files = _as_list(static_result.get("files"))
    static_summary = _as_dict(static_result.get("summary"))
    evidence_reasons = [str(x) for x in _as_list(item.get("evidence_reasons")) if str(x).strip()]
    evidence_list = _as_list(item.get("evidence_list"))
    normalized_iocs = _as_dict(item.get("normalized_iocs") or evidence_bundle.get("normalized_iocs"))
    artifact_manifest = _as_dict(item.get("artifact_manifest") or evidence_bundle.get("artifact_manifest"))
    archive_profile = _as_dict(item.get("archive_profile"))
    family_confidence = str(item.get("family_confidence") or archive_profile.get("family_confidence") or "low")
    score_breakdown = _as_dict(item.get("score_breakdown"))
    sample_hashes = _as_dict(item.get("sample_hashes"))

    file_count = int(static_summary.get("file_count", 0) or 0)
    malware_types = _as_list(item.get("malware_type_tags") or iocs.get("malware_types") or [])
    yara_matches = _as_list(iocs.get("yara_matches", []))
    exec_count = int(dynamic_result.get("archive_member_exec_count", 0) or 0)
    skipped_count = int(dynamic_result.get("archive_member_skipped_count", 0) or 0)
    network_endpoints = _as_list(_as_dict(dynamic_result.get("network_trace")).get("endpoints"))
    dropped_files_raw = _as_list(evidence_bundle.get("dropped_files") or _as_dict(dynamic_result.get("filesystem_delta")).get("created_details"))
    dropped_files = _display_drop_rows(dropped_files_raw)
    process_tree = _as_list(evidence_bundle.get("process_tree") or _as_dict(dynamic_result.get("process_delta")).get("new_process_tree"))
    memory_dumps = _as_list(evidence_bundle.get("memory_dumps") or dynamic_result.get("memory_dumps"))
    timeline = _as_list(dynamic_result.get("timeline"))

    failed_count = sum(1 for f in files if f.get("fail_reason") and f.get("fail_reason") not in {"not_executable", "document_execution_not_supported", "not_selected_for_execution"})

    def _dedupe_reason_list(values: list[str]) -> list[str]:
        counts: dict[str, int] = {}
        for raw in values:
            label = str(raw).strip()
            if not label:
                continue
            if label.startswith("YARA match"):
                key = "YARA matches"
            elif label.startswith("suspicious keywords"):
                key = "Suspicious keywords"
            elif label.startswith("downloader strings"):
                key = "Downloader strings"
            else:
                key = label[:1].upper() + label[1:]
            counts[key] = counts.get(key, 0) + 1
        out = []
        for key, count in counts.items():
            out.append(f"{key} ({count})" if count > 1 and not key.endswith('s') else key)
        return out[:8]

    summary_reasons = _dedupe_reason_list(evidence_reasons)
    summary_reasons_html = "".join(f"<li>{_e(x)}</li>" for x in summary_reasons) or "<li>No major reasons recorded.</li>"

    files_sorted = sorted(files, key=lambda x: int(x.get("final_score", x.get("score", 0)) or 0), reverse=True)
    top_files = files_sorted[:10]
    top_file_rows = ""
    for entry in top_files:
        file_score = int(entry.get("final_score", entry.get("score", 0)) or 0)
        file_verdict = str(entry.get("final_verdict", entry.get("severity", "clean")) or "clean")
        sev = _level_class(_risk_level(file_score, file_verdict))
        tags = ", ".join(str(x) for x in entry.get("malware_type_tags", [])[:4]) or "-"
        yara = ", ".join(str(x) for x in entry.get("yara_matches", [])[:3] if not str(x).startswith("yara_error:")) or "-"
        evidence = "; ".join(str(x) for x in entry.get("top_evidence", [])[:2]) or "-"
        attempted = bool(entry.get("member_runtime", {}).get("attempted"))
        succeeded = bool(entry.get("member_runtime", {}).get("succeeded")) or bool(entry.get("executed"))
        failed = bool(entry.get("member_runtime", {}).get("failed"))
        executed = "success" if succeeded else ("failed" if failed else "no")
        attempt = "yes" if attempted else "no"
        top_file_rows += (
            f"<tr><td class='file-col'>{_e(entry.get('file', '-'))}</td>"
            f"<td>{file_score}</td>"
            f"<td><span class='sev {sev}'>{_e(file_verdict)}</span></td>"
            f"<td>{_e(executed)}</td>"
            f"<td>{_e(attempt)}</td>"
            f"<td>{_e(tags)}</td>"
            f"<td>{_e(yara)}</td>"
            f"<td>{_e(evidence)}</td></tr>"
        )
    top_file_rows = top_file_rows or "<tr><td colspan='8' class='muted'>No files analyzed.</td></tr>"

    evidence_link_map = {str(x.get("signal") or ""): _as_list(x.get("links")) for x in _as_list(artifact_manifest.get("evidence_links"))}
    evidence_sorted = sorted(evidence_list, key=lambda x: int(x.get("weight", 0) or 0), reverse=True)[:12]
    evidence_rows = ""
    for entry in evidence_sorted:
        links = evidence_link_map.get(str(entry.get("signal") or ""), [])[:2]
        link_html = " ".join(f"<a class='btn btn-small' href='{_e(link.get('url'))}'>{_e(link.get('label'))}</a>" for link in links) or "-"
        evidence_rows += (
            f"<tr><td><span class='tag'>{_e(entry.get('category', '-'))}</span></td>"
            f"<td>{_e(entry.get('signal', '-'))}</td>"
            f"<td>{_e(entry.get('source', '-'))}</td>"
            f"<td>{_e(entry.get('weight', 0))}</td>"
            f"<td>{_e(entry.get('detail', '-'))}</td>"
            f"<td>{link_html}</td></tr>"
        )
    evidence_rows = evidence_rows or "<tr><td colspan='6' class='muted'>No structured evidence recorded.</td></tr>"

    families = _as_list(iocs.get("suspected_families", []))[:8]
    urls = _as_list(iocs.get("urls", []))[:8]
    ips = _as_list(iocs.get("ips", []))[:8]
    ioc_summary_cards = []
    for label, values in [("Families", families), ("URLs", urls), ("IPs", ips), ("YARA", yara_matches[:8])]:
        chips = "".join(f"<span class='chip'>{_e(v)}</span>" for v in values) or "<span class='muted'>None</span>"
        ioc_summary_cards.append(f"<div class='ioc-block'><h3>{_e(label)}</h3><div class='chips'>{chips}</div></div>")
    ioc_summary_html = "".join(ioc_summary_cards)

    normalized_items = _as_list(normalized_iocs.get('items'))[:40]
    normalized_ioc_rows = "".join(
        f"<tr><td>{_e(entry.get('type', '-'))}</td><td><code>{_e(entry.get('value', '-'))}</code></td><td>{_e(', '.join(_as_list(entry.get('sources'))[:3]))}</td></tr>"
        for entry in normalized_items
    ) or "<tr><td colspan='3' class='muted'>No normalized IOCs.</td></tr>"

    artifact_files = _as_list(artifact_manifest.get("files"))[:20]
    artifact_rows = "".join(
        f"<tr><td>{_e(entry.get('category', '-'))}</td><td>{_e(entry.get('name', '-'))}</td><td>{_e(entry.get('size_bytes', '-'))}</td><td><a class='btn btn-small' href='{_e(entry.get('download_url', '#'))}'>download</a></td></tr>"
        for entry in artifact_files
    ) or "<tr><td colspan='4' class='muted'>No raw artifacts collected.</td></tr>"

    dropped_rows = "".join(
        f"<tr><td>{_e(x.get('path', '-'))}</td><td>{_e(x.get('category', '-'))}</td></tr>" for x in dropped_files[:25]
    ) or "<tr><td colspan='2' class='muted'>No dropped files recorded.</td></tr>"
    process_rows = "".join(
        f"<tr><td>{_e(x.get('pid', '-'))}</td><td>{_e(x.get('name', '-'))}</td><td>{_e(x.get('cmdline', '-'))}</td></tr>" for x in process_tree[:20]
    ) or "<tr><td colspan='3' class='muted'>No new process tree recorded.</td></tr>"
    network_rows = "".join(
        f"<tr><td>{_e(x.get('pid', '-'))}</td><td>{_e(x.get('remote_ip', '-'))}</td><td>{_e(x.get('remote_port', '-'))}</td><td>{_e(x.get('status', '-'))}</td></tr>" for x in network_endpoints[:20]
    ) or "<tr><td colspan='4' class='muted'>No network endpoints recorded.</td></tr>"
    if any(int(x.get('pid', 0) or 0) == 0 for x in network_endpoints):
        network_rows += "<tr><td colspan='4' class='muted'>Note: PID 0 or unowned connections are weak signals and may reflect background VM traffic.</td></tr>"
    timeline_rows = "".join(
        f"<tr><td>{_e(x.get('ts', '-'))}</td><td>{_e(x.get('stage', '-'))}</td><td>{_e(json.dumps({k: v for k, v in x.items() if k not in {'ts', 'stage'}}, ensure_ascii=False))}</td></tr>" for x in timeline[:20]
    ) or "<tr><td colspan='3' class='muted'>No timeline events recorded.</td></tr>"

    failure_section = ""
    if status.lower() in {"failed", "timeout", "killed"} or failure_detail or item.get("failure_reason"):
        failure_rows = _render_kv_table({
            'Failed stage': failure_detail.get('failed_stage') or '-',
            'Error type': failure_detail.get('error_type') or '-',
            'Error message': failure_detail.get('error_message') or item.get('failure_reason') or '-',
            'Last successful step': failure_detail.get('last_successful_step') or '-',
            'Analysis state': failure_detail.get('analysis_state') or dynamic_result.get('analysis_state') or '-',
        }, 'Field', 'Value')
        traceback_html = f"<details><summary>Traceback</summary><pre>{_e(failure_detail.get('traceback') or dynamic_result.get('traceback') or 'No traceback recorded.')}</pre></details>"
        failure_section = f"<section class='card'><h2>Failure details</h2>{failure_rows}{traceback_html}</section>"

    hash_html = "".join(f"<div><strong>{_e(k.upper())}</strong><br><code>{_e(v)}</code></div>" for k, v in sample_hashes.items()) or "<span class='muted'>No hashes recorded.</span>"
    malware_type_html = "".join(f"<span class='chip'>{_e(v)}</span>" for v in malware_types[:8]) or "<span class='muted'>Unclassified</span>"
    advanced_metrics = [
        ("Top file", score_breakdown.get("top_file", 0)),
        ("Top 3 avg", score_breakdown.get("top3_average", 0)),
        ("Runtime bonus", score_breakdown.get("archive_runtime", 0)),
        ("Distribution", score_breakdown.get("distribution", 0)),
        ("Benign penalty", score_breakdown.get("benign_penalty", 0)),
        ("Memory dumps", len(memory_dumps)),
        ("Skipped exec", skipped_count),
        ("YARA hits", len(yara_matches)),
    ]
    advanced_metrics_html = "".join(f"<div class='metric small-metric'><span>{_e(label)}</span><strong>{_e(value)}</strong></div>" for label, value in advanced_metrics)

    html = f"""
    <!doctype html>
    <html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>{_e(item.get('report_id', 'report'))}</title>
    <style>
    :root{{--bg:#f8fafc;--card:#fff;--line:#e2e8f0;--text:#0f172a;--muted:#64748b;--critical:#b91c1c;--critical-bg:#fee2e2;--high:#c2410c;--high-bg:#ffedd5;--medium:#a16207;--medium-bg:#fef3c7;--low:#166534;--low-bg:#dcfce7;}}
    *{{box-sizing:border-box}} body{{font-family:Arial,sans-serif;margin:0;background:var(--bg);color:var(--text)}} .page{{max-width:1360px;margin:0 auto;padding:24px}} .card{{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;margin-bottom:16px;box-shadow:0 6px 18px rgba(15,23,42,.05)}}
    .hero,.grid,.metrics,.detail-grid{{display:grid;gap:16px}} .hero{{grid-template-columns:1.5fr .9fr}} .grid{{grid-template-columns:1fr 1fr}} .detail-grid{{grid-template-columns:1fr 1fr 1fr}} .metrics{{grid-template-columns:repeat(4,1fr)}} .metric{{border:1px solid var(--line);border-radius:14px;padding:14px;background:#fbfdff}} .metric span{{display:block;font-size:12px;color:var(--muted);margin-bottom:8px}} .metric strong{{font-size:24px}} .small-metric strong{{font-size:18px}}
    .badge{{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;font-weight:700;font-size:12px}} .critical{{color:var(--critical);background:var(--critical-bg)}} .high{{color:var(--high);background:var(--high-bg)}} .medium{{color:var(--medium);background:var(--medium-bg)}} .low{{color:var(--low);background:var(--low-bg)}}
    .summary-list{{margin:0;padding-left:18px;line-height:1.7}} .ioc-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}} .ioc-block{{border:1px solid var(--line);border-radius:14px;padding:14px;background:#fbfdff}} .chips,.hashes,.toolbar{{display:flex;flex-wrap:wrap;gap:8px}} .chip,.tag{{display:inline-flex;padding:6px 10px;border-radius:999px;border:1px solid var(--line);background:#fff;font-size:12px}} .muted{{color:var(--muted)}}
    table{{width:100%;border-collapse:collapse;background:#fff}} th,td{{border-bottom:1px solid var(--line);padding:12px 10px;text-align:left;vertical-align:top}} th{{color:var(--muted);font-size:13px}} .file-col{{max-width:320px;word-break:break-word}} .sev{{display:inline-flex;padding:5px 9px;border-radius:999px;font-size:12px;font-weight:700;text-transform:capitalize}} pre{{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;padding:14px;border-radius:12px;max-height:460px;overflow:auto}} code{{word-break:break-all}}
    .toolbar{{margin-top:12px}} .btn{{display:inline-block;padding:10px 14px;border-radius:12px;border:1px solid var(--line);background:#fff;text-decoration:none;color:var(--text);font-weight:700}} .btn-small{{padding:6px 10px;font-size:12px}} details{{margin-top:10px}} details summary{{cursor:pointer;font-weight:700}} .section-intro{{margin-top:4px;color:var(--muted)}}
    @media (max-width:980px){{.hero,.grid,.metrics,.detail-grid,.ioc-grid{{grid-template-columns:1fr}}}}
    </style></head><body><main class='page'>
    <section class='hero'>
      <div class='card'>
        <h1 style='margin:0 0 10px'>{_e(item.get('filename', '-'))}</h1>
        <div style='display:flex;gap:10px;align-items:center;flex-wrap:wrap'>
          <span class='badge {level_class}'>{_e(risk_level)} Risk</span>
          <span class='badge {level_class}'>{_e(str(verdict).upper())}</span>
          <span class='badge low'>STATUS: {_e(str(status).upper())}</span>
        </div>
        <p style='margin:14px 0 0;line-height:1.65'>{_e(item.get('summary', ''))}</p>
        <div class='toolbar'>
          <a class='btn' href='/api/reports/{_e(report_id)}' target='_blank' rel='noopener noreferrer'>Open JSON</a>
          <a class='btn' href='/api/reports/{_e(report_id)}/download'>Download JSON</a>
          <a class='btn' href='/api/reports/{_e(report_id)}/evidence'>Download evidence</a>
        </div>
      </div>
      <div class='card'>
        <div class='metrics'>
          <div class='metric'><span>Risk score</span><strong>{score}/100</strong></div>
          <div class='metric'><span>Files analyzed</span><strong>{file_count}</strong></div>
          <div class='metric'><span>Executed</span><strong>{exec_count}</strong></div>
          <div class='metric'><span>Failed exec</span><strong>{failed_count}</strong></div>
          <div class='metric'><span>Network endpoints</span><strong>{len(network_endpoints)}</strong></div>
          <div class='metric'><span>Dropped files</span><strong>{len(dropped_files)}</strong></div>
          <div class='metric'><span>Attempted exec</span><strong>{_e(dynamic_result.get('archive_member_attempted_count', 0))}</strong></div>
          <div class='metric'><span>Processes</span><strong>{len(process_tree)}</strong></div>
          <div class='metric'><span>Family confidence</span><strong>{_e(family_confidence.upper())}</strong></div>
        </div>
      </div>
    </section>

    <section class='grid'>
      <div class='card'>
        <h2>Key findings</h2>
        <p class='section-intro'>판정에 가장 크게 기여한 핵심 이유만 먼저 보여줍니다.</p>
        <ul class='summary-list'>{summary_reasons_html}</ul>
      </div>
      <div class='card'>
        <h2>Sample profile</h2>
        <div class='hashes'>{hash_html}</div>
        <h3 style='margin:16px 0 8px'>Malware type tags</h3>
        <div class='chips'>{malware_type_html}</div>
      </div>
    </section>

    <section class='card'>
      <h2>Top evidence</h2>
      <p class='section-intro'>가중치가 높은 증거만 먼저 정렬해서 보여줍니다.</p>
      <table><thead><tr><th>Category</th><th>Signal</th><th>Source</th><th>Weight</th><th>Detail</th><th>Artifacts</th></tr></thead><tbody>{evidence_rows}</tbody></table>
    </section>

    <section class='grid'>
      <div class='card'>
        <h2>Behavior summary</h2>
        <table><thead><tr><th>File</th><th>Score</th><th>Severity</th><th>Exec</th><th>Attempt</th><th>Type tags</th><th>YARA</th><th>Top evidence</th></tr></thead><tbody>{top_file_rows}</tbody></table>
      </div>
      <div class='card'>
        <h2>IOC summary</h2>
        <div class='ioc-grid'>{ioc_summary_html}</div>
      </div>
    </section>

    {failure_section}

    <section class='card'>
      <h2>Advanced metrics</h2>
      <details>
        <summary>Show advanced metrics</summary>
        <div class='metrics' style='margin-top:14px'>{advanced_metrics_html}</div>
      </details>
    </section>

    <section class='detail-grid'>
      <div class='card'>
        <h2>Normalized IOCs</h2>
        <table><thead><tr><th>Type</th><th>Value</th><th>Sources</th></tr></thead><tbody>{normalized_ioc_rows}</tbody></table>
      </div>
      <div class='card'>
        <h2>Dropped files</h2>
        <table><thead><tr><th>Path</th><th>Category</th></tr></thead><tbody>{dropped_rows}</tbody></table>
      </div>
      <div class='card'>
        <h2>Process tree</h2>
        <table><thead><tr><th>PID</th><th>Name</th><th>Cmdline</th></tr></thead><tbody>{process_rows}</tbody></table>
      </div>
    </section>

    <section class='grid'>
      <div class='card'>
        <h2>Network activity</h2>
        <table><thead><tr><th>PID</th><th>Remote IP</th><th>Port</th><th>Status</th></tr></thead><tbody>{network_rows}</tbody></table>
      </div>
      <div class='card'>
        <h2>Execution timeline</h2>
        <table><thead><tr><th>Time</th><th>Stage</th><th>Detail</th></tr></thead><tbody>{timeline_rows}</tbody></table>
      </div>
    </section>

    <section class='card'>
      <h2>Raw artifacts</h2>
      <details>
        <summary>Show artifact downloads</summary>
        <table style='margin-top:14px'><thead><tr><th>Category</th><th>Name</th><th>Size</th><th>Open</th></tr></thead><tbody>{artifact_rows}</tbody></table>
      </details>
    </section>

    <section class='grid'>
      <div class='card'>
        <h2>Dynamic analysis JSON</h2>
        <details><summary>Show dynamic JSON</summary><pre>{_e(json.dumps(dynamic_result, ensure_ascii=False, indent=2))}</pre></details>
      </div>
      <div class='card'>
        <h2>Full report JSON</h2>
        <details><summary>Show full report JSON</summary><pre>{_e(json.dumps(item, ensure_ascii=False, indent=2))}</pre></details>
      </div>
    </section>
    </main></body></html>
    """
    return html

@router.get("/compare")
def compare_reports(a: str, b: str, token: str | None = Query(default=None)):
    if not _artifact_access_allowed(token):
        raise HTTPException(status_code=403, detail="artifact access denied")
    left = get_report(a)
    right = get_report(b)
    if not left or not right:
        raise HTTPException(status_code=404, detail="one or both reports not found")
    left_iocs = _as_dict(left.get("normalized_iocs") or {})
    right_iocs = _as_dict(right.get("normalized_iocs") or {})
    added = {}
    removed = {}
    for key in sorted(set(left_iocs) | set(right_iocs)):
        la = {json.dumps(x, ensure_ascii=False, sort_keys=True) for x in _as_list(left_iocs.get(key))}
        rb = {json.dumps(x, ensure_ascii=False, sort_keys=True) for x in _as_list(right_iocs.get(key))}
        added_vals = [json.loads(x) for x in sorted(rb - la)]
        removed_vals = [json.loads(x) for x in sorted(la - rb)]
        if added_vals:
            added[key] = added_vals
        if removed_vals:
            removed[key] = removed_vals
    return {
        "left": {"report_id": left.get("report_id"), "filename": left.get("filename"), "verdict": left.get("verdict"), "risk_score": left.get("risk_score")},
        "right": {"report_id": right.get("report_id"), "filename": right.get("filename"), "verdict": right.get("verdict"), "risk_score": right.get("risk_score")},
        "score_delta": int(right.get("risk_score") or 0) - int(left.get("risk_score") or 0),
        "verdict_changed": str(left.get("verdict")) != str(right.get("verdict")),
        "ioc_diff": {"added": added, "removed": removed},
    }


@router.get("/{report_id}/iocs/export")
def export_iocs(
    report_id: str,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    token: str | None = Query(default=None),
):
    if not _artifact_access_allowed(token):
        raise HTTPException(status_code=403, detail="artifact access denied")

    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")

    payload = _as_dict(item.get("normalized_iocs") or item.get("iocs") or {})

    if format == "json":
        return Response(
            content=json.dumps(payload, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="iocs_{report_id}.json"'},
        )

    lines = ["type,value"]
    for key, values in payload.items():
        for value in _as_list(values):
            if isinstance(value, dict):
                compact = json.dumps(value, ensure_ascii=False, sort_keys=True)
            else:
                compact = str(value)
            compact = compact.replace('"', '""')
            lines.append(f'"{key}","{compact}"')

    return Response(
        content="\n".join(lines),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="iocs_{report_id}.csv"'},
    )