from __future__ import annotations

import json
from html import escape

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from app.models.report_models import ReportOut
from app.repository.report_store import get_report, list_reports
from app.services.job_service import submit_report
from app.services.report_service import create_reanalysis_job

router = APIRouter(prefix="/api/reports", tags=["reports"])


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


def _filtered_reports(q: str | None = None, verdict: str | None = None, status: str | None = None, limit: int = 30):
    items = list_reports(limit=max(limit, 200))
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
def reports(q: str | None = None, verdict: str | None = None, status: str | None = None, limit: int = Query(default=30, ge=1, le=200)):
    return _filtered_reports(q=q, verdict=verdict, status=status, limit=limit)


@router.get("/stats")
def report_stats():
    items = list_reports(limit=200)
    verdicts = {}
    statuses = {}
    for item in items:
        verdicts[str(item.get("verdict") or "unknown")] = verdicts.get(str(item.get("verdict") or "unknown"), 0) + 1
        statuses[str(item.get("status") or "unknown")] = statuses.get(str(item.get("status") or "unknown"), 0) + 1
    return {"total": len(items), "verdicts": verdicts, "statuses": statuses}


@router.get("/{report_id}", response_model=ReportOut)
def report_detail(report_id: str):
    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
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
def report_download(report_id: str):
    item = get_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    return Response(
        content=json.dumps(item, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="report_{report_id}.json"'},
    )


@router.get("/{report_id}/evidence")
def report_evidence(report_id: str):
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


@router.get("/{report_id}/view", response_class=HTMLResponse)
def report_view(report_id: str):
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
    iocs = _as_dict(item.get("iocs"))
    files = _as_list(static_result.get("files"))[:80]
    static_summary = _as_dict(static_result.get("summary"))
    evidence_reasons = _as_list(item.get("evidence_reasons"))
    score_breakdown = _as_dict(item.get("score_breakdown"))
    sample_hashes = _as_dict(item.get("sample_hashes"))
    verdict_policy = _as_dict(item.get("verdict_policy"))
    file_count = int(static_summary.get("file_count", 0) or 0)

    total_urls = len(iocs.get("urls", []))
    malware_types = _as_list(item.get("malware_type_tags") or iocs.get("malware_types") or [])
    total_domains = len(iocs.get("domains", []))
    total_ips = len(iocs.get("ips", []))
    total_emails = len(iocs.get("emails", []))
    yara_count = len(iocs.get("yara_matches", []))
    exec_count = int(dynamic_result.get("archive_member_exec_count", 0))
    skipped_count = int(dynamic_result.get("archive_member_skipped_count", 0))
    failed_count = sum(1 for f in files if f.get("fail_reason") and f.get("fail_reason") not in {"not_executable", "document_execution_not_supported", "not_selected_for_execution"})
    high_files = sum(1 for f in files if f.get("severity") == "high")
    med_files = sum(1 for f in files if f.get("severity") == "medium")

    files_html = ""
    for entry in files:
        tags = "".join(f"<span class='tag'>{_e(tag)}</span>" for tag in entry.get("tags", [])[:8])
        file_score = int(entry.get('final_score', entry.get('score', 0)) or 0)
        file_verdict = str(entry.get('final_verdict', entry.get('severity', 'clean')) or 'clean')
        sev = _level_class(_risk_level(file_score, file_verdict))
        reasons = "".join(f"<li>{_e(x)}</li>" for x in entry.get("summary_reasons", [])[:5]) or "<li>-</li>"
        yara = ", ".join(_e(x) for x in entry.get("yara_matches", [])[:4] if not str(x).startswith("yara_error:")) or "-"
        reverse_stage = _e(_as_dict(entry.get('reverse_plan')).get('stage', '-'))
        type_tags = "".join(f"<span class='tag'>{_e(tag)}</span>" for tag in entry.get("malware_type_tags", [])[:4]) or "-"
        executed = bool(entry.get('executed'))
        exec_badge = f"<span class='sev {'low' if executed else 'medium'}>{'executed' if executed else 'not executed'}</span>"
        fail_reason = _e(entry.get('fail_reason') or '-')
        top_evidence = "".join(f"<li>{_e(x)}</li>" for x in entry.get("top_evidence", [])[:3]) or "<li>-</li>"
        files_html += (
            f"<tr><td class='file-col'>{_e(entry.get('file', '-'))}</td>"
            f"<td>{_e(file_score)}</td>"
            f"<td><span class='sev {sev}'>{_e(file_verdict)}</span></td>"
            f"<td>{type_tags}</td>"
            f"<td>{_e(entry.get('static_score_component', 0))} / {_e(entry.get('dynamic_score_component', 0))}</td>"
            f"<td>{exec_badge}</td>"
            f"<td>{fail_reason}</td>"
            f"<td><ul class='reasons'>{top_evidence}</ul></td>"
            f"<td>{reverse_stage}</td>"
            f"<td><ul class='reasons'>{reasons}</ul></td>"
            f"<td>{_e(yara)}</td><td>{tags or '-'}</td></tr>"
        )

    ioc_html = ""
    for label, values in [("Families", iocs.get("suspected_families", [])), ("URLs", iocs.get("urls", [])), ("Domains", iocs.get("domains", [])), ("IPs", iocs.get("ips", [])), ("Emails", iocs.get("emails", [])), ("YARA", iocs.get("yara_matches", []))]:
        chips = "".join(f"<span class='chip'>{_e(v)}</span>" for v in values[:20]) or "<span class='muted'>None</span>"
        ioc_html += f"<div class='ioc-block'><h3>{_e(label)}</h3><div class='chips'>{chips}</div></div>"

    hash_html = "".join(f"<div><strong>{_e(k.upper())}</strong><br><code>{_e(v)}</code></div>" for k, v in sample_hashes.items()) or "<span class='muted'>No hashes recorded.</span>"
    malware_type_html = "".join(f"<span class='chip'>{_e(v)}</span>" for v in malware_types[:10]) or "<span class='muted'>Unclassified</span>"
    policy_rows = "".join(f"<tr><td>{_e(k)}</td><td>{_e(v.get('min'))}</td><td>{_e(v.get('max'))}</td></tr>" for k, v in verdict_policy.items())
    evidence_html = "".join(f"<li>{_e(x)}</li>" for x in evidence_reasons) or "<li>No evidence reasons recorded.</li>"
    dynamic_pretty = _e(json.dumps(dynamic_result, ensure_ascii=False, indent=2))
    item_pretty = _e(json.dumps(item, ensure_ascii=False, indent=2))

    html = f"""
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{_e(item.get('report_id', 'report'))}</title>
    <style>
    :root{{--bg:#f8fafc;--card:#fff;--line:#e2e8f0;--text:#0f172a;--muted:#64748b;--critical:#b91c1c;--critical-bg:#fee2e2;--high:#c2410c;--high-bg:#ffedd5;--medium:#a16207;--medium-bg:#fef3c7;--low:#166534;--low-bg:#dcfce7;}}
    body{{font-family:Arial,sans-serif;margin:0;background:var(--bg);color:var(--text)}} .page{{max-width:1280px;margin:0 auto;padding:24px}} .card{{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;margin-bottom:16px;box-shadow:0 6px 18px rgba(15,23,42,.05)}}
    .hero,.grid,.ioc-grid,.metrics{{display:grid;gap:16px}} .hero{{grid-template-columns:1.6fr .9fr}} .grid,.ioc-grid{{grid-template-columns:1fr 1fr}} .metrics{{grid-template-columns:repeat(4,1fr)}} .metric{{border:1px solid var(--line);border-radius:14px;padding:14px;background:#fbfdff}} .metric span{{display:block;font-size:12px;color:var(--muted);margin-bottom:8px}} .metric strong{{font-size:24px}}
    .badge{{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;font-weight:700;font-size:12px}} .critical{{color:var(--critical);background:var(--critical-bg)}} .high{{color:var(--high);background:var(--high-bg)}} .medium{{color:var(--medium);background:var(--medium-bg)}} .low{{color:var(--low);background:var(--low-bg)}}
    .ioc-block{{border:1px solid var(--line);border-radius:14px;padding:14px;background:#fbfdff}} .chips,.hashes{{display:flex;flex-wrap:wrap;gap:8px}} .chip,.tag{{display:inline-flex;padding:6px 10px;border-radius:999px;border:1px solid var(--line);background:#fff;font-size:12px}} .muted{{color:var(--muted)}}
    table{{width:100%;border-collapse:collapse;background:#fff}} th,td{{border-bottom:1px solid var(--line);padding:12px 10px;text-align:left;vertical-align:top}} th{{color:var(--muted);font-size:13px}} .file-col{{max-width:320px;word-break:break-word}} .sev{{display:inline-flex;padding:5px 9px;border-radius:999px;font-size:12px;font-weight:700;text-transform:capitalize}} pre{{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;padding:14px;border-radius:12px}} code{{word-break:break-all}}
    .reasons{{margin:0;padding-left:18px}} .toolbar{{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}} .btn{{display:inline-block;padding:10px 14px;border-radius:12px;border:1px solid var(--line);background:#fff;text-decoration:none;color:var(--text);font-weight:700}}
    @media (max-width:980px){{.hero,.grid,.ioc-grid,.metrics{{grid-template-columns:1fr}}}}
    </style></head><body><main class="page">
    <section class="hero"><div class="card"><h1 style="margin:0 0 10px;">{_e(item.get('filename', '-'))}</h1><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;"><span class="badge {level_class}">{_e(risk_level)} Risk</span><span class="badge {level_class}">{_e(str(verdict).upper())}</span><span class="badge low">STATUS: {_e(str(status).upper())}</span></div><p style="margin:14px 0 0;line-height:1.65;">{_e(item.get('summary', ''))}</p><div class="toolbar"><a class="btn" href="/api/reports/{_e(report_id)}" target="_blank" rel="noopener noreferrer">Open JSON</a><a class="btn" href="/api/reports/{_e(report_id)}/download">Download JSON</a><a class="btn" href="/api/reports/{_e(report_id)}/evidence">Download evidence</a></div></div>
    <div class="card"><div class="metrics"><div class="metric"><span>Risk score</span><strong>{score}/100</strong></div><div class="metric"><span>PE</span><strong>{_e(score_breakdown.get('pe', 0))}</strong></div><div class="metric"><span>YARA</span><strong>{_e(score_breakdown.get('yara', 0))}</strong></div><div class="metric"><span>Runtime</span><strong>{_e(score_breakdown.get('runtime', 0))}</strong></div><div class="metric"><span>IOC</span><strong>{_e(score_breakdown.get('ioc', 0))}</strong></div><div class="metric"><span>Obfuscation</span><strong>{_e(score_breakdown.get('obfuscation', 0))}</strong></div><div class="metric"><span>Family</span><strong>{_e(score_breakdown.get('family', 0))}</strong></div><div class="metric"><span>Misc</span><strong>{_e(score_breakdown.get('misc', 0))}</strong></div><div class="metric"><span>Files analyzed</span><strong>{file_count}</strong></div><div class="metric"><span>Executed</span><strong>{exec_count}</strong></div><div class="metric"><span>High severity</span><strong>{high_files}</strong></div><div class="metric"><span>YARA hits</span><strong>{yara_count}</strong></div><div class="metric"><span>URLs / Domains</span><strong>{total_urls + total_domains}</strong></div><div class="metric"><span>IPs / Emails</span><strong>{total_ips + total_emails}</strong></div><div class="metric"><span>Medium severity</span><strong>{med_files}</strong></div><div class="metric"><span>Timeout</span><strong>{_e(dynamic_result.get('timed_out', False))}</strong></div></div></div></section>
    <section class="grid"><div class="card"><h2 style="margin-top:0;">Evidence reasons</h2><ul class="reasons">{evidence_html}</ul></div><div class="card"><h2 style="margin-top:0;">Sample hashes</h2><div class="hashes">{hash_html}</div><h3 style="margin:16px 0 8px;">Malware type tags</h3><div class="chips">{malware_type_html}</div></div></section>
    <section class="card"><h2 style="margin-top:0;">Verdict policy</h2><table><thead><tr><th>Verdict</th><th>Min score</th><th>Max score</th></tr></thead><tbody>{policy_rows}</tbody></table></section>
    <section class="card"><h2 style="margin-top:0;">Indicators</h2><div class="ioc-grid">{ioc_html}</div></section>
    <section class="card"><h2 style="margin-top:0;">Analyzed Files</h2><table><thead><tr><th>File</th><th>Score</th><th>Severity</th><th>Type tags</th><th>Static / Dynamic</th><th>Reverse plan</th><th>Evidence</th><th>YARA</th><th>Tags</th></tr></thead><tbody>{files_html}</tbody></table></section>
    <section class="grid"><div class="card"><h2 style="margin-top:0;">Dynamic analysis</h2><pre>{dynamic_pretty}</pre></div><div class="card"><h2 style="margin-top:0;">Full report JSON</h2><pre>{item_pretty}</pre></div></section>
    </main></body></html>
    """
    return html
