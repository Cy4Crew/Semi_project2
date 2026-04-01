import logging
from html import escape
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes.reports import router as reports_router
from app.api.routes.samples import router as samples_router
from app.core.config import settings
from app.repository.report_store import ensure_report_store

logger = logging.getLogger(__name__)

app = FastAPI(title=settings.app_name)
BUILD_ID = "full-hardening-2026-04-01-201"
app.include_router(samples_router)
app.include_router(reports_router)

ui_dir = Path(__file__).resolve().parents[2] / "ui"
if ui_dir.exists():
    app.mount("/static", StaticFiles(directory=ui_dir), name="static")


@app.on_event("startup")
def startup() -> None:
    Path(settings.samples_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.artifacts_dir).mkdir(parents=True, exist_ok=True)
    (Path(settings.artifacts_dir) / "reports").mkdir(parents=True, exist_ok=True)
    (Path(settings.artifacts_dir) / "logs").mkdir(parents=True, exist_ok=True)
    Path(settings.yara_rules_dir).mkdir(parents=True, exist_ok=True)
    ensure_report_store()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s", request.url.path, exc_info=exc)
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})
    return HTMLResponse(status_code=500, content="<h1>500 Internal Server Error</h1><p>An unexpected error occurred.</p>")


@app.get("/health")
def health():
    return {"status": "ok", "build": BUILD_ID}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    title = escape(settings.app_name)
    return f"""
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
    <style>
    body {{ font-family: Arial, sans-serif; background:#f8fafc; margin:0; color:#0f172a; }} .page {{ max-width: 1260px; margin: 0 auto; padding: 24px; }}
    .card {{ background:white; border:1px solid #e2e8f0; border-radius:18px; padding:20px; margin-bottom:18px; box-shadow:0 8px 24px rgba(15,23,42,0.05); overflow:hidden; }} .grid {{ display:grid; grid-template-columns: minmax(0,1fr) minmax(0,1fr); gap:16px; }} .stats {{ display:grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap:16px; }}
    button {{ background:#2563eb; color:white; border:0; border-radius:12px; padding:12px 16px; font-weight:700; cursor:pointer; }} input, select {{ padding:10px 12px; border:1px solid #cbd5e1; border-radius:12px; min-width:0; }} table {{ width:100%; border-collapse:collapse; table-layout:fixed; }} th, td {{ border-bottom:1px solid #e2e8f0; text-align:left; padding:10px; vertical-align:top; overflow-wrap:anywhere; word-break:break-word; }} td:last-child {{ white-space:nowrap; }}
    pre {{ background:#0f172a; color:#e2e8f0; padding:14px; border-radius:14px; overflow:auto; white-space:pre-wrap; word-break:break-word; max-height:380px; }} .muted {{ color:#64748b; }} .pill {{ display:inline-block; padding:4px 10px; border-radius:999px; background:#eff6ff; color:#1d4ed8; font-size:12px; font-weight:700; }} .toolbar {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }} a.btn {{ display:inline-block; padding:8px 12px; border-radius:10px; border:1px solid #cbd5e1; color:#0f172a; text-decoration:none; }} .kv {{ display:grid; grid-template-columns: 130px minmax(0,1fr); gap:8px 12px; align-items:start; }} .kv div {{ overflow-wrap:anywhere; word-break:break-word; }} .mini-title {{ font-size:12px; font-weight:700; color:#475569; text-transform:uppercase; letter-spacing:.04em; }} .summary-box {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:14px; padding:14px; }} .summary-list {{ margin:8px 0 0; padding-left:18px; }} .summary-list li {{ margin:4px 0; overflow-wrap:anywhere; word-break:break-word; }} .json-note {{ margin-top:10px; font-size:13px; color:#64748b; }} @media (max-width: 980px) {{ .grid, .stats {{ grid-template-columns: 1fr; }} .kv {{ grid-template-columns: 1fr; }} }}
    </style></head><body><main class="page"><div class="card"><h1>{title}</h1><p class="muted">Malware analysis demo with static analysis, ZIP member inspection, YARA matching, sample hashing, evidence export, and sandbox-style runtime analysis.</p><p class="muted">Build: {BUILD_ID}</p></div>
    <div class="card"><h2>Upload sample</h2><form id="uploadForm" class="toolbar"><input id="fileInput" type="file" name="file" accept=".zip" required /><button type="submit">Analyze</button></form><p class="muted">ZIP only. Max upload: {settings.max_upload_bytes} bytes. Max files: {settings.max_archive_files}. Max uncompressed bytes: {settings.max_zip_total_uncompressed_bytes}.</p><p id="status" class="muted">Idle</p></div>
    <div class="stats"><div class="card"><h3>Total</h3><div id="statTotal">-</div></div><div class="card"><h3>Verdicts</h3><div id="statVerdicts">-</div></div><div class="card"><h3>Statuses</h3><div id="statStatuses">-</div></div><div class="card"><h3>Policy</h3><div>clean 0-19<br>review 20-39<br>suspicious 40-69<br>malicious 70-100<br><br>override:<br>strong evidence may escalate verdict to malicious regardless of score</div></div></div>
    <div class="grid"><div class="card"><h2>Readable result</h2><div id="resultSummary" class="muted">No result yet.</div></div><div class="card"><h2>Analysis summary</h2><div id="resultJson" class="summary-box muted">Upload response will appear here.</div><p class="json-note">Full JSON is available in the detail page and evidence download.</p></div></div>
    <div class="card"><h2>Recent reports</h2><div class="toolbar" style="margin-bottom:12px;"><input id="filterQ" placeholder="Search filename"><select id="filterVerdict"><option value="">All verdicts</option><option value="clean">clean</option><option value="review">review</option><option value="suspicious">suspicious</option><option value="malicious">malicious</option></select><select id="filterStatus"><option value="">All statuses</option><option value="queued">queued</option><option value="running">running</option><option value="done">done</option><option value="timeout">timeout</option><option value="killed">killed</option><option value="failed">failed</option></select><button type="button" id="filterBtn">Apply</button></div><table><thead><tr><th>ID</th><th>Status</th><th>Verdict</th><th>Score</th><th>Actions</th></tr></thead><tbody id="reportsTable"><tr><td colspan="5">Loading...</td></tr></tbody></table></div></main>
    <script>

    function esc(value) {{ return String(value ?? '').replace(/[&<>"']/g, (ch) => ({{ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }})[ch]); }}
    async function readResponseSafely(res) {{ const text = await res.text(); try {{ return {{ ok:true, data:JSON.parse(text), rawText:text }}; }} catch (_) {{ return {{ ok:false, data:null, rawText:text }}; }} }}
    function toPairs(obj) {{ return Object.entries(obj || {{}}).map(([k,v]) => `${{esc(k)}}: ${{esc(v)}}`).join('<br>') || '-'; }}
    function renderList(items, emptyText='-') {{
      const arr = Array.isArray(items) ? items.filter(Boolean).slice(0, 6) : [];
      if (!arr.length) return `<div>${{esc(emptyText)}}</div>`;
      return `<ul class="summary-list">${{arr.map(v => `<li>${{esc(v)}}</li>`).join('')}}</ul>`;
    }}
    function renderSummaryPanel(data) {{
      if (!data || typeof data !== 'object') return '<div class="muted">No summary yet.</div>';
      const hashes = data.sample_hashes || {{}};
      const iocs = data.iocs || {{}};
      const breakdown = data.score_breakdown || {{}};
      const evidence = Array.isArray(data.evidence_reasons) ? data.evidence_reasons : [];
      const dyn = data.dynamic_result || {{}};
      const staticSummary = (data.static_result && data.static_result.summary) || {{}};
      const analysisState = dyn.analysis_state || '-';
      const skipped = dyn.archive_member_skipped_count ?? 0;
      const executed = dyn.archive_member_exec_count ?? 0;
      return `
        <div class="kv">
          <div class="mini-title">File</div><div>${{esc(data.filename || '-')}}</div>
          <div class="mini-title">Status</div><div>${{esc(data.status || '-')}}</div>
          <div class="mini-title">Verdict</div><div>${{esc(data.verdict || '-')}}</div>
          <div class="mini-title">Risk score</div><div>${{esc(data.risk_score ?? '-')}}</div>
          <div class="mini-title">SHA-256</div><div>${{esc(hashes.sha256 || '-')}}</div>
          <div class="mini-title">Summary</div><div>${{esc(data.summary || '-')}}</div>
          <div class="mini-title">Analysis state</div><div>${{esc(analysisState)}}</div>
          <div class="mini-title">Archive members</div><div>executed: ${{esc(executed)}} / skipped: ${{esc(skipped)}} / total files: ${{esc(staticSummary.file_count ?? '-')}}</div>
          <div class="mini-title">Score breakdown</div><div>${{toPairs(breakdown)}}</div>
          <div class="mini-title">Top evidence</div><div>${{renderList(evidence, 'No evidence reasons')}}</div>
          <div class="mini-title">IOCs</div><div>urls: ${{esc((iocs.urls || []).length)}} / domains: ${{esc((iocs.domains || []).length)}} / ips: ${{esc((iocs.ips || []).length)}} / emails: ${{esc((iocs.emails || []).length)}}</div>
          <div class="mini-title">Dynamic flags</div><div>network: ${{esc(Boolean(dyn.network_signal))}} / exec: ${{esc(Boolean(dyn.exec_signal))}} / persistence: ${{esc(Boolean(dyn.persistence_signal))}} / file: ${{esc(Boolean(dyn.file_signal))}}</div>
        </div>
      `;
    }}
    function renderReadableResult(data) {{
      if (!data || typeof data !== 'object') return '<p>No result yet.</p>';
      const hashes = data.sample_hashes ? `<p>SHA-256: ${{esc(data.sample_hashes.sha256 || '')}}</p>` : '';
      return `<p><strong>${{esc(data.filename || '-')}}</strong></p><p>Status: ${{esc(data.status || '-')}}</p><p>Verdict: ${{esc(data.verdict || '-')}}</p><p>Risk score: ${{esc(data.risk_score ?? '-')}}</p>${{hashes}}<p>${{esc(data.summary || '-')}}</p><p><a class="btn" href="/api/reports/${{encodeURIComponent(data.report_id || '')}}/view" target="_blank">Open detail</a> <a class="btn" href="/api/reports/${{encodeURIComponent(data.report_id || '')}}/evidence">Download evidence</a></p>`;
    }}
    function renderErrorSummary(text) {{
      return `<div class="kv"><div class="mini-title">Status</div><div>failed</div><div class="mini-title">Message</div><div>${{esc(text || 'Unknown error')}}</div></div>`;
    }}
    async function refreshStats() {{ const res = await fetch('/api/reports/stats', {{ cache:'no-store' }}); const parsed = await readResponseSafely(res); if (!parsed.ok) return; document.getElementById('statTotal').innerHTML = esc(parsed.data.total); document.getElementById('statVerdicts').innerHTML = toPairs(parsed.data.verdicts); document.getElementById('statStatuses').innerHTML = toPairs(parsed.data.statuses); }}
    async function refreshReports() {{ try {{ const q = encodeURIComponent(document.getElementById('filterQ').value || ''); const verdict = encodeURIComponent(document.getElementById('filterVerdict').value || ''); const status = encodeURIComponent(document.getElementById('filterStatus').value || ''); const res = await fetch(`/api/reports/?q=${{q}}&verdict=${{verdict}}&status=${{status}}&limit=50`, {{ cache:'no-store' }}); const parsed = await readResponseSafely(res); const tbody = document.getElementById('reportsTable'); if (!parsed.ok || !Array.isArray(parsed.data)) {{ tbody.innerHTML = '<tr><td colspan="5">Failed to load reports.</td></tr>'; return; }} if (parsed.data.length === 0) {{ tbody.innerHTML = '<tr><td colspan="5">No reports.</td></tr>'; return; }} tbody.innerHTML = parsed.data.map(r => `<tr><td>${{esc(r.report_id)}}</td><td><span class="pill">${{esc(r.status || '-')}}</span></td><td>${{esc(r.verdict)}}</td><td>${{esc(r.risk_score)}}</td><td><a class="btn" href="/api/reports/${{encodeURIComponent(r.report_id)}}/view" target="_blank" rel="noopener noreferrer">open</a>&nbsp;<a class="btn" href="/api/reports/${{encodeURIComponent(r.report_id)}}/evidence">evidence</a>&nbsp;<button onclick="reanalyze('${{esc(r.report_id)}}')">reanalyze</button></td></tr>`).join(''); }} catch (_) {{ document.getElementById('reportsTable').innerHTML = '<tr><td colspan="6">Failed to load reports.</td></tr>'; }} }}
    async function reanalyze(reportId) {{ const res = await fetch(`/api/reports/${{encodeURIComponent(reportId)}}/reanalyze`, {{ method:'POST' }}); const parsed = await readResponseSafely(res); if (!res.ok || !parsed.ok) {{ alert('Reanalyze failed'); return; }} document.getElementById('status').textContent = 'Reanalysis queued'; if (parsed.data.report_id) await pollReport(parsed.data.report_id); }}
    async function pollReport(reportId) {{ for (let i = 0; i < 60; i += 1) {{ const res = await fetch(`/api/reports/${{encodeURIComponent(reportId)}}`, {{ cache:'no-store' }}); const parsed = await readResponseSafely(res); if (!res.ok || !parsed.ok) break; const data = parsed.data || {{}}; document.getElementById('resultJson').innerHTML = renderSummaryPanel(data); document.getElementById('resultSummary').innerHTML = renderReadableResult(data); document.getElementById('status').textContent = ['done','failed','timeout','killed'].includes(data.status) ? data.status : 'analyzing'; refreshReports(); refreshStats(); if (['done','failed','timeout','killed'].includes(data.status)) return; await new Promise(r => setTimeout(r, 1500)); }} }}
    document.getElementById('uploadForm').addEventListener('submit', async (e) => {{ e.preventDefault(); const input = document.getElementById('fileInput'); if (!input.files.length) return; const form = new FormData(); form.append('file', input.files[0]); document.getElementById('status').textContent = 'uploading'; try {{ const res = await fetch('/api/samples/upload', {{ method:'POST', body:form }}); const parsed = await readResponseSafely(res); if (!res.ok) {{ const errorText = parsed.ok ? (parsed.data.detail || JSON.stringify(parsed.data)) : (parsed.rawText || `HTTP ${{res.status}}`); document.getElementById('resultJson').innerHTML = renderErrorSummary(errorText); document.getElementById('resultSummary').innerHTML = `<p>${{esc(errorText)}}</p>`; document.getElementById('status').textContent = 'failed'; return; }} const data = parsed.data || {{}}; document.getElementById('resultJson').innerHTML = renderSummaryPanel(data); document.getElementById('resultSummary').innerHTML = renderReadableResult(data); document.getElementById('status').textContent = 'analyzing'; refreshReports(); refreshStats(); if (data.report_id) await pollReport(data.report_id); }} catch (err) {{ document.getElementById('status').textContent = 'failed'; document.getElementById('resultJson').innerHTML = renderErrorSummary(String(err)); document.getElementById('resultSummary').innerHTML = `<p>${{esc(String(err))}}</p>`; }} }});
    document.getElementById('filterBtn').addEventListener('click', refreshReports);
    refreshStats(); refreshReports(); setInterval(() => {{ refreshStats(); refreshReports(); }}, 5000);

    </script></body></html>
    """
