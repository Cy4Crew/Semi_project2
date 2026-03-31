from html import escape
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes.reports import router as reports_router
from app.api.routes.samples import router as samples_router
from app.core.config import settings
from app.repository.report_store import list_reports

app = FastAPI(title=settings.app_name)
BUILD_ID = "full-hardening-2026-04-01-003"
app.include_router(samples_router)
app.include_router(reports_router)

ui_dir = Path(__file__).resolve().parents[2] / "ui"
if ui_dir.exists():
    app.mount("/static", StaticFiles(directory=ui_dir), name="static")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    reports = list_reports(limit=20)
    rows = ""
    for report in reports:
        report_id = escape(str(report.get("report_id", "-")))
        verdict = escape(str(report.get("verdict", "-")))
        status = escape(str(report.get("status", "-")))
        risk_score = escape(str(report.get("risk_score", 0)))
        summary = escape(str(report.get("summary", "")))
        rows += (
            f"<tr><td>{report_id}</td><td>{status}</td><td>{verdict}</td><td>{risk_score}</td>"
            f"<td>{summary}</td><td><a href='/api/reports/{report_id}/view' target='_blank' rel='noopener noreferrer'>open</a></td></tr>"
        )

    title = escape(settings.app_name)
    return f"""
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
    <style>
    body {{ font-family: Arial, sans-serif; background:#f8fafc; margin:0; color:#0f172a; }} .page {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
    .card {{ background:white; border:1px solid #e2e8f0; border-radius:18px; padding:20px; margin-bottom:18px; box-shadow:0 8px 24px rgba(15,23,42,0.05); }} .grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:16px; }}
    button {{ background:#2563eb; color:white; border:0; border-radius:12px; padding:12px 16px; font-weight:700; cursor:pointer; }} table {{ width:100%; border-collapse:collapse; }} th, td {{ border-bottom:1px solid #e2e8f0; text-align:left; padding:10px; vertical-align:top; }}
    pre {{ background:#0f172a; color:#e2e8f0; border-radius:14px; padding:14px; min-height:240px; white-space:pre-wrap; word-break:break-word; }} .muted {{ color:#64748b; }} .pill {{ display:inline-block; padding:4px 10px; border-radius:999px; background:#eff6ff; color:#1d4ed8; font-size:12px; font-weight:700; }} @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    </style></head><body><main class="page"><div class="card"><h1>{title}</h1><p class="muted">정적 분석, ZIP 내부 파일 분석, 샌드박스식 실행 분석을 결합한 과제용 통합 플랫폼</p><p class="muted">Build: {BUILD_ID}</p></div>
    <div class="card"><h2>Upload sample</h2><form id="uploadForm"><input id="fileInput" type="file" name="file" accept=".zip" required /><button type="submit">Analyze</button></form><p class="muted">ZIP only. Max upload: {settings.max_upload_bytes} bytes. Max files: {settings.max_archive_files}. Max uncompressed bytes: {settings.max_zip_total_uncompressed_bytes}.</p><p id="status" class="muted">대기 중</p></div>
    <div class="grid"><div class="card"><h2>Readable result</h2><div id="resultSummary" class="muted">아직 결과가 없습니다.</div></div><div class="card"><h2>Raw JSON</h2><pre id="resultJson">업로드 응답이 여기에 표시됩니다.</pre></div></div>
    <div class="card"><h2>Recent reports</h2><table><thead><tr><th>ID</th><th>Status</th><th>Verdict</th><th>Score</th><th>Summary</th><th>Link</th></tr></thead><tbody id="reportsTable">{rows}</tbody></table></div></main>
    <script>
    function esc(value) {{ return String(value ?? '').replace(/[&<>"']/g, (ch) => ({{ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }})[ch]); }}
    async function readResponseSafely(res) {{ const text = await res.text(); try {{ return {{ ok:true, data:JSON.parse(text), rawText:text }}; }} catch (_) {{ return {{ ok:false, data:null, rawText:text }}; }} }}
    async function refreshReports() {{ try {{ const res = await fetch('/api/reports/', {{ cache:'no-store' }}); const parsed = await readResponseSafely(res); const tbody = document.getElementById('reportsTable'); if (!parsed.ok || !Array.isArray(parsed.data)) {{ tbody.innerHTML = '<tr><td colspan="6">리포트를 불러오지 못했습니다.</td></tr>'; return; }} if (parsed.data.length === 0) {{ tbody.innerHTML = '<tr><td colspan="6">리포트가 없습니다.</td></tr>'; return; }} tbody.innerHTML = parsed.data.map(r => `<tr><td>${{esc(r.report_id)}}</td><td><span class="pill">${{esc(r.status || '-')}}</span></td><td>${{esc(r.verdict)}}</td><td>${{esc(r.risk_score)}}</td><td>${{esc(r.summary)}}</td><td><a href="/api/reports/${{encodeURIComponent(r.report_id)}}/view" target="_blank" rel="noopener noreferrer">open</a></td></tr>`).join(''); }} catch (_) {{ document.getElementById('reportsTable').innerHTML = '<tr><td colspan="6">리포트를 불러오지 못했습니다.</td></tr>'; }} }}
    document.getElementById('uploadForm').addEventListener('submit', async (e) => {{ e.preventDefault(); const input = document.getElementById('fileInput'); if (!input.files.length) return; const form = new FormData(); form.append('file', input.files[0]); document.getElementById('status').textContent = '분석 중...'; try {{ const res = await fetch('/api/samples/upload', {{ method:'POST', body:form }}); const parsed = await readResponseSafely(res); document.getElementById('resultJson').textContent = parsed.ok ? JSON.stringify(parsed.data, null, 2) : (parsed.rawText || `HTTP ${{res.status}}`); if (!res.ok) {{ const errorText = parsed.ok ? (parsed.data.detail || JSON.stringify(parsed.data)) : (parsed.rawText || `HTTP ${{res.status}}`); document.getElementById('resultSummary').innerHTML = `<p>${{esc(errorText)}}</p>`; document.getElementById('status').textContent = '실패'; return; }} const data = parsed.data || {{}}; document.getElementById('resultSummary').innerHTML = `<p><strong>${{esc(data.filename)}}</strong></p><p>Status: ${{esc(data.status)}}</p><p>Verdict: ${{esc(data.verdict)}}</p><p>Risk score: ${{esc(data.risk_score)}}</p><p>${{esc(data.summary)}}</p>`; document.getElementById('status').textContent = '완료'; refreshReports(); }} catch (err) {{ document.getElementById('status').textContent = '실패'; document.getElementById('resultJson').textContent = String(err); document.getElementById('resultSummary').innerHTML = `<p>${{esc(String(err))}}</p>`; }} }});
    setInterval(refreshReports, 3000);
    </script></body></html>
    """
