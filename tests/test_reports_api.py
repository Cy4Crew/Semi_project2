from fastapi.testclient import TestClient

from app.api.main import app
from app.db import migrations
from app.repository import report_store


def test_reports_endpoint_returns_saved_report(tmp_path, monkeypatch):
    db_path = tmp_path / "reports.db"
    monkeypatch.setattr(migrations, "DB_PATH", db_path)
    monkeypatch.setattr(report_store, "DB_PATH", db_path)
    monkeypatch.setattr(report_store, "REPORT_DIR", tmp_path / "reports")
    migrations._INITIALIZED = False
    report_store.ensure_report_store()
    report_store.save_report({
        "report_id": "rep001",
        "status": "done",
        "filename": "sample.zip",
        "verdict": "review",
        "risk_score": 25,
        "timestamps": {"created_at": "2026-01-01T00:00:00+00:00"},
    })
    client = TestClient(app)
    response = client.get("/api/reports/")
    assert response.status_code == 200
    data = response.json()
    assert any(item["report_id"] == "rep001" for item in data)
