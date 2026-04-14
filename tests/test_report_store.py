from app.db import migrations
from app.repository import report_store


def test_cache_lookup_uses_sha256(tmp_path, monkeypatch):
    db_path = tmp_path / "reports.db"
    monkeypatch.setattr(migrations, "DB_PATH", db_path)
    monkeypatch.setattr(report_store, "DB_PATH", db_path)
    monkeypatch.setattr(report_store, "REPORT_DIR", tmp_path / "reports")
    migrations._INITIALIZED = False
    report_store.ensure_report_store()
    payload = {
        "report_id": "abc123",
        "status": "done",
        "filename": "sample.zip",
        "verdict": "review",
        "risk_score": 33,
        "sample_hashes": {"sha256": "deadbeef"},
        "timestamps": {"created_at": "2026-01-01T00:00:00+00:00"},
    }
    report_store.save_report(payload)
    found = report_store.find_cached_report_by_sha256("deadbeef", ["done"])
    assert found is not None
    assert found["report_id"] == "abc123"
