from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def isolated_paths(tmp_path, monkeypatch):
    db_path = tmp_path / "reports.db"
    artifacts_dir = tmp_path / "artifacts"
    samples_dir = tmp_path / "samples"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    samples_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("REPORT_DB_PATH", str(db_path))
    monkeypatch.setenv("ARTIFACTS_DIR", str(artifacts_dir))
    monkeypatch.setenv("SAMPLES_DIR", str(samples_dir))
    return {"db_path": db_path, "artifacts_dir": artifacts_dir, "samples_dir": samples_dir}
