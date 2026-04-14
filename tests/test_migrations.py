import sqlite3

from app.db import migrations


def test_schema_version_table_created(tmp_path, monkeypatch):
    db_path = tmp_path / "reports.db"
    monkeypatch.setattr(migrations, "DB_PATH", db_path)
    migrations._INITIALIZED = False
    migrations.initialize_database()
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[0] >= 3
