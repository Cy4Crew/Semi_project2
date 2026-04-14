from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
ARTIFACTS_DIR = BASE_DIR / "artifacts"
REPORTS_DIR = ARTIFACTS_DIR / "reports"
LOGS_DIR = ARTIFACTS_DIR / "logs"
RULES_DIR = BASE_DIR / "rules"
SCRIPTS_DIR = BASE_DIR / "scripts"
