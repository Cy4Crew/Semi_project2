from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Malware Sandbox Platform"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    samples_dir: str = str(BASE_DIR / "samples")
    artifacts_dir: str = str(BASE_DIR / "artifacts")
    yara_rules_dir: str = str(BASE_DIR / "rules")

    sample_timeout_seconds: int = 5
    max_archive_files: int = 100
    max_archive_exec_members: int = 8
    entropy_threshold: float = 7.2
    enable_pcap: bool = False

    max_upload_bytes: int = 25 * 1024 * 1024
    max_zip_total_uncompressed_bytes: int = 80 * 1024 * 1024
    allowed_upload_extensions: str = ".zip"
    allowed_upload_content_types: str = "application/zip,application/x-zip-compressed,multipart/x-zip"

settings = Settings()
