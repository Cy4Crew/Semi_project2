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
    report_db_path: str = str(BASE_DIR / "artifacts" / "reports.db")

    sample_timeout_seconds: int = 5
    max_archive_files: int = 100
    max_archive_exec_members: int = 8
    entropy_threshold: float = 7.2
    enable_pcap: bool = False
    analysis_worker_count: int = 2
    report_db_busy_timeout_ms: int = 5000

    max_upload_bytes: int = 25 * 1024 * 1024
    max_zip_total_uncompressed_bytes: int = 80 * 1024 * 1024
    max_zip_entry_uncompressed_bytes: int = 20 * 1024 * 1024
    max_zip_compression_ratio: float = 250.0
    max_zip_depth_hint: int = 3
    reject_encrypted_archives: bool = True
    allowed_upload_extensions: str = ".zip"
    allowed_upload_content_types: str = "application/zip,application/x-zip-compressed,multipart/x-zip"

    sandbox_memory_limit_mb: int = 256
    sandbox_file_size_limit_mb: int = 32
    sandbox_max_processes: int = 16
    sandbox_drop_privileges: bool = True
    sandbox_disable_network: bool = True
    sandbox_network_sample_interval_ms: int = 250
    sandbox_runtime_root: str = "/tmp/malware_sandbox"

    sandbox_backend: str = "auto"
    sandbox_bridge_url: str = "http://host.docker.internal:9080"
    sandbox_vm_name: str = "analysis-win10"
    sandbox_vm_snapshot: str = "clean"
    sandbox_job_timeout_seconds: int = 180
    sandbox_require_dynamic_success: bool = False

    verdict_clean_max: int = 19
    verdict_review_max: int = 39
    verdict_suspicious_max: int = 69


settings = Settings()
