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
    allowed_upload_magic_hex: str = "504b0304,504b0506,504b0708"
    artifact_access_token: str = ""
    bridge_auth_token: str = ""

    sandbox_memory_limit_mb: int = 256
    sandbox_file_size_limit_mb: int = 32
    sandbox_max_processes: int = 16
    sandbox_drop_privileges: bool = True
    sandbox_disable_network: bool = True
    sandbox_network_sample_interval_ms: int = 250
    sandbox_runtime_root: str = "/tmp/malware_sandbox"

    sandbox_backend: str = "auto"
    sandbox_bridge_url: str = "http://host.docker.internal:9080"
    sandbox_vm_name: str = "win10x64"
    sandbox_vm_snapshot: str = "clean"
    sandbox_job_timeout_seconds: int = 180
    sandbox_require_dynamic_success: bool = False

    suricata_binary: str = ""
    suricata_rules_path: str = str(BASE_DIR / "rules" / "suricata.rules")
    volatility3_binary: str = ""
    procdump_path: str = r"C:\Tools\Sysinternals\procdump64.exe"
    sandbox_bridge_urls: str = ""
    sandbox_vm_names: str = ""
    monitor_logs_dir: str = r"C:\analysis\monitor"

    benign_whitelist_path: str = str(BASE_DIR / "rules" / "benign_whitelist.json")
    benign_whitelist_enabled: bool = True
    reports_default_page_size: int = 30
    reports_max_page_size: int = 200

    sandbox_bridge_health_ttl_seconds: int = 10
    sandbox_vm_slot_cooldown_seconds: int = 20
    sandbox_bridge_submit_retries: int = 2
    sandbox_bridge_retry_backoff_seconds: float = 2.0
    sandbox_enable_result_cache: bool = True
    sandbox_cache_reuse_statuses: str = "done,timeout,killed"
    analysis_max_retries: int = 2
    analysis_retry_backoff_seconds: float = 2.0
    dead_letter_dir: str = str(BASE_DIR / "artifacts" / "dead_letter")

    verdict_clean_max: int = 19
    verdict_review_max: int = 39
    verdict_suspicious_max: int = 69

    strong_override_min_score: int = 60
    suspicious_exec_floor: int = 58
    malicious_exec_floor: int = 72
    text_family_hint_cap: int = 12
    benign_penalty_max: int = 10
    archive_network_signal_min_links: int = 2

    artifact_output_names: str = (
        "done.txt,events.jsonl,stdout.txt,stderr.txt,analysis_log.jsonl,network_trace.jsonl,"
        "report.json,report_static.json,report_dynamic.json,report_memory.json"
    )
    artifact_output_prefixes: str = "report_,analysis_,network_"
    artifact_output_suffixes: str = ".stdout.txt,.stderr.txt,.jsonl.trace,.report.json"
    artifact_output_dirs: str = "artifacts,artifact,evidence,analysis,logs,output,results,network,trace,sandbox"
    dynamic_noise_process_names: str = (
        "system,idle,registry,smss.exe,csrss.exe,wininit.exe,services.exe,lsass.exe,svchost.exe,"
        "fontdrvhost.exe,dwm.exe,explorer.exe,searchhost.exe,searchindexer.exe,runtimebroker.exe,"
        "sihost.exe,shellexperiencehost.exe,textinputhost.exe,ctfmon.exe,taskhostw.exe,conhost.exe,"
        "wmiadap.exe,wmiprvse.exe,dllhost.exe"
    )
    dynamic_noise_path_keywords: str = (
        "\\windows\\system32,\\windows\\syswow64,\\program files\\vmware,\\programdata\\vmware,"
        "\\windows\\servicing,\\windows\\winsxs"
    )
    report_hidden_reason_tokens: str = (
        "text-like file cap,test artifact cap,text evidence cap,low-risk document cap,ignored analysis artifact"
    )

    @property
    def artifact_output_name_set(self) -> set[str]:
        return {item.strip().lower() for item in self.artifact_output_names.split(",") if item.strip()}

    @property
    def artifact_output_prefix_list(self) -> list[str]:
        return [item.strip().lower() for item in self.artifact_output_prefixes.split(",") if item.strip()]

    @property
    def artifact_output_suffix_list(self) -> list[str]:
        return [item.strip().lower() for item in self.artifact_output_suffixes.split(",") if item.strip()]

    @property
    def artifact_output_dir_set(self) -> set[str]:
        return {item.strip().lower() for item in self.artifact_output_dirs.split(",") if item.strip()}

    @property
    def dynamic_noise_process_name_set(self) -> set[str]:
        return {item.strip().lower() for item in self.dynamic_noise_process_names.split(",") if item.strip()}

    @property
    def dynamic_noise_path_keyword_list(self) -> list[str]:
        return [item.strip().lower() for item in self.dynamic_noise_path_keywords.split(",") if item.strip()]

    @property
    def report_hidden_reason_token_set(self) -> set[str]:
        return {item.strip().lower() for item in self.report_hidden_reason_tokens.split(",") if item.strip()}


settings = Settings()
