from __future__ import annotations

from pydantic import BaseModel


class UploadResponse(BaseModel):
    report_id: str
    filename: str
    verdict: str
    risk_score: int
    summary: str
    status: str | None = None


class ReportOut(BaseModel):
    report_id: str
    filename: str
    verdict: str
    risk_score: int
    summary: str
    raw_score: int | None = None
    score_breakdown: dict | None = None
    evidence_reasons: list[str] | None = None
    status: str | None = None
    failure_reason: str | None = None
    failure_detail: dict | None = None
    sample_hashes: dict | None = None
    normalized_iocs: dict | None = None
    artifact_manifest: dict | None = None
    verdict_policy: dict | None = None
    static_result: dict
    dynamic_result: dict
    iocs: dict
    malware_type_tags: list[str] | None = None
    primary_malware_type: str | None = None
    primary_family: str | None = None
    family_matches: list[dict] | None = None
