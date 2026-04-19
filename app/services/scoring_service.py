from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services.family_classifier import classify_family
from app.services.whitelist_service import evaluate_benign_indicators

EXECUTABLE_SUFFIXES = {".exe", ".dll", ".com", ".scr", ".ps1", ".hta", ".vbs", ".wsf", ".js", ".jse", ".bat", ".cmd", ".docm", ".xlsm"}
SCRIPT_SUFFIXES = {".ps1", ".hta", ".vbs", ".wsf", ".js", ".jse", ".bat", ".cmd", ".py", ".sh"}
DOC_SUFFIXES = {".docm", ".xlsm", ".doc", ".docx", ".xls", ".xlsx"}
TEXTISH_SUFFIXES = {".txt", ".md", ".rst", ".csv", ".log", ".json", ".yaml", ".yml"}
SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".cpp", ".cs"}
IMAGEISH_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"}
LOW_SIGNAL_SUFFIXES = TEXTISH_SUFFIXES | SOURCE_SUFFIXES | IMAGEISH_SUFFIXES | {".css", ".scss", ".map", ".lock", ".toml", ".ini"}

MALWARE_TYPE_PRIORITY = ["ransomware", "infostealer", "rat", "backdoor", "dropper", "downloader", "loader", "trojan", "persistence", "script"]

TEXT_FAMILY_HINT_CAP = 6
SOURCE_FAMILY_HINT_CAP = 6
SUSPICIOUS_EXEC_FLOOR = 70
MALICIOUS_EXEC_FLOOR = 78
STRONG_OVERRIDE_MIN_SCORE = 60


def _severity_from_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "review"
    return "clean"


def normalize_member_path(path_str: str) -> str:
    if not path_str:
        return ""
    raw = str(path_str).replace("\\", "/")
    for marker in ["/extract/", "sandbox_work/", "sandbox_shared/inbox/"]:
        idx = raw.lower().find(marker)
        if idx != -1:
            return raw[idx + len(marker):].lstrip("/")
    return raw.lstrip("/")


def member_result_map(dynamic_result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapped = {}
    for item in dynamic_result.get("archive_member_results", []) or []:
        if not isinstance(item, dict):
            continue
        key = normalize_member_path(item.get("path") or item.get("member_path") or item.get("name") or "")
        if key:
            mapped[key] = item
            mapped[Path(key).name] = item
    return mapped


def _evidence(category: str, signal: str, weight: int, source: str, detail: str) -> dict[str, Any]:
    return {
        "category": category,
        "signal": signal,
        "weight": weight,
        "source": source,
        "detail": detail,
        "summary": f"[{category}] {signal}: {detail}",
    }

def _dynamic_context(dynamic_result: dict[str, Any]) -> dict[str, Any]:
    sysmon_summary = dynamic_result.get("sysmon_summary") or {}
    anti_signals = sysmon_summary.get("anti_analysis_signals") or dynamic_result.get("anti_analysis_signals") or []
    registry_changes = sysmon_summary.get("registry_changes") or dynamic_result.get("registry_diff", {}).get("added") or []
    network_endpoints = sysmon_summary.get("network_endpoints") or dynamic_result.get("network_trace", {}).get("endpoints") or []
    return {
        "execution_observed": bool(dynamic_result.get("execution_observed")) or bool(sysmon_summary.get("execution_observed")),
        "anti_analysis": bool(dynamic_result.get("anti_analysis_signal")) or bool(anti_signals),
        "anti_signals": anti_signals,
        "registry_changes": registry_changes,
        "network_endpoints": network_endpoints,
    }


def _member_behavior(member: dict[str, Any] | None, path: str) -> dict[str, Any]:
    if not member:
        return {
            "executed": False,
            "attempted": False,
            "av_blocked": False,
            "execution_observed": False,
            "anti_analysis": False,
            "score": 0,
            "reasons": [],
            "evidence": [],
        }

    attempted = bool(member.get("attempted"))
    succeeded = bool(member.get("succeeded"))
    skip_reason = str(member.get("skip_reason") or "").lower()
    execution_observed = bool(member.get("execution_observed")) or bool(succeeded)
    anti_analysis = bool(member.get("anti_analysis"))
    sysmon_summary = member.get("sysmon_summary") or {}

    av_blocked = False
    if "winerror 225" in skip_reason or "virus" in skip_reason or "user consent" in skip_reason:
        av_blocked = True

    score = 0
    reasons = []
    evidence = []

    if succeeded:
        score += 12
        reasons.append("executed in sandbox")
        evidence.append(_evidence("dynamic", "sandbox_execution", 12, path, "member executed"))
    elif attempted:
        if av_blocked:
            score += 30
            reasons.append("blocked by endpoint protection")
            evidence.append(_evidence("dynamic", "av_block", 30, path, "execution blocked by AV"))
        else:
            score += 4
            reasons.append("execution attempted")
            evidence.append(_evidence("dynamic", "execution_attempt", 4, path, "member execution attempted"))

    if execution_observed and not succeeded:
        score += 10
        reasons.append("observed post-launch behavior")
        evidence.append(_evidence("dynamic", "observed_behavior", 10, path, "behavior observed after launch"))

    if anti_analysis:
        anti_count = int(sysmon_summary.get("anti_analysis_count") or 1)
        score += 30
        reasons.append("anti-analysis behavior")
        evidence.append(_evidence("dynamic", "anti_analysis", 30, path, f"task manager kill or similar behavior observed ({anti_count})"))

    return {
        "executed": succeeded,
        "attempted": attempted,
        "av_blocked": av_blocked,
        "execution_observed": execution_observed,
        "anti_analysis": anti_analysis,
        "score": score,
        "reasons": reasons,
        "evidence": evidence,
    }

def _classify_types(item: dict[str, Any]) -> list[str]:
    fam = set(item.get("suspected_family", []) or [])
    return [x for x in MALWARE_TYPE_PRIORITY if x in fam][:4]


def calculate_file_assessment(static_item: dict[str, Any], dynamic_result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(static_item, dict):
        static_item = {"file": str(static_item), "score": 0}

    item = dict(static_item)
    path = normalize_member_path(item.get("file", ""))
    item["file"] = path

    suffix = Path(path).suffix.lower()
    pe = item.get("pe") or {}
    suspicious_imports = pe.get("suspicious_imports", []) or []
    medium_imports = pe.get("medium_imports", []) or []
    entropy = float(item.get("entropy") or 0.0)
    yara_hits = item.get("yara_matches", []) or []
    families = set(item.get("suspected_family", []) or [])

    member_map = member_result_map(dynamic_result)
    member = member_map.get(path) or member_map.get(Path(path).name)
    behavior = _member_behavior(member, path)
    ctx = _dynamic_context(dynamic_result)

    score = 0
    reasons: list[str] = []
    evidence: list[dict[str, Any]] = []

    if suspicious_imports:
        score += 10
        reasons.append("suspicious PE import")
        evidence.append(_evidence("static", "suspicious_import", 10, path, suspicious_imports[0]))
    elif medium_imports:
        score += 4
        reasons.append("medium-risk PE import")

    if entropy >= float(getattr(settings, "entropy_threshold", 7.2) or 7.2):
        score += 8
        reasons.append("high entropy")
        evidence.append(_evidence("static", "packed_or_obfuscated", 8, path, "high entropy"))

    family_only_text = suffix in TEXTISH_SUFFIXES | SOURCE_SUFFIXES and families and not suspicious_imports and not yara_hits

    if families:
        if family_only_text:
            score = min(max(score, 2), TEXT_FAMILY_HINT_CAP if suffix in TEXTISH_SUFFIXES else SOURCE_FAMILY_HINT_CAP)
        else:
            score += 14
            reasons.append("malware family indicator")
            evidence.append(_evidence("static", "family_hint", 14, path, ",".join(sorted(families))))

    if suffix == ".locked":
        score += 18
        reasons.append("locked-file ransomware indicator")
        evidence.append(_evidence("static", "locked_file", 18, path, "locked extension"))

    if "readme_restore" in path.lower() or "restore_files" in path.lower():
        score += 20
        reasons.append("ransom note indicator")
        evidence.append(_evidence("static", "ransom_note", 20, path, "restore/decrypt note language"))

    score += behavior["score"]
    reasons.extend(behavior["reasons"])
    evidence.extend(behavior["evidence"])

    if ctx["anti_analysis"]:
        score = max(score, MALICIOUS_EXEC_FLOOR)
        reasons.append("anti-analysis signal in dynamic telemetry")
        evidence.append(_evidence("dynamic", "anti_analysis_global", 35, path, "taskkill/taskmgr or similar anti-analysis behavior observed"))

    if ctx["execution_observed"] and suffix == ".exe" and not behavior["executed"]:
        score = max(score, SUSPICIOUS_EXEC_FLOOR)
        reasons.append("execution observed via telemetry")
        evidence.append(_evidence("dynamic", "execution_observed", 16, path, "telemetry observed even without clean success return code"))

    if ctx["registry_changes"]:
        score += 8
        reasons.append("registry modifications observed")
        evidence.append(_evidence("dynamic", "registry_change", 8, path, f"observed {len(ctx['registry_changes'])} registry changes"))

    if ctx["network_endpoints"]:
        score += 8
        reasons.append("network activity observed")
        evidence.append(_evidence("dynamic", "network_activity", 8, path, f"observed {len(ctx['network_endpoints'])} network endpoints"))

    av_blocked = bool(behavior.get("av_blocked"))
    suspicious_static_combo = bool(suspicious_imports) and entropy >= float(getattr(settings, "entropy_threshold", 7.2) or 7.2)
    suspicious_signal = suspicious_static_combo or bool(families) or bool(yara_hits)

    if suffix == ".exe" and behavior["executed"] and suspicious_signal:
        score = max(score, SUSPICIOUS_EXEC_FLOOR)

    if suffix == ".exe" and families and suspicious_imports and entropy >= float(getattr(settings, "entropy_threshold", 7.2) or 7.2) and bool(behavior.get("attempted")) and av_blocked:
        score = max(score, 72)
        reasons.append("av-blocked malicious execution candidate")
        evidence.append(_evidence("dynamic", "av_blocked_malware_candidate", 32, path, "AV blocked suspicious executable during execution attempt"))

    benign = evaluate_benign_indicators(item)
    if benign.get("is_likely_benign") and not families and not suspicious_imports and not av_blocked and not behavior["executed"]:
        score = max(0, score - 6)

    final_score = max(0, min(100, score))
    tags = _classify_types(item)

    item.update(
        {
            "static_score_component": max(0, final_score - behavior["score"]),
            "dynamic_score_component": behavior["score"],
            "final_score": final_score,
            "final_verdict": _severity_from_score(final_score),
            "member_runtime": member or {},
            "malware_type_tags": tags,
            "primary_malware_type": (tags or ["unknown"])[0],
            "summary_reasons": list(dict.fromkeys(reasons))[:10],
            "executed": behavior["executed"] or behavior.get("execution_observed"),
            "anti_analysis": behavior.get("anti_analysis") or ctx.get("anti_analysis"),
            "top_evidence": [x["summary"] for x in sorted(evidence, key=lambda e: abs(int(e.get("weight", 0))), reverse=True)[:3]],
            "evidence_items": sorted(evidence, key=lambda e: abs(int(e.get("weight", 0))), reverse=True)[:12],
            "severity": _severity_from_score(final_score),
        }
    )
    return item

def assess_files(static_results: list[dict[str, Any]] | dict[str, Any], dynamic_result: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(static_results, dict):
        items = static_results.get("files") or []
    elif isinstance(static_results, list):
        items = static_results
    else:
        items = []

    rows = [calculate_file_assessment(x, dynamic_result) for x in items if isinstance(x, dict)]
    rows.sort(key=lambda x: (-int(x.get("final_score", 0)), x.get("file", "")))
    return rows


def calculate_score(scored_files: list[dict[str, Any]], dynamic_result: dict[str, Any]) -> dict[str, Any]:
    if not scored_files:
        return {"score": 0, "raw_score": 0, "verdict": "clean"}

    top_scores = [int(x.get("final_score", 0)) for x in scored_files[:3]]
    max_score = max(top_scores)
    avg3 = round(sum(top_scores) / len(top_scores))

    malicious = sum(1 for x in scored_files if x.get("final_verdict") == "malicious")
    suspicious = sum(1 for x in scored_files if x.get("final_verdict") == "suspicious")
    review = sum(1 for x in scored_files if x.get("final_verdict") == "review")

    distribution = min(12, malicious * 4 + suspicious * 2 + review)
    sysmon_summary = dynamic_result.get("sysmon_summary") or {}
    anti_analysis = bool(dynamic_result.get("anti_analysis_signal")) or bool(sysmon_summary.get("anti_analysis_signals"))
    observed = bool(dynamic_result.get("execution_observed")) or bool(sysmon_summary.get("execution_observed"))
    dynamic_bonus = 0
    if int(dynamic_result.get("archive_member_success_count", 0)) > 0:
        dynamic_bonus += 6
    if observed:
        dynamic_bonus += 6
    if anti_analysis:
        dynamic_bonus += 18

    raw = round(max_score * 0.55 + avg3 * 0.20 + distribution + dynamic_bonus)

    if anti_analysis:
        raw = max(raw, MALICIOUS_EXEC_FLOOR)
    elif malicious:
        raw = max(raw, max_score)
    elif suspicious:
        raw = max(raw, 45)

    raw = max(0, min(100, raw))

    return {
        "score": raw,
        "raw_score": raw,
        "verdict": _severity_from_score(raw),
        "file_count": len(scored_files),
        "static_score": max_score,
        "dynamic_score": dynamic_bonus,
        "aggregate_score": distribution,
        "evidence_reasons": [],
        "score_breakdown": {
            "top_file": max_score,
            "top3_average": avg3,
            "distribution": distribution,
            "archive_runtime": dynamic_bonus,
            "benign_penalty": 0,
        },
    }