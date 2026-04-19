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


def _evidence_entry(category: str, signal: str, weight: int, source: str, detail: str) -> dict[str, Any]:
    return {
        "category": category,
        "signal": signal,
        "weight": weight,
        "source": source,
        "detail": detail,
        "summary": f"[{category}] {signal}: {detail}",
    }


def _member_behavior(member: dict[str, Any] | None, path: str) -> dict[str, Any]:
    if not member:
        return {
            "executed": False,
            "network_signal": False,
            "persistence_signal": False,
            "ransomware_signal": False,
            "execution_signal": False,
            "injection_signal": False,
            "timed_out": False,
            "nonzero_exit": False,
            "score": 0,
            "reasons": [],
            "evidence_items": [],
        }
      

    text = _text_blob(member.get("stdout_preview"), member.get("stderr_preview"))
    command_text = _text_blob(member.get("command"))
    package = str(member.get("package") or "")
    network_hits = _count_present(NETWORK_MARKERS, text)
    persistence_hits = _count_present(PERSISTENCE_MARKERS, text)
    ransomware_hits = _count_present(RANSOMWARE_MARKERS, text)
    injection_hits = _count_present(INJECTION_MARKERS, text)
    exec_hits = _count_present(HIGH_RISK_PROCESS_MARKERS, text)
    if package not in DOCUMENT_PACKAGES:
        exec_hits = max(exec_hits, _count_present(HIGH_RISK_PROCESS_MARKERS, command_text))
    score = 0
    reasons: list[str] = []
    evidence_items: list[dict[str, Any]] = []
    executed = bool(member.get("succeeded"))
    returncode = member.get("returncode")
    timed_out = bool(member.get("timed_out"))
    if executed:
        base_pts = 6 if package in DOCUMENT_PACKAGES else 10
        score += base_pts
        reasons.append("executed in sandbox")
        evidence_items.append(_evidence_entry("dynamic", "sandbox_execution", base_pts, path, "archive member executed inside sandbox", "medium"))
    if exec_hits and package not in DOCUMENT_PACKAGES:
        pts = min(14, 4 + exec_hits * 2)
        score += pts
        reasons.append("suspicious runtime command or process marker")
        evidence_items.append(_evidence_entry("dynamic", "suspicious_runtime_process", pts, path, f"high-risk runtime markers observed ({exec_hits})", "high"))
    if network_hits:
        pts = min(18, 6 + network_hits * 2)
        score += pts
        reasons.append("runtime download or remote communication marker")
        evidence_items.append(_evidence_entry("dynamic", "network_or_download", pts, path, f"remote communication or download marker count={network_hits}", "high"))
    if persistence_hits:
        pts = min(20, 8 + persistence_hits * 2)
        score += pts
        reasons.append("runtime persistence marker")
        evidence_items.append(_evidence_entry("dynamic", "persistence", pts, path, f"autorun/service/task marker count={persistence_hits}", "critical"))
    if ransomware_hits:
        pts = min(24, 12 + ransomware_hits * 3)
        score += pts
        reasons.append("runtime ransomware marker")
        evidence_items.append(_evidence_entry("dynamic", "ransomware_behavior", pts, path, f"destructive or ransom-related marker count={ransomware_hits}", "critical"))
    if injection_hits:
        pts = min(20, 8 + injection_hits * 2)
        score += pts
        reasons.append("runtime injection or memory tampering marker")
        evidence_items.append(_evidence_entry("dynamic", "process_injection", pts, path, f"injection marker count={injection_hits}", "critical"))
    if timed_out:
        score += 4
        reasons.append("sandbox execution timed out")
        evidence_items.append(_evidence_entry("dynamic", "timeout", 4, path, "sandbox run hit timeout", "medium"))
    if returncode not in (None, 0, "0") and not timed_out:
        score += 3
        reasons.append("non-zero exit during execution")
        evidence_items.append(_evidence_entry("dynamic", "nonzero_exit", 3, path, f"process exited with return code {returncode}", "medium"))
    if network_hits > 0 and persistence_hits > 0:
        score += 25
        reasons.append("C2 + Persistence chain detected")
        evidence_items.append(_evidence_entry(
            "dynamic",
            "c2_persistence_chain",
            25,
            path,
            "network + persistence behavior observed together",
            "critical"
        ))
    # Ransomware + 실행
    if ransomware_hits > 0 and executed:
        score += 40
        reasons.append("Active ransomware execution")
        evidence_items.append(_evidence_entry(
            "dynamic",
            "active_ransomware",
            40,
            path,
            "ransomware behavior detected during execution",
            "critical"
        ))
    return {
        "executed": executed,
        "network_signal": network_hits > 0,
        "persistence_signal": persistence_hits > 0,
        "ransomware_signal": ransomware_hits > 0,
        "execution_signal": exec_hits > 0 and package not in DOCUMENT_PACKAGES,
        "injection_signal": injection_hits > 0,
        "timed_out": timed_out,
        "nonzero_exit": returncode not in (None, 0, "0"),
        "score": min(score, 70),
        "reasons": reasons,
        "evidence_items": evidence_items,
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
    runtime_ms = int(member.get("runtime_ms", 0)) if member else 0
    
    breakdown = {
      "imports": 0,
      "ioc": 0,
      "obfuscation": 0,
      "keywords": 0,
      "dynamic": behavior["score"]
    }

    reasons: list[str] = []
    evidence_items: list[dict[str, Any]] = []

    if suspicious_imports:
        breakdown["imports"] += 10
        reasons.append("suspicious PE import")
        evidence_items.append(_evidence_entry(
            "static",
            "suspicious_import",
            10,
            path,
            suspicious_imports[0],
            "high"
        ))
    elif medium_imports:
        breakdown["imports"] += 3
    
    tags = item.get("tags", [])
    ioc_count = len(item.get("iocs", {}).get("urls", []))
    high_families = bool(families)

    if ioc_count >= 4:
        breakdown["ioc"] += 8
        reasons.append("multiple external IOCs")
        evidence_items.append(_evidence_entry("static", "multiple_iocs", 8, path, f"found {ioc_count} external IOC values", "medium"))
    elif ioc_count >= 2:
        breakdown["ioc"] += 5
        reasons.append("external IOC present")
        evidence_items.append(_evidence_entry("static", "external_ioc", 5, path, f"found {ioc_count} IOC values", "medium"))
    elif ioc_count == 1:
        breakdown["ioc"] += 2

    if "script_obfuscation" in tags or "packed_or_obfuscated" in tags:
        breakdown["obfuscation"] += 6
        reasons.append("obfuscation marker")
        evidence_items.append(_evidence_entry("static", "obfuscation", 8, path, "strong obfuscation or packing marker", "medium"))
    elif "light_obfuscation" in tags or entropy >= float(settings.entropy_threshold):
        breakdown["obfuscation"] += 3
        reasons.append("packed-like or elevated entropy")
        evidence_items.append(_evidence_entry("static", "elevated_entropy", 4, path, "entropy above threshold or light obfuscation", "low"))

    keyword_hits = 0
    keyword_details = []
    if any(tag in tags for tag in ["powershell", "downloadstring", "invoke-webrequest", "createremotethread", "writeprocessmemory", "mimikatz", "cmd.exe"]):
        keyword_hits += 1
        keyword_details.append("strong malware keyword")
    if "ioc_present" in tags or "medium_risk_imports" in tags:
        keyword_hits += 1
        keyword_details.append("medium risk static marker")
    if keyword_hits >= 2:
        breakdown["keywords"] += 4
        evidence_items.append(_evidence_entry("static", "keyword_cluster", 6, path, "; ".join(keyword_details), "medium"))
    elif keyword_hits == 1:
        breakdown["keywords"] += 2

    static_score = sum(v for k, v in breakdown.items() if k != "dynamic")
    raw_score = min(100, static_score + breakdown["dynamic"])

    if behavior.get("executed") and behavior.get("network_signal"):
        raw_score += 15
        reasons.append("Executed file with network activity")
    if behavior.get("executed") and behavior.get("persistence_signal"):
        raw_score += 20
        reasons.append("Executed file establishing persistence")
    if suffix in TEXTISH_SUFFIXES and not high_families and not yara_hits and breakdown["dynamic"] == 0:
        raw_score = min(raw_score, 16)
    if suffix in SOURCE_SUFFIXES and not high_families and not yara_hits and breakdown["dynamic"] == 0:
        raw_score = min(raw_score, 12)
    if item.get("developer_artifact") and breakdown["dynamic"] == 0 and not high_families:
        raw_score = min(raw_score, 8)
    if behavior.get("ransomware_signal") or (behavior.get("network_signal") and behavior.get("persistence_signal")):
        raw_score = max(raw_score, 75)
    if behavior.get("injection_signal") and behavior.get("executed"):
        raw_score = max(raw_score, 68)
    if "ransom_note_txt" in tags and breakdown["dynamic"] == 0:
        raw_score = max(raw_score, 28)
    if "script_like_txt" in tags and breakdown["dynamic"] == 0:
        raw_score = max(raw_score, 35)

    if member and member.get("succeeded") and suffix == ".exe":
        raw_score += 8
        reasons.append("successful PE execution")
        evidence_items.append(_evidence_entry("dynamic", "successful_pe_execution", 8, path, "portable executable completed in sandbox", "high"))
        if runtime_ms >= 10000:
            raw_score += 8
            reasons.append("sustained runtime observed")
            evidence_items.append(_evidence_entry("dynamic", "sustained_runtime", 8, path, f"runtime {runtime_ms} ms", "high"))
        if runtime_ms >= 30000:
            raw_score += 4
            evidence_items.append(_evidence_entry("dynamic", "long_runtime", 4, path, f"extended runtime {runtime_ms} ms", "medium"))
    if member and member.get("succeeded") and suffix in SCRIPT_SUFFIXES:
        raw_score += 4
    if suffix == ".exe" and member and member.get("succeeded") and (high_families or suspicious_imports or "packed_or_obfuscated" in tags):
        raw_score = max(raw_score, 45)
        
    test_indicator = False
    benign_info = {"is_likely_benign": False, "benign_hits": [], "benign_strength": 0}
   
    skip_reason = str(member.get("skip_reason") or "").lower() if member else ""
    av_blocked = "winerror 225" in skip_reason or "virus" in skip_reason

    if test_indicator and breakdown["dynamic"] == 0:
        raw_score = min(raw_score, 22)
    elif test_indicator and breakdown["dynamic"] > 0:
        raw_score = max(0, raw_score - 8)

    benign_hits = benign_info.get("benign_hits") or []
    if benign_info.get("is_likely_benign") and breakdown["dynamic"] == 0 and not high_families and not yara_hits:
        penalty = 6 + int(benign_info.get("benign_strength") or 0) * 3
        raw_score = max(0, raw_score - penalty)
        reasons.append("benign development/package indicator")
        evidence_items.append(_evidence_entry("benign_hint", "benign_whitelist", -penalty, path, "; ".join(benign_hits[:4]), "low"))

    final_score = min(100, raw_score)
    final_verdict = _severity_from_score(final_score)
    if behavior["reasons"]:
        reasons.extend(behavior["reasons"])
    evidence_items.extend(behavior["evidence_items"])
    reverse_plan = _reverse_plan(item, member, behavior)
    malware_type_tags = _classify_malware_types(item, behavior, member)
    summary_reasons = (list(dict.fromkeys((item.get("summary_reasons") or []) + reasons)))[:10]
    evidence_items = sorted(evidence_items, key=lambda e: abs(int(e.get("weight") or 0)), reverse=True)

    fail_reason = None
    if member:
        if member.get("skipped"):
            skip_reason = str(member.get("skip_reason") or member.get("fail_reason") or "skipped")
            fail_reason = "not_executable" if skip_reason == "unsupported_extension" else skip_reason
        elif member.get("timed_out"):
            fail_reason = "timeout"
        elif member.get("returncode") not in (None, 0, "0"):
            fail_reason = "nonzero_exit"
    elif suffix not in EXECUTABLE_SUFFIXES and suffix not in DOC_SUFFIXES:
        fail_reason = "not_executable"
    elif suffix in DOC_SUFFIXES:
        fail_reason = "document_execution_not_supported"
    else:
        fail_reason = "not_selected_for_execution"


    suspicious_static_combo = bool(suspicious_imports) and entropy >= float(getattr(settings, "entropy_threshold", 7.2) or 7.2)
    suspicious_signal = suspicious_static_combo or bool(families) or bool(yara_hits)

    if suffix == ".exe" and behavior["executed"] and suspicious_signal:
        raw_score = max(raw_score, SUSPICIOUS_EXEC_FLOOR)

    if suffix == ".exe" and families and suspicious_imports and entropy >= float(getattr(settings, "entropy_threshold", 7.2) or 7.2) and av_blocked:
        raw_score = max(raw_score, 72)
        reasons.append("av-blocked malicious execution candidate")
        evidence_items.append(_evidence_entry("dynamic", "av_blocked_malware_candidate", 32, path, "AV blocked suspicious executable during execution attempt"))

    benign = evaluate_benign_indicators(item)
    if benign.get("is_likely_benign") and not families and not suspicious_imports and not av_blocked and not behavior["executed"]:
        raw_score = max(0, raw_score - 6)

    final_score = max(0, min(100, raw_score))


    item.update(
        {
            "static_score_component": max(0, final_score - behavior["score"]),
            "dynamic_score_component": behavior["score"],
            "final_score": final_score,
            "final_verdict": _severity_from_score(final_score),
            "member_runtime": member or {},
            "malware_type_tags": malware_type_tags,
            "primary_malware_type": (tags or ["unknown"])[0],
            "summary_reasons": list(dict.fromkeys(reasons))[:10],
            "executed": behavior["executed"],
            "top_evidence": [x["summary"] for x in sorted(evidence_items, key=lambda e: abs(int(e.get("weight", 0))), reverse=True)[:3]],
            "evidence_items": sorted(evidence_items, key=lambda e: abs(int(e.get("weight", 0))), reverse=True)[:12],
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

    archive_profile = _archive_profile(scored_files, dynamic_result)
    top_scores = [int(item.get("final_score") or item.get("score") or 0) for item in scored_files[:3]]
    max_score = top_scores[0]
    top3_avg = round(sum(top_scores) / len(top_scores)) if top_scores else 0
    malicious_count = sum(1 for item in scored_files if (item.get("final_verdict") or _severity_from_score(int(item.get("final_score") or item.get("score") or 0))) == "malicious")
    suspicious_count = sum(1 for item in scored_files if (item.get("final_verdict") or _severity_from_score(int(item.get("final_score") or item.get("score") or 0))) == "suspicious")
    review_count = sum(1 for item in scored_files if (item.get("final_verdict") or _severity_from_score(int(item.get("final_score") or item.get("score") or 0))) == "review")

    dynamic_bonus = 0
    network_strength, linked_endpoints = _network_signal_strength(dynamic_result)
    if network_strength == 2:
        dynamic_bonus += 10
    elif network_strength == 1:
        dynamic_bonus += 3
    if dynamic_result.get("persistence_signal"):
        dynamic_bonus += 14
    if dynamic_result.get("ransomware_signal"):
        dynamic_bonus += 18
    if dynamic_result.get("exec_signal"):
        dynamic_bonus += 5
    if int(dynamic_result.get("archive_member_exec_count", 0) or 0) > 0:
        dynamic_bonus += 6
    if _interesting_created_details(dynamic_result):
        dynamic_bonus += min(6, 2 + len(_interesting_created_details(dynamic_result)))
    if dynamic_result.get("timed_out"):
        dynamic_bonus += 2

    distribution = min(12, malicious_count * 4 + suspicious_count * 2 + review_count)
    pre_penalty_score = min(100, round(max_score * 0.45 + top3_avg * 0.15 + distribution + dynamic_bonus))
    benign_penalty = int(archive_profile.get("benign_penalty") or 0)
    raw_score = max(0, pre_penalty_score - benign_penalty)
    if dynamic_result.get("ransomware_signal"):
        raw_score = max(raw_score, 85)
    if dynamic_result.get("persistence_signal") and dynamic_result.get("network_signal"):
        raw_score = max(raw_score, 75)
    strong_override = bool(dynamic_result.get("ransomware_signal")) or ((network_strength == 2) and dynamic_result.get("persistence_signal")) or malicious_count >= 2
    if strong_override:
        raw_score = max(raw_score, 72)
    if archive_profile.get("developer_heavy") and not strong_override and malicious_count == 0 and suspicious_count == 0:
        raw_score = min(raw_score, 18)
    verdict = _severity_from_score(raw_score)
    developer_heavy = bool(archive_profile.get("developer_heavy"))
    evidence_list = _aggregate_evidence_list(scored_files, dynamic_result, archive_profile)
    family_info = classify_family(scored_files, dynamic_result)


    return {
        "score": raw_score,
        "raw_score": raw_score,
        "verdict": verdict,
        "file_count": len(scored_files),
        "static_score": max_score,
        "dynamic_score": dynamic_bonus,
        "aggregate_score": distribution,
        "evidence_reasons": [],
        "score_breakdown": {
            "top_file": max_score,
            "top3_average": top3_avg,
            "distribution": distribution,
            "archive_runtime": dynamic_bonus,
            "benign_penalty": 0,
        },
    }