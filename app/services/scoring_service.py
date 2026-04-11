from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from app.core.config import settings

EXECUTABLE_SUFFIXES = {".exe", ".dll", ".com", ".scr", ".ps1", ".hta", ".vbs", ".wsf", ".js", ".jse", ".bat", ".cmd", ".docm", ".xlsm"}
SCRIPT_SUFFIXES = {".ps1", ".hta", ".vbs", ".wsf", ".js", ".jse", ".bat", ".cmd", ".py", ".sh"}
DOC_SUFFIXES = {".docm", ".xlsm", ".doc", ".docx", ".xls", ".xlsx"}
TEXTISH_SUFFIXES = {".txt", ".md", ".rst", ".csv", ".log", ".json", ".yaml", ".yml"}
SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".cpp", ".cs"}
HIGH_RISK_PROCESS_MARKERS = {"powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32", "mshta", "schtasks", "certutil", "bitsadmin", "wmic", "msbuild", "installutil"}
NETWORK_MARKERS = {"http://", "https://", "ftp://", "downloadstring", "invoke-webrequest", "urlmon", "urldownloadtofile", "bitsadmin", "certutil -urlcache", ".onion"}
PERSISTENCE_MARKERS = {"currentversion\\run", "runonce", "schtasks", "startup", "scheduledtasks", "reg add", "reg.exe add", "service create", "createservice"}
RANSOMWARE_MARKERS = {"vssadmin", "wbadmin", "bcdedit", "ransom", "decrypt", ".locked", ".encrypted", "shadowcopy"}
INJECTION_MARKERS = {"createremotethread", "writeprocessmemory", "virtualalloc", "queueuserapc", "setwindowshookex"}


MALWARE_TYPE_PRIORITY = ["ransomware", "infostealer", "rat", "backdoor", "dropper", "downloader", "loader", "trojan", "persistence", "script"]


def _ordered_unique(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _classify_malware_types(item: dict[str, Any], behavior: dict[str, Any], member: dict[str, Any] | None) -> list[str]:
    tags = set(item.get("tags", []) or [])
    families = set(item.get("suspected_family", []) or [])
    suffix = Path(str(item.get("file") or "")).suffix.lower()
    text = _text_blob(
        item.get("summary_reasons"),
        item.get("yara_matches"),
        item.get("pe"),
        member.get("command") if member else "",
        member.get("stdout_preview") if member else "",
        member.get("stderr_preview") if member else "",
    )

    types: list[str] = []
    if "ransomware" in families or behavior.get("ransomware_signal") or "ransom_note_txt" in tags:
        types.append("ransomware")
    if "infostealer" in families or any(k in text for k in ["login data", "web data", "cookies", "wallet", "token", "metamask", "telegram"]):
        types.append("infostealer")
    if "rat" in families or any(k in text for k in ["reverse shell", "meterpreter", "connectback", "backdoor", "beacon", "c2"]):
        types.append("rat")
    if behavior.get("persistence_signal") or any(k in text for k in ["runonce", "currentversion\run", "schtasks", "service create", "startup"]):
        types.append("persistence")
    if "dropper" in families or (behavior.get("executed") and behavior.get("network_signal") and any(k in text for k in ["download", "temp", "appdata", "payload", "extract dropped files"])):
        types.append("dropper")
    if "downloader" in families or any(k in text for k in ["urldownloadtofile", "invoke-webrequest", "downloadstring", "certutil -urlcache", "bitsadmin", "urlmon"]):
        types.append("downloader")
    if behavior.get("injection_signal") or any(k in text for k in ["createremotethread", "writeprocessmemory", "virtualalloc", "queueuserapc"]):
        types.append("loader")
    if suffix in SCRIPT_SUFFIXES or "script_like_txt" in tags or any(k in text for k in ["powershell", "wscript", "cscript", "mshta", "javascript"]):
        types.append("script")
    if any(k in text for k in ["trojan", "malware", "payload", "dropper-like evidence chain"]) and not types:
        types.append("trojan")
    if not types and (behavior.get("executed") or item.get("yara_matches") or item.get("suspected_family")):
        types.append("trojan")

    ordered = [t for t in MALWARE_TYPE_PRIORITY if t in types]
    for t in types:
        if t not in ordered:
            ordered.append(t)
    return ordered[:4]


def _aggregate_malware_types(scored_files: list[dict[str, Any]], dynamic_result: dict[str, Any]) -> list[str]:
    counts: Counter[str] = Counter()
    for item in scored_files:
        weight = 3 if item.get("final_verdict") == "malicious" else 2 if item.get("final_verdict") == "suspicious" else 1
        for t in item.get("malware_type_tags", [])[:4]:
            counts[t] += weight
    if dynamic_result.get("ransomware_signal"):
        counts["ransomware"] += 4
    if dynamic_result.get("persistence_signal"):
        counts["persistence"] += 2
    if dynamic_result.get("network_signal"):
        counts["downloader"] += 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], MALWARE_TYPE_PRIORITY.index(kv[0]) if kv[0] in MALWARE_TYPE_PRIORITY else 99, kv[0]))
    return [name for name, _ in ranked[:5]]


def normalize_member_path(path_str: str) -> str:
    if not path_str:
        return ""
    raw = str(path_str).replace("\\", "/")
    lowered = raw.lower()
    markers = ["/tmp/sample_ext/", "/extract/", "sandbox_work/", "sandbox_shared/inbox/"]
    for marker in markers:
        idx = lowered.find(marker)
        if idx != -1:
            return raw[idx + len(marker):].lstrip("/")
    return Path(raw).name if ":" in raw else raw.lstrip("/")


def member_result_map(dynamic_result: dict) -> dict[str, dict]:
    mapped: dict[str, dict] = {}
    for item in dynamic_result.get("archive_member_results", []) or []:
        key = normalize_member_path(str(item.get("path") or ""))
        if key and key not in mapped:
            cloned = dict(item)
            cloned["normalized_path"] = key
            mapped[key] = cloned
    return mapped


def _text_blob(*parts: Any) -> str:
    return " ".join(str(p or "") for p in parts).lower()


def _count_present(markers: set[str], text: str) -> int:
    return sum(1 for marker in markers if marker in text)


def _severity_from_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "review"
    return "clean"


def _member_behavior(member_result: dict | None) -> dict[str, Any]:
    if not member_result:
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
        }
    text = _text_blob(member_result.get("command"), member_result.get("stdout_preview"), member_result.get("stderr_preview"))
    network_hits = _count_present(NETWORK_MARKERS, text)
    persistence_hits = _count_present(PERSISTENCE_MARKERS, text)
    ransomware_hits = _count_present(RANSOMWARE_MARKERS, text)
    injection_hits = _count_present(INJECTION_MARKERS, text)
    exec_hits = _count_present(HIGH_RISK_PROCESS_MARKERS, text)
    score = 0
    reasons: list[str] = []
    executed = not bool(member_result.get("skipped"))
    if executed:
        score += 8
        reasons.append("executed in sandbox")
    if exec_hits:
        score += min(12, 4 + exec_hits * 2)
        reasons.append("suspicious runtime command or process marker")
    if network_hits:
        score += min(16, 6 + network_hits * 2)
        reasons.append("runtime download or remote communication marker")
    if persistence_hits:
        score += min(18, 8 + persistence_hits * 2)
        reasons.append("runtime persistence marker")
    if ransomware_hits:
        score += min(24, 12 + ransomware_hits * 3)
        reasons.append("runtime ransomware marker")
    if injection_hits:
        score += min(20, 10 + injection_hits * 2)
        reasons.append("runtime injection or memory tampering marker")
    if bool(member_result.get("timed_out")):
        score += 6
        reasons.append("sandbox execution timed out")
    rc = member_result.get("returncode")
    if rc not in (None, 0, "0") and not bool(member_result.get("timed_out")):
        score += 4
        reasons.append("non-zero exit during execution")
    return {
        "executed": executed,
        "network_signal": network_hits > 0,
        "persistence_signal": persistence_hits > 0,
        "ransomware_signal": ransomware_hits > 0,
        "execution_signal": exec_hits > 0,
        "injection_signal": injection_hits > 0,
        "timed_out": bool(member_result.get("timed_out")),
        "nonzero_exit": rc not in (None, 0, "0"),
        "score": min(score, 45),
        "reasons": reasons,
    }


def _reverse_plan(static_item: dict, member_result: dict | None, behavior: dict[str, Any]) -> dict[str, Any]:
    tags = set(static_item.get("tags", []) or [])
    families = set(static_item.get("suspected_family", []) or [])
    yara_hits = [m for m in static_item.get("yara_matches", []) if not str(m).startswith("yara_error:")]
    pe = static_item.get("pe", {}) or {}
    suspicious_imports = pe.get("suspicious_imports", []) or []
    entropy = float(static_item.get("entropy") or 0.0)
    path = normalize_member_path(static_item.get("file", ""))
    suffix = Path(path).suffix.lower()
    triggers: list[str] = []
    recommended_tools: list[str] = []
    stage = "static_only"

    if behavior.get("ransomware_signal"):
        triggers.append("runtime ransomware signal")
    if behavior.get("persistence_signal"):
        triggers.append("runtime persistence signal")
    if behavior.get("network_signal"):
        triggers.append("runtime remote communication signal")
    if behavior.get("injection_signal"):
        triggers.append("runtime injection signal")
    if entropy >= float(settings.entropy_threshold):
        triggers.append("high entropy or packed-like content")
    if "script_obfuscation" in tags or "packed_or_obfuscated" in tags:
        triggers.append("obfuscation marker")
    if yara_hits:
        triggers.append("YARA match")
    if suspicious_imports:
        triggers.append("suspicious PE imports")
    if families:
        triggers.append("family hint: " + ", ".join(sorted(families)[:2]))
    if suffix in {".docm", ".xlsm"}:
        triggers.append("macro-capable document")

    if behavior.get("ransomware_signal") or behavior.get("persistence_signal") or behavior.get("network_signal") or behavior.get("injection_signal"):
        stage = "dynamic_then_targeted_reverse"
        recommended_tools = [
            "extract dropped files",
            "inspect runtime stdout/stderr",
            "disassemble executed member",
            "review process tree and network trace",
        ]
    elif yara_hits or suspicious_imports or entropy >= float(settings.entropy_threshold) or "script_obfuscation" in tags or families:
        stage = "targeted_reverse"
        recommended_tools = [
            "strings and config extraction",
            "deobfuscate script or payload",
            "PE import and section review",
        ]
    elif suffix in EXECUTABLE_SUFFIXES or suffix in DOC_SUFFIXES:
        stage = "light_reverse_if_needed"
        recommended_tools = ["basic strings review", "header or import inspection"]
    else:
        recommended_tools = ["static triage only"]

    if suffix in SCRIPT_SUFFIXES and stage != "static_only":
        recommended_tools.append("pretty-print or deobfuscate script")
    if suffix in {".exe", ".dll", ".com", ".scr"} and stage != "static_only":
        recommended_tools.append("Ghidra or Cutter triage")

    return {
        "stage": stage,
        "triggers": triggers[:6],
        "recommended_tools": recommended_tools[:6],
        "capesandbox_inspiration": "process tree + dropped files + network + targeted payload or config extraction",
    }


def calculate_file_assessment(static_item: dict, dynamic_result: dict) -> dict[str, Any]:
    item = dict(static_item)
    path = normalize_member_path(item.get("file", ""))
    item["file"] = path
    suffix = Path(path).suffix.lower()
    tags = set(item.get("tags", []) or [])
    iocs = item.get("iocs", {}) or {}
    families = set(item.get("suspected_family", []) or [])
    yara_hits = [m for m in item.get("yara_matches", []) if not str(m).startswith("yara_error:")]
    pe = item.get("pe", {}) or {}
    suspicious_imports = pe.get("suspicious_imports", []) or []
    medium_imports = pe.get("medium_imports", []) or []
    entropy = float(item.get("entropy") or 0.0)
    ioc_count = sum(len(iocs.get(k, []) or []) for k in ["urls", "domains", "ips", "emails"])
    member = member_result_map(dynamic_result).get(path)
    behavior = _member_behavior(member)

    reasons: list[str] = []
    breakdown = {
        "extension": 0,
        "yara": 0,
        "family": 0,
        "imports": 0,
        "ioc": 0,
        "obfuscation": 0,
        "keywords": 0,
        "dynamic": behavior["score"],
    }

    if suffix in {".exe", ".dll", ".com", ".scr"}:
        breakdown["extension"] += 4
    elif suffix in SCRIPT_SUFFIXES:
        breakdown["extension"] += 3
    elif suffix in {".docm", ".xlsm"}:
        breakdown["extension"] += 4
    elif suffix in TEXTISH_SUFFIXES:
        breakdown["extension"] += 1

    if len(yara_hits) >= 2:
        breakdown["yara"] += 20
        reasons.append(f"YARA matches: {len(yara_hits)}")
    elif len(yara_hits) == 1:
        breakdown["yara"] += 12
        reasons.append("single YARA match")

    high_families = families & {"ransomware", "infostealer", "dropper", "rat", "downloader"}
    if "ransomware" in high_families:
        breakdown["family"] += 20
        reasons.append("ransomware family indicator")
    elif high_families:
        breakdown["family"] += 14
        reasons.append("malware family indicator")

    if len(suspicious_imports) >= 2:
        breakdown["imports"] += 16
        reasons.append("multiple suspicious PE imports")
    elif len(suspicious_imports) == 1:
        breakdown["imports"] += 10
        reasons.append("suspicious PE import")
    elif medium_imports:
        breakdown["imports"] += 4

    if ioc_count >= 4:
        breakdown["ioc"] += 12
        reasons.append("multiple external IOCs")
    elif ioc_count >= 2:
        breakdown["ioc"] += 8
        reasons.append("external IOC present")
    elif ioc_count == 1:
        breakdown["ioc"] += 4

    if "script_obfuscation" in tags or "packed_or_obfuscated" in tags:
        breakdown["obfuscation"] += 10
        reasons.append("obfuscation marker")
    elif "light_obfuscation" in tags or entropy >= float(settings.entropy_threshold):
        breakdown["obfuscation"] += 6
        reasons.append("packed-like or elevated entropy")

    keyword_hits = 0
    if any(tag in tags for tag in ["powershell", "downloadstring", "invoke-webrequest", "createremotethread", "writeprocessmemory", "mimikatz", "cmd.exe"]):
        keyword_hits += 1
    if "ioc_present" in tags or "medium_risk_imports" in tags:
        keyword_hits += 1
    if keyword_hits >= 2:
        breakdown["keywords"] += 10
    elif keyword_hits == 1:
        breakdown["keywords"] += 5

    static_score = sum(v for k, v in breakdown.items() if k != "dynamic")
    raw_score = min(100, static_score + breakdown["dynamic"])

    if suffix in TEXTISH_SUFFIXES and not high_families and not yara_hits and breakdown["dynamic"] == 0:
        raw_score = min(raw_score, 18)
    if suffix in SOURCE_SUFFIXES and not high_families and not yara_hits and breakdown["dynamic"] == 0:
        raw_score = min(raw_score, 15)
    if item.get("developer_artifact") and breakdown["dynamic"] == 0 and not high_families:
        raw_score = min(raw_score, 10)
    if behavior.get("ransomware_signal") or (behavior.get("network_signal") and behavior.get("persistence_signal")):
        raw_score = max(raw_score, 72)
    if "ransom_note_txt" in tags and breakdown["dynamic"] == 0:
        raw_score = max(raw_score, 35)
    if "script_like_txt" in tags and breakdown["dynamic"] == 0:
        raw_score = max(raw_score, 42)

    final_score = min(100, raw_score)
    final_verdict = _severity_from_score(final_score)
    if behavior["reasons"]:
        reasons.extend(behavior["reasons"])
    reverse_plan = _reverse_plan(item, member, behavior)
    malware_type_tags = _classify_malware_types(item, behavior, member)
    summary_reasons = (list(dict.fromkeys((item.get("summary_reasons") or []) + reasons)))[:10]

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

    item.update(
        {
            "static_score_component": min(100, static_score),
            "dynamic_score_component": behavior["score"],
            "final_score": final_score,
            "final_verdict": final_verdict,
            "score_breakdown_detail": breakdown,
            "member_runtime": member or None,
            "reverse_plan": reverse_plan,
            "malware_type_tags": malware_type_tags,
            "primary_malware_type": malware_type_tags[0] if malware_type_tags else "unknown",
            "summary_reasons": summary_reasons,
            "executed": bool(behavior.get("executed")),
            "fail_reason": fail_reason,
            "top_evidence": summary_reasons[:3],
        }
    )
    if final_score >= 70:
        item["severity"] = "high"
    elif final_score >= 40:
        item["severity"] = "medium"
    else:
        item["severity"] = "low"
    return item


def assess_files(static_results: list[dict], dynamic_result: dict) -> list[dict]:
    enriched = [calculate_file_assessment(item, dynamic_result) for item in static_results]
    enriched.sort(key=lambda x: (-int(x.get("final_score") or 0), str(x.get("file") or "").lower()))
    return enriched


def _top_reasons(files: list[dict], dynamic_result: dict) -> list[str]:
    counter: Counter[str] = Counter()
    for item in files[:12]:
        weight = 4 if item.get("final_verdict") == "malicious" else 2 if item.get("final_verdict") == "suspicious" else 1
        for reason in item.get("summary_reasons", [])[:6]:
            counter[str(reason)] += weight
    if dynamic_result.get("network_signal"):
        counter["archive-level network activity observed"] += 4
    if dynamic_result.get("persistence_signal"):
        counter["archive-level persistence activity observed"] += 4
    if dynamic_result.get("ransomware_signal"):
        counter["archive-level ransomware behavior observed"] += 5
    if dynamic_result.get("exec_signal"):
        counter["sandbox execution completed for at least one member"] += 2
    return [reason for reason, _ in counter.most_common(12)]


def calculate_score(scored_files: list[dict], dynamic_result: dict) -> dict[str, Any]:
    if not scored_files:
        return {
            "score": 0,
            "raw_score": 0,
            "verdict": "clean",
            "file_count": 0,
            "static_score": 0,
            "dynamic_score": 0,
            "aggregate_score": 0,
            "developer_heavy": False,
            "strong_override": False,
            "dynamic_skipped": False,
            "high_confidence_files": 0,
            "high_severity_files": 0,
            "malicious_static_bundle": False,
            "evidence_reasons": [],
            "score_breakdown": {"top_file": 0, "top3_average": 0, "distribution": 0, "archive_runtime": 0},
        }

    top_scores = [int(item.get("final_score") or 0) for item in scored_files[:3]]
    max_score = top_scores[0]
    top3_avg = round(sum(top_scores) / len(top_scores)) if top_scores else 0
    malicious_count = sum(1 for item in scored_files if item.get("final_verdict") == "malicious")
    suspicious_count = sum(1 for item in scored_files if item.get("final_verdict") == "suspicious")
    review_count = sum(1 for item in scored_files if item.get("final_verdict") == "review")

    dynamic_bonus = 0
    if dynamic_result.get("network_signal"):
        dynamic_bonus += 8
    if dynamic_result.get("persistence_signal"):
        dynamic_bonus += 10
    if dynamic_result.get("ransomware_signal"):
        dynamic_bonus += 15
    if dynamic_result.get("exec_signal"):
        dynamic_bonus += 4
    if dynamic_result.get("timed_out"):
        dynamic_bonus += 2

    distribution = min(15, malicious_count * 5 + suspicious_count * 3 + review_count)
    raw_score = min(100, round(max_score * 0.65 + top3_avg * 0.20 + distribution + dynamic_bonus))
    strong_override = bool(dynamic_result.get("ransomware_signal")) or (dynamic_result.get("network_signal") and dynamic_result.get("persistence_signal")) or malicious_count >= 2
    if strong_override:
        raw_score = max(raw_score, 72)
    verdict = _severity_from_score(raw_score)
    developer_heavy = all(Path(str(item.get("file") or "")).suffix.lower() in (TEXTISH_SUFFIXES | SOURCE_SUFFIXES) for item in scored_files) and raw_score < 20

    return {
        "score": raw_score,
        "raw_score": raw_score,
        "verdict": verdict,
        "file_count": len(scored_files),
        "static_score": max_score,
        "dynamic_score": dynamic_bonus,
        "aggregate_score": distribution,
        "developer_heavy": developer_heavy,
        "strong_override": strong_override,
        "dynamic_skipped": any(bool((item.get("member_runtime") or {}).get("skipped")) for item in scored_files if item.get("member_runtime")),
        "high_confidence_files": malicious_count,
        "high_severity_files": malicious_count + suspicious_count,
        "malicious_static_bundle": malicious_count > 0,
        "evidence_reasons": _top_reasons(scored_files, dynamic_result),
        "malware_type_tags": _aggregate_malware_types(scored_files, dynamic_result),
        "primary_malware_type": (_aggregate_malware_types(scored_files, dynamic_result)[0] if _aggregate_malware_types(scored_files, dynamic_result) else "unknown"),
        "score_breakdown": {
            "top_file": max_score,
            "top3_average": top3_avg,
            "distribution": distribution,
            "archive_runtime": dynamic_bonus,
        },
    }
