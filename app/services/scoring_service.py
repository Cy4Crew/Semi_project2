from __future__ import annotations

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
HIGH_RISK_PROCESS_MARKERS = {"powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32", "mshta", "schtasks", "certutil", "bitsadmin", "wmic", "msbuild", "installutil"}
NETWORK_MARKERS = {"http://", "https://", "ftp://", "downloadstring", "invoke-webrequest", "urlmon", "urldownloadtofile", "bitsadmin", "certutil -urlcache", ".onion"}
PERSISTENCE_MARKERS = {"currentversion\\run", "runonce", "schtasks", "startup", "scheduledtasks", "reg add", "reg.exe add", "service create", "createservice"}
RANSOMWARE_MARKERS = {"vssadmin", "wbadmin", "bcdedit", "ransom", "decrypt", ".locked", ".encrypted", "shadowcopy"}
INJECTION_MARKERS = {"createremotethread", "writeprocessmemory", "virtualalloc", "queueuserapc", "setwindowshookex"}

MALWARE_TYPE_PRIORITY = ["ransomware", "infostealer", "rat", "backdoor", "dropper", "downloader", "loader", "trojan", "persistence", "script"]

ARTIFACT_BASENAMES = {"stdout.txt", "stderr.txt"}
DOCUMENT_PACKAGES = {"office_macro", "office_document", "pdf", "shortcut"}

def _is_artifact_output_path(path: str) -> bool:
    lowered = str(path or "").replace("/", "\\").lower()
    name = Path(lowered).name
    if name.endswith("_stdout.txt") or name.endswith("_stderr.txt"):
        return True
    if "\\artifacts\\" in lowered and name.endswith(".txt"):
        return True
    return False


def _interesting_created_details(dynamic_result: dict[str, Any]) -> list[dict[str, Any]]:
    items = []
    for entry in ((dynamic_result.get("filesystem_delta") or {}).get("created_details") or []):
        path = str(entry.get("path") or "")
        if _is_artifact_output_path(path):
            continue
        items.append(entry)
    return items


def _network_signal_strength(dynamic_result: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    endpoints = []
    for row in ((dynamic_result.get("network_trace") or {}).get("endpoints") or []):
        try:
            pid = int(row.get("pid") or 0)
        except Exception:
            pid = 0
        ip = str(row.get("remote_ip") or "")
        if not ip:
            continue
        if pid > 0:
            endpoints.append(dict(row))
    if endpoints:
        return 2, endpoints
    fallback = []
    for row in ((dynamic_result.get("network_trace") or {}).get("endpoints") or []):
        ip = str(row.get("remote_ip") or "")
        if ip:
            fallback.append(dict(row))
    return (1 if fallback else 0), fallback


def _member_runtime_ms(dynamic_result: dict[str, Any], path: str) -> int:
    wanted = normalize_member_path(path)
    current_member = None
    started = None
    duration = 0
    for event in dynamic_result.get("timeline", []) or []:
        if event.get("event") == "member_start":
            current_member = normalize_member_path(str(event.get("member") or ""))
            started = event.get("ts")
        elif event.get("event") == "member_end":
            member = normalize_member_path(str(event.get("member") or ""))
            if member == wanted:
                try:
                    duration = int(event.get("duration_ms") or 0)
                except Exception:
                    duration = 0
                break
    return duration


def _contains_test_indicator(item: dict[str, Any]) -> bool:
    text = _text_blob(item.get("file"), item.get("summary_reasons"), item.get("tags"), item.get("iocs"), item.get("base64_decoded_snippets"))
    return any(marker in text for marker in ["example.invalid", "benign test", "safe_malware_test_samples"])


def _ordered_unique(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


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


def _evidence_entry(category: str, signal: str, weight: int, source: str, detail: str, severity: str = "medium") -> dict[str, Any]:
    return {
        "category": category,
        "signal": signal,
        "weight": int(weight),
        "source": source,
        "detail": detail,
        "severity": severity,
        "summary": f"[{category}] {signal}: {detail}",
    }


def _member_behavior(member_result: dict | None, path: str = "archive") -> dict[str, Any]:
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
            "evidence_items": [],
        }
    text = _text_blob(member_result.get("stdout_preview"), member_result.get("stderr_preview"))
    command_text = _text_blob(member_result.get("command"))
    package = str(member_result.get("package") or "")
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
    executed = bool(member_result.get("succeeded"))
    returncode = member_result.get("returncode")
    timed_out = bool(member_result.get("timed_out"))
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
        "score": min(score, 55),
        "reasons": reasons,
        "evidence_items": evidence_items,
    }


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
    if behavior.get("persistence_signal") or any(k in text for k in ["runonce", "currentversion\\run", "schtasks", "service create", "startup"]):
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
        triggers.append("high entropy or packing signal")
    if suspicious_imports:
        triggers.append("suspicious PE imports")
    if yara_hits:
        triggers.append("YARA hit")
    if families:
        triggers.append("malware family hint")

    if behavior.get("executed"):
        stage = "dynamic_runtime"
        recommended_tools.extend(["Procmon or API monitor", "PCAP review", "strings on dropped files"])
    elif suffix in {".exe", ".dll", ".com", ".scr"}:
        stage = "pe_static"
        recommended_tools.extend(["PEStudio", "Detect It Easy", "capa"])
    elif suffix in SCRIPT_SUFFIXES:
        stage = "script_static"
        recommended_tools.extend(["PowerShell deobfuscation", "manual string decoding", "capa-like behavior mapping"])
    elif suffix in DOC_SUFFIXES:
        stage = "document_static"
        recommended_tools.extend(["OLE macro extraction", "oletools", "sandbox with Office macro support"])
    elif suffix in TEXTISH_SUFFIXES and ("script_like_txt" in tags or "ransom_note_txt" in tags):
        stage = "text_payload_triage"
        recommended_tools.extend(["extract embedded commands", "IOC clustering", "relationship mapping"])
    else:
        stage = "archive_triage"
        recommended_tools.extend(["archive member prioritization", "manual triage"])

    if member_result and member_result.get("timed_out"):
        recommended_tools.append("increase runtime timeout or inspect stalled process tree")
    if suffix == ".dll":
        recommended_tools.append("export-aware DLL loader or rundll32 entrypoint review")

    return {
        "stage": stage,
        "triggers": _ordered_unique(triggers)[:6],
        "recommended_tools": _ordered_unique(recommended_tools)[:6],
        "notes": {
            "capev2_inspiration": "package-specific execution, dropped files, process tree, and runtime artifacts",
            "capesandbox_inspiration": "process tree + dropped files + network + targeted payload or config extraction",
        },
    }


def _archive_profile(scored_or_static_files: list[dict[str, Any]], dynamic_result: dict[str, Any]) -> dict[str, Any]:
    file_count = len(scored_or_static_files)
    if file_count == 0:
        return {
            "developer_heavy": False,
            "benign_penalty": 0,
            "evidence_items": [],
            "summary": [],
            "family_confidence": "low",
        }
    dev_count = sum(1 for item in scored_or_static_files if item.get("developer_artifact"))
    low_signal_count = 0
    executable_like_count = 0
    suspicious_static_count = 0
    medium_or_higher = 0
    for item in scored_or_static_files:
        suffix = Path(str(item.get("file") or "")).suffix.lower()
        if suffix in LOW_SIGNAL_SUFFIXES:
            low_signal_count += 1
        if suffix in EXECUTABLE_SUFFIXES or suffix in DOC_SUFFIXES:
            executable_like_count += 1
        if item.get("yara_matches") or item.get("suspected_family") or item.get("final_score", 0) >= 40:
            suspicious_static_count += 1
        if item.get("final_score", 0) >= 40:
            medium_or_higher += 1
    executed = int(dynamic_result.get("archive_member_exec_count", 0) or 0)
    network_strength, _ = _network_signal_strength(dynamic_result)
    runtime_signal = bool(network_strength) or any(bool(dynamic_result.get(k)) for k in ["persistence_signal", "ransomware_signal", "exec_signal"])
    developer_heavy = (
        file_count >= 4
        and (dev_count / file_count) >= 0.35
        and (low_signal_count / file_count) >= 0.55
        and executable_like_count <= max(1, file_count // 8)
        and not runtime_signal
        and suspicious_static_count <= max(1, file_count // 6)
        and executed == 0
    )
    evidence_items: list[dict[str, Any]] = []
    benign_penalty = 0
    summary: list[str] = []
    if developer_heavy:
        benign_penalty = 18
        summary.append("developer-heavy archive profile")
        evidence_items.append(_evidence_entry("benign_archive", "developer_heavy_archive", -18, "archive", f"dev_artifacts={dev_count}/{file_count}, low_signal={low_signal_count}/{file_count}, executable_like={executable_like_count}", "low"))
    elif low_signal_count / file_count >= 0.75 and executable_like_count == 0 and not runtime_signal:
        benign_penalty = 10
        summary.append("mostly low-signal text/source archive")
        evidence_items.append(_evidence_entry("benign_archive", "low_signal_archive", -10, "archive", f"low-signal files dominate ({low_signal_count}/{file_count}) with no runtime evidence", "low"))

    if medium_or_higher >= 2 or dynamic_result.get("ransomware_signal") or (dynamic_result.get("network_signal") and dynamic_result.get("persistence_signal")):
        family_confidence = "high"
    elif medium_or_higher >= 1 or suspicious_static_count >= 2 or runtime_signal:
        family_confidence = "medium"
    else:
        family_confidence = "low"
    return {
        "developer_heavy": developer_heavy,
        "benign_penalty": benign_penalty,
        "evidence_items": evidence_items,
        "summary": summary,
        "family_confidence": family_confidence,
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
    behavior = _member_behavior(member, path)
    benign_info = evaluate_benign_indicators(item)
    runtime_ms = _member_runtime_ms(dynamic_result, path)
    test_indicator = _contains_test_indicator(item)

    reasons: list[str] = []
    evidence_items: list[dict[str, Any]] = []
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
        breakdown["extension"] += 2
    elif suffix in SCRIPT_SUFFIXES:
        breakdown["extension"] += 2
    elif suffix in {".docm", ".xlsm"}:
        breakdown["extension"] += 1

    if len(yara_hits) >= 2:
        breakdown["yara"] += 14
        reasons.append(f"YARA matches: {len(yara_hits)}")
        evidence_items.append(_evidence_entry("static", "multiple_yara_hits", 18, path, f"matched {len(yara_hits)} YARA rules", "high"))
    elif len(yara_hits) == 1:
        breakdown["yara"] += 10
        reasons.append("single YARA match")
        evidence_items.append(_evidence_entry("static", "single_yara_hit", 12, path, f"matched YARA rule {yara_hits[0]}", "high"))

    high_families = families & {"ransomware", "infostealer", "dropper", "rat", "downloader"}
    if "ransomware" in high_families:
        breakdown["family"] += 16
        reasons.append("ransomware family indicator")
        evidence_items.append(_evidence_entry("static", "family_ransomware", 14, path, "static family hint points to ransomware", "critical"))
    elif high_families:
        breakdown["family"] += 12
        reasons.append("malware family indicator")
        evidence_items.append(_evidence_entry("static", "family_hint", 10, path, f"family hint(s): {', '.join(sorted(high_families))}", "high"))

    if len(suspicious_imports) >= 2:
        breakdown["imports"] += 10
        reasons.append("multiple suspicious PE imports")
        evidence_items.append(_evidence_entry("static", "suspicious_imports", 10, path, f"multiple high-risk PE imports ({len(suspicious_imports)})", "medium"))
    elif len(suspicious_imports) == 1:
        breakdown["imports"] += 6
        reasons.append("suspicious PE import")
        evidence_items.append(_evidence_entry("static", "single_suspicious_import", 6, path, f"PE import {suspicious_imports[0]}", "medium"))
    elif medium_imports:
        breakdown["imports"] += 3

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
            "top_evidence": [e.get("summary") for e in evidence_items[:3]] or summary_reasons[:3],
            "evidence_items": evidence_items[:12],
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
    network_strength, _ = _network_signal_strength(dynamic_result)
    if network_strength == 2:
        counter["archive-level network activity observed"] += 4
    elif network_strength == 1:
        counter["weak archive-level network activity observed"] += 1
    if dynamic_result.get("persistence_signal"):
        counter["archive-level persistence activity observed"] += 4
    if dynamic_result.get("ransomware_signal"):
        counter["archive-level ransomware behavior observed"] += 5
    if dynamic_result.get("exec_signal"):
        counter["sandbox execution completed for at least one member"] += 2
    return [reason for reason, _ in counter.most_common(12)]


def _aggregate_evidence_list(files: list[dict], dynamic_result: dict, archive_profile: dict[str, Any]) -> list[dict[str, Any]]:
    evidence_items: list[dict[str, Any]] = []
    for item in files[:10]:
        evidence_items.extend(item.get("evidence_items", [])[:6])
    if dynamic_result.get("ransomware_signal"):
        evidence_items.append(_evidence_entry("dynamic", "archive_ransomware_signal", 18, "archive", "archive-level ransomware behavior observed", "critical"))
    if dynamic_result.get("persistence_signal"):
        evidence_items.append(_evidence_entry("dynamic", "archive_persistence_signal", 14, "archive", "archive-level persistence behavior observed", "critical"))
    network_strength, linked_endpoints = _network_signal_strength(dynamic_result)
    if network_strength == 2:
        evidence_items.append(_evidence_entry("dynamic", "archive_network_signal", 10, "archive", f"archive-level network communication observed ({len(linked_endpoints)} linked endpoint(s))", "high"))
    elif network_strength == 1:
        evidence_items.append(_evidence_entry("dynamic", "weak_archive_network_signal", 4, "archive", "unlinked network activity observed during sandbox run", "low"))
    evidence_items.extend(archive_profile.get("evidence_items", []))
    evidence_items = sorted(evidence_items, key=lambda e: abs(int(e.get("weight") or 0)), reverse=True)
    deduped: list[dict[str, Any]] = []
    seen = set()
    for entry in evidence_items:
        key = (entry.get("category"), entry.get("signal"), entry.get("source"), entry.get("detail"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped[:20]


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
            "evidence_list": [],
            "score_breakdown": {"top_file": 0, "top3_average": 0, "distribution": 0, "archive_runtime": 0, "benign_penalty": 0},
            "family_confidence": "low",
        }

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
    if dynamic_result.get("network_signal") and dynamic_result.get("persistence_signal"):
        raw_score = max(raw_score, 75)
    if dynamic_result.get("ransomware_signal"):
        raw_score = max(raw_score, 80)
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
        "developer_heavy": developer_heavy,
        "strong_override": strong_override,
        "dynamic_skipped": any(bool((item.get("member_runtime") or {}).get("skipped")) for item in scored_files if item.get("member_runtime")),
        "high_confidence_files": malicious_count,
        "high_severity_files": malicious_count + suspicious_count,
        "malicious_static_bundle": malicious_count > 0,
        "evidence_reasons": _top_reasons(scored_files, dynamic_result),
        "evidence_list": evidence_list,
        "malware_type_tags": _aggregate_malware_types(scored_files, dynamic_result),
        "primary_malware_type": (_aggregate_malware_types(scored_files, dynamic_result)[0] if _aggregate_malware_types(scored_files, dynamic_result) else "unknown"),
        "score_breakdown": {
            "top_file": max_score,
            "top3_average": top3_avg,
            "distribution": distribution,
            "archive_runtime": dynamic_bonus,
            "benign_penalty": benign_penalty,
        },
        "family_confidence": family_info.get("confidence") or archive_profile.get("family_confidence", "low"),
        "family_matches": family_info.get("family_matches") or [],
        "primary_family": family_info.get("primary_family") or "unknown",
        "archive_profile": archive_profile,
    }
