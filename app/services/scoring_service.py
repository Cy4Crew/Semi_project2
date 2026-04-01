from __future__ import annotations

from collections import Counter
from pathlib import Path

from app.core.config import settings


CRITICAL_TAGS = {
    "downloadstring", "powershell", "invoke-webrequest", "mimikatz", "sekurlsa",
    "lsass", "createremotethread", "writeprocessmemory", "virtualalloc",
    "certutil", "rundll32", "cmd.exe"
}
EXECUTABLE_SUFFIXES = {".exe", ".dll", ".com", ".scr", ".ps1", ".hta", ".vbs", ".wsf", ".js", ".jse", ".bat", ".cmd", ".docm", ".xlsm"}
TEXTISH_SUFFIXES = {".txt", ".md", ".rst", ".csv", ".log", ".json", ".yaml", ".yml", ".yar"}
SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".cpp", ".cs"}
TEST_NAME_MARKERS = {"sample", "samples", "test", "eicar", "readme", "generate_", "yara_bait", "fake_", "benign"}


def _top_reasons(static_results: list[dict], dynamic_result: dict) -> list[str]:
    counter: Counter[str] = Counter()
    for item in static_results:
        sev = str(item.get("severity", "low"))
        weight = 3 if sev == "high" else 2 if sev == "medium" else 1
        for reason in item.get("summary_reasons", [])[:5]:
            if reason and not str(reason).startswith("analysis error"):
                counter[str(reason)] += weight

    if dynamic_result.get("persistence_signal"):
        counter["runtime persistence signal"] += 4
    if dynamic_result.get("network_signal"):
        counter["runtime network signal"] += 3
    if dynamic_result.get("exec_signal"):
        counter["runtime execution signal"] += 2
    if dynamic_result.get("file_signal"):
        counter["runtime filesystem change"] += 2
    if dynamic_result.get("timed_out"):
        counter["runtime timeout observed"] += 1

    return [reason for reason, _ in counter.most_common(8)]


def _looks_like_test_artifact(path_str: str) -> bool:
    lowered = path_str.lower()
    return any(marker in lowered for marker in TEST_NAME_MARKERS)


def calculate_score(static_results: list[dict], dynamic_result: dict):
    file_score = 0
    yara_score = 0
    runtime_score = 0
    ioc_score = 0
    obf_score = 0
    chain_score = 0
    bonus_score = 0
    strong_override = False
    developer_heavy = False

    high_risk_files = 0
    medium_risk_files = 0
    total_yara_hits = 0
    family_hits: set[str] = set()
    critical_tag_count = 0
    dynamic_skipped = False

    executable_like_files = 0
    textish_files = 0
    source_files = 0
    developer_files = 0
    test_like_files = 0
    real_binary_files = 0
    chain_ready_files = 0
    high_signal_exec_files = 0
    multi_yara_exec_files = 0
    ioc_rich_exec_files = 0

    for r in static_results:
        path_str = str(r.get("file", ""))
        suffix = Path(path_str).suffix.lower()
        tags = set(r.get("tags", []))
        severity = str(r.get("severity", "low"))
        source_code = bool(r.get("source_code"))
        dev_artifact = bool(r.get("developer_artifact"))
        clean_yara = [m for m in r.get("yara_matches", []) if not str(m).startswith("yara_error:")]
        has_yara = bool(clean_yara)
        iocs = r.get("iocs", {}) or {}
        ioc_count = sum(len(iocs.get(k, [])) for k in ["urls", "domains", "ips", "emails"])
        has_ioc = ioc_count > 0
        has_heavy_obf = "heavy_obfuscation" in tags or "script_obfuscation" in tags
        has_light_obf = "light_obfuscation" in tags
        pe_data = r.get("pe", {}) or {}
        pe_susp = len(set(pe_data.get("suspicious_imports", [])))
        pe_is_real = bool(pe_data.get("is_pe"))

        suspected_family = set(r.get("suspected_family", []) or [])
        is_ransom = any("ransom" in t for t in tags) or "ransomware" in suspected_family
        is_stealer = any("stealer" in t for t in tags) or "infostealer" in suspected_family
        is_dropper = "dropper_like" in tags or "dropper" in suspected_family
        is_downloader = any(tag.startswith("downloader_") for tag in tags) or "downloader" in suspected_family
        is_rat = any(tag.startswith("rat_") for tag in tags) or "rat" in suspected_family
        family_signal = is_ransom or is_stealer or is_dropper or is_downloader or is_rat

        is_textish = suffix in TEXTISH_SUFFIXES
        is_exec_like = suffix in EXECUTABLE_SUFFIXES
        is_source = source_code or suffix in SOURCE_SUFFIXES
        is_test = _looks_like_test_artifact(path_str)

        if is_exec_like:
            executable_like_files += 1
        if is_textish:
            textish_files += 1
        if is_source:
            source_files += 1
        if dev_artifact:
            developer_files += 1
        if is_test:
            test_like_files += 1
        if pe_is_real and suffix in {".exe", ".dll", ".com", ".scr"}:
            real_binary_files += 1

        if severity == "high":
            high_risk_files += 1
        elif severity == "medium":
            medium_risk_files += 1

        total_yara_hits += len(clean_yara)
        family_hits.update(suspected_family)
        critical_tag_count += sum(1 for t in tags if t in CRITICAL_TAGS)

        real_exec_signal = is_exec_like or pe_is_real or suffix in {".docm", ".xlsm"}

        chain_ready = real_exec_signal and has_ioc and (has_yara or has_heavy_obf or family_signal)
        if chain_ready:
            chain_ready_files += 1

        if real_exec_signal and (family_signal or pe_susp >= 1 or has_heavy_obf):
            high_signal_exec_files += 1
        if real_exec_signal and len(clean_yara) >= 2:
            multi_yara_exec_files += 1
        if real_exec_signal and ioc_count >= 2:
            ioc_rich_exec_files += 1

        per_file = 0
        if severity == "high":
            per_file += 6
        elif severity == "medium":
            per_file += 3

        if has_yara:
            per_file += min(6, len(clean_yara) * 2)
        if has_ioc:
            per_file += min(4, 1 + min(ioc_count, 3))
        if pe_susp:
            per_file += min(6, pe_susp * 2)
        if has_heavy_obf:
            per_file += 4
        elif has_light_obf:
            per_file += 2
        if family_signal:
            per_file += 4

        if is_textish:
            per_file = min(per_file, 4)
        elif is_source:
            per_file = min(per_file, 4)
        elif suffix == ".yar":
            per_file = min(per_file, 2)

        if is_test and not real_exec_signal:
            per_file = min(per_file, 4)
        if dev_artifact and not real_exec_signal:
            per_file = min(per_file, 1)

        file_score += min(per_file, 12)

        ps_download_chain = (
            real_exec_signal
            and ("powershell" in tags or "invoke-webrequest" in tags or "downloadstring" in tags)
            and has_ioc and (has_yara or has_heavy_obf)
        )
        dropper_chain = (
            real_exec_signal
            and ("invoke-webrequest" in tags or "downloadstring" in tags or is_downloader or is_dropper)
            and has_ioc and (has_yara or has_heavy_obf)
        )
        ransom_chain = real_exec_signal and is_ransom and (has_yara or has_heavy_obf or ioc_count >= 1)
        stealer_chain = real_exec_signal and is_stealer and (has_yara or has_heavy_obf or ioc_count >= 1)

        if ps_download_chain:
            chain_score = max(chain_score, 12)
            strong_override = True
        if dropper_chain:
            chain_score = max(chain_score, 12)
            strong_override = True
        if ransom_chain:
            chain_score = max(chain_score, 10)
        if stealer_chain:
            chain_score = max(chain_score, 10)

    file_score = min(file_score, 30)
    yara_score = min(total_yara_hits * 2, 18)
    ioc_score = min(sum(1 for r in static_results if any((r.get("iocs", {}) or {}).get(k) for k in ["urls", "domains", "ips", "emails"])) * 2, 10)

    if any(("heavy_obfuscation" in set(r.get("tags", [])) or "script_obfuscation" in set(r.get("tags", []))) for r in static_results):
        obf_score = 7
    elif any("light_obfuscation" in set(r.get("tags", [])) for r in static_results):
        obf_score = 3

    if dynamic_result.get("persistence_signal"):
        runtime_score += 8
    if dynamic_result.get("network_signal"):
        runtime_score += 8
    if dynamic_result.get("exec_signal"):
        runtime_score += 6
    if dynamic_result.get("file_signal"):
        runtime_score += 4
    if dynamic_result.get("timed_out"):
        runtime_score += 2

    member_results = dynamic_result.get("archive_member_results", []) or []
    if member_results and any(m.get("skipped") for m in member_results):
        dynamic_skipped = True
        runtime_score += 2

    runtime_score = min(runtime_score, 18)

    bonus_score += min(8, len(family_hits) * 2)
    bonus_score += min(6, critical_tag_count // 3)
    bonus_score += min(6, high_risk_files * 2)
    bonus_score += min(4, medium_risk_files)
    bonus_score = min(bonus_score, 16)

    no_runtime_behavior = runtime_score <= 2 and not dynamic_result.get("network_signal") and not dynamic_result.get("exec_signal") and not dynamic_result.get("persistence_signal")
    mostly_text = len(static_results) > 0 and (textish_files + source_files) / max(1, len(static_results)) >= 0.7
    mostly_test = len(static_results) > 0 and test_like_files / max(1, len(static_results)) >= 0.5
    no_real_binary = real_binary_files == 0
    no_exec_members = int(dynamic_result.get("archive_member_exec_count", 0)) == 0

    has_ransom_note_txt = any("ransom_note_txt" in set(r.get("tags", [])) for r in static_results)
    has_script_like_txt = any("script_like_txt" in set(r.get("tags", [])) for r in static_results)

    malicious_static_bundle = (
        chain_ready_files >= 1
        or high_signal_exec_files >= 2
        or multi_yara_exec_files >= 1
        or ioc_rich_exec_files >= 1
    )

    if mostly_text and no_real_binary:
        developer_heavy = True

    raw_score = file_score + yara_score + ioc_score + obf_score + runtime_score + chain_score + bonus_score

    if no_runtime_behavior and no_real_binary and (mostly_text or mostly_test) and not malicious_static_bundle and not has_ransom_note_txt and not has_script_like_txt:
        raw_score = min(raw_score, 20)
        strong_override = False
    elif no_runtime_behavior and no_exec_members and executable_like_files == 0 and not malicious_static_bundle and not has_ransom_note_txt and not has_script_like_txt:
        raw_score = min(raw_score, 25)
        strong_override = False
    elif source_files >= max(3, len(static_results) // 2) and no_runtime_behavior and no_real_binary and not malicious_static_bundle and not has_ransom_note_txt and not has_script_like_txt:
        raw_score = min(raw_score, 22)
        strong_override = False

    if has_ransom_note_txt and no_runtime_behavior and no_real_binary:
        raw_score = max(raw_score, 38)

    if has_script_like_txt and no_runtime_behavior and no_real_binary:
        raw_score = max(raw_score, 35)

    if malicious_static_bundle:
        raw_score = max(raw_score, 55)

    raw_score = min(raw_score, 100)
    score = raw_score

    if strong_override and not (no_runtime_behavior and no_real_binary and mostly_text and not malicious_static_bundle) and score < 70:
        score = 70

    score = min(score, 100)

    if strong_override or score > int(settings.verdict_suspicious_max):
        verdict = "malicious"
    elif score > int(settings.verdict_review_max):
        verdict = "suspicious"
    elif score > int(settings.verdict_clean_max):
        verdict = "review"
    else:
        verdict = "clean"

    return {
        "score": score,
        "raw_score": raw_score,
        "verdict": verdict,
        "file_count": len(static_results),
        "static_score": file_score + yara_score + ioc_score + obf_score + chain_score + bonus_score,
        "dynamic_score": runtime_score,
        "aggregate_score": bonus_score,
        "developer_heavy": developer_heavy,
        "strong_override": strong_override,
        "dynamic_skipped": dynamic_skipped,
        "high_confidence_files": high_risk_files,
        "high_severity_files": high_risk_files,
        "malicious_static_bundle": malicious_static_bundle,
        "evidence_reasons": _top_reasons(static_results, dynamic_result),
        "score_breakdown": {
            "file": file_score,
            "yara": yara_score,
            "runtime": runtime_score,
            "ioc": ioc_score,
            "obfuscation": obf_score,
            "chain": chain_score,
            "aggregate": bonus_score,
        },
    }
