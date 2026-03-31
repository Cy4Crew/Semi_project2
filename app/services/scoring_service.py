from __future__ import annotations

from collections import Counter


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


def calculate_score(static_results: list[dict], dynamic_result: dict):
    pe_score = 0
    yara_score = 0
    runtime_score = 0
    ioc_score = 0
    obfuscation_score = 0
    family_score = 0
    misc_score = 0
    developer_heavy = False
    strong_override = False
    source_files = 0
    dev_like_files = 0

    high_confidence_files = 0
    high_severity_files = 0

    for r in static_results:
        tags = set(r.get("tags", []))
        severity = r.get("severity", "low")
        source_code = bool(r.get("source_code"))
        dev_artifact = bool(r.get("developer_artifact"))
        clean_yara = [m for m in r.get("yara_matches", []) if not str(m).startswith("yara_error:")]
        has_yara = len(clean_yara) > 0
        has_ioc = any(r.get("iocs", {}).get(k) for k in ["urls", "domains", "ips", "emails"])
        has_heavy_obf = "heavy_obfuscation" in tags
        has_light_obf = "light_obfuscation" in tags
        is_ransom = any(tag.startswith("ransom_") for tag in tags)
        is_stealer = any(tag.startswith("stealer_") for tag in tags)
        is_dropper = "dropper_like" in tags
        is_downloader = any(tag.startswith("downloader_") for tag in tags)
        is_rat = any(tag.startswith("rat_") for tag in tags)
        pe_susp = len(set(r.get("pe", {}).get("suspicious_imports", [])))

        if source_code:
            source_files += 1
        if source_code or dev_artifact:
            dev_like_files += 1
        if severity == "high":
            high_severity_files += 1
        if has_yara or (has_ioc and (is_ransom or is_stealer or is_dropper or is_rat)):
            high_confidence_files += 1

        has_ps_download_chain = (
            ("powershell" in tags or "invoke-webrequest" in tags or "downloadstring" in tags)
            and has_ioc and (has_yara or has_heavy_obf)
        )
        has_dropper_chain = (
            ("invoke-webrequest" in tags or "downloadstring" in tags or is_downloader or is_dropper)
            and has_ioc and (has_yara or has_heavy_obf)
        )
        has_ransom_chain = is_ransom and (has_heavy_obf or has_yara)
        has_stealer_chain = is_stealer and has_ioc and (has_yara or has_heavy_obf)

        if pe_susp >= 2:
            pe_score = max(pe_score, 30)
        elif pe_susp == 1:
            pe_score = max(pe_score, 16)

        if has_yara and pe_susp >= 1:
            yara_score = max(yara_score, 25)
        elif has_yara and has_ioc:
            yara_score = max(yara_score, 18)
        elif has_yara:
            yara_score = max(yara_score, 6 if source_code else 10)

        if has_ioc:
            ioc_count = (
                len(r.get("iocs", {}).get("urls", []))
                + len(r.get("iocs", {}).get("domains", []))
                + len(r.get("iocs", {}).get("ips", []))
                + len(r.get("iocs", {}).get("emails", []))
            )
            ioc_score = max(ioc_score, min(10, 3 + ioc_count * 2))

        if has_heavy_obf:
            obfuscation_score = max(obfuscation_score, 12)
        elif has_light_obf:
            obfuscation_score = max(obfuscation_score, 6)

        if is_ransom:
            family_score = max(family_score, 26)
        elif is_stealer:
            family_score = max(family_score, 20)
        elif is_dropper:
            family_score = max(family_score, 18)
        elif is_rat:
            family_score = max(family_score, 18)
        elif is_downloader:
            family_score = max(family_score, 12)

        if severity == "high" and not source_code:
            misc_score = max(misc_score, 4)
        elif severity == "medium" and not source_code:
            misc_score = max(misc_score, 2)

        if has_ps_download_chain:
            misc_score = max(misc_score, 8)
            strong_override = True
        if has_dropper_chain:
            misc_score = max(misc_score, 8)
            strong_override = True
        if has_ransom_chain:
            misc_score = max(misc_score, 8)
        if has_stealer_chain:
            misc_score = max(misc_score, 7)

        if (
            (has_yara and pe_susp >= 1)
            or (is_ransom and has_ioc and has_heavy_obf)
            or (is_stealer and has_ioc and has_yara)
            or (is_dropper and has_ioc and has_yara and has_heavy_obf)
            or (is_rat and has_ioc and has_yara)
            or ("com_executable_indicator" in tags and has_yara)
        ):
            strong_override = True

    if dynamic_result.get("persistence_signal"):
        runtime_score += 10
    if dynamic_result.get("network_signal"):
        runtime_score += 6
    if dynamic_result.get("exec_signal"):
        runtime_score += 5
    if dynamic_result.get("file_signal"):
        runtime_score += 3
    if dynamic_result.get("persistence_signal") and dynamic_result.get("network_signal"):
        runtime_score += 2
    runtime_score = min(runtime_score, 14)

    if source_files >= 8 and dev_like_files >= 5 and pe_score == 0 and family_score == 0:
        developer_heavy = True

    raw_score = pe_score + yara_score + runtime_score + ioc_score + obfuscation_score + family_score + misc_score

    if developer_heavy:
        raw_score = max(0, raw_score - 12)
        if pe_score == 0 and family_score == 0 and runtime_score <= 6:
            raw_score = min(raw_score, 22)

    raw_score = min(raw_score, 100)
    score = raw_score

    if strong_override or score >= 70:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    elif score >= 20:
        verdict = "review"
    else:
        verdict = "clean"

    return {
        "score": score,
        "raw_score": raw_score,
        "verdict": verdict,
        "file_count": len(static_results),
        "static_score": pe_score + yara_score + ioc_score + obfuscation_score + family_score + misc_score,
        "dynamic_score": runtime_score,
        "developer_heavy": developer_heavy,
        "strong_override": strong_override,
        "high_confidence_files": high_confidence_files,
        "high_severity_files": high_severity_files,
        "evidence_reasons": _top_reasons(static_results, dynamic_result),
        "score_breakdown": {
            "pe": pe_score,
            "yara": yara_score,
            "runtime": runtime_score,
            "ioc": ioc_score,
            "obfuscation": obfuscation_score,
            "family": family_score,
            "misc": misc_score,
        },
    }
