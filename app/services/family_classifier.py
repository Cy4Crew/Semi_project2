
from __future__ import annotations

from collections import Counter
from typing import Any

FAMILY_HINTS = {
    "ransomware": ["ransom", "decrypt", ".locked", "shadowcopy", "vssadmin", "wbadmin"],
    "infostealer": ["cookies", "web data", "login data", "metamask", "wallet", "token"],
    "rat": ["reverse shell", "beacon", "backdoor", "connectback", "meterpreter"],
    "downloader": ["downloadstring", "invoke-webrequest", "urlmon", "urldownloadtofile", "bitsadmin"],
    "dropper": ["payload", "dropped", "extract", "temp", "appdata"],
}


def classify_family(scored_files: list[dict[str, Any]], dynamic_result: dict[str, Any]) -> dict[str, Any]:
    counter: Counter[str] = Counter()
    reasons: dict[str, list[str]] = {}

    for item in scored_files[:20]:
        file_name = str(item.get("file") or "sample")
        for fam in item.get("suspected_family", []) or []:
            counter[fam] += 4
            reasons.setdefault(fam, []).append(f"static family hint in {file_name}")
        for hit in item.get("yara_matches", []) or []:
            lower = str(hit).lower()
            for fam in FAMILY_HINTS:
                if fam in lower:
                    counter[fam] += 5
                    reasons.setdefault(fam, []).append(f"yara:{hit} in {file_name}")
        blob = " ".join(str(x) for x in (item.get("summary_reasons") or []) + (item.get("tags") or [])).lower()
        for fam, hints in FAMILY_HINTS.items():
            matched = [h for h in hints if h in blob]
            if matched:
                counter[fam] += min(3, len(matched))
                reasons.setdefault(fam, []).append(f"keyword hit in {file_name}: {', '.join(matched[:3])}")

    if dynamic_result.get("ransomware_signal"):
        counter["ransomware"] += 8
        reasons.setdefault("ransomware", []).append("dynamic ransomware signal")
    if dynamic_result.get("network_signal"):
        counter["downloader"] += 3
        reasons.setdefault("downloader", []).append("dynamic network signal")
    if dynamic_result.get("persistence_signal"):
        counter["rat"] += 2
        reasons.setdefault("rat", []).append("dynamic persistence signal")

    ranked = [{"family": fam, "score": score, "reasons": reasons.get(fam, [])[:5]} for fam, score in counter.most_common(5)]
    primary = ranked[0]["family"] if ranked else "unknown"
    confidence = "low"
    if ranked:
        top = ranked[0]["score"]
        confidence = "high" if top >= 8 else "medium" if top >= 4 else "low"
    return {"primary_family": primary, "family_matches": ranked, "confidence": confidence}
