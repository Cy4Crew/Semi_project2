from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

RANSOMWARE_KEYWORDS = {
    "ransom", "restore", "recover files", "recover your files", "decrypt",
    "decryption", "readme_restore_files", ".locked", ".encrypted",
    "bitcoin", "payment", "tor browser", "private key",
    "your files have been", "all your files", "restore_files",
}
INFOSTEALER_KEYWORDS = {
    "cookie", "cookies", "login data", "saved password", "passwords",
    "wallet", "metamask", "token", "telegram", "browser_login",
    "browser data", "credentials", "seed phrase", "local state", "web data",
}
RAT_KEYWORDS = {
    "reverse shell", "rat", "remote admin", "connectback", "beacon", "c2",
    "backdoor", "meterpreter",
}
DOWNLOADER_KEYWORDS = {
    "download", "urlmon", "urldownloadtofile", "invoke-webrequest",
    "downloadstring", "bitsadmin", "certutil -urlcache", "wget", "curl",
}
DROPPER_KEYWORDS = {"dropper", "payload", "extract", "staged", "dropped file"}
BACKDOOR_KEYWORDS = {
    "backdoor", "persistence", "currentversion\\run", "runonce", "schtasks",
    "service create", "startup",
}
FAMILY_ORDER = ["ransomware", "infostealer", "rat", "backdoor", "dropper", "downloader", "trojan"]

def _text_blob(*parts: Any) -> str:
    return " ".join(str(p or "") for p in parts).lower()

def _file_family_hints(item: dict[str, Any]) -> list[str]:
    path = str(item.get("file") or "").replace("\\", "/").lower()
    suffix = Path(path).suffix.lower()
    text = _text_blob(path, item.get("tags"), item.get("summary_reasons"), item.get("base64_decoded_snippets"), item.get("iocs"), item.get("top_evidence"))
    pe = item.get("pe") or {}
    imports = _text_blob(pe.get("imports"), pe.get("suspicious_imports"), pe.get("medium_imports"))
    full = f"{text} {imports}"
    hits: list[str] = []

    ransomware_score = sum(1 for k in RANSOMWARE_KEYWORDS if k in full)
    if suffix == ".locked":
        ransomware_score += 2
    if "readme_restore" in path or "restore_files" in path:
        ransomware_score += 2
    if ransomware_score >= 2:
        hits.append("ransomware")

    infostealer_score = sum(1 for k in INFOSTEALER_KEYWORDS if k in full)
    if suffix in {".txt", ".json", ".log"} and infostealer_score <= 1 and "wallet" in full and ".locked" not in full:
        infostealer_score = 1
    if infostealer_score >= 2:
        hits.append("infostealer")

    if any(k in full for k in RAT_KEYWORDS):
        hits.append("rat")
    if any(k in full for k in BACKDOOR_KEYWORDS):
        hits.append("backdoor")
    if any(k in full for k in DROPPER_KEYWORDS):
        hits.append("dropper")
    if any(k in full for k in DOWNLOADER_KEYWORDS):
        hits.append("downloader")
    return [x for x in FAMILY_ORDER if x in hits]

def classify_family(scored_files: list[dict[str, Any]], dynamic_result: dict[str, Any] | None = None) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    dynamic_text = _text_blob(dynamic_result or {})
    if any(k in dynamic_text for k in RANSOMWARE_KEYWORDS):
        counts["ransomware"] += 3
    if any(k in dynamic_text for k in INFOSTEALER_KEYWORDS):
        counts["infostealer"] += 2
    if any(k in dynamic_text for k in RAT_KEYWORDS):
        counts["rat"] += 2
    if any(k in dynamic_text for k in BACKDOOR_KEYWORDS):
        counts["backdoor"] += 2
    if any(k in dynamic_text for k in DROPPER_KEYWORDS):
        counts["dropper"] += 1
    if any(k in dynamic_text for k in DOWNLOADER_KEYWORDS):
        counts["downloader"] += 1

    for item in scored_files or []:
        weight = 3 if int(item.get("final_score", item.get("score", 0)) or 0) >= 40 else 1
        for fam in _file_family_hints(item):
            counts[fam] += weight

    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], FAMILY_ORDER.index(kv[0]) if kv[0] in FAMILY_ORDER else 99))
    matches = [name for name, score in ranked if score > 0]
    if not matches:
        return {"primary_family": "unknown", "family_matches": [], "confidence": "low"}

    primary = matches[0]
    top_score = ranked[0][1]
    confidence = "high" if top_score >= 4 else "medium" if top_score >= 2 else "low"
    return {"primary_family": primary, "family_matches": matches[:5], "confidence": confidence}
