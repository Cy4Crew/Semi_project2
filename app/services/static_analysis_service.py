from __future__ import annotations

import base64
import ipaddress
import math
import os
import re
import shutil
import zipfile
from pathlib import Path

import pefile
import yara

from app.core.config import settings

STRONG_MALWARE_KEYWORDS = {
    "createremotethread", "writeprocessmemory", "virtualalloc",
    "mimikatz", "sekurlsa", "lsass",
}
MEDIUM_MALWARE_KEYWORDS = {
    "powershell", "invoke-webrequest", "downloadstring", "frombase64string",
    "certutil", "regsvr32", "rundll32", "schtasks", "urlmon",
    "wget", "curl", "cmd.exe",
}

RANSOMWARE_KEYWORDS = {
    "vssadmin delete shadows",
    "wbadmin delete catalog",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "shadowcopy",
    "readme.txt",
    ".locked",
    ".encrypted",
    "decrypt",
    "ransom",
    "recover files",
    "bitcoin",
}
DOWNLOADER_KEYWORDS = {
    "urlmon", "urldownloadtofile", "downloadstring", "invoke-webrequest",
    "bitsadmin", "certutil -urlcache", "powershell -enc", "frombase64string",
    "wget", "curl", "mshta", "javascript:eval",
}
RAT_KEYWORDS = {
    "reverse shell", "connectback", "remote shell", "meterpreter", "cmd /c",
    "wscript.shell", "backdoor", "c2", "beacon", "shellcode",
}
STEALER_KEYWORDS = {
    "login data",
    "web data",
    "cookies",
    "local state",
    "discord",
    "token",
    "wallet",
    "metamask",
    "chromium",
    "firefox",
    "sqlite",
    "browser credential",
    "telegram",
}

DEV_PATH_MARKERS = {
    "__pycache__", ".git", ".idea", ".vscode", "node_modules", ".pytest_cache",
    "dist", "build", ".next", ".nuxt", ".mypy_cache", ".venv", "venv",
}
LOW_RISK_SUFFIXES = {
    ".md", ".txt", ".rst", ".yml", ".yaml", ".json", ".css", ".scss",
    ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".lock",
}
SOURCE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".cpp", ".cs"}
DOC_SUFFIXES = {".docm", ".xlsm", ".doc", ".docx", ".xls", ".xlsx"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".com"}

PE_IMPORTS_HIGH = {
    "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory", "WinExec",
    "URLDownloadToFileA", "URLDownloadToFileW", "CreateServiceA", "CreateServiceW",
    "RegSetValueExA", "RegSetValueExW", "SetWindowsHookExA", "SetWindowsHookExW",
}
PE_IMPORTS_MEDIUM = {
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "CreateProcessA",
    "CreateProcessW", "InternetConnectA", "InternetConnectW",
}

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BASE64_RE = re.compile(rb"(?:[A-Za-z0-9+/]{20,}={0,2})")
LOCAL_DOMAINS = {"localhost", "127.0.0.1", "example.com", "example.invalid", "mail.example.org", "8.8.8.8"}

SELF_ANALYZER_MARKERS = {
    "yara.compile", "pefile.pe", "createremotethread", "writeprocessmemory",
    "rule suspicious_", "pe_imports_high", "malware_keywords", "virustotal",
}
BENIGN_DEV_MARKERS = {
    "fastapi", "uvicorn", "jinja2", "sqlalchemy", "pydantic", "react", "nextjs",
    "docker compose", "dockerfile", "requirements.txt", "package.json",
}

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    ln = len(data)
    for f in freq.values():
        p = f / ln
        entropy -= p * math.log2(p)
    return entropy

def extract_strings(data: bytes):
    return re.findall(rb"[ -~]{4,}", data)

def _is_dev_artifact(file_path: Path) -> bool:
    lowered = str(file_path).lower()
    return any(marker in lowered for marker in DEV_PATH_MARKERS)

def _is_low_risk_doc(file_path: Path) -> bool:
    return file_path.suffix.lower() in LOW_RISK_SUFFIXES

def _is_source_code(file_path: Path) -> bool:
    return file_path.suffix.lower() in SOURCE_SUFFIXES

def _joined(texts: list[str]) -> str:
    return "\n".join(texts).lower()

def _has_self_analyzer_markers(texts: list[str]) -> bool:
    joined = _joined(texts)
    return sum(1 for marker in SELF_ANALYZER_MARKERS if marker.lower() in joined) >= 2

def _has_benign_dev_markers(texts: list[str]) -> bool:
    joined = _joined(texts)
    return sum(1 for marker in BENIGN_DEV_MARKERS if marker.lower() in joined) >= 2

def analyze_keyword_tiers(strings, source_code: bool):
    lowered = [s.lower() for s in strings]
    strong = set()
    medium = set()
    ransom = set()
    stealer = set()
    for s in lowered:
        for k in STRONG_MALWARE_KEYWORDS:
            if k.encode() in s:
                strong.add(k)
        for k in MEDIUM_MALWARE_KEYWORDS:
            if k.encode() in s:
                medium.add(k)
        for k in RANSOMWARE_KEYWORDS:
            if k.encode() in s:
                ransom.add(k)
        for k in STEALER_KEYWORDS:
            if k.encode() in s:
                stealer.add(k)
    if source_code:
        medium = set(list(sorted(medium))[:2])
    return sorted(strong), sorted(medium), sorted(ransom), sorted(stealer)

def extract_iocs_from_texts(texts):
    joined = "\n".join(texts)
    urls = [u for u in sorted(set(URL_RE.findall(joined))) if "localhost" not in u and "127.0.0.1" not in u][:20]
    emails = [e for e in sorted(set(EMAIL_RE.findall(joined))) if e.split("@")[-1].lower() not in LOCAL_DOMAINS][:20]

    ips = []
    for candidate in IP_RE.findall(joined):
        try:
            ip = ipaddress.ip_address(candidate)
            if not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast) and candidate not in LOCAL_DOMAINS:
                ips.append(candidate)
        except ValueError:
            pass

    domains = set()
    for url in urls:
        try:
            host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0].lower()
            if host and host not in LOCAL_DOMAINS:
                domains.add(host)
        except Exception:
            continue
    for email in emails:
        host = email.split("@")[-1].lower()
        if host and host not in LOCAL_DOMAINS:
            domains.add(host)

    return {
        "urls": urls,
        "emails": emails,
        "domains": sorted(domains)[:20],
        "ips": sorted(set(ips))[:20],
    }

def try_decode_base64_blobs(data: bytes):
    decoded_texts = []
    for blob in BASE64_RE.findall(data):
        try:
            decoded = base64.b64decode(blob, validate=True)
            if len(decoded) < 16:
                continue
            printable_ratio = sum(32 <= b <= 126 or b in (9, 10, 13) for b in decoded) / max(1, len(decoded))
            if printable_ratio < 0.8:
                continue
            decoded_texts.append(decoded.decode("utf-8", errors="ignore"))
        except Exception:
            continue
    return decoded_texts[:8]



def _resolve_within(base_dir: Path, relative_name: str) -> Path:
    base = base_dir.resolve()
    target = (base_dir / relative_name).resolve()
    if os.path.commonpath([str(base), str(target)]) != str(base):
        raise ValueError(f"unsafe_zip_member:{relative_name}")
    return target


def safe_extract_zip(zip_path: Path, extract_dir: Path) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            target = _resolve_within(extract_dir, member.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)


def analyze_yara_rules(file_path: Path):
    matches = []
    try:
        file_map = {p.stem: str(p) for p in Path(settings.yara_rules_dir).glob("*.yar")}
        if not file_map:
            return []
        rules = yara.compile(filepaths=file_map)
        for m in rules.match(str(file_path)):
            matches.append(m.rule)
    except Exception as e:
        matches.append(f"yara_error:{e}")
    return matches

def analyze_pe_imports(file_path: Path):
    result = {
        "imports": [],
        "suspicious_imports": [],
        "medium_imports": [],
        "is_pe": False,
        "compile_timestamp": None,
    }
    try:
        pe = pefile.PE(str(file_path), fast_load=False)
        result["is_pe"] = True
        result["compile_timestamp"] = getattr(pe.FILE_HEADER, "TimeDateStamp", None)

        all_imports = []
        suspicious = set()
        medium = set()

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore") if entry.dll else "unknown"
                for imp in entry.imports:
                    name = imp.name.decode(errors="ignore") if imp.name else ""
                    if name:
                        all_imports.append(f"{dll_name}:{name}")
                        if name in PE_IMPORTS_HIGH:
                            suspicious.add(name)
                        elif name in PE_IMPORTS_MEDIUM:
                            medium.add(name)

        result["imports"] = all_imports[:150]
        result["suspicious_imports"] = sorted(suspicious)
        result["medium_imports"] = sorted(medium)
    except Exception as e:
        result["error"] = str(e)
    return result

def _has_macro_indicator(data: bytes, texts: list[str]) -> bool:
    lowered = _joined(texts)
    return b"vba" in data.lower() or "macros/vba" in lowered or "thisdocument" in lowered or "autoopen" in lowered


def _com_binary_heuristics(data: bytes, texts: list[str]) -> tuple[bool, list[str]]:
    reasons = []
    lowered = "\n".join(texts).lower()
    # DOS/Windows COM style binary/script indicators
    mz_like = data[:2] == b"MZ"
    has_cmd_markers = any(k in lowered for k in [
        "powershell", "cmd.exe", "rundll32", "regsvr32", "certutil",
        "wget", "curl", "invoke-webrequest", "downloadstring"
    ])
    high_entropy = calculate_entropy(data) > settings.entropy_threshold + 0.2
    if mz_like:
        reasons.append("mz_header")
    if has_cmd_markers:
        reasons.append("suspicious_command_markers")
    if high_entropy:
        reasons.append("packed_like")
    return (mz_like or has_cmd_markers or high_entropy), reasons


def _count_obfuscation_markers(texts: list[str], data: bytes) -> int:
    joined = _joined(texts)
    markers = 0
    if "frombase64string" in joined or "powershell -enc" in joined:
        markers += 1
    if "javascript:eval" in joined or "eval(" in joined:
        markers += 1
    if "charcodeat" in joined or "fromcharcode" in joined:
        markers += 1
    if "xor" in joined and ("decode" in joined or "decrypt" in joined):
        markers += 1
    if len(BASE64_RE.findall(data)) >= 2:
        markers += 1
    return markers

def _detect_family_keywords(texts: list[str]):
    joined = _joined(texts)
    ransom = sorted({k for k in RANSOMWARE_KEYWORDS if k in joined})
    stealer = sorted({k for k in STEALER_KEYWORDS if k in joined})
    downloader = sorted({k for k in DOWNLOADER_KEYWORDS if k in joined})
    rat = sorted({k for k in RAT_KEYWORDS if k in joined})
    return ransom, stealer, downloader, rat

def _looks_like_dropper(source_code: bool, clean_yara: list[str], downloader_kw: list[str], rat_kw: list[str], has_ioc: bool) -> bool:
    if clean_yara and (downloader_kw or rat_kw) and has_ioc:
        return True
    if not source_code and len(downloader_kw) >= 2 and has_ioc:
        return True
    return False

def analyze_file(file_path: Path):
    source_code = _is_source_code(file_path)
    dev_artifact = _is_dev_artifact(file_path)
    low_risk_doc = _is_low_risk_doc(file_path)

    result = {
        "file": str(file_path),
        "score": 0,
        "tags": [],
        "iocs": {"urls": [], "emails": [], "domains": [], "ips": []},
        "base64_decoded_snippets": [],
        "yara_matches": [],
        "pe": {},
        "severity": "low",
        "summary_reasons": [],
        "source_code": source_code,
        "developer_artifact": dev_artifact,
        "evidence_tier": "none",
        "suspected_family": [],
    }

    try:
        if dev_artifact or file_path.suffix.lower() == ".pyc":
            result["summary_reasons"].append("ignored developer artifact")
            return result

        data = file_path.read_bytes()
        strings = extract_strings(data)
        ascii_texts = [s.decode("utf-8", errors="ignore") for s in strings[:350]]
        decoded_texts = try_decode_base64_blobs(data)
        all_texts = ascii_texts + decoded_texts

        result["base64_decoded_snippets"] = decoded_texts[:4]

        self_analyzer = _has_self_analyzer_markers(all_texts)
        benign_dev = _has_benign_dev_markers(all_texts)

        # File type expectations
        if file_path.suffix.lower() in EXECUTABLE_EXTENSIONS:
            pe_result = analyze_pe_imports(file_path)
            result["pe"] = pe_result
            if not pe_result.get("is_pe"):
                result["summary_reasons"].append("not a real PE file")
                return result

        if file_path.suffix.lower() in DOC_SUFFIXES and file_path.suffix.lower() in {".docm", ".xlsm"}:
            if not _has_macro_indicator(data, all_texts):
                result["summary_reasons"].append("no macro indicator")
                return result

        if file_path.suffix.lower() == ".com":
            com_hit, com_reasons = _com_binary_heuristics(data, all_texts)
            if not com_hit:
                result["summary_reasons"].append("no executable .com indicator")
                return result
            result["summary_reasons"].append("suspicious .com executable indicator")
            result["tags"].append("com_executable_indicator")

        strong_kw, medium_kw, ransom_kw, stealer_kw = analyze_keyword_tiers(strings + [t.encode("utf-8", errors="ignore") for t in decoded_texts], source_code)
        ransom_kw2, stealer_kw2, downloader_kw, rat_kw = _detect_family_keywords(all_texts)
        ransom_kw = sorted(set(ransom_kw + ransom_kw2))
        stealer_kw = sorted(set(stealer_kw + stealer_kw2))
        iocs = extract_iocs_from_texts(all_texts)
        result["iocs"] = iocs
        ioc_count = len(iocs["urls"]) + len(iocs["emails"]) + len(iocs["domains"]) + len(iocs["ips"])

        yara_matches = analyze_yara_rules(file_path)
        result["yara_matches"] = yara_matches
        clean_yara = [m for m in yara_matches if not str(m).startswith("yara_error:")]

        entropy = calculate_entropy(data)
        result["entropy"] = entropy
        obf_markers = _count_obfuscation_markers(all_texts, data)

        pe_high = 0
        pe_medium = 0
        if file_path.suffix.lower() in [".exe", ".dll", ".com"]:
            pe_result = result["pe"]
            pe_high = len(pe_result.get("suspicious_imports", []))
            pe_medium = len(pe_result.get("medium_imports", []))
            result["tags"].extend(pe_result.get("suspicious_imports", []))
            if pe_medium:
                result["tags"].append("medium_risk_imports")

        strong_evidence = 0
        medium_evidence = 0

        if pe_high >= 2:
            strong_evidence += 1
            result["summary_reasons"].append("high-risk import combination")
        elif pe_high == 1:
            medium_evidence += 1
            result["summary_reasons"].append("single high-risk import")

        if clean_yara and not self_analyzer:
            if source_code and not ioc_count and not strong_kw and not ransom_kw and not stealer_kw:
                medium_evidence += 1
            else:
                strong_evidence += 1
            result["tags"].append("yara_match")
            result["summary_reasons"].append(f"YARA match ({len(clean_yara)})")

        if strong_kw:
            medium_evidence += 1
            result["tags"].extend(strong_kw[:3])
            result["summary_reasons"].append(f"strong malware keywords ({len(strong_kw)})")

        if medium_kw and (ioc_count or clean_yara or pe_high or ransom_kw or stealer_kw):
            medium_evidence += 1
            result["tags"].extend(medium_kw[:3])
            result["summary_reasons"].append(f"suspicious keywords ({len(medium_kw)})")

        if ioc_count and not low_risk_doc:
            medium_evidence += 1
            result["tags"].append("ioc_present")
            result["summary_reasons"].append("external IOC present")

        if entropy > settings.entropy_threshold + 0.4 and not low_risk_doc and not source_code:
            medium_evidence += 1
            result["tags"].append("packed_or_obfuscated")
            result["summary_reasons"].append("high entropy")

        if obf_markers >= 2:
            medium_evidence += 1
            result["tags"].append("script_obfuscation")
            result["summary_reasons"].append("multiple obfuscation markers")
        elif obf_markers == 1 and (clean_yara or ioc_count or downloader_kw):
            medium_evidence += 1
            result["tags"].append("light_obfuscation")
            result["summary_reasons"].append("obfuscation marker")

        if downloader_kw:
            medium_evidence += 1
            result["suspected_family"].append("downloader")
            result["summary_reasons"].append(f"downloader strings ({len(downloader_kw)})")

        if len(rat_kw) >= 2:
            medium_evidence += 1
            result["suspected_family"].append("rat")
            result["summary_reasons"].append("remote access / shell strings")
        elif rat_kw:
            result["suspected_family"].append("rat")

        if _looks_like_dropper(source_code, clean_yara, downloader_kw, rat_kw, bool(ioc_count)):
            strong_evidence += 1
            result["suspected_family"].append("dropper")
            result["summary_reasons"].append("dropper-like evidence chain")

        # Family inference
        if len(ransom_kw) >= 2 or any("ransom" in x or "decrypt" in x or "shadow" in x for x in ransom_kw):
            result["suspected_family"].append("ransomware")
            strong_evidence += 1
            result["summary_reasons"].append("ransomware-like behavior strings")
        elif ransom_kw:
            medium_evidence += 1
            result["suspected_family"].append("ransomware")
            result["summary_reasons"].append("ransomware-related strings")

        if len(stealer_kw) >= 2:
            result["suspected_family"].append("infostealer")
            medium_evidence += 1
            result["summary_reasons"].append("credential theft / wallet strings")
        elif stealer_kw:
            result["suspected_family"].append("infostealer")

        score = 0
        if strong_evidence >= 2:
            score += 8
            result["evidence_tier"] = "strong"
        elif strong_evidence == 1:
            score += 5
            result["evidence_tier"] = "strong"

        if medium_evidence >= 3:
            score += 4
        elif medium_evidence == 2:
            score += 3
        elif medium_evidence == 1:
            score += 1

        high_family = bool(set(result["suspected_family"]) & {"ransomware", "infostealer", "dropper", "rat", "downloader"})
        if source_code and benign_dev and not high_family:
            score = min(score, 3)
            result["summary_reasons"].append("source code cap")
        elif source_code and not high_family:
            score = min(score, 5)
        if low_risk_doc:
            score = min(score, 1)
            result["summary_reasons"].append("low-risk document cap")

        result["score"] = max(0, score)

        if result["score"] >= 8:
            result["severity"] = "high"
        elif result["score"] >= 4:
            result["severity"] = "medium"
        else:
            result["severity"] = "low"

    except Exception as e:
        result["error"] = str(e)
        result["summary_reasons"].append(f"analysis error: {e}")

    result["tags"] = sorted(set(result["tags"]))
    result["suspected_family"] = sorted(set(result["suspected_family"]))
    return result

def analyze_archive(zip_path: str):
    results = []
    extract_dir = Path("/tmp/sample_ext")

    if extract_dir.exists():
        shutil.rmtree(extract_dir)

    with zipfile.ZipFile(zip_path) as z:
        z.extractall(extract_dir)

    count = 0
    for f in extract_dir.rglob("*"):
        if f.is_file():
            results.append(analyze_file(f))
            count += 1
            if count >= settings.max_archive_files:
                break

    return results
