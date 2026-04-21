from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

EVENT_IDS = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    5: "ProcessTerminate",
    7: "ImageLoad",
    10: "ProcessAccess",
    11: "FileCreate",
<<<<<<< HEAD
    12: "RegistryCreateDelete",
=======
    12: "RegistryObject",
>>>>>>> origin/main
    13: "RegistryValueSet",
    22: "DNSQuery",
}

NOISE_PROCESSES = {
    "svchost.exe", "taskhostw.exe", "conhost.exe", "backgroundtaskhost.exe",
    "runtimebroker.exe", "dllhost.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "sppsvc.exe", "sppextcomobj.exe", "slui.exe", "musnotification.exe",
    "musnotifyicon.exe", "wuauclt.exe", "usoclient.exe", "tiworker.exe",
    "trustedinstaller.exe", "compattelrunner.exe", "mpcmdrun.exe", "wsqmcons.exe",
    "disksnapshot.exe", "defrag.exe", "cleanmgr.exe", "dmclient.exe",
    "apphostregistrationverifier.exe", "locationnotificationwindows.exe",
}

<<<<<<< HEAD
def collect_sysmon_events(after_ts: float | None = None, max_events: int = 20) -> list[dict]:
    events = []
    event_id_filter = " or ".join(f"EventID={eid}" for eid in EVENT_IDS.keys())
    try:
        cmd = [
            "powershell", "-Command",
            f"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
            f"-FilterXPath '*[System[{event_id_filter}]]' "
            f"-MaxEvents {max_events * len(EVENT_IDS)} -ErrorAction SilentlyContinue | "
            f"Select-Object -Property TimeCreated, Id, Message | "
            f"ConvertTo-Json -Depth 3"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.stdout.strip():
            raw = json.loads(result.stdout)
            if isinstance(raw, dict):
                raw = [raw]
            for item in raw:
                event_id = int(item.get("Id", 0))
                event_name = EVENT_IDS.get(event_id, "Unknown")
                msg = str(item.get("Message", ""))
                img_line = next((l for l in msg.splitlines() if l.strip().startswith("Image:")), "")
                img_name = img_line.split("\\")[-1].strip().lower() if img_line else ""
                if img_name in NOISE_PROCESSES:
                    continue
                ts = item.get("TimeCreated", {})
                events.append({
                    "event_id": event_id,
                    "event_name": event_name,
                    "time": str(ts),
                    "message": msg[:500],
                })
    except Exception:
        pass
    events += collect_file_create_events()
    return events
=======
FIELD_NAMES = {
    "UtcTime", "ProcessGuid", "ProcessId", "Image", "CommandLine", "CurrentDirectory",
    "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes",
    "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser",
    "RuleName", "EventType", "TargetObject", "Details", "Protocol", "SourceIsIpv6",
    "SourceIp", "SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6",
    "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName", "ImageLoaded",
    "QueryName", "QueryStatus", "QueryResults", "Archived"
}
>>>>>>> origin/main


def _run_powershell(script: str, timeout: int = 15) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return result.stdout or ""


def _parse_message(message: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for raw_line in str(message or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key in FIELD_NAMES:
            parsed[key] = value
    return parsed


def _normalize_event(event_id: int, item: dict[str, Any]) -> dict[str, Any] | None:
    message = str(item.get("Message") or "")
    parsed = _parse_message(message)
    image = str(parsed.get("Image") or "")
    image_name = Path(image).name.lower() if image else ""
    if image_name in NOISE_PROCESSES:
        return None

    event: dict[str, Any] = {
        "event_id": int(event_id),
        "event_name": EVENT_IDS.get(int(event_id), f"Event{event_id}"),
        "time": str(item.get("TimeCreated") or ""),
        "message": message[:1200],
        "image": image,
        "image_name": image_name,
        "command_line": str(parsed.get("CommandLine") or ""),
        "parent_image": str(parsed.get("ParentImage") or ""),
        "parent_command_line": str(parsed.get("ParentCommandLine") or ""),
        "target_object": str(parsed.get("TargetObject") or ""),
        "details": str(parsed.get("Details") or ""),
        "destination_ip": str(parsed.get("DestinationIp") or ""),
        "destination_port": str(parsed.get("DestinationPort") or ""),
        "query_name": str(parsed.get("QueryName") or ""),
        "raw": parsed,
        "tags": [],
    }

    lowered = " ".join(
        [
            event["image_name"],
            event["command_line"].lower(),
            Path(event["parent_image"]).name.lower(),
            event["parent_command_line"].lower(),
            event["target_object"].lower(),
        ]
    )
    if "taskkill" in lowered and "taskmgr.exe" in lowered:
        event["tags"].append("anti_analysis")
    if "currentversion\\run" in lowered or "runonce" in lowered or "startup" in lowered:
        event["tags"].append("persistence")
    if event["event_id"] == 3 and (event["destination_ip"] or event["destination_port"]):
        event["tags"].append("network")
    if event["event_id"] in {12, 13} and event["target_object"]:
        event["tags"].append("registry")
    if event["event_id"] == 1 and event["image"]:
        event["tags"].append("process")
    return event


def collect_sysmon_events(after_ts: float | None = None, max_events: int = 120) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for event_id in EVENT_IDS:
        try:
            script = (
                f"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                f"-FilterXPath '*[System[EventID={int(event_id)}]]' -MaxEvents {int(max_events)} "
                "-ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 4"
            )
            raw_text = _run_powershell(script, timeout=20)
            if not raw_text.strip():
                continue
            raw = json.loads(raw_text)
            if isinstance(raw, dict):
                raw = [raw]
            for item in raw:
                normalized = _normalize_event(int(event_id), item)
                if not normalized:
                    continue
                if after_ts is not None:
                    event_epoch = None
                    raw_time = str(normalized.get("time") or "")
                    if raw_time:
                        try:
                            from datetime import datetime
                            event_epoch = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).timestamp()
                        except Exception:
                            event_epoch = None
                    if event_epoch is not None and event_epoch < float(after_ts):
                        continue
                events.append(normalized)
        except Exception:
            continue
    events.sort(key=lambda x: str(x.get("time") or ""))
    return events


def summarize_sysmon_events(events: list[dict[str, Any]] | None, sample_paths: list[str] | None = None) -> dict[str, Any]:
    rows = list(events or [])
    sample_keys = {Path(str(x)).name.lower() for x in (sample_paths or []) if str(x).strip()}
    process_tree = []
    registry = []
    network = []
    dns = []
    anti = []
    images = []
    execution_observed = False
    matched = []

    for event in rows:
        image = str(event.get("image") or "")
        parent_image = str(event.get("parent_image") or "")
        cmd = str(event.get("command_line") or "")
        image_name = Path(image).name.lower() if image else ""
        parent_name = Path(parent_image).name.lower() if parent_image else ""
        related = not sample_keys or image_name in sample_keys or parent_name in sample_keys or any(key and key in cmd.lower() for key in sample_keys)
        if related:
            matched.append(event)
        if event.get("event_id") == 1 and related:
            execution_observed = True
            process_tree.append({
                "pid": event.get("raw", {}).get("ProcessId") or "-",
                "name": Path(image).name or image or "-",
                "cmdline": cmd or image,
                "parent_image": parent_image,
                "parent_command_line": event.get("parent_command_line") or "",
                "time": event.get("time"),
            })
        if event.get("event_id") in {12, 13} and related:
            registry.append({
                "event_id": event.get("event_id"),
                "image": image,
                "target_object": event.get("target_object"),
                "details": event.get("details"),
                "time": event.get("time"),
            })
        if event.get("event_id") == 3 and related:
            network.append({
                "pid": event.get("raw", {}).get("ProcessId") or 0,
                "remote_ip": event.get("destination_ip") or "",
                "remote_port": int(str(event.get("destination_port") or "0") or 0),
                "status": "connected",
                "image": image,
                "time": event.get("time"),
            })
        if event.get("event_id") == 22 and related:
            dns.append({
                "query_name": event.get("query_name") or "",
                "image": image,
                "time": event.get("time"),
            })
        if "anti_analysis" in (event.get("tags") or []):
            anti.append({
                "signal": "taskkill_taskmgr",
                "image": image,
                "command_line": cmd,
                "parent_image": parent_image,
                "time": event.get("time"),
            })
        if event.get("event_id") == 7 and related:
            images.append({
                "image": image,
                "details": event.get("details"),
                "time": event.get("time"),
            })

    return {
        "event_count": len(rows),
        "matched_event_count": len(matched),
        "execution_observed": execution_observed or bool(process_tree) or bool(anti),
        "process_tree": process_tree[:40],
        "registry_changes": registry[:60],
        "network_endpoints": network[:40],
        "dns_queries": dns[:40],
        "anti_analysis_signals": anti[:20],
        "image_loads": images[:40],
    }


def clear_sysmon_log() -> None:
<<<<<<< HEAD
    try:
        subprocess.run(
            ["powershell", "-Command", "Clear-EventLog -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue"],
            capture_output=True, timeout=15
        )
    except Exception:
        pass
def summarize_sysmon_events(events: list[dict], member_paths: list | None = None) -> dict:
    dns_queries = [e for e in events if e.get("event_id") == 22]
    network_endpoints = [e for e in events if e.get("event_id") == 3]
    registry_changes = [e for e in events if e.get("event_id") in (12, 13)]
    process_tree = [e for e in events if e.get("event_id") == 1]
    image_loads = [e for e in events if e.get("event_id") == 7]
    anti_analysis = [e for e in events if e.get("event_id") == 10]
=======
    for cmd in (
        ["wevtutil", "cl", "Microsoft-Windows-Sysmon/Operational"],
        ["powershell", "-NoProfile", "-Command", "Clear-EventLog -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue"],
    ):
        try:
            subprocess.run(cmd, capture_output=True, timeout=15)
            break
        except Exception:
            continue
>>>>>>> origin/main

    return {
        "event_count": len(events),
        "matched_event_count": len(events),
        "execution_observed": bool(process_tree),
        "process_tree": process_tree[:20],
        "registry_changes": registry_changes[:20],
        "network_endpoints": network_endpoints[:20],
        "dns_queries": dns_queries[:20],
        "anti_analysis_signals": anti_analysis[:10],
        "image_loads": image_loads[:20],
    }

def save_sysmon_events(events: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    events = collect_sysmon_events(after_ts=time.time() - 600)
    print(f"Collected {len(events)} Sysmon events")
    save_sysmon_events(events, Path("sysmon_events.json"))
