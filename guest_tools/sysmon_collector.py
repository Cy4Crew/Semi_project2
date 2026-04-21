from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path


EVENT_IDS = {
    1: "ProcessCreate",
    3: "NetworkConnect", 
    7: "ImageLoad",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryCreateDelete",
    13: "RegistryValueSet",
}


NOISE_PROCESSES = {
    "svchost.exe", "taskhostw.exe", "conhost.exe", "backgroundtaskhost.exe",
    "runtimebroker.exe", "dllhost.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "sppsvc.exe", "sppextcomobj.exe", "slui.exe", "musnotification.exe",
    "musnotifyicon.exe", "wuauclt.exe", "usoclient.exe", "tiworker.exe",
    "trustedinstaller.exe", "compattelrunner.exe", "mpcmdrun.exe", "wsqmcons.exe",
    "disksnapshot.exe", "defrag.exe", "cleanmgr.exe", "dmclient.exe",
    "apphostreg istrationverifier.exe", "locationnotificationwindows.exe",
}

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

def collect_file_create_events(watch_dirs: list | None = None) -> list[dict]:
    """TEMP, APPDATA, Startup 폴더 파일 생성 탐지 (Sysmon ID 11 대체)"""
    if watch_dirs is None:
        watch_dirs = [
            r"C:\Windows\Temp",
            r"C:\Users\Public",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        ]
    events = []
    try:
        dirs = ",".join(f'"{d}"' for d in watch_dirs)
        cmd = [
            "powershell", "-Command",
            f"Get-ChildItem -Path {dirs} -Recurse -ErrorAction SilentlyContinue "
            "| Select-Object FullName, CreationTime, Length | ConvertTo-Json -Depth 2"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.stdout.strip():
            raw = json.loads(result.stdout)
            if isinstance(raw, dict):
                raw = [raw]
            for item in raw:
                events.append({
                    "event_id": 11,
                    "event_name": "FileCreate",
                    "time": str(item.get("CreationTime", "")),
                    "message": f"File created: {item.get('FullName', '')}",
                })
    except Exception:
        pass
    return events

def clear_sysmon_log() -> None:
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
    events = collect_sysmon_events()
    print(f"Collected {len(events)} Sysmon events")
    save_sysmon_events(events, Path("sysmon_events.json"))