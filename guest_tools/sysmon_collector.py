from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path


EVENT_IDS = {
    1: "ProcessCreate",
    3: "NetworkConnect", 
    7: "ImageLoad",
    11: "FileCreate",
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
    for event_id, event_name in EVENT_IDS.items():
        try:
            cmd = [
                "powershell", "-Command",
                f"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                f"-FilterXPath '*[System[EventID={event_id}]]' "
                f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
                f"Select-Object -Property TimeCreated, Id, Message | "
                f"ConvertTo-Json -Depth 3"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.stdout.strip():
                raw = json.loads(result.stdout)
                if isinstance(raw, dict):
                    raw = [raw]
                for item in raw:
                    msg = str(item.get("Message", ""))
                    # 노이즈 프로세스 필터링
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
            continue
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


def save_sysmon_events(events: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    events = collect_sysmon_events()
    print(f"Collected {len(events)} Sysmon events")
    save_sysmon_events(events, Path("sysmon_events.json"))