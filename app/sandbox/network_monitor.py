from __future__ import annotations

from pathlib import Path

def reserve_pcap_path(path: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path

def start_tcpdump(path: str):
    return None

def stop_tcpdump(proc):
    return None
