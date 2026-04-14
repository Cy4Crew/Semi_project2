from __future__ import annotations

import json
import shutil
from pathlib import Path

from app.core.config import settings
from app.utils.subprocess_helper import run_command


def run_suricata_on_pcap(pcap_path: str | None, artifact_root: str) -> dict:
    if not pcap_path:
        return {"enabled": False, "reason": "pcap_missing", "alerts": []}
    binary = str(getattr(settings, "suricata_binary", "") or "")
    if not binary:
        binary = shutil.which("suricata") or ""
    if not binary:
        return {"enabled": False, "reason": "suricata_binary_missing", "alerts": []}

    pcap = Path(pcap_path)
    if not pcap.exists():
        return {"enabled": False, "reason": "pcap_not_found", "alerts": []}

    out_dir = Path(artifact_root) / "suricata"
    out_dir.mkdir(parents=True, exist_ok=True)
    eve_path = out_dir / "eve.json"
    rule_path = Path(getattr(settings, "suricata_rules_path", "") or (Path(settings.yara_rules_dir).parent / "rules" / "suricata.rules"))

    args = [binary, "-r", str(pcap), "-l", str(out_dir)]
    if rule_path.exists():
        args.extend(["-S", str(rule_path)])

    try:
        result = run_command(args, timeout=120, cwd=str(out_dir))
    except Exception as exc:
        return {"enabled": True, "reason": f"suricata_failed:{exc}", "alerts": []}

    alerts = []
    if eve_path.exists():
        for line in eve_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("event_type") == "alert":
                alert = row.get("alert") or {}
                alerts.append({
                    "signature": alert.get("signature"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                    "src_ip": row.get("src_ip"),
                    "dest_ip": row.get("dest_ip"),
                    "dest_port": row.get("dest_port"),
                })
    return {
        "enabled": True,
        "reason": None,
        "alerts": alerts[:100],
        "stdout": result.stdout[:4000],
        "stderr": result.stderr[:4000],
        "eve_path": str(eve_path),
    }
