from __future__ import annotations

import json
import shutil
from pathlib import Path

from app.core.config import settings
from app.utils.subprocess_helper import run_command


def analyze_memory_artifacts(dynamic_result: dict, artifact_root: str) -> dict:
    dumps = []
    for item in dynamic_result.get("memory_dumps", []) or []:
        path = str(item.get("path") or "")
        if path:
            dumps.append(path)
    dump_dir = Path(artifact_root) / "memory"
    if dump_dir.exists():
        for p in dump_dir.glob("*.dmp"):
            dumps.append(str(p))
    dumps = list(dict.fromkeys(dumps))
    if not dumps:
        return {"enabled": False, "reason": "memory_dump_missing", "findings": []}

    volatility = str(getattr(settings, "volatility3_binary", "") or "") or shutil.which("vol") or shutil.which("vol.py") or ""
    if not volatility:
        return {"enabled": False, "reason": "volatility_binary_missing", "findings": [{"dump": d, "status": "collected_only"} for d in dumps]}

    out_dir = Path(artifact_root) / "memory_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = []
    for dump in dumps[:8]:
        dump_path = Path(dump)
        plugins = [
            [volatility, "-f", str(dump_path), "windows.pslist"],
            [volatility, "-f", str(dump_path), "windows.netscan"],
            [volatility, "-f", str(dump_path), "windows.cmdline"],
        ]
        plugin_rows = []
        for args in plugins:
            try:
                res = run_command(args, timeout=180, cwd=str(out_dir))
                plugin_rows.append({"plugin": args[-1], "returncode": res.returncode, "stdout": res.stdout[:5000], "stderr": res.stderr[:2000]})
            except Exception as exc:
                plugin_rows.append({"plugin": args[-1], "error": str(exc)})
        findings.append({"dump": str(dump_path), "plugins": plugin_rows})

    out_path = out_dir / "memory_findings.json"
    out_path.write_text(json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"enabled": True, "reason": None, "findings": findings, "output_path": str(out_path)}
