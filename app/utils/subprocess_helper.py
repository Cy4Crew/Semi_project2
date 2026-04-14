from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass
class CompletedProcessResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


_DECODE_CANDIDATES = ("utf-8", "cp949", "utf-16", "latin-1")


def decode_bytes(data: bytes | None) -> str:
    raw = data or b""
    for enc in _DECODE_CANDIDATES:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def run_command(
    args: Sequence[str],
    *,
    timeout: int | float | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    check: bool = False,
    preexec_fn=None,
) -> CompletedProcessResult:
    proc = subprocess.run(
        list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        cwd=cwd,
        env=env,
        check=check,
        preexec_fn=preexec_fn,
    )
    return CompletedProcessResult(
        args=list(args),
        returncode=int(proc.returncode),
        stdout=decode_bytes(proc.stdout),
        stderr=decode_bytes(proc.stderr),
    )
