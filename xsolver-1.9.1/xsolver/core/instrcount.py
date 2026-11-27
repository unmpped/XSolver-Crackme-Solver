from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_GUEST_INSTRS_RE = re.compile(rb"guest instrs:\s*([\d,]+)")

@dataclass
class InstructionCountResult:
    count: int | None
    stdout: bytes
    exit_code: int | None
    timed_out: bool
    unit: str = "instructions"

def valgrind_available() -> bool:
    return shutil.which("valgrind") is not None

def _is_pe(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False

def pe_counter_available() -> bool:
    from xsolver.core import importcount
    return importcount.available()

def oracle_available(binary_path: str | Path) -> bool:
    if _is_pe(Path(binary_path)):
        return pe_counter_available()
    return valgrind_available()

def counter_unit(binary_path: str | Path) -> str:
    return "library calls" if _is_pe(Path(binary_path)) else "guest instructions"

def _count_pe(binary_path: Path, argv: list[str] | None, stdin_data: bytes | None,
              timeout_seconds: float, command: list[str] | None) -> InstructionCountResult:
    from xsolver.core import importcount
    count = importcount.count_calls(binary_path, argv=argv, stdin_data=stdin_data,
                                    timeout_seconds=timeout_seconds, command=command)
    return InstructionCountResult(count=count, stdout=b"", exit_code=None,
                                  timed_out=False, unit="library calls")

def count_instructions(
    binary_path: str | Path,
    argv: list[str] | None = None,
    stdin_data: bytes | None = None,
    timeout_seconds: float = 10.0,
) -> InstructionCountResult:
    resolved_path = Path(binary_path).resolve()
    if _is_pe(resolved_path):
        return _count_pe(resolved_path, argv, stdin_data, timeout_seconds, command=None)
    try:
        mode = resolved_path.stat().st_mode
        if not mode & 0o111:
            resolved_path.chmod(mode | 0o111)
    except OSError:
        pass
    cmd = ["valgrind", "--tool=lackey", "--basic-counts=yes", "--", str(resolved_path)] + (argv or [])

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            cwd=str(resolved_path.parent),
            env={"PATH": "/usr/bin:/bin"},
        )
    except subprocess.TimeoutExpired:
        return InstructionCountResult(count=None, stdout=b"", exit_code=None, timed_out=True)
    except (OSError, PermissionError):
        return InstructionCountResult(count=None, stdout=b"", exit_code=None, timed_out=False)

    match = _GUEST_INSTRS_RE.search(proc.stderr)
    count = int(match.group(1).replace(b",", b"")) if match else None

    return InstructionCountResult(
        count=count,
        stdout=proc.stdout,
        exit_code=proc.returncode,
        timed_out=False,
    )
