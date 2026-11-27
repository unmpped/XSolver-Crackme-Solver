from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from xsolver.core.hostenv import base_env

PERF_TYPE_HARDWARE = 0
PERF_COUNT_HW_INSTRUCTIONS = 1
_SYSCALLS = {"x86_64": 298, "amd64": 298, "aarch64": 241, "arm64": 241}
_ATTR_SIZE = 128
_FLAGS = 2 | 4
_available: bool | None = None

@dataclass
class PerfResult:
    count: int | None
    stdout: bytes
    exit_code: int | None
    timed_out: bool

def _libc():
    name = ctypes.util.find_library("c") or "libc.so.6"
    return ctypes.CDLL(name, use_errno=True)

def _syscall_number() -> int | None:
    machine = platform.machine().lower()
    return _SYSCALLS.get(machine)

def _attr() -> bytes:
    buffer = bytearray(_ATTR_SIZE)
    struct.pack_into("<I", buffer, 0, PERF_TYPE_HARDWARE)
    struct.pack_into("<I", buffer, 4, _ATTR_SIZE)
    struct.pack_into("<Q", buffer, 8, PERF_COUNT_HW_INSTRUCTIONS)
    struct.pack_into("<Q", buffer, 40, _FLAGS)
    return bytes(buffer)

def paranoid_level() -> int:
    try:
        with open("/proc/sys/kernel/perf_event_paranoid", "r", encoding="ascii") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return 3

def relax_hint() -> str:
    level = paranoid_level()
    if level <= 1:
        return ""
    return ("perf_event_paranoid=" + str(level) +
            ": run 'sudo sysctl -w kernel.perf_event_paranoid=1' to enable the counter")

def _open_counter(pid: int) -> int | None:
    number = _syscall_number()
    if number is None:
        return None
    try:
        libc = _libc()
    except OSError:
        return None
    attr = _attr()
    handle = ctypes.create_string_buffer(attr, len(attr))
    fd = libc.syscall(ctypes.c_long(number), handle, ctypes.c_int(pid),
                      ctypes.c_int(-1), ctypes.c_int(-1), ctypes.c_ulong(0))
    if fd < 0:
        return None
    return int(fd)

def available(pid: int = 0) -> bool:
    global _available
    if pid == 0 and _available is not None:
        return bool(_available)
    handle = _open_counter(pid)
    if handle is None:
        if pid == 0:
            _available = False
        return False
    try:
        os.close(handle)
    except OSError:
        pass
    if pid == 0:
        _available = True
    return True

def count_instructions(
    binary_path: str | Path,
    argv: list[str] | None = None,
    stdin_data: bytes | None = None,
    timeout_seconds: float = 10.0,
    command: list[str] | None = None,
) -> PerfResult:
    resolved = Path(binary_path).resolve()
    cmd = command or ([str(resolved)] + (argv or []))
    if not available():
        return PerfResult(None, b"", None, False)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=str(resolved.parent),
                                env=base_env())
    except (OSError, PermissionError):
        return PerfResult(None, b"", None, False)
    fd = _open_counter(proc.pid)
    timed_out = False
    try:
        out, _err = proc.communicate(input=stdin_data, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out = b""
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    count = None
    if fd is not None:
        try:
            raw = os.read(fd, 8)
            if len(raw) == 8:
                count = struct.unpack("<Q", raw)[0]
        except OSError:
            count = None
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    return PerfResult(count, out or b"", proc.returncode, timed_out)

def measure_pair(binary_path: str | Path, argv: list[str] | None = None,
                 stdin_data: bytes | None = None, timeout_seconds: float = 10.0,
                 rounds: int = 2) -> int | None:
    best = None
    for _ in range(max(1, rounds)):
        result = count_instructions(binary_path, argv=argv, stdin_data=stdin_data,
                                    timeout_seconds=timeout_seconds)
        if result.count is None:
            continue
        best = result.count if best is None else max(best, result.count)
    return best
