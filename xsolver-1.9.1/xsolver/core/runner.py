from __future__ import annotations

import os
import selectors
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from xsolver.core.hostenv import IS_WINDOWS, base_env, kill_tree, spawn_kwargs

try:
    import resource
except ImportError:
    resource = None

@dataclass
class ExecutionResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    crashed: bool
    flooded: bool = False

@dataclass
class RunnerLimits:
    timeout_seconds: float = 2.0
    max_cpu_seconds: int = 2
    max_memory_bytes: int = 256 * 1024 * 1024
    max_output_bytes: int = 64 * 1024

def _apply_limits(limits: RunnerLimits):
    if resource is None:
        return None

    def setter():
        resource.setrlimit(resource.RLIMIT_CPU, (limits.max_cpu_seconds, limits.max_cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (limits.max_memory_bytes, limits.max_memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        try:
            running = len(os.listdir("/proc"))
        except OSError:
            running = 64
        resource.setrlimit(resource.RLIMIT_NPROC, (running + 64, running + 64))
        os.setsid()
    return setter

def _write_stdin(stream, data: bytes | None) -> None:
    try:
        if data:
            stream.write(data)
        stream.flush()
    except (BrokenPipeError, ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass

def _run_threaded(
    cmd: list[str],
    stdin_data: bytes | None,
    limits: RunnerLimits,
    env: dict[str, str] | None,
    cwd: str | None,
    new_session: bool,
) -> ExecutionResult:
    cap = max(1, limits.max_output_bytes)
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            **spawn_kwargs(new_session),
        )
    except (OSError, PermissionError) as exc:
        return ExecutionResult(None, b"", str(exc).encode(), False, True)

    out = bytearray()
    err = bytearray()
    counter = {"produced": 0}

    def reader(stream, sink):
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                if len(sink) < cap:
                    sink.extend(chunk[: cap - len(sink)])
                counter["produced"] += len(chunk)
        except (OSError, ValueError):
            pass

    writer = threading.Thread(target=_write_stdin, args=(proc.stdin, stdin_data), daemon=True)
    readers = [
        threading.Thread(target=reader, args=(proc.stdout, out), daemon=True),
        threading.Thread(target=reader, args=(proc.stderr, err), daemon=True),
    ]
    writer.start()
    for thread in readers:
        thread.start()

    deadline = time.monotonic() + max(0.05, limits.timeout_seconds)
    timed_out = False
    flooded = False
    while proc.poll() is None:
        if counter["produced"] > cap:
            flooded = True
            kill_tree(proc, new_session)
            break
        if time.monotonic() > deadline:
            timed_out = True
            kill_tree(proc, new_session)
            break
        time.sleep(0.02)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        kill_tree(proc, new_session)
    writer.join(timeout=0.5)
    for thread in readers:
        thread.join(timeout=1.0)
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except (OSError, ValueError):
            pass

    stdout = bytes(out)
    stderr = bytes(err)
    if len(stdout) >= cap or len(stderr) >= cap:
        flooded = True
    exit_code = proc.returncode
    crashed = exit_code is not None and exit_code < 0 and not (timed_out or flooded)
    return ExecutionResult(stdout=stdout, stderr=stderr, exit_code=exit_code,
                           timed_out=timed_out, crashed=crashed, flooded=flooded)

def run_bounded(
    cmd: list[str],
    stdin_data: bytes | None,
    limits: RunnerLimits,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    preexec_fn=None,
    start_new_session: bool = False,
) -> ExecutionResult:
    if IS_WINDOWS:
        return _run_threaded(cmd, stdin_data, limits, env, cwd, start_new_session)
    cap = max(1, limits.max_output_bytes)
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            preexec_fn=preexec_fn,
            start_new_session=start_new_session,
        )
    except (OSError, PermissionError) as exc:
        return ExecutionResult(None, b"", str(exc).encode(), False, True)

    writer = threading.Thread(target=_write_stdin, args=(proc.stdin, stdin_data), daemon=True)
    writer.start()

    buffers = {proc.stdout.fileno(): bytearray(), proc.stderr.fileno(): bytearray()}
    selector = selectors.DefaultSelector()
    for stream in (proc.stdout, proc.stderr):
        selector.register(stream, selectors.EVENT_READ)

    deadline = time.monotonic() + max(0.05, limits.timeout_seconds)
    timed_out = False
    flooded = False
    produced = 0

    def drain(timeout: float) -> bool:
        nonlocal produced
        over = False
        for key, _ in selector.select(timeout=timeout):
            try:
                chunk = os.read(key.fileobj.fileno(), 65536)
            except OSError:
                chunk = b""
            if not chunk:
                try:
                    selector.unregister(key.fileobj)
                except (KeyError, ValueError):
                    pass
                continue
            data = buffers[key.fileobj.fileno()]
            if len(data) < cap:
                data.extend(chunk[: cap - len(data)])
            produced += len(chunk)
            if produced > cap:
                over = True
        return over

    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            _kill_process_group(proc, start_new_session)
            break
        if drain(min(remaining, 0.5)):
            flooded = True
            _kill_process_group(proc, start_new_session)
            break

    for _ in range(50):
        if not selector.get_map():
            break
        drain(0.01)
    try:
        selector.close()
    except Exception:
        pass

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc, start_new_session)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    writer.join(timeout=0.2)

    stdout = bytes(buffers[proc.stdout.fileno()]) if not proc.stdout.closed else b""
    stderr = bytes(buffers[proc.stderr.fileno()]) if not proc.stderr.closed else b""
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except (OSError, ValueError):
            pass

    if len(stdout) >= cap or len(stderr) >= cap:
        flooded = True
    exit_code = proc.returncode
    crashed = exit_code is not None and exit_code < 0 and not (timed_out or flooded)
    return ExecutionResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        crashed=crashed,
        flooded=flooded,
    )

def stdin_payload(text: str) -> bytes:
    if text.endswith("\n"):
        return text.encode("latin-1", "replace")
    try:
        return (text + "\n").encode("latin-1")
    except UnicodeEncodeError:
        return (text + "\n").encode("utf-8", "replace")

def run_candidate(
    binary_path: str | Path,
    argv: list[str] | None = None,
    stdin_data: bytes | None = None,
    limits: RunnerLimits | None = None,
    env: dict[str, str] | None = None,
) -> ExecutionResult:
    limits = limits or RunnerLimits()
    resolved_path = Path(binary_path).resolve()
    cmd = [str(resolved_path)] + (argv or [])

    return run_bounded(
        cmd,
        stdin_data,
        limits,
        env=env or base_env(),
        cwd=str(resolved_path.parent),
        preexec_fn=_apply_limits(limits),
    )

def _kill_process_group(proc: subprocess.Popen, new_session: bool = False):
    kill_tree(proc, new_session)
