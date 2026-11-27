from __future__ import annotations

import subprocess
import time
from pathlib import Path

from xsolver.core.hostenv import base_env, launcher

HOOK = """
try {{
    Interceptor.attach(ptr('0x{addr:x}'), {{
        onEnter: function () {{ send({{ count: 1, name: '{name}' }}); }}
    }});
}} catch (error) {{}}
"""

def available() -> bool:
    try:
        import frida
    except ImportError:
        return False
    return True

def _same_image(reported: str, wanted: str) -> bool:
    return reported.replace("\\", "/").rsplit("/", 1)[-1].lower() == wanted.lower()

def _import_names(path: Path) -> list[str]:
    try:
        import pefile
    except ImportError:
        return []
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        return []
    names: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for symbol in entry.imports:
            if symbol.name:
                value = symbol.name.decode("latin-1")
                if value not in names:
                    names.append(value)
    return names

def count_calls(binary_path: str | Path, argv: list[str] | None = None,
                stdin_data: bytes | None = None, timeout_seconds: float = 10.0,
                command: list[str] | None = None) -> int | None:
    if not available():
        return None
    import frida

    from xsolver.analysis.winintercept import _exports, _image_modules

    resolved = Path(binary_path).resolve()
    wanted = _import_names(resolved)[:400]
    if not wanted:
        return None
    cmd = command or (launcher(str(resolved)) + list(argv or []))
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=str(resolved.parent),
                                env=base_env())
    except (OSError, PermissionError):
        return None
    session = None
    state = {"total": 0, "detail": {}}
    try:
        device = frida.get_local_device()
        pid = None
        deadline = time.time() + min(8.0, max(2.0, timeout_seconds))
        while time.time() < deadline and pid is None:
            if proc.poll() is not None:
                break
            for item in device.enumerate_processes():
                if _same_image(item.name, resolved.name):
                    pid = item.pid
                    break
            if pid is None:
                time.sleep(0.03)
        if pid is None:
            return None
        time.sleep(0.15)
        snippets = []
        for path, base in _image_modules(pid):
            table = _exports(path)
            for name in wanted:
                offset = table.get(name)
                if offset is None:
                    continue
                snippets.append(HOOK.format(addr=base + offset, name=name))
        if not snippets:
            return None
        source = "".join(snippets)
        session = frida.attach(pid)
        script = session.create_script(source)

        def on_message(message, data):
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("count"):
                state["total"] += 1
                name = payload.get("name")
                if name:
                    state["detail"][name] = state["detail"].get(name, 0) + 1

        script.on("message", on_message)
        script.load()
        try:
            if stdin_data:
                proc.stdin.write(stdin_data)
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass
        try:
            proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            return None
        try:
            proc.stdout.read()
        except Exception:
            pass
        time.sleep(0.15)
        return int(state["total"])
    except Exception:
        return None
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass

def measure_pair(binary_path: str | Path, argv: list[str] | None = None,
                 stdin_data: bytes | None = None, timeout_seconds: float = 10.0,
                 rounds: int = 2) -> int | None:
    for _ in range(max(1, rounds)):
        value = count_calls(binary_path, argv=argv, stdin_data=stdin_data,
                            timeout_seconds=timeout_seconds)
        if value is not None:
            return value
    return None
