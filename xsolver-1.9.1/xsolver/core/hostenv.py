from __future__ import annotations

import os
import subprocess
import sys

IS_WINDOWS = os.name == "nt" or os.environ.get("XSOLVER_HOST") == "windows"
IS_LINUX = sys.platform.startswith("linux")

def base_env() -> dict[str, str]:
    if IS_WINDOWS:
        return {k: v for k, v in os.environ.items()
                if k.upper() not in {"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"}}
    return {"PATH": "/usr/bin:/bin"}

def launcher(path: str) -> list[str]:
    if IS_WINDOWS:
        return [str(path)]
    return ["wine", str(path)]

def spawn_kwargs(session: bool = False) -> dict:
    if IS_WINDOWS:
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if session else 0
        return {"creationflags": flags} if flags else {}
    return {"start_new_session": session}

def kill_tree(proc: subprocess.Popen, group: bool = False) -> None:
    if IS_WINDOWS:
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            proc.kill()
        except OSError:
            pass
        return
    if group:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
            return
        except OSError:
            pass
    try:
        proc.kill()
    except OSError:
        pass

def module_ranges(pid: int) -> list[tuple[str, int, int]]:
    if not IS_WINDOWS:
        return []
    try:
        import frida

        session = frida.attach(pid)
    except Exception:
        return []
    try:
        return [(m.path, m.base_address, m.size) for m in session.enumerate_modules()]
    except Exception:
        return []
    finally:
        try:
            session.detach()
        except Exception:
            pass
