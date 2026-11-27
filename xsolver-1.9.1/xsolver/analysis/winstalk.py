from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from xsolver.core.hostenv import IS_WINDOWS, base_env, launcher, module_ranges

ATTACH_SECONDS = 6.0
_last_error: str | None = None

_last_error = None

def last_error() -> str | None:
    return _last_error

def _same_image(reported: str, wanted: str) -> bool:
    tail = reported.replace("\\", "/").rsplit("/", 1)[-1]
    return tail.lower() == wanted.lower()

def _wine_env() -> dict[str, str]:
    if IS_WINDOWS:
        return base_env()
    env = dict(os.environ)
    env.setdefault("WINEPREFIX", str(Path.home() / ".cache/xsolver-wine"))
    env["WINEDEBUG"] = "-all"
    env.setdefault("XDG_RUNTIME_DIR", "/tmp/rt")
    env.setdefault("DISPLAY", ":99")
    return env

def _image_range(pid: int, image_name: str) -> tuple[int, int] | None:
    if IS_WINDOWS:
        for path, base, size in module_ranges(pid):
            if _same_image(path, image_name):
                return base, base + size
        return None
    low, high = None, None
    try:
        lines = Path(f"/proc/{pid}/maps").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) < 6 or not parts[5].lower().endswith((".exe", ".dll")):
            continue
        if not _same_image(parts[5], image_name):
            continue
        start, end = (int(value, 16) for value in parts[0].split("-"))
        low = start if low is None else min(low, start)
        high = end if high is None else max(high, end)
    if low is None or high is None:
        return None
    return low, high

STALKER = r"""
var imageLow = ptr('0x{low:x}');
var imageHigh = ptr('0x{high:x}');
var seen = {{}};
var count = 0;
var threads = Process.enumerateThreads();
var followed = 0;
threads.forEach(function (thread) {{
  try {{
    Stalker.follow(thread.id, {{
      events: {{ exec: true }},
      transform: function (iterator) {{
        var instruction = iterator.next();
        do {{
          count++;
          var in_image = instruction.address.compare(imageLow) >= 0 && instruction.address.compare(imageHigh) < 0;
          if (in_image) seen[instruction.address.toString()] = 1;
          iterator.keep();
        }} while ((instruction = iterator.next()) !== null);
      }}
    }});
    followed++;
  }} catch (e) {{}}
}});
rpc.exports = {{
  stop: function () {{
    Stalker.unfollow();
    Stalker.garbageCollect();
    Stalker.flush();
    var total = 0;
    for (var key in seen) total++;
    return {{ instructions: count, blocks: total, threads: followed }};
  }}
}};
"""

def coverage(binary_path: Path, stdin_data: bytes = b"", timeout: float = 6.0) -> dict | None:
    global _last_error
    _last_error = None
    try:
        import frida
    except ImportError:
        _last_error = "frida not installed"
        return None
    binary_path = Path(binary_path)
    proc = subprocess.Popen(launcher(binary_path), stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            cwd=str(binary_path.parent), env=_wine_env())
    pid = None
    deadline = time.time() + ATTACH_SECONDS
    try:
        device = frida.get_local_device()
    except Exception as exc:
        _last_error = f"no device: {exc}"
        proc.kill()
        return None
    while time.time() < deadline and pid is None:
        if proc.poll() is not None:
            break
        try:
            for item in device.enumerate_processes():
                if _same_image(item.name, binary_path.name):
                    pid = item.pid
                    break
        except Exception:
            pass
        if pid is None:
            time.sleep(0.1)
    if pid is None:
        _last_error = "target exited before attach"
        try:
            proc.kill()
        except OSError:
            pass
        return None
    span = _image_range(pid, binary_path.name)
    if span is None:
        _last_error = "image not mapped yet"
        proc.kill()
        return None
    result = None
    session = None
    try:
        session = frida.attach(pid)
        script = session.create_script(STALKER.format(low=span[0], high=span[1]))
        script.load()
        try:
            if stdin_data:
                proc.stdin.write(stdin_data)
                proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass
        end = time.time() + timeout
        while time.time() < end and proc.poll() is None:
            time.sleep(0.05)
        try:
            result = script.exports_sync.stop()
        except Exception as exc:
            _last_error = f"stalker stop failed: {exc}"
    except Exception as exc:
        _last_error = f"stalker failed: {exc}"
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            proc.kill()
        if session:
            try:
                session.detach()
            except Exception:
                pass
    if result is None:
        return None
    return {"instructions": int(result.get("instructions", 0)),
            "blocks": int(result.get("blocks", 0))}
