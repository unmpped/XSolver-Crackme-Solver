from __future__ import annotations

import os
import pty
import re
import select
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from xsolver.core.hostenv import IS_WINDOWS, base_env, launcher, module_ranges

COMPARE_FUNCS = ("strcmp", "_stricmp", "strncmp", "_strnicmp", "memcmp", "wcscmp", "_wcsicmp")
NOISE_WORDS = {
    "c", "", "apppolicygetprocessterminationmethod", "isvalidlocalename", "tr_tr",
    "turkish_turkey.1254", "en_us", "utf-8",
}
MAX_BINARY = 25_000_000
ATTACH_SECONDS = 6.0
READ_BYTES = 64

_last_error: str | None = None

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

def _image_modules(pid: int) -> list[tuple[str, int]]:
    if IS_WINDOWS:
        return [(path, base) for path, base, _ in module_ranges(pid)]
    modules: dict[str, list[int]] = {}
    try:
        lines = Path(f"/proc/{pid}/maps").read_text().splitlines()
    except OSError:
        return []
    for line in lines:
        parts = line.split()
        if len(parts) < 6 or not parts[5].lower().endswith((".dll", ".exe")):
            continue
        low, high = (int(value, 16) for value in parts[0].split("-"))
        modules.setdefault(parts[5], []).append(low)
        modules[parts[5]].append(high)
    return [(path, min(spans)) for path, spans in modules.items()]

def _exports(path: str) -> dict[str, int]:
    try:
        import pefile

        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        return {symbol.name.decode("latin-1"): symbol.address
                for symbol in getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []) if symbol.name}
    except Exception:
        return {}

HOOK_TEMPLATE = (
    "try{{Interceptor.attach(ptr('0x{addr:x}'),{{onEnter:function(a){{"
    "var o={{fn:'{name}',mod:'{mod}'}};"
    "try{{o.x=hexdump(a[0],{{length:{size},header:false,ansi:false}})}}catch(e){{o.x=''}}"
    "try{{o.y=hexdump(a[1],{{length:{size},header:false,ansi:false}})}}catch(e){{o.y=''}}"
    "o.n=-1;try{{o.n=a[2].toInt32()}}catch(e){{}}"
    "send(o);}}}});}}catch(e){{}}"
)

PREAMBLE = "var armed=0;\n"

def _decode(hexdump_text: str) -> bytes:
    out = bytearray()
    for token in hexdump_text.split():
        if len(token) != 2:
            continue
        try:
            out.append(int(token, 16))
        except ValueError:
            continue
    return bytes(out).split(b"\x00")[0]

CODEPAGE = re.compile(r"^\.[A-Za-z0-9_-]{0,20}$")

def _is_noise(left: str, right: str) -> bool:
    low_left, low_right = left.lower(), right.lower()
    if CODEPAGE.match(left) and CODEPAGE.match(right):
        return True
    if CODEPAGE.match(left) or CODEPAGE.match(right):
        return True
    if low_left == low_right:
        return True
    if low_left in NOISE_WORDS or low_right in NOISE_WORDS:
        return True
    if low_left.startswith(("turkish", "american", "english")) or \
       low_right.startswith(("turkish", "american", "english")):
        return True
    return False

@dataclass
class WindowsIntercept:
    comparisons: list[tuple[str, str, str]] = field(default_factory=list)
    hooks: int = 0

    def candidates(self) -> list[str]:
        seen: list[str] = []
        for _, left, right in self.comparisons:
            for value in (left, right):
                if 3 <= len(value) <= 64 and value.isprintable() and value not in seen:
                    seen.append(value)
        return seen

def intercept_windows(binary_path: Path, stdin_data: bytes = b"",
                      argv: list[str] | None = None,
                      timeout: float = 6.0) -> WindowsIntercept | None:
    global _last_error
    _last_error = None
    try:
        import frida
    except ImportError:
        _last_error = "frida not installed"
        return None
    binary_path = Path(binary_path)
    if binary_path.stat().st_size > MAX_BINARY:
        _last_error = "binary too big to attach"
        return None
    command = launcher(binary_path) + list(argv or [])
    master = None
    if IS_WINDOWS:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, cwd=str(binary_path.parent),
                                env=_wine_env())
    else:
        master, slave = pty.openpty()
        proc = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                cwd=str(binary_path.parent), env=_wine_env(),
                                start_new_session=True)
        os.close(slave)
    pid = None
    deadline = time.time() + ATTACH_SECONDS
    device = None
    try:
        device = frida.get_local_device()
    except Exception as exc:
        _last_error = f"no frida device: {exc}"
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
    snippets, count = [], 0
    module_deadline = time.time() + 2.5
    while count == 0 and time.time() < module_deadline:
        time.sleep(0.15)
        snippets, count = [], 0
        for path, base in _image_modules(pid):
            table = _exports(path)
            for name in COMPARE_FUNCS:
                address = table.get(name)
                if address is None:
                    continue
                snippets.append(HOOK_TEMPLATE.format(addr=base + address, name=name,
                                                     mod=Path(path).name, size=READ_BYTES))
                count += 1
    events: list[dict] = []
    session = None
    if snippets:
        source = PREAMBLE + "\n".join(snippets)
        try:
            session = frida.attach(pid)
            script = session.create_script(source)
            script.on("message", lambda message, data: events.append(message.get("payload", {})))
            script.load()
        except Exception as exc:
            _last_error = f"attach failed: {exc}"
    try:
        if stdin_data:
            payload = stdin_data.replace(b"\n", b"\r") if master is not None else stdin_data
            if master is not None:
                os.write(master, payload)
            else:
                proc.stdin.write(payload)
                proc.stdin.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    end = time.time() + timeout
    while time.time() < end and proc.poll() is None:
        if master is None:
            time.sleep(0.05)
            continue
        try:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                os.read(master, 65536)
        except OSError:
            time.sleep(0.05)
    if master is not None:
        try:
            os.close(master)
        except OSError:
            pass
    else:
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
    comparisons: list[tuple[str, str, str]] = []
    for event in events:
        if "x" not in event:
            continue
        left = _decode(event.get("x") or "").decode("latin-1", "replace")
        right = _decode(event.get("y") or "").decode("latin-1", "replace")
        if not left and not right:
            continue
        if _is_noise(left, right):
            continue
        item = (str(event.get("fn")), left, right)
        if item not in comparisons:
            comparisons.append(item)
    if count and not comparisons:
        _last_error = "no crt comparison observed"
    return WindowsIntercept(comparisons=comparisons, hooks=count)
