from __future__ import annotations

import re
import time
from pathlib import Path

from xsolver.core.binary import BinaryProfile
from xsolver.core.hostenv import launcher

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,38}\.[A-Za-z0-9]{1,5}$")
_EXT_RE = re.compile(r"^[A-Za-z0-9]{1,5}$")
_STEM_RE = re.compile(r"^[a-z0-9_-]{2,12}$")
_DENY_EXT = {"so", "dll", "exe", "sys", "ocx", "drv", "pdb", "obj", "lib", "c", "h",
             "hpp", "cpp", "cc", "md", "py", "o", "a", "def", "rc", "res"}
_DENY_STEMS = {"libc", "libm", "libdl", "ld", "glibc", "kernel32", "msvcrt", "ntdll",
               "user32", "advapi32", "ucrtbase", "completed"}
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{2,64}")
_SKIP_SUFFIXES = {
    ".dll", ".exe", ".sys", ".ocx", ".drv", ".pdb", ".manifest", ".obj", ".lib",
    ".a", ".o", ".so", ".dylib", ".c", ".h", ".cpp", ".py", ".txt.md",
}
_SKIP_NAMES = {"ntdll.dll", "kernel32.dll", "msvcrt.dll"}

_PROBE_SCRIPT = """
var targets = [
  ['msvcrt.dll', 'fopen', 0], ['msvcrt.dll', '_wfopen', 1], ['msvcrt.dll', 'fopen_s', 1],
  ['msvcrt.dll', '_open', 0], ['ucrtbase.dll', 'fopen', 0], ['ucrtbase.dll', 'fopen_s', 1],
  ['kernel32.dll', 'CreateFileA', 0], ['kernel32.dll', 'CreateFileW', 1],
  ['kernel32.dll', 'GetFileAttributesA', 0], ['kernel32.dll', 'GetFileAttributesW', 1]
];
var seen = {};
targets.forEach(function (item) {
  var module = item[0], name = item[1], wide = item[2];
  try {
    var address = Module.getExportByName(module, name);
    Interceptor.attach(address, {
      onEnter: function (args) {
        var text = null;
        try { text = wide ? args[0].readUtf16String() : args[0].readUtf8String(); } catch (error) {}
        if (text && !seen[text]) { seen[text] = 1; send({fn: name, path: text}); }
      }
    });
  } catch (error) {}
});
"""

_last_error: str | None = None

def last_error() -> str | None:
    return _last_error

def _same_image(reported: str, wanted: str) -> bool:
    tail = reported.replace("\\", "/").rsplit("/", 1)[-1]
    return tail.lower() == wanted.lower()

def _plausible_name(text: str) -> bool:
    if not _NAME_RE.match(text) or ".." in text or "/" in text or "\\" in text:
        return False
    if text.count(".") != 1:
        return False
    stem, _, extension = text.partition(".")
    if not stem or not _EXT_RE.match(extension) or extension.isdigit():
        return False
    if extension.lower() in _DENY_EXT or stem.lower() in _DENY_STEMS:
        return False
    if stem.lower() in _SKIP_NAMES:
        return False
    if not any(character.islower() for character in stem):
        return False
    return True

def static_side_names(profile: BinaryProfile, limit: int = 6) -> list[str]:
    strings = [match.decode("latin-1").strip() for match in _PRINTABLE_RE.findall(profile.raw)]
    names: list[str] = []
    for text in strings:
        if _plausible_name(text) and text not in names:
            names.append(text)
        if len(names) >= limit:
            break
    if len(names) < limit:
        for index, text in enumerate(strings):
            if "%s" not in text or "." not in text or index < 2:
                continue
            left, right = strings[index - 2], strings[index - 1]
            if not _STEM_RE.match(left) or not _STEM_RE.match(right):
                continue
            for combined in (f"{right}.{left}", f"{left}.{right}"):
                if combined not in names and _plausible_name(combined):
                    names.append(combined)
                if len(names) >= limit:
                    return names
    return names

def probe_side_names(binary_path: Path, timeout: float = 6.0) -> list[str]:
    global _last_error
    _last_error = None
    try:
        import frida
    except ImportError:
        _last_error = "frida not installed"
        return []
    import subprocess

    binary_path = Path(binary_path)
    command = launcher(str(binary_path))
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                cwd=str(binary_path.parent))
    except OSError as exc:
        _last_error = str(exc)
        return []
    pid = None
    deadline = time.time() + timeout
    events: list[dict] = []
    session = None
    try:
        device = frida.get_local_device()
    except Exception as exc:
        _last_error = f"no frida device: {exc}"
        proc.kill()
        return []
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
            time.sleep(0.05)
    if pid is not None:
        try:
            session = frida.attach(pid)
            script = session.create_script(_PROBE_SCRIPT)
            script.on("message", lambda message, data: events.append(message.get("payload", {})))
            script.load()
        except Exception as exc:
            _last_error = f"attach failed: {exc}"
    else:
        _last_error = _last_error or "target exited before attach"
    if session:
        time.sleep(0.4)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except (OSError, ValueError):
        pass
    end = time.time() + 1.5
    while time.time() < end and proc.poll() is None:
        time.sleep(0.05)
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

    names: list[str] = []
    for event in events:
        raw = str(event.get("path") or "")
        tail = raw.replace("\\", "/").rsplit("/", 1)[-1]
        if not tail or (binary_path.parent / tail).exists():
            continue
        if tail not in names and _NAME_RE.match(tail):
            names.append(tail)
    return names

def side_file_names(binary_path: Path, profile: BinaryProfile | None = None) -> list[str]:
    names: list[str] = []
    try:
        names.extend(probe_side_names(Path(binary_path)))
    except Exception:
        pass
    if profile is not None:
        for name in static_side_names(profile):
            if name not in names:
                names.append(name)
    return names[:4]
