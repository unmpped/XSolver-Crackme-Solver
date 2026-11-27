from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import termios
except ImportError:
    termios = None

from xsolver.core.binary import BinaryProfile, load_binary
from xsolver.core.hostenv import IS_WINDOWS, base_env
from xsolver.core.pe import imported_modules, parse_pe
from xsolver.core.runner import ExecutionResult, RunnerLimits

def _wine_binary() -> str | None:
    if IS_WINDOWS:
        return None
    for candidate in ("wine", "wine64", "/usr/lib/wine/wine64"):
        found = shutil.which(candidate) if not candidate.startswith("/") else (
            candidate if os.path.exists(candidate) else None
        )
        if found:
            return found
    return None

def _default_wineprefix() -> str:
    env = os.environ.get("XSOLVER_WINEPREFIX")
    if env:
        return env
    fallback = Path.home() / ".cache" / "xsolver-wine"
    for candidate in (fallback, Path.home() / ".wine-xsolver", Path.home() / ".wineprefix", Path.home() / ".wine"):
        if candidate.is_dir():
            return str(candidate)
    return str(fallback)

_PREPARED_PREFIXES: set[str] = set()

_SYSTEM_DLLS = (
    "kernel32", "user32", "gdi32", "advapi32", "shell32", "ole32", "oleaut32",
    "comctl32", "comdlg32", "ws2_32", "wsock32", "winmm", "msvcrt", "ntdll",
    "shlwapi", "version", "uxtheme", "crypt32", "iphlpapi", "riched20", "opengl32",
    "msimg32", "dwmapi", "secur32", "bcrypt", "wininet", "psapi", "dbghelp",
    "msvcp", "msvcr", "vcruntime", "vccorlib", "concrt", "ucrtbase", "mfc",
    "d3d", "dxgi", "dsound", "winspool", "imm32", "wintrust", "normaliz",
    "iertutil", "urlmon", "authid", "netapi32", "userenv", "wtsapi32",
)
_RUNTIME_DLLS = Path(__file__).resolve().parent.parent.parent / "runtime_dlls"
_TOOLS = Path(__file__).resolve().parent.parent.parent / "tools"
_DISPLAY = ":99"
_xvfb_started = False
_MINGW_GCC_GLOBS = (
    "/usr/lib/gcc/*-w64-mingw32/*/*.dll",
    "/usr/x86_64-w64-mingw32/lib/*.dll",
)

def _is_system_dll(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith(("api-ms-win", "ext-ms-win")):
        return True
    return any(lowered.startswith(prefix) for prefix in _SYSTEM_DLLS)

def _dll_search_dirs(path: Path, is_64: bool) -> list[Path]:
    arch = "x64" if is_64 else "x86"
    prefix = Path(os.environ.get("XSOLVER_WINEPREFIX") or _default_wineprefix())
    dirs = [
        path.parent,
        _RUNTIME_DLLS / arch,
        prefix / "drive_c" / "windows" / ("system32" if is_64 else "syswow64"),
        prefix / "drive_c" / "windows" / "system32",
    ]
    for pattern in _MINGW_GCC_GLOBS:
        dirs.extend(Path(p) for p in glob.glob(pattern))
    return [d for d in dirs if d.is_dir()]

def _ensure_xvfb() -> str:
    global _xvfb_started
    if Path(f"/tmp/.X11-unix/X{_DISPLAY[1:]}").exists():
        return _DISPLAY
    if _xvfb_started:
        return _DISPLAY
    xvfb = shutil.which("Xvfb")
    if not xvfb:
        return ""
    try:
        subprocess.Popen([xvfb, _DISPLAY, "-screen", "0", "800x600x24"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except OSError:
        return ""
    _xvfb_started = True
    for _ in range(40):
        if Path(f"/tmp/.X11-unix/X{_DISPLAY[1:]}").exists():
            return _DISPLAY
        time.sleep(0.1)
    return ""

def capture_dialog(path: str | Path, seconds: float = 2.0) -> str:
    if IS_WINDOWS:
        return ""
    import tempfile

    display = _ensure_xvfb()
    if not display:
        return ""
    path = Path(path)
    try:
        is_64 = parse_pe(path.read_bytes()).is_64
    except Exception:
        return ""
    watcher = _TOOLS / ("winwatch64.exe" if is_64 else "winwatch32.exe")
    if not watcher.is_file():
        return ""

    prefix = os.environ.get("XSOLVER_WINEPREFIX") or _default_wineprefix()
    runtime_dir = os.path.join(os.environ.get("TMPDIR", "/tmp"), "runtime-xsolver")
    os.makedirs(runtime_dir, mode=0o700, exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"),
           "WINEDEBUG": "-all", "WINEPREFIX": prefix, "XDG_RUNTIME_DIR": runtime_dir,
           "DISPLAY": display}
    wine = _wine_binary() or "wine"
    log = Path(tempfile.mkstemp(prefix="dialog-", suffix=".txt")[1])
    try:
        subprocess.run([shutil.which("wineserver") or "wineserver", "-k"], env=env,
                       timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        watch = subprocess.Popen([wine, str(watcher), str(int(seconds * 1000) + 500), str(log)],
                                 env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
        target = subprocess.Popen([wine, str(path)], env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  cwd=str(path.parent), start_new_session=True)
        time.sleep(seconds)
        for proc in (target, watch):
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except OSError:
                pass
        watch.wait(timeout=5)
        lines = []
        for line in log.read_text(errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2].strip() and parts[2] not in lines:
                lines.append(parts[2].strip())
        return " / ".join(lines[:4])
    except Exception:
        return ""
    finally:
        try:
            log.unlink()
        except OSError:
            pass

def provision_dependencies(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
        info = parse_pe(data)
        modules = imported_modules(data)
    except Exception:
        return []
    missing = []
    for module in modules:
        if _is_system_dll(module):
            continue
        found = None
        for folder in _dll_search_dirs(path, info.is_64):
            candidate = folder / module
            if candidate.is_file():
                found = candidate
                break
        if found is None:
            missing.append(module)
            continue
        if found.parent != path.parent:
            try:
                shutil.copyfile(found, path.parent / module)
            except OSError:
                missing.append(module)
    return missing

def _ensure_wineprefix(prefix: str) -> None:
    if prefix in _PREPARED_PREFIXES:
        return
    try:
        os.makedirs(prefix, mode=0o700, exist_ok=True)
    except OSError:
        return
    if not os.path.exists(os.path.join(prefix, "system.reg")):
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": os.environ.get("HOME", "/tmp"),
            "WINEDEBUG": "-all",
            "WINEPREFIX": prefix,
            "DISPLAY": "",
        }
        try:
            subprocess.run(["wineboot", "-i"], env=env, timeout=180,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            pass
    _PREPARED_PREFIXES.add(prefix)

def prepare_execution(path: str | Path) -> str:
    profile = load_binary(path)
    if not profile.format.startswith("PE"):
        return "native"
    if _wine_binary() is None:
        return "none"
    prefix = os.environ.get("XSOLVER_WINEPREFIX") or _default_wineprefix()
    _ensure_wineprefix(prefix)
    return "wine"

class RuntimeUnavailable(RuntimeError):
    pass

@dataclass
class TargetRuntime:
    path: Path
    profile: BinaryProfile
    runner: str
    wine_path: str | None = None
    missing_dlls: list[str] = field(default_factory=list)
    console_only: bool = False

    @classmethod
    def for_path(cls, path: str | Path) -> "TargetRuntime":
        path = Path(path)
        profile = load_binary(path)
        is_pe = profile.format.startswith("PE")
        if not is_pe:
            return cls(path=path, profile=profile, runner="native")
        if IS_WINDOWS:
            return cls(path=path, profile=profile, runner="native")
        wine = _wine_binary()
        if wine:
            missing = provision_dependencies(path)
            return cls(path=path, profile=profile, runner="wine", wine_path=wine,
                       missing_dlls=missing)
        return cls(path=path, profile=profile, runner="none")

    @property
    def is_pe(self) -> bool:
        return self.profile.format.startswith("PE")

    @property
    def executable(self) -> bool:
        return self.runner in ("native", "wine")

    def command(self, argv: list[str] | None = None) -> list[str]:
        if self.runner == "wine":
            return [self.wine_path or "wine", str(self.path)] + (argv or [])
        if self.runner == "native":
            return [str(self.path)] + (argv or [])
        raise RuntimeUnavailable(f"{self.path.name}: no way to run a PE (Wine missing)")

    def environment(self) -> dict[str, str]:
        if self.runner == "wine":
            prefix = os.environ.get("XSOLVER_WINEPREFIX") or _default_wineprefix()
            _ensure_wineprefix(prefix)
            runtime_dir = os.path.join(os.environ.get("TMPDIR", "/tmp"), "runtime-xsolver")
            try:
                os.makedirs(runtime_dir, mode=0o700, exist_ok=True)
            except OSError:
                runtime_dir = os.environ.get("TMPDIR", "/tmp")
            return {
                "PATH": "/usr/bin:/bin",
                "HOME": os.environ.get("HOME", "/tmp"),
                "WINEDEBUG": "-all",
                "WINEPREFIX": prefix,
                "XDG_RUNTIME_DIR": runtime_dir,
                "DISPLAY": "",
            }
        return base_env()

    def run(
        self,
        argv: list[str] | None = None,
        stdin_data: bytes | None = None,
        limits: RunnerLimits | None = None,
        side_files: dict[str, bytes] | None = None,
    ) -> ExecutionResult:
        if side_files:
            folder, target = _prepare_side_workspace(self.path, side_files)
            try:
                clone = TargetRuntime.for_path(target)
                return clone.run(argv=argv, stdin_data=stdin_data, limits=limits)
            finally:
                shutil.rmtree(folder, ignore_errors=True)
        if not self.executable:
            raise RuntimeUnavailable(
                f"{self.path.name} is a PE binary and Wine is not installed"
            )
        limits = limits or RunnerLimits()
        if self.runner == "wine":
            limits = RunnerLimits(
                timeout_seconds=max(limits.timeout_seconds, 10.0),
                max_cpu_seconds=max(limits.max_cpu_seconds, 10),
                max_memory_bytes=max(limits.max_memory_bytes, 2 << 30),
                max_output_bytes=limits.max_output_bytes,
            )
            result = _run_direct(self.command(argv), stdin_data, limits, self.environment())
            if self.missing_dlls and not (result.stdout or result.stderr):
                blob = (result.stdout or b"") + (result.stderr or b"")
                if any(marker in blob for marker in _LOAD_FAILURE):
                    raise RuntimeUnavailable(
                        f"{self.path.name}: missing dll {', '.join(self.missing_dlls)}"
                    )
            if _needs_console(self.path, result):
                console = _run_console(self.command(argv), stdin_data, limits, self.environment())
                if console.stdout or console.stderr:
                    self.console_only = True
                    return console
            return result
        return _run_direct(self.command(argv), stdin_data, limits, base_env())

    def run_candidate(self, candidate: str, mode: str, limits: RunnerLimits | None = None,
                      side_files: dict[str, bytes] | None = None):
        from xsolver.core.modes import argv_for, payload_for

        argv = argv_for(mode, candidate)
        if argv is not None:
            return self.run(argv=argv, limits=limits, side_files=side_files)
        return self.run(stdin_data=payload_for(mode, candidate), limits=limits,
                        side_files=side_files)

_SIDE_SUFFIXES = {".dll", ".dat", ".bin", ".txt", ".key", ".cfg", ".ini", ".lic"}

def _prepare_side_workspace(path: Path, side_files: dict[str, bytes]) -> tuple[Path, Path]:
    folder = Path(tempfile.mkdtemp(prefix="xs-side-"))
    target = folder / path.name
    shutil.copyfile(path, target)
    try:
        os.chmod(target, 0o755)
    except OSError:
        pass
    for sibling in path.parent.iterdir():
        if not sibling.is_file() or sibling == path:
            continue
        if sibling.suffix.lower() in _SIDE_SUFFIXES:
            try:
                shutil.copyfile(sibling, folder / sibling.name)
            except OSError:
                pass
    for name, data in side_files.items():
        destination = folder / Path(name).name
        try:
            destination.write_bytes(data)
        except OSError:
            pass
    return folder, target

_RUNTIME_CACHE: dict[str, "TargetRuntime"] = {}

def runtime_for(path: str | Path) -> "TargetRuntime":
    key = str(Path(path).resolve())
    if key not in _RUNTIME_CACHE:
        _RUNTIME_CACHE[key] = TargetRuntime.for_path(key)
    return _RUNTIME_CACHE[key]

def run_on_target(
    path: str | Path,
    argv: list[str] | None = None,
    stdin_data: bytes | None = None,
    limits: RunnerLimits | None = None,
    side_files: dict[str, bytes] | None = None,
    use_patch: bool | None = None,
) -> ExecutionResult:
    effective = path
    if use_patch is not False:
        try:
            from xsolver.core.antidebug import patched_for

            patched = patched_for(path)
            if patched is not None:
                effective = patched
        except Exception as exc:
            PATCH_ERRORS[str(path)] = f"{type(exc).__name__}: {exc}"[:200]
            effective = path
    return runtime_for(effective).run(argv=argv, stdin_data=stdin_data, limits=limits,
                                      side_files=side_files)

_CONSOLE_APIS = (b"WriteConsoleA", b"WriteConsoleW", b"ReadConsoleA", b"ReadConsoleW")

_LOAD_FAILURE = (b"module not found", b"import_dll", b"c0000135", b"err:module",
                 b"could not load", b"cannot find module")

_CONSOLE_HINT_CACHE: dict[tuple[str, int, int], bool] = {}
PATCH_ERRORS: dict[str, str] = {}

def _needs_console(path: Path, result) -> bool:
    if result.stdout or result.stderr or result.timed_out:
        return False
    try:
        stat = Path(path).stat()
        key = (str(path), stat.st_size, int(stat.st_mtime))
    except OSError:
        return False
    cached = _CONSOLE_HINT_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        blob = Path(path).read_bytes()
    except OSError:
        return False
    value = any(api in blob for api in _CONSOLE_APIS)
    _CONSOLE_HINT_CACHE[key] = value
    return value

def _run_console(cmd, stdin_data, limits: RunnerLimits, env) -> ExecutionResult:
    import errno
    import select
    import time

    try:
        import pty
    except ImportError:
        return ExecutionResult(None, b"", b"no pty", False, False)

    master, slave = pty.openpty()
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~(termios.ECHO | termios.ICANON)
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
    except (OSError, AttributeError):
        pass
    try:
        proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                                env=env, start_new_session=True,
                                preexec_fn=_limits_fn(limits))
    except OSError as exc:
        os.close(master)
        os.close(slave)
        return ExecutionResult(None, b"", str(exc).encode(), False, True)
    os.close(slave)

    buffer = bytearray()
    deadline = time.monotonic() + max(0.5, limits.timeout_seconds)
    timed_out = False
    if stdin_data:
        time.sleep(0.35)
        try:
            os.write(master, stdin_data.replace(b"\n", b"\r"))
        except OSError:
            pass
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except OSError:
                pass
            break
        ready, _, _ = select.select([master], [], [], min(remaining, 0.2))
        if ready:
            try:
                chunk = os.read(master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                chunk = b""
            if not chunk:
                break
            if len(buffer) < limits.max_output_bytes:
                buffer.extend(chunk[: limits.max_output_bytes - len(buffer)])
        elif proc.poll() is not None:
            break
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.close(master)
    crashed = proc.returncode is not None and proc.returncode < 0 and not timed_out
    return ExecutionResult(proc.returncode, bytes(buffer), b"", timed_out, crashed)

def _limits_fn(limits: RunnerLimits):
    from xsolver.core.runner import _apply_limits

    base = _apply_limits(limits)

    def apply() -> None:
        try:
            base()
        except OSError:
            pass

    return apply

def _run_direct(cmd, stdin_data, limits: RunnerLimits, env) -> ExecutionResult:
    from xsolver.core.runner import run_bounded

    return run_bounded(
        cmd,
        stdin_data,
        limits,
        env=env,
        cwd=str(Path(cmd[-1]).parent) if cmd else None,
        start_new_session=True,
    )
