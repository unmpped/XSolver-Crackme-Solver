from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

SHIM_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void xs_log(const char *kind, const void *data, size_t length) {
    const char *path = getenv("XSOLVER_CAPTURE");
    if (!path || !data || length == 0 || length > 512) return;
    char buffer[1200];
    size_t used = 0;
    used += (size_t)snprintf(buffer + used, sizeof(buffer) - used, "%s:", kind);
    const unsigned char *bytes = (const unsigned char *)data;
    for (size_t i = 0; i < length && used + 3 < sizeof(buffer); i++) {
        used += (size_t)snprintf(buffer + used, sizeof(buffer) - used, "%02x", bytes[i]);
    }
    used += (size_t)snprintf(buffer + used, sizeof(buffer) - used, "\n");
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    ssize_t ignored = write(fd, buffer, used);
    (void)ignored;
    close(fd);
}

int strcmp(const char *a, const char *b) {
    static int (*real)(const char *, const char *);
    if (!real) real = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "strcmp");
    if (a && b) { xs_log("strcmp.a", a, strlen(a)); xs_log("strcmp.b", b, strlen(b)); }
    return real(a, b);
}

int strcasecmp(const char *a, const char *b) {
    static int (*real)(const char *, const char *);
    if (!real) real = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "strcasecmp");
    if (a && b) { xs_log("strcasecmp.a", a, strlen(a)); xs_log("strcasecmp.b", b, strlen(b)); }
    return real(a, b);
}

int strncmp(const char *a, const char *b, size_t n) {
    static int (*real)(const char *, const char *, size_t);
    if (!real) real = (int (*)(const char *, const char *, size_t))dlsym(RTLD_NEXT, "strncmp");
    if (a && b) { xs_log("strncmp.a", a, strnlen(a, n)); xs_log("strncmp.b", b, strnlen(b, n)); }
    return real(a, b, n);
}

int memcmp(const void *a, const void *b, size_t n) {
    static int (*real)(const void *, const void *, size_t);
    if (!real) real = (int (*)(const void *, const void *, size_t))dlsym(RTLD_NEXT, "memcmp");
    if (a && b) { xs_log("memcmp.a", a, n); xs_log("memcmp.b", b, n); }
    return real(a, b, n);
}
"""

@dataclass
class CapturedComparison:
    kind: str
    left: bytes
    right: bytes

    def printable(self, minimum: int = 3) -> list[str]:
        values = []
        for side in (self.left, self.right):
            if len(side) < minimum:
                continue
            if all(0x20 <= byte < 0x7F for byte in side):
                text = side.decode("ascii")
                if text not in values:
                    values.append(text)
        return values

@dataclass
class InterceptionResult:
    comparisons: list[CapturedComparison] = field(default_factory=list)
    output: bytes = b""

    def candidates(self, minimum: int = 3) -> list[str]:
        seen: list[str] = []
        ordered = sorted(self.comparisons, key=lambda c: 0 if c.right else 1)
        for comparison in ordered:
            for text in comparison.printable(minimum):
                if text not in seen:
                    seen.append(text)
        return sorted(seen, key=len, reverse=True)

_SHIM_CACHE = Path(tempfile.gettempdir()) / "xsolver-shim" / "libxscapture.so"
_SHIM_LOCK = _SHIM_CACHE.with_suffix(".lock")

_LAST_ERROR: str | None = None

def last_error() -> str | None:
    return _LAST_ERROR

def _set_error(message: str | None) -> None:
    global _LAST_ERROR
    _LAST_ERROR = message

def _build_shim(compiler: str) -> Path | None:
    _SHIM_CACHE.parent.mkdir(parents=True, exist_ok=True)
    source = _SHIM_CACHE.with_suffix(".c")
    source.write_text(SHIM_SOURCE)
    handle, temporary = tempfile.mkstemp(prefix=".libxscapture-", suffix=".so",
                                         dir=str(_SHIM_CACHE.parent))
    os.close(handle)
    try:
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O1", "-o", temporary, str(source), "-ldl"],
            check=True, capture_output=True, timeout=120,
        )
        os.replace(temporary, _SHIM_CACHE)
    except (subprocess.SubprocessError, OSError) as exc:
        _set_error(f"shim build failed ({exc.__class__.__name__})")
        return None
    finally:
        if os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass
    return _SHIM_CACHE if _SHIM_CACHE.exists() else None

def shim_path() -> Path | None:
    if _SHIM_CACHE.exists():
        return _SHIM_CACHE
    compiler = "cc" if _which("cc") else ("gcc" if _which("gcc") else None)
    if compiler is None:
        _set_error("no C compiler for the shim")
        return None
    try:
        import fcntl
    except ImportError:
        return _build_shim(compiler)
    _SHIM_CACHE.parent.mkdir(parents=True, exist_ok=True)
    with open(_SHIM_LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _SHIM_CACHE.exists():
            return _SHIM_CACHE
        return _build_shim(compiler)

def _which(name: str) -> str | None:
    from shutil import which

    return which(name)

def intercept(path: str | Path, stdin_data: bytes | None = b"zzqqzz\n",
              timeout: float = 25.0, argv: list[str] | None = None) -> InterceptionResult | None:
    _set_error(None)
    library = shim_path()
    if library is None:
        return None

    path = Path(path)
    if not path.exists():
        _set_error(f"missing: {path}")
        return None
    with tempfile.NamedTemporaryFile(prefix="xscapture-", suffix=".log", delete=False) as handle:
        capture_path = Path(handle.name)
    try:
        env = {
            "PATH": "/usr/bin:/bin",
            "LD_PRELOAD": str(library),
            "XSOLVER_CAPTURE": str(capture_path),
        }
        command = [str(path), *(argv or [])]
        try:
            completed = subprocess.run(
                command,
                input=stdin_data or b"",
                capture_output=True,
                timeout=timeout,
                env=env,
                cwd=str(path.parent),
            )
        except subprocess.TimeoutExpired:
            try:
                completed = subprocess.run(command, input=stdin_data or b"",
                                           capture_output=True, timeout=timeout * 2,
                                           env=env, cwd=str(path.parent))
            except subprocess.TimeoutExpired:
                _set_error(f"the target did not finish within {timeout * 2:.0f} s")
                return None
            except (subprocess.SubprocessError, OSError) as exc:
                _set_error(f"launch failed ({exc.__class__.__name__})")
                return None
        except (subprocess.SubprocessError, OSError) as exc:
            _set_error(f"launch failed ({exc.__class__.__name__})")
            return None

        raw = capture_path.read_text(errors="replace")
        comparisons: list[CapturedComparison] = []
        sides: dict[str, bytes] = {}
        for line in raw.splitlines():
            if ":" not in line:
                continue
            kind, payload = line.split(":", 1)
            try:
                data = bytes.fromhex(payload)
            except ValueError:
                continue
            sides[kind] = data
            prefix = "strcmp" if kind.startswith("strcmp") else kind
            left = sides.get(f"{prefix}.a")
            right = sides.get(f"{prefix}.b")
            if left is not None and right is not None:
                if not comparisons or comparisons[-1].left != left or comparisons[-1].right != right:
                    comparisons.append(CapturedComparison(prefix, left, right))
        return InterceptionResult(comparisons=comparisons,
                                  output=completed.stdout + completed.stderr)
    finally:
        try:
            capture_path.unlink()
        except OSError:
            pass

def is_available() -> bool:
    return shim_path() is not None
