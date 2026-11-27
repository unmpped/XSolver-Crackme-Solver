from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from xsolver.core.binary import load_binary
from xsolver.analysis import gopcln

FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x1000193
_MAGIC_MUL = 0x159
_MAGIC_DIV = 0x5F
_MAGIC_SHIFT = 0xF

def fnv1a(data: bytes) -> int:
    value = FNV_OFFSET
    for byte in data:
        value ^= byte
        value = (value * FNV_PRIME) & 0xFFFFFFFF
    return value

def build_keystream(seed: bytes, out_len: int) -> bytes:
    if not seed or out_len <= 0:
        return b""
    state = fnv1a(seed)
    seed_len = len(seed)
    out = bytearray(out_len)
    for index in range(out_len):
        mixed = seed[index % seed_len] ^ ((state ^ index) & 0xFFFFFFFF)
        low = mixed & 0xFF
        magic = (((low * _MAGIC_MUL) >> _MAGIC_SHIFT) * _MAGIC_DIV) & 0xFFFFFFFF
        reduced = (mixed - magic) & 0xFFFFFFFF
        out[index] = (reduced + 0x20) & 0xFF
    return bytes(out)

def is_go_keystream(path) -> bool:
    try:
        profile = load_binary(path)
    except Exception:
        return False
    names = set(gopcln.function_names(profile).values())
    return (
        "main.buildKeystream" in names
        and "main.xorWithKeystream" in names
        and "main.main" in names
    )

def _wine_env() -> dict[str, str] | None:
    if os.name == "nt" or os.environ.get("XSOLVER_HOST") == "windows":
        return None
    wine = shutil.which("wine") or shutil.which("wine64")
    if not wine:
        return None
    prefix = os.environ.get("XSOLVER_WINEPREFIX")
    if not prefix:
        fallback = Path.home() / ".cache" / "xsolver-wine"
        for candidate in (fallback, Path.home() / ".wine-xsolver",
                          Path.home() / ".wineprefix", Path.home() / ".wine"):
            if candidate.is_dir():
                prefix = str(candidate)
                break
        else:
            prefix = str(fallback)
    runtime_dir = os.path.join(os.environ.get("TMPDIR", "/tmp"), "runtime-xsolver")
    os.makedirs(runtime_dir, exist_ok=True)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/tmp"),
        "WINEDEBUG": "-all",
        "WINEPREFIX": prefix,
        "XDG_RUNTIME_DIR": runtime_dir,
        "USER": os.environ.get("USER", "user"),
        "USERNAME": os.environ.get("USERNAME", "user"),
        "USERDOMAIN": os.environ.get("USERDOMAIN", ""),
    }

def _clean_name(raw: str) -> str:
    return raw.strip().strip('"').replace("\r", "")

def username_candidates() -> list[str]:
    found: list[str] = []

    def add(name: str) -> None:
        name = _clean_name(name)
        if not name or len(name) > 256:
            return
        if name not in found:
            found.append(name)

    env = _wine_env()
    if env is not None:
        wine = shutil.which("wine") or shutil.which("wine64")
        if wine:
            try:
                proc = subprocess.run(
                    [wine, "whoami"],
                    capture_output=True,
                    timeout=15,
                    env=env,
                )
                if proc.returncode == 0 and proc.stdout:
                    add(proc.stdout.decode("utf-8", "replace"))
            except (OSError, subprocess.SubprocessError):
                pass
            try:
                proc = subprocess.run(
                    [wine, "cmd", "/c", "echo %USERDOMAIN%\\%USERNAME%"],
                    capture_output=True,
                    timeout=15,
                    env=env,
                )
                if proc.returncode == 0 and proc.stdout:
                    add(proc.stdout.decode("utf-8", "replace"))
            except (OSError, subprocess.SubprocessError):
                pass
    else:
        for key in ("USERNAME", "USER", "LOGNAME"):
            value = os.environ.get(key)
            if value:
                add(value)

    for key in ("USERNAME", "USER", "LOGNAME", "USERDOMAIN"):
        value = os.environ.get(key)
        if value:
            add(value)

    expanded: list[str] = []
    for name in found:
        if name not in expanded:
            expanded.append(name)
        if "\\" in name:
            bare = name.split("\\", 1)[1]
            if bare and bare not in expanded:
                expanded.append(bare)
        elif os.environ.get("USERDOMAIN"):
            domain = os.environ["USERDOMAIN"]
            combined = f"{domain}\\{name}"
            if combined not in expanded:
                expanded.append(combined)
    return expanded

def go_keystream_candidates(path, seeds: list[str] | None = None) -> list[str]:
    if not is_go_keystream(path):
        return []
    names = seeds if seeds is not None else username_candidates()
    candidates: list[str] = []
    for seed in names:
        raw = seed.encode("utf-8")
        if not raw:
            continue
        keystream = build_keystream(raw, len(raw))
        if not keystream:
            continue
        try:
            text = keystream.decode("ascii")
        except UnicodeDecodeError:
            text = keystream.decode("latin-1")
        if text and text not in candidates:
            candidates.append(text)
    return candidates
