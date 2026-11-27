from __future__ import annotations

from xsolver.core.runner import stdin_payload

ARGV_FILLER = "player"
STDIN_FILLER = "player"
ARGV_MODES = ("argv", "argv2")
STDIN_MODES = ("stdin", "stdin2")

def is_argv(mode: str | None) -> bool:
    return mode in ARGV_MODES

def is_stdin2(mode: str | None) -> bool:
    return mode == "stdin2"

def argv_for(mode: str | None, candidate: str, filler: str = ARGV_FILLER) -> list[str] | None:
    if mode == "argv":
        return [candidate]
    if mode == "argv2":
        return [filler, candidate]
    return None

def payload_for(mode: str | None, candidate: str, filler: str = STDIN_FILLER) -> bytes:
    if mode == "stdin2":
        return (f"{filler}\n{candidate}\n").encode("latin-1", "replace")
    return stdin_payload(candidate)

def probe_argv(mode: str, filler: str = ARGV_FILLER) -> list[str]:
    return [filler, "zzqqzz"] if mode == "argv2" else ["zzqqzz"]

def fallback_modes(likely: str) -> list[str]:
    modes = [likely] if likely and likely != "unknown" else ["stdin", "argv"]
    for extra in ("stdin", "argv"):
        if extra not in modes:
            modes.append(extra)
    return modes
