from __future__ import annotations

import os
from pathlib import Path

from xsolver.core.pepatch import PatchResult, patched_copy, verify_patch

_CACHE: dict[str, tuple[Path | None, list[str]]] = {}
_REASONS: dict[str, str] = {}

_PATCH_APIS = (
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "NtSetInformationThread", "NtQuerySystemInformation", "NtYieldExecution",
    "OutputDebugStringA", "OutputDebugStringW", "DebugBreak", "GetThreadContext",
    "IsProcessorFeaturePresent", "GetTickCount", "GetTickCount64", "timeGetTime",
    "QueryPerformanceCounter", "QueryPerformanceFrequency",
)

def enabled() -> bool:
    return os.environ.get("XSOLVER_NO_ANTIDEBUG", "").strip() not in ("1", "true", "yes")

def _verdict(output: bytes) -> str | None:
    from xsolver.analysis.prompts import classify

    try:
        return classify(output.decode("latin-1"))
    except Exception:
        return None

def _probe(path: Path) -> list[dict]:
    from xsolver.core.runner import RunnerLimits
    from xsolver.core.runtime import run_on_target

    results = []
    for data in (None, b"\n"):
        try:
            run = run_on_target(path, argv=[], stdin_data=data,
                                limits=RunnerLimits(timeout_seconds=10), use_patch=False)
        except Exception as exc:
            results.append({"error": str(exc)[:120], "output": b"", "crashed": True,
                            "timed_out": True, "exit": -1})
            continue
        results.append({"output": (run.stdout or b"") + (run.stderr or b""),
                        "crashed": bool(run.crashed), "timed_out": bool(run.timed_out),
                        "exit": run.exit_code})
    return results

def _compatible(original: list[dict], patched: list[dict]) -> tuple[bool, str]:
    for before, after in zip(original, patched):
        if after.get("crashed") and not before.get("crashed"):
            return False, "patched copy crashes"
        if after.get("timed_out") and not before.get("timed_out"):
            return False, "patched copy hangs"
        if before.get("output") and not after.get("output"):
            return False, "patched copy went silent"
        if (before.get("exit") == 0 and after.get("exit") not in (0, None)
                and before.get("output") and after.get("output")):
            return False, "patched copy turned a success into a failure"
        before_verdict = _verdict(before.get("output") or b"")
        after_verdict = _verdict(after.get("output") or b"")
        if after_verdict == "failure" and before_verdict in ("progress", "success"):
            return False, "patched copy now reports a failure (integrity check?)"
    return True, ""

def patched_for(path: str | Path) -> Path | None:
    if not enabled():
        return None
    key = str(Path(path).resolve())
    if key in _CACHE:
        return _CACHE[key][0]
    target = Path(path)
    if target.suffix.lower() not in (".exe", ".dll", ".scr", ".com", ""):
        _CACHE[key] = (None, [])
        return None
    try:
        head = target.read_bytes()[:2]
    except OSError:
        _CACHE[key] = (None, [])
        return None
    if head != b"MZ":
        _CACHE[key] = (None, [])
        return None

    result: PatchResult = patched_copy(target, apis=list(_PATCH_APIS), rdtsc=True)
    if not result.applied:
        _REASONS[key] = result.error or "nothing to patch"
        _CACHE[key] = (None, [])
        return None
    destination = result.destination
    if destination is None or not destination.exists() or not verify_patch(destination, result):
        _REASONS[key] = "patch verification failed"
        _CACHE[key] = (None, [])
        return None
    compatible, reason = _compatible(_probe(target), _probe(destination))
    if not compatible:
        _REASONS[key] = reason
        _CACHE[key] = (None, [])
        return None
    _CACHE[key] = (destination, result.patched)
    return destination

def patched_apis(path: str | Path) -> list[str]:
    key = str(Path(path).resolve())
    if key not in _CACHE:
        patched_for(path)
    return list(_CACHE.get(key, (None, []))[1])

def fallback_reason(path: str | Path) -> str:
    key = str(Path(path).resolve())
    if key not in _CACHE:
        patched_for(path)
    return _REASONS.get(key, "")

def patch_summary(path: str | Path) -> str:
    apis = patched_apis(path)
    if not apis:
        reason = fallback_reason(path)
        return f"antidebug not neutralised ({reason})" if reason else ""
    return "antidebug neutralised: " + ", ".join(apis)
