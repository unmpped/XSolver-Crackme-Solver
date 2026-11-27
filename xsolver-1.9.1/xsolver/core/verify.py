from __future__ import annotations

import os
from typing import Callable

from xsolver.core.runner import ExecutionResult

_MUTATION_CHARS = "QZ7x_"

_VERIFY_WORKERS = max(1, int(os.environ.get("XSOLVER_VERIFY_WORKERS", "1")))

def _run_safely(run: Callable[[str], ExecutionResult], text: str) -> ExecutionResult | None:
    try:
        return run(text)
    except Exception:
        return None

def _run_many(run: Callable[[str], ExecutionResult],
              texts: list[str]) -> list[ExecutionResult | None]:
    if len(texts) < 2 or _VERIFY_WORKERS < 2:
        return [_run_safely(run, text) for text in texts]
    try:
        from concurrent.futures import ThreadPoolExecutor
    except ImportError:
        return [_run_safely(run, text) for text in texts]
    with ThreadPoolExecutor(max_workers=min(_VERIFY_WORKERS, len(texts))) as pool:
        return list(pool.map(lambda text: _run_safely(run, text), texts))

def normalize(result: ExecutionResult) -> bytes:
    return b" ".join((result.stdout + result.stderr).lower().split())

def _strip_echo(output: bytes, text: str) -> bytes:
    if len(text) < 4:
        return output
    return output.replace(text.lower().encode("latin-1", "replace"), b"")

def mutations(text: str) -> list[str]:
    if not text:
        return []
    variants: list[str] = []
    positions = [0] if len(text) == 1 else [0, len(text) // 2, len(text) - 1]
    for position in positions:
        for char in _MUTATION_CHARS:
            if text[position] != char:
                variants.append(text[:position] + char + text[position + 1:])
                break
    variants.append(text + "Q")
    return variants[:3]

def isolated_success(
    run: Callable[[str], ExecutionResult],
    candidate: str,
    result: ExecutionResult,
    minimum_mutants: int = 2,
) -> bool:
    if result.timed_out or result.crashed or result.exit_code is None:
        return False
    base = normalize(result)
    if not base:
        return False
    observed = []
    variants = mutations(candidate)
    for variant, mutant in zip(variants, _run_many(run, variants)):
        if mutant is None or mutant.timed_out or mutant.crashed:
            continue
        observed.append(_strip_echo(normalize(mutant), variant))
    if len(observed) < minimum_mutants:
        return False
    failure_class = set(observed)
    if len(failure_class) != 1:
        repeats = []
        for again in _run_many(run, [candidate, candidate]):
            if again is None or again.timed_out or again.crashed:
                return False
            repeats.append(_strip_echo(normalize(again), candidate))
        return all(item == _strip_echo(base, candidate) for item in repeats)
    return _strip_echo(base, candidate) not in failure_class
