from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from xsolver.analysis.triage import TriageResult
from xsolver.core.report import StrategyAttempt
from xsolver.core.runner import ExecutionResult, RunnerLimits

SuccessDetector = Callable[[ExecutionResult], bool]

@dataclass
class StrategyResult:
    found: bool
    key: str | None
    input_mode: str | None
    attempt: StrategyAttempt
    steps: list[str] | None = None

    verify_path: Path | None = None

def _normalize(result: ExecutionResult) -> bytes:
    raw = (result.stdout + result.stderr).lower()
    return b" ".join(raw.split())

NEGATIVE_HINTS = (
    b"wrong", b"incorrect", b"denied", b"invalid", b"try again", b"fail",
    b"error", b"unclosed", b"exception", b"not found", b"cannot",
    b"undefined", b"unknown", b"missing", b"syntax", b"nice try",
    b"ignore", b"decoy", b"not the", b"not it", b"rehearsal",
)
POSITIVE_HINTS = (
    b"correct", b"congrat", b"success", b"welcome", b"granted",
    b"right", b"valid", b"authenticated", b"approved", b"authorized",
    b"nice", b"got it", b"well done", b"unlocked", b"yea", b"great", b"flag{",
    b"cmo{", b"ctf{", b"you win", b"access", b"accepted", b"passed",
    b"hello", b"enjoy", b"master", b"good job", b"let's go",
    b"ok!", b"okay", b"ok", b"cracked", b"bravo", b"bien joue", b"unlocked it",
)

VERDICT_HINTS = (
    b"wrong", b"incorrect", b"denied", b"invalid", b"not ok", b"try again",
    b"nope", b"failure", b"failed", b"bad password", b"fail",
)

def default_success_detector(
    baseline: ExecutionResult,
    negatives: list[ExecutionResult] | None = None,
) -> SuccessDetector:
    negative_outputs = {_normalize(negative) for negative in (negatives or [])}
    negative_outputs.add(_normalize(baseline))
    failure_codes = {baseline.exit_code} if baseline.exit_code is not None else set()
    failure_text_fragments = _extract_fragments(baseline.stdout + baseline.stderr)
    baseline_blob = (baseline.stdout + baseline.stderr).lower()
    negative_counts = {hint: baseline_blob.count(hint) for hint in NEGATIVE_HINTS}
    positive_counts = {hint: baseline_blob.count(hint) for hint in POSITIVE_HINTS}

    def detector(result: ExecutionResult) -> bool:
        if result.timed_out or result.crashed or result.exit_code is None:
            return False
        combined = (result.stdout + result.stderr).lower()
        normalized = _normalize(result)
        if normalized in negative_outputs:
            return False
        if not normalized:
            return False
        if result.exit_code in failure_codes and result.exit_code != 0:
            if any(frag in combined for frag in failure_text_fragments):
                return False
        if any(combined.count(hint) > count for hint, count in negative_counts.items()):
            return False
        if any(combined.count(hint) > count for hint, count in positive_counts.items()):
            return True
        if any(baseline_blob.count(hint) > 0 and combined.count(hint) == 0
               for hint in VERDICT_HINTS):
            return True
        if baseline.exit_code is not None and result.exit_code != baseline.exit_code:
            return True
        return False

    return detector

def _extract_fragments(data: bytes) -> list[bytes]:
    lowered = data.lower()
    fragments = []
    for marker in (b"wrong", b"incorrect", b"denied", b"invalid", b"usage", b"try again"):
        if marker in lowered:
            fragments.append(marker)
    return fragments

class Strategy(ABC):
    name: str = "base"

    def __init__(self, binary_path: Path, triage: TriageResult, limits: RunnerLimits, budget_seconds: float):
        self.binary_path = binary_path
        self.triage = triage
        self.limits = limits
        self.budget_seconds = budget_seconds

    @abstractmethod
    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        raise NotImplementedError

    def _try_candidate(self, candidate: str, input_mode: str) -> ExecutionResult:
        from xsolver.core.runtime import run_on_target

        from xsolver.core.modes import argv_for, payload_for

        argv = argv_for(input_mode, candidate)
        if argv is not None:
            return run_on_target(self.binary_path, argv=argv, limits=self.limits)
        return run_on_target(
            self.binary_path, stdin_data=payload_for(input_mode, candidate), limits=self.limits
        )

    def _is_win(self, candidate: str, mode: str, result: ExecutionResult,
                detector: SuccessDetector) -> bool:
        if not detector(result):
            return False
        from xsolver.core.verify import isolated_success

        return isolated_success(
            lambda text: self._try_candidate(text, mode), candidate, result
        )

    def _time_left(self, start: float) -> float:
        return self.budget_seconds - (time.monotonic() - start)
