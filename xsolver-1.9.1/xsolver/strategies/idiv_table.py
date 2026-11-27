from __future__ import annotations

import time

from xsolver.analysis.idiv_table import find_idiv_tables
from xsolver.core.modes import is_argv
from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

MAX_CANDIDATES = 60
MIN_KEY_LEN = 4
MAX_KEY_LEN = 24

def _middles(text: str, output: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def add(mid: str) -> None:
        if mid and mid not in seen:
            seen.add(mid)
            out.append(mid)

    for split in range(len(output) + 1):
        prefix, suffix = output[:split], output[split:]
        if not text.startswith(prefix) or not text.endswith(suffix):
            continue
        if len(text) < len(prefix) + len(suffix):
            continue
        add(text[len(prefix):len(text) - len(suffix)] if suffix else text[len(prefix):])
    if not out:
        for split in range(len(output) + 1):
            suffix = output[split:]
            if suffix and text.endswith(suffix):
                add(text[:len(text) - len(suffix)])
    if not out:
        for split in range(len(output) + 1):
            prefix = output[:split]
            if prefix and text.startswith(prefix):
                add(text[len(prefix):])
    if not out:
        add(text)
    return out

def _segments(mid: str) -> list[str]:
    out: list[str] = []
    upper = min(MAX_KEY_LEN, len(mid))
    for size in range(MIN_KEY_LEN, upper + 1):
        out.append(mid[:size])
    for size in range(MIN_KEY_LEN, upper + 1):
        out.append(mid[len(mid) - size:])
    if MIN_KEY_LEN <= len(mid) <= MAX_KEY_LEN:
        out.append(mid)
    return out

class IdivTableStrategy(Strategy):
    name = "idiv-table"

    def _modes(self) -> list[str]:
        modes = [self.triage.likely_input_mode]
        if not is_argv(self.triage.likely_input_mode):
            modes.append("argv")
        if self.triage.likely_input_mode != "stdin":
            modes.append("stdin")
        return modes

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()

        def finish(found: bool, key: str | None, mode: str | None,
                   tried: int, outcome: str, detail: str) -> StrategyResult:
            return StrategyResult(
                found=found,
                key=key,
                input_mode=mode,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=tried,
                    duration_seconds=time.monotonic() - start,
                    outcome=outcome,
                    detail=detail,
                ),
            )

        try:
            tables = find_idiv_tables(self.binary_path)
        except Exception as exc:
            return finish(False, None, None, 0, "error", f"table scan failed: {exc}")
        if not tables:
            return finish(False, None, None, 0, "exhausted", "no idiv-indexed table")

        tried = 0
        detail = "no candidate verified"
        for mode in self._modes():
            if self._time_left(start) <= 0:
                break
            try:
                baseline = self._try_candidate("", mode)
            except Exception:
                continue
            output = (baseline.stdout + baseline.stderr).decode("latin-1", "replace")
            output = output.rstrip("\r\n")
            for text in tables:
                for mid in _middles(text, output):
                    for candidate in _segments(mid):
                        if tried >= MAX_CANDIDATES or self._time_left(start) <= 0:
                            break
                        tried += 1
                        try:
                            result = self._try_candidate(candidate, mode)
                            if self._is_win(candidate, mode, result, success_detector):
                                return finish(
                                    True, candidate, mode, tried, "success",
                                    f"idiv table decoded, key via {mode}",
                                )
                        except Exception:
                            continue
                        detail = "candidate rejected"
                if tried >= MAX_CANDIDATES or self._time_left(start) <= 0:
                    break
            if tried >= MAX_CANDIDATES:
                break
        return finish(False, None, None, tried, "exhausted", detail)
