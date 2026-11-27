from __future__ import annotations

import time

from xsolver.analysis.xor_loop import xor_loop_candidates
from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

MAX_CANDIDATES = 30

class XorLoopStrategy(Strategy):
    name = "xor-loop"

    def _modes(self) -> list[str]:
        modes = ["stdin"]
        likely = self.triage.likely_input_mode
        if likely and likely not in modes:
            modes.append(likely)
        if "argv" not in modes:
            modes.append("argv")
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
            raw = self.binary_path.read_bytes()
            candidates = xor_loop_candidates(raw)
        except Exception as exc:
            return finish(False, None, None, 0, "error", f"xor-loop scan failed: {exc}")
        if not candidates:
            return finish(False, None, None, 0, "exhausted",
                          "no xor decode loop found")
        modes = self._modes()
        tried = 0
        detail = "no candidate verified"
        for candidate, _key in candidates[:MAX_CANDIDATES]:
            for mode in modes:
                if self._time_left(start) <= 0:
                    break
                tried += 1
                try:
                    result = self._try_candidate(candidate, mode)
                    if self._is_win(candidate, mode, result, success_detector):
                        return finish(True, candidate, mode, tried, "success",
                                      f"xor-decode loop, key via {mode}")
                except Exception:
                    continue
                detail = "candidate rejected"
            if self._time_left(start) <= 0:
                break
        return finish(False, None, None, tried, "exhausted", detail)
