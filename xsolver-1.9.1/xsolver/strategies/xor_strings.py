from __future__ import annotations

import time

from xsolver.analysis.xor_strings import xor_string_candidates
from xsolver.core.report import StrategyAttempt
from xsolver.core.modes import is_argv
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

class XorStringsStrategy(Strategy):
    name = "xor-strings"

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        candidates = xor_string_candidates(self.triage.profile.raw)

        modes = [self.triage.likely_input_mode]
        if not is_argv(self.triage.likely_input_mode):
            modes.append("argv")
        if self.triage.likely_input_mode != "stdin":
            modes.append("stdin")

        tried = 0
        for candidate in candidates:
            for mode in modes:
                if self._time_left(start) <= 0:
                    break
                tried += 1
                result = self._try_candidate(candidate, mode)
                if self._is_win(candidate, mode, result, success_detector):
                    return StrategyResult(
                        found=True,
                        key=candidate,
                        input_mode=mode,
                        attempt=StrategyAttempt(
                            strategy=self.name,
                            candidates_tried=tried,
                            duration_seconds=time.monotonic() - start,
                            outcome="success",
                            detail=f"string accepted by {mode} "
                            f"({len(candidates)} candidates)",
                        ),
                    )

        return StrategyResult(
            found=False,
            key=None,
            input_mode=None,
            attempt=StrategyAttempt(
                strategy=self.name,
                candidates_tried=tried,
                duration_seconds=time.monotonic() - start,
                outcome="exhausted",
                detail=f"no xor string out of {len(candidates)} accepted",
            ),
        )
