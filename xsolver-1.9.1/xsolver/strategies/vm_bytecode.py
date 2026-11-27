from __future__ import annotations

import time

from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

class VmBytecodeStrategy(Strategy):
    name = "vm-bytecode"

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()

        try:
            from xsolver.analysis import vmcode

            candidates = vmcode.solve_input(self.triage.profile)
        except Exception as exc:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="error",
                    detail=f"vm analysis failed: {exc}",
                ),
            )

        if not candidates:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="skipped",
                    detail="no bytecode vm",
                ),
            )

        tried = 0
        for candidate in candidates:
            if self._time_left(start) <= 0:
                break
            tried += 1
            result = self._try_candidate(candidate, "stdin")
            if self._is_win(candidate, "stdin", result, success_detector):
                return StrategyResult(
                    found=True,
                    key=candidate,
                    input_mode="stdin",
                    attempt=StrategyAttempt(
                        strategy=self.name,
                        candidates_tried=tried,
                        duration_seconds=time.monotonic() - start,
                        outcome="success",
                        detail=f"vm bytecode solved ({len(candidates)} inputs)",
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
                detail=f"{len(candidates)} vm inputs rejected",
            ),
        )
