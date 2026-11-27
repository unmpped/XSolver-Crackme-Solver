from __future__ import annotations

import time

from xsolver.analysis.imm_strings import immediate_strings
from xsolver.analysis.static_extract import extract_candidate_keys
from xsolver.core.report import StrategyAttempt
from xsolver.core.modes import is_argv
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

class StaticConstantStrategy(Strategy):
    name = "static-constant"

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()

        try:
            candidates = extract_candidate_keys(self.triage.profile)
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
                    detail=f"disassembly failed: {exc}",
                ),
            )

        try:
            for text in immediate_strings(self.triage.profile, limit=6):
                if text not in candidates:
                    candidates.append(text)
        except Exception:
            pass

        if not candidates:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="exhausted",
                    detail="no static comparison found",
                ),
            )

        modes = [self.triage.likely_input_mode]
        if not is_argv(self.triage.likely_input_mode):
            modes.append("argv")
        if self.triage.likely_input_mode != "stdin":
            modes.append("stdin")

        tried = 0
        for mode in modes:
            for candidate in candidates:
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
                            detail=f"key from disassembly via {mode} ({len(candidates)} static candidates)",
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
                detail=f"{len(candidates)} static candidates, none verified",
            ),
        )
