from __future__ import annotations

import time

from xsolver.analysis import checkflow, constraints
from xsolver.core.modes import is_argv
from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

_MAX_CANDIDATES = 24

class InlineSynthesisStrategy(Strategy):

    name = "inline-synthesis"

    def _candidates(self) -> list[str]:
        found: list[str] = []
        try:
            found.extend(constraints.candidates(self.triage.profile, limit=_MAX_CANDIDATES))
        except Exception:
            pass
        try:
            for text in checkflow.candidate_keys(self.triage.profile, limit=_MAX_CANDIDATES):
                if text not in found:
                    found.append(text)
        except Exception:
            pass
        seen = set()
        unique = []
        for text in found:
            if not text or text in seen:
                continue
            seen.add(text)
            unique.append(text)
        return unique[:_MAX_CANDIDATES]

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        candidates = self._candidates()
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
                    detail="no inline comparison could be turned into a key",
                ),
            )

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
                if not self._is_win(candidate, mode, result, success_detector):
                    continue
                return StrategyResult(
                    found=True,
                    key=candidate,
                    input_mode=mode,
                    attempt=StrategyAttempt(
                        strategy=self.name,
                        candidates_tried=tried,
                        duration_seconds=time.monotonic() - start,
                        outcome="success",
                        detail=f"key synthesised from inline predicates via {mode}",
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
                detail=f"{len(candidates)} synthesised candidates rejected",
            ),
        )
