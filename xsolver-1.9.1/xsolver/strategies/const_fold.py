from __future__ import annotations

import time

from xsolver.analysis.const_fold import const_fold_candidates
from xsolver.core.modes import is_argv
from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

MAX_CANDIDATES = 60

class ConstFoldStrategy(Strategy):
    name = "const-fold"

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
            candidates = const_fold_candidates(self.binary_path)
        except Exception as exc:
            return finish(False, None, None, 0, "error", f"fold scan failed: {exc}")
        if not candidates:
            return finish(False, None, None, 0, "exhausted",
                          "no constant-folded string")
        modes = self._modes()
        tried = 0
        detail = "no candidate verified"
        for candidate in candidates[:MAX_CANDIDATES]:
            for mode in modes:
                if self._time_left(start) <= 0:
                    break
                tried += 1
                try:
                    result = self._try_candidate(candidate, mode)
                    if self._is_win(candidate, mode, result, success_detector):
                        return finish(True, candidate, mode, tried, "success",
                                      f"folded literal+to_string, key via {mode}")
                except Exception:
                    continue
                detail = "candidate rejected"
            if self._time_left(start) <= 0:
                break
        return finish(False, None, None, tried, "exhausted", detail)
