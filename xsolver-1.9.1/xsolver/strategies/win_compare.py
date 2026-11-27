from __future__ import annotations

import time

from xsolver.analysis.winintercept import intercept_windows, last_error
from xsolver.core.modes import argv_for, is_argv
from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

PROBES = ("zzqqzz", "A1b2C3d4!")

class WindowsCompareTraceStrategy(Strategy):
    name = "win-cmp-trace"

    def _applicable(self) -> bool:
        return self.triage.profile.format.startswith("PE")

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        if not self._applicable():
            return StrategyResult(
                found=False, key=None, input_mode=None,
                attempt=StrategyAttempt(strategy=self.name, candidates_tried=0,
                                        duration_seconds=0.0, outcome="skipped",
                                        detail="PE targets only"),
            )

        captured: list[str] = []
        error: str | None = None
        preferred = self.triage.likely_input_mode
        shapes = [preferred] + [mode for mode in ("stdin", "argv") if mode != preferred]
        for probe in PROBES:
            if self._time_left(start) <= 0:
                error = error or "budget spent while probing"
                break
            for shape in shapes:
                if self._time_left(start) <= 0:
                    error = error or "budget spent while probing"
                    break
                argv = argv_for(shape, probe) if is_argv(shape) else None
                data = b"" if argv else (probe + "\n" + probe + "\n").encode()
                result = intercept_windows(self.binary_path, stdin_data=data, argv=argv)
                if result is None:
                    error = last_error() or error
                    continue
                if not result.comparisons:
                    error = last_error() or error
                    continue
                for candidate in result.candidates():
                    if probe in candidate or candidate in probe:
                        continue
                    if candidate not in captured:
                        captured.append(candidate)
                if captured:
                    break
            if captured:
                break

        tried = 0
        modes = ["stdin", "argv", "argv2"]
        for candidate in captured:
            for mode in modes:
                if self._time_left(start) <= 0:
                    break
                tried += 1
                outcome = self._try_candidate(candidate, mode)
                if self._is_win(candidate, mode, outcome, success_detector):
                    return StrategyResult(
                        found=True, key=candidate, input_mode=mode,
                        attempt=StrategyAttempt(
                            strategy=self.name, candidates_tried=tried,
                            duration_seconds=time.monotonic() - start, outcome="success",
                            detail=f"captured at runtime ({mode})",
                        ),
                    )

        if captured:
            detail = f"{len(captured)} values tried"
        elif error:
            detail = f"no effect: {error}"
        else:
            detail = "nothing intercepted"
        return StrategyResult(
            found=False, key=None, input_mode=None,
            attempt=StrategyAttempt(strategy=self.name, candidates_tried=tried,
                                    duration_seconds=time.monotonic() - start,
                                    outcome="exhausted", detail=detail),
        )
