from __future__ import annotations

import time

from xsolver.analysis.intercept import intercept, last_error
from xsolver.core.report import StrategyAttempt
from xsolver.core.modes import argv_for, is_argv
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

_PROBES = (b"zzqqzz\n", b"A1b2C3d4!\n")

class ComparisonInterceptionStrategy(Strategy):
    name = "cmp-interception"

    def _applicable(self) -> bool:
        profile = self.triage.profile
        return profile.format.startswith("ELF") and profile.is_executable_elf

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        if not self._applicable():
            return StrategyResult(
                found=False, key=None, input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name, candidates_tried=0,
                    duration_seconds=time.monotonic() - start, outcome="skipped",
                    detail="dynamic ELF only",
                ),
            )

        captured: list[str] = []
        probes: list[tuple[bytes, list[str] | None]] = [(probe, None) for probe in _PROBES]
        if is_argv(self.triage.likely_input_mode):
            probes += [
                (b"", argv_for(self.triage.likely_input_mode, probe.decode().strip()))
                for probe in _PROBES
            ]

        error: str | None = None
        for probe, argv in probes:
            if self._time_left(start) <= 0:
                error = error or "budget spent while probing"
                break
            result = intercept(self.binary_path, stdin_data=probe, argv=argv)
            if not result:
                error = last_error() or error
                continue
            if not result.comparisons:
                continue
            for candidate in result.candidates():
                if candidate in captured:
                    continue
                if candidate.encode("latin-1", "replace") in probe:
                    continue
                captured.append(candidate)
            if captured:
                break

        tried = 0
        for candidate in captured:
            if self._time_left(start) <= 0:
                break
            tried += 1
            for mode in ("stdin", "argv", "argv2"):
                result = self._try_candidate(candidate, mode)
                if self._is_win(candidate, mode, result, success_detector):
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
            attempt=StrategyAttempt(
                strategy=self.name, candidates_tried=tried,
                duration_seconds=time.monotonic() - start, outcome="exhausted",
                detail=detail,
            ),
        )
