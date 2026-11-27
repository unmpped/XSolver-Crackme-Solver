from __future__ import annotations

import time

from xsolver.core.report import StrategyAttempt
from xsolver.core.runner import RunnerLimits
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

class SymbolicInjectionStrategy(Strategy):
    name = "symbolic-injection"

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        try:
            from xsolver.symbolic.engine import SymbolicEngine, symbolic_unavailable_reason
        except Exception as exc:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="unavailable",
                    detail=f"angr unavailable: {exc}",
                ),
            )

        engine = SymbolicEngine(self.binary_path, max_len=40)
        limits = RunnerLimits(timeout_seconds=max(self.limits.timeout_seconds, 10.0),
                              max_memory_bytes=self.limits.max_memory_bytes)

        def verify(candidate: bytes) -> bool:
            text = candidate.decode("latin-1").rstrip("\n")
            result = self._try_candidate(text, "stdin")
            return self._is_win(text, "stdin", result, success_detector)

        def verify_second_field(candidate: bytes) -> bool:
            text = candidate.decode("latin-1").rstrip("\n")
            result = self._try_candidate(text, "stdin2")
            return self._is_win(text, "stdin2", result, success_detector)

        budget = max(min(self.budget_seconds, 180.0), 10.0)
        try:
            outcome = engine.solve(timeout=budget, verify=verify)
        except Exception as exc:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=1,
                    duration_seconds=time.monotonic() - start,
                    outcome="error",
                    detail=f"{type(exc).__name__}: {exc}",
                ),
            )

        if not (outcome.found and outcome.input_data) and budget > 5.0:
            try:
                second = engine.solve(prefix=b"player\n", suffix=b"\n",
                                      timeout=max(budget * 0.6, 5.0),
                                      verify=verify_second_field)
            except Exception as exc:
                second = None
            if second is not None and second.found and second.input_data:
                key = second.input_data.rstrip(b"\x00").decode("latin-1")
                return StrategyResult(
                    found=True,
                    key=key,
                    input_mode="stdin2",
                    attempt=StrategyAttempt(
                        strategy=self.name,
                        candidates_tried=max(second.attempts, 1),
                        duration_seconds=time.monotonic() - start,
                        outcome="success",
                        detail=f"second field after a fixed name: {second.detail}",
                    ),
                )

        if outcome.found and outcome.input_data:
            key = outcome.input_data.rstrip(b"\x00").decode("latin-1")
            return StrategyResult(
                found=True,
                key=key,
                input_mode="stdin",
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=max(outcome.attempts, 1),
                    duration_seconds=time.monotonic() - start,
                    outcome="success",
                    detail=outcome.detail,
                ),
            )

        return StrategyResult(
            found=False,
            key=None,
            input_mode=None,
            attempt=StrategyAttempt(
                strategy=self.name,
                candidates_tried=max(outcome.attempts, 0),
                duration_seconds=time.monotonic() - start,
                outcome="exhausted",
                detail=outcome.detail or "no input succeeds",
            ),
        )
