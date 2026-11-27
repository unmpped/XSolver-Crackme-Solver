from __future__ import annotations

import time

from xsolver.analysis.unpack import capture
from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

class UnpackedStringsStrategy(Strategy):
    name = "unpacked-strings"

    def _looks_packed(self) -> bool:
        profile = self.triage.profile
        return bool(profile.packer_suspected or profile.overall_entropy >= 7.0)

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        if not self._looks_packed():
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="skipped",
                    detail="not packed",
                ),
            )

        image = capture(self.binary_path, timeout=min(8.0, self.budget_seconds))
        if image is None:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="exhausted",
                    detail="no self-modification",
                ),
            )

        if image.code_changed_bytes < 64:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="exhausted",
                    detail=(
                        "data pages only"
                    ),
                ),
            )

        candidates = image.candidate_passwords()
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
                        detail=(f"runtime decrypted string "
                                f"({image.code_changed_bytes} bytes patched)"),
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
                detail=f"{len(candidates)} strings tried",
            ),
        )
