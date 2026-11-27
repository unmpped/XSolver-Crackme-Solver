from __future__ import annotations

import tempfile
import time
from pathlib import Path

from xsolver.analysis.lua_embed import patch_lua_random, plan_random_password
from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

class RuntimeRandomStrategy(Strategy):

    name = "runtime-random"

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        patched_path: Path | None = None
        original_path = self.binary_path

        def finish(found: bool, key: str | None, mode: str | None,
                   tried: int, outcome: str, detail: str) -> StrategyResult:
            if not found and patched_path is not None:
                try:
                    patched_path.unlink(missing_ok=True)
                except OSError:
                    pass
                patched_path_final = None
            else:
                patched_path_final = patched_path
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
                verify_path=patched_path_final,
            )

        try:
            raw = self.binary_path.read_bytes()
        except OSError as exc:
            return finish(False, None, None, 0, "error", f"read failed: {exc}")

        try:
            plan = plan_random_password(raw)
        except Exception as exc:
            return finish(False, None, None, 0, "error", f"lua scan failed: {exc}")
        if plan is None:
            return finish(False, None, None, 0, "exhausted",
                          "no embedded lua runtime-random password")

        try:
            patched, password = patch_lua_random(raw, plan)
        except Exception as exc:
            return finish(False, None, None, 0, "error", f"patch failed: {exc}")
        if not patched:
            return finish(False, None, None, 0, "error",
                          "could not recompress embedded script to slot size")

        fd, tmp_name = tempfile.mkstemp(
            prefix="xsolver_luarand_", suffix=self.binary_path.suffix or ".exe"
        )
        patched_path = Path(tmp_name)
        with open(fd, "wb") as handle:
            handle.write(patched)
        patched_path.chmod(patched_path.stat().st_mode | 0o111)

        self.binary_path = patched_path
        try:
            tried = 0
            modes = ["stdin"]
            likely = self.triage.likely_input_mode
            if likely and likely not in modes:
                modes.append(likely)
            detail = "patched copy rejected password"
            for candidate_mode in modes:
                if self._time_left(start) <= 0:
                    break
                tried += 1
                try:
                    result = self._try_candidate(password, candidate_mode)
                except Exception as exc:
                    detail = f"run failed: {exc}"
                    continue
                if not success_detector(result):
                    detail = "detector did not accept patched run"
                    continue
                if self._is_win(password, candidate_mode, result, success_detector):
                    return finish(
                        True, password, candidate_mode, tried, "success",
                        f"math.random({plan.low},{plan.high}) collapsed to "
                        f"{plan.low} in {plan.entry}",
                    )
                detail = "isolated_success rejected patched run"
            if tried == 0:
                detail = "budget spent before first run"
            return finish(False, None, None, tried, "exhausted", detail)
        finally:
            self.binary_path = original_path
