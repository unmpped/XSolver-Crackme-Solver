from __future__ import annotations

import re
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

_WORKERS = 4
_ERROR_RE = re.compile(r"step\s+(\d+)!\s*\(x:\s*(-?\d+),\s*y:\s*(-?\d+)\)")
_DIRS = ("W", "A", "S", "D")
_DELTA = {"W": (0, -1), "A": (-1, 0), "S": (0, 1), "D": (1, 0)}
_RIGHT = {"W": "D", "D": "S", "S": "A", "A": "W"}
_LEFT = {"W": "A", "A": "S", "S": "D", "D": "W"}
_BACK = {"W": "S", "S": "W", "A": "D", "D": "A"}

class MazeProbeStrategy(Strategy):
    name = "maze-probe"

    def _order(self, path: str) -> tuple[str, ...]:
        if not path:
            return _DIRS
        last = path[-1]
        return (last, _RIGHT[last], _LEFT[last], _BACK[last])

    def _probe(self, path: str, detector: SuccessDetector):
        result = self._try_candidate(path, "stdin")
        if detector(result):
            return ("win", result)
        out = result.stdout.decode("latin-1", "replace")
        match = _ERROR_RE.search(out)
        if match:
            return ("err", int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return ("ok", result)

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        raw = self.triage.profile.raw
        if b"at step" not in raw or b"(x:" not in raw:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="skipped",
                    detail="no maze oracle",
                ),
            )
        known: dict[tuple[int, int], str] = {(0, 0): "open"}
        stack: list[tuple[int, int, str]] = [(0, 0, "")]
        pending: dict = {}
        tried = 0
        solved = False
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            while True:
                while stack and len(pending) < _WORKERS * 2 and self._time_left(start) > 0:
                    x, y, path = stack.pop()
                    for direction in self._order(path):
                        dx, dy = _DELTA[direction]
                        target = (x + dx, y + dy)
                        if target in known:
                            continue
                        known[target] = "pending"
                        future = pool.submit(self._probe, path + direction, success_detector)
                        pending[future] = (target, path + direction)
                if not pending:
                    if not stack or self._time_left(start) <= 0:
                        break
                    continue
                done, _ = wait(
                    pending,
                    timeout=max(0.05, min(0.5, self._time_left(start))),
                    return_when=FIRST_COMPLETED,
                )
                for future in done:
                    target, full = pending.pop(future)
                    tried += 1
                    try:
                        outcome = future.result()
                    except Exception:
                        known[target] = "wall"
                        continue
                    if outcome[0] == "win":
                        result = outcome[1]
                        if self._is_win(full, "stdin", result, success_detector):
                            solved = True
                            break
                        known[target] = "open"
                        continue
                    if outcome[0] == "err":
                        known[target] = "wall"
                        continue
                    known[target] = "open"
                    stack.append((target[0], target[1], full))
                if solved:
                    break
            for future in pending:
                future.cancel()
        if solved:
            return StrategyResult(
                found=True,
                key=full,
                input_mode="stdin",
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=tried,
                    duration_seconds=time.monotonic() - start,
                    outcome="success",
                    detail=f"maze path accepted after {tried} probes",
                ),
            )
        detail = (
            "budget spent"
            if self._time_left(start) <= 0
            else "no unexplored cell left"
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
                detail=f"{detail} after {tried} probes",
            ),
        )
