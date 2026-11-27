from __future__ import annotations

import multiprocessing as mp
import os
import time

from xsolver.core.instrcount import count_instructions, counter_unit, oracle_available
from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

_DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_DEFAULT_MAX_LENGTH = 16
_DEFAULT_MIN_MARGIN = 2
_DEFAULT_VALGRIND_TIMEOUT = 10.0
_FILLER_CHAR = "_"

def _measure_worker(binary_path: str, mode: str, candidate: str, timeout: float, out_queue):
    from xsolver.core.modes import argv_for, payload_for

    argv = argv_for(mode, candidate)
    if argv is not None:
        result = count_instructions(binary_path, argv=argv, timeout_seconds=timeout)
    else:
        result = count_instructions(binary_path, stdin_data=payload_for(mode, candidate), timeout_seconds=timeout)
    out_queue.put((candidate, result.count))

class InstructionCountOracleStrategy(Strategy):
    name = "instruction-count-oracle"

    def __init__(
        self,
        *args,
        charset: str = _DEFAULT_CHARSET,
        max_length: int = _DEFAULT_MAX_LENGTH,
        min_margin: int = _DEFAULT_MIN_MARGIN,
        valgrind_timeout: float = _DEFAULT_VALGRIND_TIMEOUT,
        allow_pe: bool = False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.charset = charset
        self.max_length = max_length
        self.min_margin = min_margin
        self.valgrind_timeout = valgrind_timeout
        self.allow_pe = allow_pe

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()

        if not oracle_available(self.binary_path):
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="unavailable",
                    detail="no instruction counter: valgrind (ELF) or frida (PE) missing",
                ),
            )

        unit = counter_unit(self.binary_path)
        if unit != "guest instructions" and not self.allow_pe:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="unavailable",
                    detail="PE counter is opt-in (--pe-oracle), about 0.5 s per measurement",
                ),
            )

        mode = self.triage.likely_input_mode if self.triage.likely_input_mode != "unknown" else "argv"
        tried = 0
        worker_count = max(1, os.cpu_count() or 1)
        ctx = mp.get_context("fork")

        for length in range(1, self.max_length + 1):
            if self._time_left(start) <= 0:
                return self._exhausted(tried, start, "budget spent")

            prefix = ""
            position = 0
            gave_up = False

            while position < length:
                if self._time_left(start) <= 0:
                    return self._exhausted(tried, start, "budget spent mid-probe")

                candidates = [
                    prefix + ch + _FILLER_CHAR * (length - position - 1)
                    for ch in self.charset
                ]
                measurements = self._measure_batch(candidates, mode, ctx, worker_count)
                tried += len(measurements)

                ranked = sorted(
                    ((count, cand) for cand, count in measurements.items() if count is not None),
                    reverse=True,
                )
                if len(ranked) < 2:
                    gave_up = True
                    break

                top_count, top_candidate = ranked[0]
                second_count, _ = ranked[1]
                margin = top_count - second_count

                if margin < self.min_margin:
                    gave_up = True
                    break

                prefix += top_candidate[position]
                position += 1

            if gave_up:
                continue

            final_result = self._try_candidate(prefix, mode)
            tried += 1
            if self._is_win(prefix, mode, final_result, success_detector):
                return StrategyResult(
                    found=True,
                    key=prefix,
                    input_mode=mode,
                    attempt=StrategyAttempt(
                        strategy=self.name,
                        candidates_tried=tried,
                        duration_seconds=time.monotonic() - start,
                        outcome="success",
                        detail=f"key rebuilt byte by byte ({unit}), len {length}",
                    ),
                )

        return self._exhausted(tried, start, "no signal")

    def _measure_batch(self, candidates: list[str], mode: str, ctx, worker_count: int) -> dict[str, int | None]:
        results: dict[str, int | None] = {}
        out_queue = ctx.Queue()
        pending = list(candidates)

        while pending:
            batch = pending[:worker_count]
            pending = pending[worker_count:]
            processes = []
            for candidate in batch:
                p = ctx.Process(
                    target=_measure_worker,
                    args=(str(self.binary_path), mode, candidate, self.valgrind_timeout, out_queue),
                )
                p.start()
                processes.append(p)
            for _ in processes:
                candidate, count = out_queue.get()
                results[candidate] = count
            for p in processes:
                p.join(timeout=2)

        return results

    def _exhausted(self, tried: int, start: float, detail: str) -> StrategyResult:
        return StrategyResult(
            found=False,
            key=None,
            input_mode=None,
            attempt=StrategyAttempt(
                strategy=self.name,
                candidates_tried=tried,
                duration_seconds=time.monotonic() - start,
                outcome="exhausted",
                detail=detail,
            ),
        )
