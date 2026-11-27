from __future__ import annotations

import multiprocessing as mp
import os
import time
from pathlib import Path

from xsolver.core.report import StrategyAttempt
from xsolver.core.runner import (
    ExecutionResult,
    RunnerLimits,
    run_candidate,
    stdin_payload,
)
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector, default_success_detector

_DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
_DEFAULT_MAX_LENGTH = 4

def _index_to_candidate(index: int, charset: str, length: int) -> str:
    base = len(charset)
    chars = [""] * length
    for pos in range(length - 1, -1, -1):
        index, remainder = divmod(index, base)
        chars[pos] = charset[remainder]
    return "".join(chars)

def _worker_scan(
    binary_path: str,
    mode: str,
    charset: str,
    length: int,
    total: int,
    start_index: int,
    stride: int,
    deadline: float,
    baseline: ExecutionResult,
    limits: RunnerLimits,
    result_queue,
    found_event,
):
    detector = default_success_detector(baseline)
    index = start_index
    tried = 0
    while index < total:
        if found_event.is_set():
            break
        if time.monotonic() >= deadline:
            break
        candidate = _index_to_candidate(index, charset, length)
        from xsolver.core.modes import argv_for, payload_for
        from xsolver.core.runtime import run_on_target

        argv = argv_for(mode, candidate)
        if argv is not None:
            result = run_on_target(binary_path, argv=argv, limits=limits)
        else:
            result = run_on_target(binary_path, stdin_data=payload_for(mode, candidate), limits=limits)
        tried += 1
        if detector(result):
            found_event.set()
            result_queue.put(("found", candidate, tried))
            return
        index += stride
    result_queue.put(("done", None, tried))

class BruteForceStrategy(Strategy):
    name = "bounded-brute-force"

    def __init__(self, *args, charset: str = _DEFAULT_CHARSET, max_length: int = _DEFAULT_MAX_LENGTH, **kwargs):
        super().__init__(*args, **kwargs)
        self.charset = charset
        self.max_length = max_length

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        mode = self.triage.likely_input_mode if self.triage.likely_input_mode != "unknown" else "argv"
        worker_count = max(1, os.cpu_count() or 1)

        from xsolver.core.runtime import run_on_target

        baseline = run_on_target(self.binary_path, argv=[], limits=self.limits)

        ctx = mp.get_context("fork")
        found_event = ctx.Event()
        result_queue = ctx.Queue()

        total_tried = 0
        for length in range(1, self.max_length + 1):
            remaining = self._time_left(start)
            if remaining <= 0:
                return self._exhausted(total_tried, start, "budget spent")

            total_combinations = len(self.charset) ** length
            deadline = time.monotonic() + remaining

            processes = []
            for worker_id in range(worker_count):
                p = ctx.Process(
                    target=_worker_scan,
                    args=(
                        str(self.binary_path), mode, self.charset, length, total_combinations,
                        worker_id, worker_count, deadline, baseline, self.limits,
                        result_queue, found_event,
                    ),
                )
                p.start()
                processes.append(p)

            found_key = None
            received = 0
            while received < len(processes):
                status, candidate, tried = result_queue.get()
                received += 1
                total_tried += tried
                if status == "found":
                    found_key = candidate

            for p in processes:
                p.join(timeout=2)

            if found_key is not None:
                return StrategyResult(
                    found=True,
                    key=found_key,
                    input_mode=mode,
                    attempt=StrategyAttempt(
                        strategy=self.name,
                        candidates_tried=total_tried,
                        duration_seconds=time.monotonic() - start,
                        outcome="success",
                        detail=f"brute force len {length} via {mode} using {worker_count} workers",
                    ),
                )

        return self._exhausted(total_tried, start, f"space (<= {self.max_length}) exhausted")

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
