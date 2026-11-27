from __future__ import annotations

import random
import time
from collections import Counter

from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

_DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_DEFAULT_MAX_LENGTH = 10
_DEFAULT_ROUNDS = 5
_DEFAULT_MAX_ROUNDS = 30
_DEFAULT_ROUNDS_STEP = 7
_DEFAULT_MIN_VOTE_MARGIN = 2
_FILLER_CHAR = "_"

class TimingOracleStrategy(Strategy):
    name = "timing-oracle"

    def __init__(
        self,
        *args,
        charset: str = _DEFAULT_CHARSET,
        max_length: int = _DEFAULT_MAX_LENGTH,
        rounds: int = _DEFAULT_ROUNDS,
        max_rounds: int = _DEFAULT_MAX_ROUNDS,
        rounds_step: int = _DEFAULT_ROUNDS_STEP,
        min_vote_margin: int = _DEFAULT_MIN_VOTE_MARGIN,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.charset = charset
        self.max_length = max_length
        self.rounds = rounds
        self.max_rounds = max_rounds
        self.rounds_step = rounds_step
        self.min_vote_margin = min_vote_margin

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        mode = self.triage.likely_input_mode if self.triage.likely_input_mode != "unknown" else "argv"
        tried = 0

        for length in range(1, self.max_length + 1):
            if self._time_left(start) <= 0:
                return self._exhausted(tried, start, "budget spent")

            prefix = ""
            position = 0
            gave_up = False

            while position < length:
                if self._time_left(start) <= 0:
                    return self._exhausted(tried, start, "budget spent mid-probe")

                votes: Counter[str] = Counter()
                rounds_run = 0
                margin = 0
                top_char = ""

                while rounds_run < self.max_rounds:
                    batch_size = self.rounds if rounds_run == 0 else self.rounds_step
                    for _ in range(batch_size):
                        if self._time_left(start) <= 0:
                            return self._exhausted(tried, start, "budget spent mid-probe")
                        order = list(self.charset)
                        random.shuffle(order)
                        round_times: dict[str, float] = {}
                        for ch in order:
                            candidate = prefix + ch + _FILLER_CHAR * (length - position - 1)
                            t0 = time.perf_counter()
                            result = self._try_candidate(candidate, mode)
                            round_times[ch] = time.perf_counter() - t0
                            tried += 1
                            if self._is_win(candidate, mode, result, success_detector):
                                return StrategyResult(
                                    found=True,
                                    key=candidate,
                                    input_mode=mode,
                                    attempt=StrategyAttempt(
                                        strategy=self.name,
                                        candidates_tried=tried,
                                        duration_seconds=time.monotonic() - start,
                                        outcome="success",
                                        detail=f"key found, len {length}, position {position}",
                                    ),
                                )
                        slowest = max(round_times, key=round_times.get)
                        votes[slowest] += 1
                        rounds_run += 1

                    ranked = votes.most_common()
                    top_char, top_votes = ranked[0]
                    second_votes = ranked[1][1] if len(ranked) > 1 else 0
                    margin = top_votes - second_votes

                    if margin >= self.min_vote_margin:
                        break

                if margin < self.min_vote_margin:
                    gave_up = True
                    break

                prefix += top_char
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
                        detail=f"key rebuilt byte by byte, len {length}",
                    ),
                )

        return self._exhausted(tried, start, "no timing signal")

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
