from __future__ import annotations

import time
from pathlib import Path

from xsolver.analysis.fileprobe import side_file_names
from xsolver.analysis.imm_strings import immediate_strings
from xsolver.analysis.static_extract import extract_candidate_keys
from xsolver.analysis.strings import candidate_passwords
from xsolver.core.report import StrategyAttempt
from xsolver.core.runner import ExecutionResult
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector
from xsolver.strategies.common_passwords import COMMON_CRACKME_PASSWORDS

_TAIL_VARIANTS = ("", "\n", "\r\n")
_MAX_CANDIDATES = 160

class SideFileStrategy(Strategy):
    name = "side-file"

    def _names(self) -> list[str]:
        try:
            return side_file_names(self.binary_path, self.triage.profile)
        except Exception:
            return []

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        names = self._names()
        if not names:
            return StrategyResult(
                found=False, key=None, input_mode=None,
                attempt=StrategyAttempt(strategy=self.name, candidates_tried=0,
                                        duration_seconds=0.0, outcome="skipped",
                                        detail="no side file name"),
            )

        candidates = self._candidates()
        tried = 0
        for name in names:
            for candidate in candidates:
                for tail in _TAIL_VARIANTS:
                    if self._time_left(start) <= 0:
                        break
                    payload = (candidate + tail).encode("latin-1", "replace")
                    tried += 1
                    result = self._feed(name, payload)
                    if not success_detector(result):
                        continue
                    if not self._stable(name, payload, candidate, success_detector):
                        continue
                    return StrategyResult(
                        found=True, key=candidate, input_mode=f"file:{name}",
                        attempt=StrategyAttempt(
                            strategy=self.name, candidates_tried=tried,
                            duration_seconds=time.monotonic() - start, outcome="success",
                            detail=f"{candidate!r} written to {name}",
                        ),
                    )
        detail = f"{len(candidates)} candidates in {len(names)} file(s)"
        if self._time_left(start) <= 0:
            detail += ", budget spent"
        return StrategyResult(
            found=False, key=None, input_mode=None,
            attempt=StrategyAttempt(strategy=self.name, candidates_tried=tried,
                                    duration_seconds=time.monotonic() - start,
                                    outcome="exhausted", detail=detail),
        )

    def _candidates(self) -> list[str]:
        profile = self.triage.profile
        ordered: list[str] = []
        seen: set[str] = set()

        def add(text: str) -> None:
            if not text or len(text) > 64 or text in seen:
                return
            if not text.isprintable():
                return
            seen.add(text)
            ordered.append(text)

        try:
            for text in immediate_strings(profile, limit=8):
                add(text)
        except Exception:
            pass
        try:
            for text in extract_candidate_keys(profile, max_candidates=8):
                add(text)
        except Exception:
            pass
        for text in COMMON_CRACKME_PASSWORDS:
            add(text)
        try:
            for text in candidate_passwords(profile.raw, limit=80):
                add(text)
        except Exception:
            pass
        return ordered[:_MAX_CANDIDATES]

    def _feed(self, name: str, payload: bytes) -> ExecutionResult:
        from xsolver.core.runtime import run_on_target

        try:
            return run_on_target(self.binary_path, stdin_data=b"", limits=self.limits,
                                 side_files={name: payload})
        except Exception:
            return ExecutionResult(None, b"", b"", False, True)

    def _stable(self, name: str, payload: bytes, candidate: str,
                detector: SuccessDetector) -> bool:
        plain = (candidate + "Z").encode("latin-1", "replace")
        if plain == payload:
            plain = (candidate + "Q").encode("latin-1", "replace")
        return not detector(self._feed(name, plain))
