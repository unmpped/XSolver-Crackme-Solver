from __future__ import annotations

import time

from xsolver.analysis import checkflow, constraints
from xsolver.analysis.prompts import classify, prompt_role, prompt_signature
from xsolver.analysis.ptr_strings import pointer_strings
from xsolver.analysis.static_extract import extract_candidate_keys
from xsolver.analysis.strings import candidate_passwords
from xsolver.core.report import StrategyAttempt
from xsolver.core.runner import RunnerLimits
from xsolver.core.session import Session
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector
from xsolver.strategies.common_passwords import COMMON_CRACKME_PASSWORDS

_MAX_STEPS = 6
_MAX_CANDIDATES = 12
_EXTRA = ("1", "2", "0", "42", "abc", "test", "admin", "root", "level1", "level2")
_NEUTRAL_NAMES = ("Test", "Alice", "AAAA", "user", "John")

class DialogueProbeStrategy(Strategy):

    name = "dialogue-probe"

    def _static_pool(self) -> list[str]:
        profile = self.triage.profile
        pool: list[str] = []
        for source in (constraints.candidates, checkflow.candidate_keys, extract_candidate_keys):
            try:
                values = source(profile, limit=_MAX_CANDIDATES)
            except TypeError:
                try:
                    values = source(profile)
                except Exception:
                    continue
            except Exception:
                continue
            for value in values or []:
                if value and value not in pool:
                    pool.append(value)
        try:
            for value in pointer_strings(profile, limit=_MAX_CANDIDATES):
                if value not in pool:
                    pool.append(value)
        except Exception:
            pass
        return pool

    def _string_pool(self, limit: int = 40) -> list[str]:
        try:
            data = self.binary_path.read_bytes()
        except OSError:
            return []
        scored: list[tuple[int, str]] = []
        for raw in candidate_passwords(data, limit=400):
            text = raw.strip()
            if not (3 <= len(text) <= 20) or not text.isascii() or not text.isprintable():
                continue
            if any(ch.isspace() for ch in text):
                continue
            score = 0
            if text.isalnum():
                score += 3
            if 4 <= len(text) <= 12:
                score += 2
            if any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text):
                score += 1
            if "_" in text or "." in text or text.startswith("_"):
                score -= 6
            if text[0].isupper() and text[1:2].islower() and text.isalpha():
                score -= 3
            if text.islower() or text.isupper() or text.isdigit():
                score += 1
            scored.append((score, text))
        scored.sort(key=lambda item: (-item[0], len(item[1])))
        out: list[str] = []
        for score, text in scored:
            if score <= 0 or text in out:
                continue
            out.append(text)
            if len(out) >= limit:
                break
        return out

    def _pool(self) -> list[str]:
        pool = self._static_pool()
        for value in COMMON_CRACKME_PASSWORDS:
            if value not in pool:
                pool.append(value)
        for value in self._string_pool(_MAX_CANDIDATES * 2):
            if value not in pool:
                pool.append(value)
        for value in _EXTRA:
            if value not in pool:
                pool.append(value)
        return pool[:_MAX_CANDIDATES * 2 + 8]

    def _replay(self, steps: list[str], detector: SuccessDetector) -> bool:
        from xsolver.core.runtime import run_on_target

        payload = ("\n".join(steps) + "\n").encode("latin-1", "replace")
        result = run_on_target(self.binary_path, stdin_data=payload, limits=self.limits)
        return bool(detector(result))

    def _prompt_after(self, steps: list[str], quiet: float = 0.45) -> str:
        session = Session(path=self.binary_path,
                          limits=self.limits or RunnerLimits(timeout_seconds=8))
        try:
            session.open()
            text = session.read_until_quiet(quiet=quiet, timeout=6.0)
            for step in steps:
                text = session.answer(step, quiet=quiet)
            return text
        except Exception:
            return ""
        finally:
            session.close()

    def _attempt(self, steps: list[str], quiet: float = 0.45) -> tuple[str | None, str, bool]:
        session = Session(path=self.binary_path,
                          limits=self.limits or RunnerLimits(timeout_seconds=8))
        transcript = ""
        verdict = None
        alive = False
        try:
            session.open()
            session.read_until_quiet(quiet=quiet, timeout=6.0)
            for step in steps:
                reply = session.answer(step, quiet=quiet)
                transcript += reply
                verdict = classify(reply)
                if verdict == "failure":
                    break
            alive = session.alive()
        except Exception:
            return None, transcript, False
        finally:
            session.close()
        return verdict, transcript, alive

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        pool = self._pool()
        if not pool:
            return StrategyResult(
                found=False, key=None, input_mode=None,
                attempt=StrategyAttempt(strategy=self.name, candidates_tried=0,
                                        duration_seconds=0.0, outcome="exhausted",
                                        detail="no candidate pool"),
            )

        accepted: list[str] = []
        tried = 0
        detail = "no dialogue detected"

        for _step in range(_MAX_STEPS):
            before = self._prompt_after(accepted)
            before_signature = prompt_signature(before)
            role = prompt_role(before)
            candidates = list(_NEUTRAL_NAMES) + pool if role == "name" else pool
            progressed = False
            for candidate in candidates:
                if self._time_left(start) <= 0:
                    break
                tried += 1
                steps = accepted + [candidate]
                verdict, transcript, alive = self._attempt(steps)
                if verdict == "success":
                    if self._replay(steps, success_detector) and self._replay(steps, success_detector):
                        return StrategyResult(
                            found=True, key=candidate, input_mode="steps",
                            steps=list(steps),
                            attempt=StrategyAttempt(
                                strategy=self.name, candidates_tried=tried,
                                duration_seconds=time.monotonic() - start, outcome="success",
                                detail=f"{len(steps)}-step dialogue replayed cold: {steps}",
                            ),
                        )
                    detail = "successful dialogue did not survive a cold replay"
                    continue
                if verdict == "failure":
                    continue
                if not alive:
                    continue
                after_signature = prompt_signature(transcript)
                if after_signature and after_signature != before_signature:
                    accepted.append(candidate)
                    progressed = True
                    detail = f"step {len(accepted)} answered with {candidate!r}"
                    break
                detail = f"retry loop at step {len(accepted) + 1}: {candidate!r} rejected"
            if not progressed:
                break

        return StrategyResult(
            found=False, key=None, input_mode=None,
            attempt=StrategyAttempt(strategy=self.name, candidates_tried=tried,
                                    duration_seconds=time.monotonic() - start,
                                    outcome="exhausted",
                                    detail=detail),
        )
