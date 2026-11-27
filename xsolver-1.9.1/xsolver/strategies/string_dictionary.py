from __future__ import annotations

import concurrent.futures
import time

from xsolver.analysis.strings import candidate_passwords
from xsolver.core.report import StrategyAttempt
from xsolver.core.modes import is_argv
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector
from xsolver.strategies.common_passwords import COMMON_CRACKME_PASSWORDS

_MUTATION_LIMIT = 80
_WORKERS = 4
_NOISE = ("%", "\\", "/", "<", ">", "{", "}", "://", " ", "\t")
_NOISY_ENDINGS = (".exe", ".dll", ".text", ".data", ".rdata", ".rsrc", ".pdb", ".obj")

def _shift(text: str, delta: int) -> str:
    return "".join(chr(ord(ch) + delta) if ch.isprintable() else ch for ch in text)

def _rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)

def _xor_printable(text: str, key: int) -> str | None:
    data = bytes(ord(ch) ^ key for ch in text)
    if not data or any(byte < 0x20 or byte > 0x7E for byte in data):
        return None
    return data.decode("latin-1")

def plausibility(text: str) -> int:
    score = 0
    if len(text) < 3:
        score += 60
    if len(text) > 32:
        score += 25
    if any(token in text for token in _NOISE):
        score += 30
    if text.lower().endswith(_NOISY_ENDINGS):
        score += 45
    if not text.strip():
        score += 60
    if text.isdigit():
        score += 8
    return score

def order_candidates(candidates: list[str]) -> list[str]:
    indexed = list(enumerate(candidates))
    indexed.sort(key=lambda pair: (plausibility(pair[1]), pair[0]))
    return [text for _, text in indexed]

def mutate(text: str) -> list[str]:
    if not text:
        return []
    variants: list[str] = [text.upper(), text.lower(), text[::-1], text.capitalize(), _rot13(text)]
    variants.extend(_shift(text, delta) for delta in (1, -1, 2, -2))
    for key in (0x55, 0x5A, 0x20, 0x33, 0x11):
        decoded = _xor_printable(text, key)
        if decoded:
            variants.append(decoded)
    variants.extend([text + "1", "1" + text, text + "!", text + "123"])
    seen, out = set(), []
    for variant in variants:
        if variant and variant != text and variant not in seen and variant.isprintable():
            seen.add(variant)
            out.append(variant)
    return out

class StringDictionaryStrategy(Strategy):
    name = "string-dictionary"

    def _modes(self) -> list[str]:
        modes = [self.triage.likely_input_mode]
        if not is_argv(self.triage.likely_input_mode):
            modes.append("argv")
        if self.triage.likely_input_mode != "stdin":
            modes.append("stdin")
        return modes

    def _win(self, candidate: str, mode: str, result, success_detector: SuccessDetector) -> bool:
        try:
            return self._is_win(candidate, mode, result, success_detector)
        except Exception:
            return False

    def _run_pairs(self, pairs, success_detector: SuccessDetector, start: float, tried: int, detail: str):
        pending = []
        index = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            while True:
                while len(pending) < _WORKERS and index < len(pairs) and self._time_left(start) > 0:
                    candidate, mode = pairs[index]
                    index += 1
                    pending.append((candidate, mode, pool.submit(self._try_candidate, candidate, mode)))
                if not pending:
                    break
                done, _ = concurrent.futures.wait(
                    [future for _, _, future in pending],
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for item in list(pending):
                    candidate, mode, future = item
                    if future not in done:
                        continue
                    pending.remove(item)
                    tried += 1
                    try:
                        result = future.result()
                    except Exception:
                        continue
                    if self._win(candidate, mode, result, success_detector):
                        for _, _, other in pending:
                            other.cancel()
                        return StrategyResult(
                            found=True,
                            key=candidate,
                            input_mode=mode,
                            attempt=StrategyAttempt(
                                strategy=self.name,
                                candidates_tried=tried,
                                duration_seconds=time.monotonic() - start,
                                outcome="success",
                                detail=f"{detail} via {mode}",
                            ),
                        ), tried
                if self._time_left(start) <= 0 and not pending:
                    break
        return None, tried

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        candidates = candidate_passwords(self.triage.profile.raw)
        for common in COMMON_CRACKME_PASSWORDS:
            if common not in candidates:
                candidates.append(common)
        candidates = order_candidates(candidates)

        modes = self._modes()
        tried = 0

        pairs = [(candidate, mode) for candidate in candidates for mode in modes]
        result, tried = self._run_pairs(pairs, success_detector, start, tried, "string match")
        if result is not None:
            return result

        mutated = []
        for candidate in candidates[:_MUTATION_LIMIT]:
            for variant in mutate(candidate):
                for mode in modes:
                    mutated.append((variant, mode))
        result, tried = self._run_pairs(mutated, success_detector, start, tried, "mutated string")
        if result is not None:
            return result

        exhausted_budget = tried < len(candidates) * max(1, len(modes))
        return StrategyResult(
            found=False,
            key=None,
            input_mode=None,
            attempt=StrategyAttempt(
                strategy=self.name,
                candidates_tried=tried,
                duration_seconds=time.monotonic() - start,
                outcome="exhausted",
                detail=(f"budget spent after {tried} of {len(candidates)} candidates"
                        if exhausted_budget else "no string matched"),
            ),
        )
