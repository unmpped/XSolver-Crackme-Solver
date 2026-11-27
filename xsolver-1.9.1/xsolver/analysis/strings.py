from __future__ import annotations

import re
from dataclasses import dataclass

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % 4)
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % 4)

_NOISE_PATTERNS = (
    re.compile(r"^GCC:"),
    re.compile(r"^GLIBC_"),
    re.compile(r"^__"),
    re.compile(r"^lib[a-z0-9.]+\.so"),
    re.compile(r"^/(usr|lib|lib64)/"),
    re.compile(r"^\.(text|data|bss|rodata|dynamic|symtab)"),
)

_INTERESTING_HINTS = (
    "password", "passwd", "key", "flag", "correct", "wrong", "secret",
    "unlock", "access", "granted", "denied", "token", "pin", "code",
    "congrat", "nice", "well done", "serial", "license",
)

@dataclass
class StringCandidate:
    value: str
    offset: int
    score: int
    source: str

def extract_strings(data: bytes, min_length: int = 4) -> list[StringCandidate]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    results: list[StringCandidate] = []
    for match in pattern.finditer(data):
        raw = match.group()
        text = raw.decode("ascii")
        if _is_noise(text):
            continue
        results.append(StringCandidate(value=text, offset=match.start(), score=_score(text), source="ascii"))

    utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    for match in utf16_pattern.finditer(data):
        raw = match.group()
        text = raw.decode("utf-16-le", errors="ignore")
        if _is_noise(text):
            continue
        results.append(StringCandidate(value=text, offset=match.start(), score=_score(text), source="utf16"))

    results.sort(key=lambda c: c.score, reverse=True)
    return results

def _is_noise(text: str) -> bool:
    for pat in _NOISE_PATTERNS:
        if pat.search(text):
            return True
    return False

def _score(text: str) -> int:
    score = 0
    lowered = text.lower()
    for hint in _INTERESTING_HINTS:
        if hint in lowered:
            score += 10
    if 4 <= len(text) <= 32:
        score += 3
    if re.fullmatch(r"[A-Za-z0-9_{}\-!@#$%^&*]+", text):
        score += 2
    if text.isupper() and len(text) >= 6:
        score += 1
    return score

def candidate_passwords(data: bytes, limit: int = 200) -> list[str]:
    strings = extract_strings(data)
    seen: set[str] = set()
    out: list[str] = []
    for s in strings:
        if s.value in seen:
            continue
        seen.add(s.value)
        out.append(s.value)
        if len(out) >= limit:
            break
    return out
