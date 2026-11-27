from __future__ import annotations

import re

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_WORD_RUN = re.compile(rb"[A-Za-z0-9_./-]{6,}")

MAX_CANDIDATE_LENGTH = 32
_MAX_CANDIDATES = 1500

def _dominant_ratio(text: bytes) -> float:
    if not text:
        return 1.0
    return text.count(max(set(text), key=text.count)) / len(text)

def _score(text: bytes) -> float:
    if not text:
        return -100.0
    letters = sum(chr(c).isalpha() for c in text)
    digits = sum(chr(c).isdigit() for c in text)
    vowels = sum(chr(c) in "aeiouAEIOU" for c in text)
    symbols = sum(c in b"_" for c in text)
    rare = sum(chr(c) in "`{}|^~[]\\'\"<>;=+/" for c in text)
    distinct = len(set(text))
    length = len(text)

    score = letters * 2.0 + digits * 1.5 + symbols * 3.0 + distinct
    score /= max(length, 1) ** 0.5
    if letters == 0:
        score -= 6.0
    if letters >= 4 and vowels == 0:
        score -= 6.0
    if letters >= 6 and vowels * 4 < letters:
        score -= 3.0
    if rare:
        score -= 5.0 * rare
    if letters:
        vowel_ratio = vowels / letters
        upper_ratio = sum(chr(c).isupper() for c in text) / letters
        if vowel_ratio >= 0.30:
            score += 4.0
        if vowel_ratio >= 0.40:
            score += 2.0
        if upper_ratio > 0.55:
            score -= 4.0
    has_upper = any(chr(c).isupper() for c in text)
    has_lower = any(chr(c).islower() for c in text)
    if has_upper and has_lower and (digits or symbols):
        score += 3.0
    if _dominant_ratio(text) > 0.3:
        score -= 4.0
    if length > MAX_CANDIDATE_LENGTH:
        score -= 3.0
    return score

_WALL = re.compile(rb"(.)\1{2,}")

def _segments(text: bytes) -> list[bytes]:
    pieces, cursor = [], 0
    for match in _WALL.finditer(text):
        if match.start() > cursor:
            pieces.append(text[cursor:match.start()])
        cursor = match.end()
    if cursor < len(text):
        pieces.append(text[cursor:])
    return pieces

def _acceptable(piece: bytes, min_length: int) -> bool:
    return (
        min_length <= len(piece) <= MAX_CANDIDATE_LENGTH
        and len(set(piece)) >= 3
        and _dominant_ratio(piece) <= 0.4
    )

def xor_strings(raw: bytes, min_length: int = 6, max_key: int = 255) -> list[tuple[str, int]]:
    found: dict[str, int] = {}
    for key in range(1, max_key + 1):
        decoded = bytes(byte ^ key for byte in raw)
        for match in _PRINTABLE_RUN.finditer(decoded):
            run = match.group()
            pieces = [piece for piece in _WORD_RUN.findall(run)]
            if _acceptable(run, min_length):
                pieces.insert(0, run)
            expanded = list(pieces)
            for piece in pieces:
                expanded.extend(_segments(piece))
            for piece in expanded:
                if not _acceptable(piece, min_length):
                    continue
                try:
                    candidate = piece.decode("ascii")
                except UnicodeDecodeError:
                    continue
                found.setdefault(candidate, key)
    ranked = sorted(found.items(), key=lambda item: _score(item[0].encode()), reverse=True)
    return [(text, key) for text, key in ranked[:_MAX_CANDIDATES]]

def xor_string_candidates(raw: bytes) -> list[str]:
    candidates: list[str] = []

    def add(value: str) -> None:
        if len(value) >= 6 and value not in candidates:
            candidates.append(value)

    for text, _ in xor_strings(raw):
        add(text)
        stripped = text.rstrip("0123456789")
        if stripped != text:
            add(stripped)
        for part in re.split(r"[\s:,.!?]+", text):
            add(part)
    return candidates
