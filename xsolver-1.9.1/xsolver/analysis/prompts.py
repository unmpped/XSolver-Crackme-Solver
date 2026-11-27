from __future__ import annotations

import re
from pathlib import Path

FAILURE_MARKERS = (
    "wrong", "incorrect", "not correct", "denied", "invalid", "fail",
    "not a good job", "try again", "no luck", "nope", "bad", "error",
    "access refus", "rejected", "does not match", "mismatch", "sorry",
)
SUCCESS_MARKERS = (
    "correct", "congrat", "success", "welcome", "granted", "well done",
    "good job", "you win", "unlocked", "accepted", "passed", "flag{",
    "ctf{", "nice work", "right password", "solved", "bravo", "great",
)
NEGATED_SUCCESS = ("not correct", "not a good job", "not right", "not valid",
                   "isn't correct", "is not the", "incorrect")
_PROMPT_ENDINGS = (":", "?", ">", "]")
_TRIM = re.compile(r"[ \t]+")

def classify(text: str) -> str | None:
    lowered = text.lower()
    if any(phrase in lowered for phrase in NEGATED_SUCCESS):
        return "failure"
    if looks_like_prompt(text):
        return "progress"
    if any(marker in lowered for marker in SUCCESS_MARKERS):
        return "success"
    if any(marker in lowered for marker in FAILURE_MARKERS):
        return "failure"
    return None

def looks_like_prompt(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    tail = stripped.splitlines()[-1].strip()
    if not tail:
        return False
    if tail.endswith(_PROMPT_ENDINGS):
        return True
    lowered = tail.lower()
    if any(marker in lowered for marker in SUCCESS_MARKERS + FAILURE_MARKERS):
        return False
    if len(tail) > 60:
        return False
    return any(word in lowered for word in ("password", "login", "name", "serial", "code",
                                            "key", "level", "step", "stage"))

NAME_WORDS = ("username", "user name", "user", "login", "name", "identifiant", "nom")
SECRET_WORDS = ("password", "passphrase", "serial", "licence", "license", "key", "code",
                "registration", "mot de passe", "pwd")

def prompt_role(text: str) -> str:
    lowered = text.lower()
    if any(word in lowered for word in SECRET_WORDS):
        return "secret"
    if any(word in lowered for word in NAME_WORDS):
        return "name"
    return "unknown"

def prompt_signature(text: str) -> str:
    tail = text.strip().splitlines()[-1] if text.strip() else ""
    return _TRIM.sub(" ", tail.strip())[:60]

def static_prompts(path: str | Path, limit: int = 12) -> list[str]:
    from xsolver.analysis.strings import extract_strings

    try:
        raw = Path(path).read_bytes()
    except OSError:
        return []
    out: list[str] = []
    for string in extract_strings(raw):
        value = string.value.strip()
        if not value or len(value) < 4 or len(value) > 80:
            continue
        if not looks_like_prompt(value):
            continue
        if value in out:
            continue
        out.append(value)
        if len(out) >= limit:
            break
    return out

def step_count(path: str | Path) -> int:
    return len({signature for signature in (prompt_signature(p) for p in static_prompts(path))})
