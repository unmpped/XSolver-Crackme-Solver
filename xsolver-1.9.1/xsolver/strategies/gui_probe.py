from __future__ import annotations

import re
import time

from xsolver.core.report import StrategyAttempt
from xsolver.strategies.base import Strategy, StrategyResult, SuccessDetector

JUNK_PROBES = ("xsolver-probe-7q", "Zq3-probe", "9f", "probe-zz-42")
POSITIVE = (
    "correct", "congrat", "success", "granted", "welcome", "valid", "unlocked",
    "you win", "well done", "good job", "nice work", "access", "accepted", "right",
    "bravo", "felicit", "gagne", "trouve", "reussi", "bien joue", "pass",
    "flag{", "ctf{", "cmo{", "solved", "authenticated", "approved", "authorized",
)
NEGATIVE = ("wrong", "incorrect", "denied", "invalid", "error", "fail", "try again",
            "nah", "nope", "erreur", "faux", "refus")
MAX_CANDIDATES = 60

def _blob(payload: dict | None) -> str:
    if not payload:
        return ""
    texts = payload.get("texts") or []
    extra = payload.get("box") or {}
    values = [str(item) for item in texts]
    for key in ("text", "caption"):
        value = extra.get(key)
        if value:
            values.append(str(value))
    return " | ".join(values).strip().lower()

def _mentions(blob: str, words) -> list[str]:
    return [word for word in words if word in blob]

def _judge(payload: dict | None, junk_blobs: list[str]) -> tuple[bool, str]:
    blob = _blob(payload)
    if not blob:
        return False, "no dialog reaction"
    good = _mentions(blob, POSITIVE)
    bad = _mentions(blob, NEGATIVE)
    if good and not bad:
        return True, f"approval wording ({good[0]})"
    if bad and not good:
        return False, f"rejection wording ({bad[0]})"
    if blob in junk_blobs:
        return False, "same answer as a junk probe"
    if good:
        return True, f"approval wording ({good[0]})"
    return True, "answer differs from junk probes"

_KEY_CHARS = re.compile(r"^[A-Za-z0-9_\-!@#$%^&*()+=.,:;?/\\|~\[\]{}<>'\"]+$")
_SKIP_HEADS = ("_", ".", "GCC", "GLIBC", "__", "??")

def _key_like(text: str) -> bool:
    if not 3 <= len(text) <= 40:
        return False
    if any(ch.isspace() for ch in text):
        return False
    if text.startswith(_SKIP_HEADS):
        return False
    lowered = text.lower()
    if lowered.endswith((".dll", ".exe", ".so", ".a", ".o")):
        return False
    if "@" in text or "::" in text or "\\" in text:
        return False
    return bool(_KEY_CHARS.match(text))

def _data_sections(pe) -> list[tuple[int, int, str]]:
    spans = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("latin-1", "replace")
        start = int(section.PointerToRawData)
        end = start + int(section.SizeOfRawData)
        base = int(pe.OPTIONAL_HEADER.ImageBase) + int(section.VirtualAddress)
        if end > start:
            spans.append((start, end, name, base))
    return spans

def _code_section(pe):
    for section in pe.sections:
        flags = int(section.Characteristics)
        if flags & 0x20000000:
            start = int(section.PointerToRawData)
            body = bytes(section.get_data() or b"")
            return start, body, int(pe.OPTIONAL_HEADER.ImageBase) + int(section.VirtualAddress)
    return None

def referenced_keys(profile, limit: int = 30) -> list[str]:
    if not profile.format.startswith("PE"):
        return []
    try:
        import pefile
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
        from xsolver.analysis.strings import extract_strings
    except Exception:
        return []
    try:
        pe = pefile.PE(str(profile.path))
    except Exception:
        return []
    spans = _data_sections(pe)
    code = _code_section(pe)
    if not spans or code is None:
        return []
    offset, body, code_base = code
    strings = [item for item in extract_strings(profile.raw, min_length=3)
               if any(start <= item.offset < end for start, end, _n, _b in spans)]
    if not strings:
        return []
    by_va = {}
    for item in strings:
        for start, end, name, base in spans:
            if start <= item.offset < end:
                by_va[base + (item.offset - start)] = (item.value, name)
                break
    is_64 = "64" in profile.arch or "x86-64" in profile.arch or "amd64" in profile.arch.lower()
    engine = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    engine.detail = True
    found: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    for insn in engine.disasm(body, code_base):
        targets = []
        for operand in insn.operands:
            if operand.type == X86_OP_IMM:
                targets.append(operand.imm)
            elif operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                targets.append(insn.address + insn.size + operand.mem.disp)
        for target in targets:
            hit = by_va.get(target)
            if hit is None:
                continue
            value, name = hit
            if value in seen:
                continue
            seen.add(value)
            found.append((insn.address, value, name))
    found.sort()
    return [value for _address, value, _name in found][:limit]

def candidate_keys(profile, limit: int = MAX_CANDIDATES) -> list[str]:
    ranked: list[tuple[int, int, str]] = []
    seen: set[str] = set()

    def push(text: str, base: int = 0) -> None:
        if not text or text in seen or len(text) > 48:
            return
        seen.add(text)
        ranked.append((0 if _key_like(text) else 1, base, text))

    try:
        from xsolver.analysis.static_extract import extract_candidate_keys
        for index, text in enumerate(extract_candidate_keys(profile)):
            push(text, 0 - index)
    except Exception:
        pass
    referencers = referenced_keys(profile)
    for index, text in enumerate(referencers):
        push(text, 60 - index)
    for helper, weight in (("immediate_strings", 2), ("embedded_strings", 1)):
        try:
            module = __import__("xsolver.analysis.imm_strings", fromlist=[helper])
            for index, text in enumerate(getattr(module, helper)(profile, limit=12)):
                push(text, weight * 10 - index)
        except Exception:
            pass
    try:
        from xsolver.analysis.strings import extract_strings
        for item in extract_strings(profile.raw, min_length=3)[:400]:
            push(item.value, item.score)
    except Exception:
        pass
    try:
        from xsolver.analysis.strings import candidate_passwords
        for text in candidate_passwords(profile.raw, limit=40):
            push(text, -5)
    except Exception:
        pass
    try:
        from xsolver.strategies.common_passwords import COMMON_CRACKME_PASSWORDS
        for text in COMMON_CRACKME_PASSWORDS:
            push(text, -20)
    except Exception:
        pass
    order = {text: position for position, text in enumerate(referencers)}
    ranked.sort(key=lambda item: (order.get(item[2], 10_000), item[0], -item[1], len(item[2])))
    return [text for _klass, _base, text in ranked][:limit]

class GuiProbeStrategy(Strategy):
    name = "gui-probe"
    _session = None

    def _attempt(self, session, candidate: str) -> dict | None:
        try:
            return session.attempt(candidate)
        except Exception:
            return None

    def _reopen(self):
        from xsolver.analysis import winguidrive
        try:
            if self._session is not None:
                self._session.close()
        except Exception:
            pass
        self._session = winguidrive.open_session(self.binary_path)
        return self._session

    def run(self, success_detector: SuccessDetector) -> StrategyResult:
        start = time.monotonic()
        from xsolver.analysis import winguidrive

        self._session = winguidrive.open_session(self.binary_path)
        if self._session is None:
            return StrategyResult(
                found=False,
                key=None,
                input_mode=None,
                attempt=StrategyAttempt(
                    strategy=self.name,
                    candidates_tried=0,
                    duration_seconds=time.monotonic() - start,
                    outcome="unavailable",
                    detail=f"no gui session: {winguidrive.last_error()}",
                ),
            )
        tried = 0
        restarts = 0
        junk_blobs: list[str] = []

        def attempt(candidate: str) -> dict | None:
            nonlocal tried, restarts
            payload = self._attempt(self._session, candidate)
            tried += 1
            if payload is None:
                if restarts >= 3:
                    return None
                restarts += 1
                if self._reopen() is None:
                    return None
                payload = self._attempt(self._session, candidate)
                tried += 1
            return payload

        try:
            for junk in JUNK_PROBES[:3]:
                payload = attempt(junk)
                if payload:
                    junk_blobs.append(_blob(payload))
            if self._session is None:
                return StrategyResult(
                    found=False, key=None, input_mode=None,
                    attempt=StrategyAttempt(
                        strategy=self.name, candidates_tried=tried,
                        duration_seconds=time.monotonic() - start,
                        outcome="unavailable",
                        detail="target exits after the first probe",
                    ),
                )
            for candidate in candidate_keys(self.triage.profile):
                if self._time_left(start) <= 0:
                    break
                payload = attempt(candidate)
                if payload is None:
                    continue
                accepted, reason = _judge(payload, junk_blobs)
                if not accepted:
                    continue
                replay = attempt(candidate)
                again, _why = _judge(replay, junk_blobs)
                control = attempt("z" * max(1, len(candidate)))
                if again and _blob(control) not in (_blob(replay), ""):
                    return StrategyResult(
                        found=True,
                        key=candidate,
                        input_mode="gui",
                        attempt=StrategyAttempt(
                            strategy=self.name,
                            candidates_tried=tried,
                            duration_seconds=time.monotonic() - start,
                            outcome="success",
                            detail=f"accepted by the window: {reason}",
                        ),
                    )
        finally:
            if self._session is not None:
                self._session.close()
        return StrategyResult(
            found=False,
            key=None,
            input_mode=None,
            attempt=StrategyAttempt(
                strategy=self.name,
                candidates_tried=tried,
                duration_seconds=time.monotonic() - start,
                outcome="exhausted",
                detail="no candidate accepted by the window",
            ),
        )

def available() -> bool:
    try:
        import frida
    except ImportError:
        return False
    return True

def looks_graphical(profile) -> bool:
    if not profile.format.startswith("PE"):
        return False
    from xsolver.orchestrator import _GUI_APIS
    present = sum(1 for api in _GUI_APIS if api in profile.raw)
    return present >= 1
