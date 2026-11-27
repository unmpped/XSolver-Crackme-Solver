from __future__ import annotations

from xsolver.core.binary import BinaryProfile

_MIN_LENGTH = 3
_MAX_LENGTH = 48
_MAX_INSTRUCTIONS = 200_000

def _sections(path: str):
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    code = []
    readable = []
    for section in pe.sections:
        characteristics = int(section.Characteristics)
        start = base + int(section.VirtualAddress)
        body = bytes(section.get_data() or b"")
        readable.append((start, body, characteristics))
        if characteristics & 0x20000000:
            code.append((start, body))
    return base, code, readable

def _read_string(sections, address: int) -> str | None:
    for start, body, characteristics in sections:
        if not characteristics & 0x40000000:
            continue
        if not start <= address < start + len(body):
            continue
        offset = address - start
        chunk = body[offset:offset + _MAX_LENGTH + 1]
        end = chunk.find(b"\x00")
        if end < _MIN_LENGTH:
            return None
        text = chunk[:end]
        if len(text) < _MIN_LENGTH or not all(0x20 <= byte < 0x7F for byte in text):
            return None
        return text.decode("latin-1")
    return None

def _printable_ratio(text: str) -> float:
    return sum(1 for char in text if char.isprintable()) / max(1, len(text))

def pointer_strings(profile: BinaryProfile, limit: int = 40) -> list[str]:
    import capstone

    try:
        base, code, sections = _sections(profile.path)
    except Exception:
        return []
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True

    seen: dict[str, int] = {}
    processed = 0
    for start, body in code:
        for insn in engine.disasm(body, start):
            processed += 1
            if processed > _MAX_INSTRUCTIONS:
                break
            for operand in insn.operands:
                address = None
                if operand.type == 2 and isinstance(operand.imm, int):
                    address = operand.imm
                elif operand.type == 3 and operand.mem.base == 0 and not operand.mem.index:
                    address = int(operand.mem.disp)
                if address is None or address < base:
                    continue
                text = _read_string(sections, address)
                if text is None or len(text) > _MAX_LENGTH:
                    continue
                if text.startswith(("_", ".", "??")) and " " not in text:
                    continue
                seen[text] = seen.get(text, 0) + 1

    scored = []
    for text, count in seen.items():
        score = 0
        if " " not in text:
            score += 3
        if text.isalnum():
            score += 2
        if 4 <= len(text) <= 16:
            score += 2
        if text.istitle() or text.islower():
            score += 1
        if any(word in text.lower() for word in ("error", "exception", "runtime", "invalid",
                                                 "cannot", "failed", "failed", "mingw", "gcc")):
            score -= 4
        score += min(count, 3)
        scored.append((score, text))
    scored.sort(key=lambda item: (-item[0], len(item[1])))
    out: list[str] = []
    for _score, text in scored:
        if text in out:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out
