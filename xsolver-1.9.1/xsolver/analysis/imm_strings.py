from __future__ import annotations

import re

from xsolver.analysis.disasm import disassemble_functions_recursive
from xsolver.core.binary import BinaryProfile

_MOV_REG_IMM = re.compile(r"^(e?[abcd]x|e?[sd]i|e?[sb]p|r\d{1,2}d?|r\d{1,2}b|al|bl|cl|dl),"
                          r"\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_STORE_REG = re.compile(r"^(byte|word|dword|qword) ptr \[([^\]]+)\],\s*([a-z][a-z0-9]*)$")
_STORE_IMM = re.compile(r"^(byte|word|dword|qword) ptr \[([^\]]+)\],\s*"
                        r"(-?0x[0-9a-fA-F]+|-?\d+)$")
_OFFSET = re.compile(r"^([a-z]{3,4})\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)$")
_MIN_RUN = 4
_MAX_RUN = 64
_STACK_BASES = ("ebp", "esp", "rbp", "rsp")

def _imm(token: str) -> int:
    lowered = token.lower()
    return -int(lowered[1:], 16) if lowered.startswith("-0x") else (
        int(lowered, 16) if "0x" in lowered else int(lowered))

def _printable(value: int) -> bool:
    return 0x20 <= value <= 0x7E

def _stack_slot(operand: str) -> tuple[str, int] | None:
    match = _OFFSET.match(operand.replace(" ", ""))
    if not match or match.group(1) not in _STACK_BASES:
        return None
    offset = _imm(match.group(3))
    return match.group(1), offset if match.group(2) == "+" else -offset

def _packed(value: int, width: int) -> bytes | None:
    if value < 0:
        value += 1 << (8 * width)
    if value >= 1 << (8 * width):
        return None
    raw = value.to_bytes(width, "little").rstrip(b"\x00")
    if raw and all(_printable(byte) for byte in raw):
        return raw
    return None

def _byte_store(insn, pending: dict[str, int]) -> tuple[bytes, str, int] | None:
    stored = _STORE_IMM.match(insn.op_str)
    value = None
    width_name = None
    operand = None
    if stored:
        width_name, operand = stored.group(1), stored.group(2)
        value = _imm(stored.group(3))
    else:
        stored = _STORE_REG.match(insn.op_str)
        if not stored:
            return None
        width_name, operand = stored.group(1), stored.group(2)
        value = pending.get(stored.group(3))
    if value is None:
        return None
    width = {"byte": 1, "word": 2, "dword": 4, "qword": 8}.get(width_name, 0)
    raw = bytes([value]) if width == 1 and _printable(value) else _packed(value, width) if width else None
    if not raw:
        return None
    slot = _stack_slot(operand.strip())
    if slot is None:
        return None
    return raw, slot[0], slot[1]

def _runs(instructions) -> list[bytes]:
    events: list[tuple[int, str, int]] = []
    pending: dict[str, int] = {}
    for insn in instructions:
        if insn.mnemonic == "mov":
            match = _MOV_REG_IMM.match(insn.op_str)
            if match:
                pending[match.group(1)] = _imm(match.group(2))
                continue
        store = _byte_store(insn, pending)
        if store is not None:
            events.append(store)

    found: list[bytes] = []
    index = 0
    while index < len(events):
        blob = bytearray(events[index][0])
        base, last = events[index][1], events[index][2]
        cursor = index + 1
        while cursor < len(events) and len(blob) < _MAX_RUN:
            raw, next_base, next_offset = events[cursor]
            if next_base != base or next_offset == last or abs(next_offset - last) > 8:
                break
            blob.extend(raw)
            last = next_offset
            cursor += 1
        if len(blob) >= _MIN_RUN:
            found.append(bytes(blob))
        index = max(cursor, index + 1)
    return found

def immediate_strings(profile: BinaryProfile, limit: int = 12) -> list[str]:
    functions = disassemble_functions_recursive(profile)
    out: list[str] = []
    seen: set[str] = set()
    for name in sorted(functions, key=lambda item: (item != "main", item)):
        for raw in _runs(functions[name]):
            text = raw.decode("latin-1").strip()
            if len(text) < _MIN_RUN or text in seen:
                continue
            seen.add(text)
            out.append(text)
            if len(out) >= limit:
                return out
    return out

_CMP_IMM = re.compile(r"^([a-z][a-z0-9]*(?: ptr \[[^\]]+\])?),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_EMBED_MNEMONICS = {"cmp", "mov", "push"}
_MIN_EMBED = 4

def _embed_value(insn) -> bytes | None:
    if insn.mnemonic not in _EMBED_MNEMONICS:
        return None
    match = _CMP_IMM.match(insn.op_str)
    if not match:
        return None
    token = match.group(2).lower()
    width = 4
    if token.endswith("h") or token.startswith("0x"):
        digits = token.replace("-", "").replace("0x", "")
        width = max(1, min(8, (len(digits) + 1) // 2))
    narrowed = {"byte": 1, "word": 2, "dword": 4, "qword": 8}
    for prefix, size in narrowed.items():
        if prefix in match.group(1):
            width = size
            break
    return _packed(_imm(token), width)

def embedded_strings(profile: BinaryProfile, limit: int = 12) -> list[str]:
    functions = disassemble_functions_recursive(profile)
    out: list[str] = []
    seen: set[str] = set()
    for name in sorted(functions, key=lambda item: (item != "main", item)):
        blob = bytearray()
        for insn in functions[name]:
            raw = _embed_value(insn)
            if raw and len(raw) >= 2:
                blob.extend(raw)
                continue
            if len(blob) >= _MIN_EMBED:
                text = bytes(blob).decode("latin-1")
                if text not in seen:
                    seen.add(text)
                    out.append(text)
                    if len(out) >= limit:
                        return out
            blob = bytearray()
        if len(blob) >= _MIN_EMBED:
            text = bytes(blob).decode("latin-1")
            if text not in seen:
                seen.add(text)
                out.append(text)
                if len(out) >= limit:
                    return out
    return out
