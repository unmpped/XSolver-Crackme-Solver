from __future__ import annotations

import bisect
import re
import struct
from dataclasses import dataclass

from xsolver.core.binary import BinaryProfile

_MAGIC_16 = 0xFFFFFFFA
_MAGIC_18 = 0xFFFFFFF0
_MAGIC_20 = 0xFFFFFFF1
_MAGICS = (_MAGIC_20, _MAGIC_18, _MAGIC_16)

_COMPARE_NAMES = (
    "memequal", "eqstring", "cmpstring", "memcmp", "strcmp", "strncmp",
    "strcmpbody", "cmpbody", "bytes.Equal", "slicebytetostringcmp",
)

_MAX_NAME = 128

@dataclass(frozen=True)
class PclnTable:
    offset: int
    magic: int
    pointer_size: int
    text_start: int
    function_name_offset: int
    func_count: int
    func_table: int
    version: str

    @property
    def modern(self) -> bool:
        return self.magic in (_MAGIC_18, _MAGIC_20)

def _uint(raw: bytes, offset: int, size: int) -> int:
    if size == 8:
        return struct.unpack_from("<Q", raw, offset)[0]
    return struct.unpack_from("<I", raw, offset)[0]

def _header_at(raw: bytes, offset: int) -> PclnTable | None:
    if offset + 72 > len(raw):
        return None
    magic, = struct.unpack_from("<I", raw, offset)
    if magic not in _MAGICS:
        return None
    if raw[offset + 4] or raw[offset + 5]:
        return None
    min_inst, pointer_size = raw[offset + 6], raw[offset + 7]
    if pointer_size not in (4, 8) or min_inst not in (1, 2, 4):
        return None
    count = _uint(raw, offset + 8, pointer_size)
    if not 0 < count < 400000:
        return None
    if magic == _MAGIC_16:
        name_offset = _uint(raw, offset + 8 + 2 * pointer_size, pointer_size)
        table = _uint(raw, offset + 8 + 6 * pointer_size, pointer_size)
        if not 0 < name_offset < len(raw) or not 0 < table < len(raw):
            return None
        return PclnTable(offset, magic, pointer_size, 0, name_offset, count,
                         offset + table, "1.16")
    text_start = _uint(raw, offset + 8 + 2 * pointer_size, pointer_size)
    name_offset = _uint(raw, offset + 8 + 3 * pointer_size, pointer_size)
    table = _uint(raw, offset + 8 + 7 * pointer_size, pointer_size)
    if not 0 < name_offset < len(raw) or not 0 < table < len(raw):
        return None
    return PclnTable(offset, magic, pointer_size, text_start, name_offset, count,
                     offset + table, "1.18" if magic == _MAGIC_18 else "1.20")

def find_table(profile: BinaryProfile) -> PclnTable | None:
    raw = profile.raw
    for magic in _MAGICS:
        needle = struct.pack("<I", magic)
        start = 0
        while True:
            position = raw.find(needle, start)
            if position < 0:
                break
            start = position + 1
            table = _header_at(raw, position)
            if table is not None:
                return table
    return None

def is_go(profile: BinaryProfile) -> bool:
    if b"Go build ID:" in profile.raw[:0x2000] or b"go1." in profile.raw[:0x4000]:
        return find_table(profile) is not None
    return find_table(profile) is not None

def _name_at(raw: bytes, table: PclnTable, offset: int) -> str:
    base = table.offset + table.function_name_offset + offset
    if not 0 <= base < len(raw):
        return ""
    end = raw.find(b"\x00", base, base + _MAX_NAME)
    if end < 0:
        return ""
    return raw[base:end].decode("latin-1")

def _function_base(raw: bytes, table: PclnTable, function_offset: int,
                   entry: int, expected: int) -> int | None:
    for base in (table.func_table + function_offset, table.offset + function_offset):
        if base + 8 > len(raw):
            continue
        stored, = struct.unpack_from("<I", raw, base)
        if stored == expected:
            return base
    return None

def _align(profile: BinaryProfile, names: dict[int, str], text_start: int) -> dict[int, str]:
    if not names:
        return names
    from xsolver.analysis.disasm import executable_sections

    sections = executable_sections(profile)
    if not sections:
        return names
    low = min(section.virtual_address for section in sections)
    high = max(section.virtual_address + len(section.data) for section in sections)
    biases = [0]
    if text_start >= high:
        biases.append(text_start - low)
    for bias in biases:
        shifted = {key - bias: value for key, value in names.items()}
        inside = sum(1 for key in shifted if low <= key < high)
        if inside >= len(shifted) * 0.9:
            return shifted
    return names

def function_names(profile: BinaryProfile, table: PclnTable | None = None,
                   aligned: bool = True) -> dict[int, str]:
    table = table or find_table(profile)
    if table is None:
        return {}
    raw = profile.raw
    names: dict[int, str] = {}
    entry_size = 8 if table.modern else 2 * table.pointer_size
    for index in range(table.func_count):
        position = table.func_table + index * entry_size
        if position + entry_size > len(raw):
            break
        entry_offset = 0
        if table.modern:
            entry_offset, = struct.unpack_from("<I", raw, position)
            function_offset, = struct.unpack_from("<I", raw, position + 4)
            entry = table.text_start + entry_offset
            name_field = 4
        else:
            entry = _uint(raw, position, table.pointer_size)
            function_offset = _uint(raw, position + table.pointer_size, table.pointer_size)
            name_field = table.pointer_size
        if not function_offset or function_offset >= len(raw):
            continue
        base = _function_base(raw, table, function_offset, entry, entry_offset if table.modern else entry)
        if base is None:
            continue
        name_offset, = struct.unpack_from("<i", raw, base + name_field)
        name = _name_at(raw, table, name_offset)
        if name:
            names[entry] = name
    return _align(profile, names, table.text_start) if aligned else names

def compare_calls(instructions, names: dict[int, str]) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for insn in instructions:
        if insn.mnemonic != "call" or not insn.op_str.startswith("0x"):
            continue
        try:
            target = int(insn.op_str, 16)
        except ValueError:
            continue
        name = names.get(target)
        if not name:
            continue
        lowered = name.lower()
        if any(token.lower() in lowered for token in _COMPARE_NAMES):
            found.append((insn.address, name))
    return found

_LEA_RIP = re.compile(r"^(\w+), \[rip ([+-]) (0x[0-9a-f]+)\]$")
_MOV_IMM = re.compile(r"^\w+, (0x[0-9a-f]+)$")
_MAX_RUN = 48
_SHORT_RUN = 24

def _plausible(value: str) -> bool:
    text = value.strip()
    if len(text) < 4 or len(set(text)) < 3:
        return False
    if any(ch in text for ch in "\\/%\"'"):
        return False
    if not any(ch.isalnum() for ch in text):
        return False
    return sum(ch.isalnum() for ch in text) >= len(text) * 0.6

def _hex_literals(text: str) -> list[str]:
    digits = 0
    while digits < len(text) and text[digits] in "0123456789abcdefABCDEF":
        digits += 1
    if digits < 16 or digits % 2:
        return []
    out = [text[:digits]]
    try:
        decoded = bytes.fromhex(text[:digits]).decode("latin-1")
    except ValueError:
        return out
    if all(0x20 <= ord(ch) < 0x7F for ch in decoded):
        out.append(decoded)
    return out

def _function_slices(instructions, names, wanted) -> list[tuple[str, list]]:
    if not names or not instructions:
        return []
    starts = sorted(names)
    addresses = [insn.address for insn in instructions]
    slices = []
    for index, start in enumerate(starts):
        name = names[start]
        if wanted and not name.startswith(wanted):
            continue
        end = starts[index + 1] if index + 1 < len(starts) else instructions[-1].address + 16
        low = bisect.bisect_left(addresses, start)
        high = bisect.bisect_left(addresses, end)
        if low < high:
            slices.append((name, instructions[low:high]))
    return slices

def go_strings(profile: BinaryProfile, instructions=None, limit: int = 24,
               wanted: str = "main.") -> list[str]:
    from xsolver.analysis import disasm

    instructions = instructions if instructions is not None else disasm.disassemble(profile)
    names = function_names(profile)
    slices = _function_slices(instructions, names, wanted)
    if not slices:
        return []
    space = disasm.AddressSpace(disasm._all_sections(profile))
    found: list[str] = []
    for _name, body in slices:
        for index, insn in enumerate(body):
            if insn.mnemonic != "lea":
                continue
            match = _LEA_RIP.match(insn.op_str)
            if not match:
                continue
            delta = int(match.group(3), 16)
            origin = insn.address + insn.size
            target = origin + delta if match.group(2) == "+" else origin - delta
            data = space.read(target, _MAX_RUN)
            if not data:
                continue
            run = bytearray()
            for byte in data:
                if 0x20 <= byte < 0x7F:
                    run.append(byte)
                else:
                    break
            if len(run) < 4:
                continue
            text = run.decode("latin-1")
            size = None
            for near in body[max(0, index - 8):index + 9]:
                if near.mnemonic not in ("mov", "cmp"):
                    continue
                value_match = _MOV_IMM.match(near.op_str)
                if not value_match:
                    continue
                value = int(value_match.group(1), 16)
                if 4 <= value <= _MAX_RUN and value <= len(text):
                    size = value
                    break
            if size is None:
                if len(text) > _SHORT_RUN:
                    hexes = _hex_literals(text)
                    for value in hexes:
                        if _plausible(value) and value not in found:
                            found.append(value)
                    continue
            else:
                text = text[:size]
            for variant in (text, text.rstrip()):
                if _plausible(variant) and variant not in found:
                    found.append(variant)
            if len(found) >= limit:
                return found
    return found[:limit]
