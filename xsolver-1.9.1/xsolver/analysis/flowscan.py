from __future__ import annotations

import struct
from dataclasses import dataclass, field

from xsolver.core.binary import BinaryProfile
from xsolver.core.elf import NotElfError, parse_elf
from xsolver.core.pe import NotPeError, parse_pe

@dataclass
class FunctionRange:
    start: int
    end: int
    name: str = ""
    source: str = ""

    def __contains__(self, address: int) -> bool:
        return self.start <= address < self.end

    @property
    def size(self) -> int:
        return max(0, self.end - self.start)

@dataclass
class FlowMap:
    ranges: list[FunctionRange] = field(default_factory=list)
    source: str = ""
    _starts: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.ranges.sort(key=lambda r: r.start)
        self._starts = {r.start: r for r in self.ranges}

    def __len__(self) -> int:
        return len(self.ranges)

    def at(self, address: int) -> FunctionRange | None:
        low, high = 0, len(self.ranges) - 1
        while low <= high:
            middle = (low + high) // 2
            candidate = self.ranges[middle]
            if address < candidate.start:
                high = middle - 1
            elif address >= candidate.end:
                low = middle + 1
            else:
                return candidate
        return None

    def start_of(self, address: int) -> int:
        found = self.at(address)
        return found.start if found else address

    def slice(self, instructions, address: int) -> list:
        found = self.at(address)
        if found is None:
            return [insn for insn in instructions if insn.address <= address]
        return [insn for insn in instructions if found.start <= insn.address < found.end]

def _section_bytes(profile: BinaryProfile, wanted: tuple[str, ...]) -> tuple[int, bytes] | None:
    data = profile.raw
    try:
        if profile.format.startswith("PE"):
            info = parse_pe(data)
            for section in info.sections:
                name = section.name.lstrip(".").lower()
                if name in wanted:
                    body = data[section.raw_offset:section.raw_offset + section.raw_size]
                    if body:
                        return section.virtual_address, body
        else:
            info = parse_elf(data)
            for section in info.sections:
                name = section.name.lstrip(".").lower()
                if name in wanted and section.size:
                    body = data[section.offset:section.offset + section.size]
                    if body:
                        return section.addr, body
    except (NotPeError, NotElfError, struct.error, IndexError, ValueError):
        return None
    return None

def pe_functions(profile: BinaryProfile) -> list[FunctionRange]:
    found = _section_bytes(profile, ("pdata",))
    if found is None:
        return []
    base, body = found
    ranges: list[FunctionRange] = []
    for offset in range(0, len(body) - 11, 12):
        begin, end, _unwind = struct.unpack_from("<III", body, offset)
        if not begin or end <= begin:
            continue
        if end - begin > 0x100000:
            continue
        ranges.append(FunctionRange(begin, end, source="pdata"))
    return ranges

def _uleb(data: bytes, index: int) -> tuple[int, int]:
    result = shift = 0
    while index < len(data):
        byte = data[index]
        index += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return result, index

def _sleb(data: bytes, index: int) -> tuple[int, int]:
    result = shift = 0
    while index < len(data):
        byte = data[index]
        index += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                result -= 1 << shift
            break
    return result, index

def _read_encoded(data: bytes, index: int, encoding: int, field_address: int) -> tuple[int, int]:
    if encoding == 0xFF:
        return 0, index
    size = {0x00: 8, 0x01: 2, 0x02: 4, 0x03: 8, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}.get(encoding & 0x0F)
    if size is None:
        return 0, index
    if index + size > len(data):
        return 0, len(data)
    raw = data[index:index + size]
    signed = (encoding & 0x0F) in (0x09, 0x0A, 0x0B, 0x0C)
    value = int.from_bytes(raw, "little", signed=signed)
    index += size
    application = encoding & 0x70
    if application == 0x10:
        value += field_address
    return value, index

def elf_functions(profile: BinaryProfile) -> list[FunctionRange]:
    found = _section_bytes(profile, ("eh_frame",))
    if found is None:
        return []
    base, body = found
    ranges: list[FunctionRange] = []
    index = 0
    cies: dict[int, int] = {}
    while index + 4 <= len(body):
        record_start = index
        length = struct.unpack_from("<I", body, index)[0]
        index += 4
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            if index + 8 > len(body):
                break
            length = struct.unpack_from("<Q", body, index)[0]
            index += 8
        record_end = index + length
        if record_end > len(body) or length < 4:
            break
        cie_id_field = index
        cie_id = struct.unpack_from("<I", body, index)[0]
        index += 4
        if cie_id == 0:
            version = body[index]
            index += 1
            end = body.find(b"\x00", index)
            augmentation = body[index:end].decode("latin-1") if end >= 0 else ""
            index = (end + 1) if end >= 0 else index
            _code_align, index = _uleb(body, index)
            _data_align, index = _sleb(body, index)
            if version == 1:
                index += 1
            else:
                _ra, index = _uleb(body, index)
            encoding = 0x00
            if augmentation.startswith("z"):
                aug_len, index = _uleb(body, index)
                aug_end = index + aug_len
                cursor = index
                for letter in augmentation[1:]:
                    if letter == "R":
                        encoding = body[cursor]
                        cursor += 1
                    elif letter == "P":
                        personality = body[cursor]
                        _value, cursor = _read_encoded(body, cursor + 1, personality, 0)
                    elif letter == "L":
                        cursor += 1
                    elif letter in "SB":
                        pass
                index = aug_end
            cies[record_start] = encoding
        else:
            cie_offset = cie_id_field - cie_id
            encoding = cies.get(cie_offset, 0x00)
            field_address = base + index
            start, index = _read_encoded(body, index, encoding, field_address)
            span_size = {0x00: 8, 0x01: 2, 0x02: 4, 0x03: 8, 0x04: 8}.get(encoding & 0x0F, 4)
            if index + span_size > len(body):
                break
            span = int.from_bytes(body[index:index + span_size], "little",
                                  signed=(encoding & 0x0F) in (0x09, 0x0A, 0x0B, 0x0C))
            index += span_size
            if start and span > 0 and span < 0x100000:
                ranges.append(FunctionRange(start, start + span, source="eh_frame"))
        index = record_end
    return ranges

def elf_symbol_functions(profile: BinaryProfile) -> list[FunctionRange]:
    from xsolver.core.elf import parse_elf_symbols

    try:
        symbols = parse_elf_symbols(profile.raw)
    except (NotElfError, struct.error, IndexError, ValueError):
        return []
    return [FunctionRange(sym.value, sym.value + max(sym.size, 1), sym.name, "symtab")
            for sym in symbols if sym.is_function and sym.size]

def _prologue_scan(profile: BinaryProfile, instructions) -> list[FunctionRange]:
    starts: list[int] = []
    for index, insn in enumerate(instructions):
        if index == 0:
            starts.append(insn.address)
            continue
        previous = instructions[index - 1]
        if previous.mnemonic in ("int3", "ret", "retn", "hlt", "ud2", "nop"):
            if insn.mnemonic in ("push", "endbr64", "mov", "sub", "lea", "xor", "call"):
                if insn.mnemonic == "push" and insn.op_str not in ("rbp", "ebx", "r12", "r13", "r14", "r15", "rsi", "rdi"):
                    continue
                starts.append(insn.address)
    ranges: list[FunctionRange] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else instructions[-1].address + instructions[-1].size
        if end > start:
            ranges.append(FunctionRange(start, end, source="scan"))
    return ranges

def function_map(profile: BinaryProfile, instructions=None) -> FlowMap:
    if profile.format.startswith("PE"):
        ranges = pe_functions(profile)
        if ranges:
            return FlowMap(ranges, "pdata")
        ranges = _prologue_scan(profile, instructions) if instructions else []
        return FlowMap(ranges, "scan")
    ranges = elf_functions(profile)
    if ranges:
        return FlowMap(ranges, "eh_frame")
    ranges = elf_symbol_functions(profile)
    if ranges:
        return FlowMap(ranges, "symtab")
    ranges = _prologue_scan(profile, instructions) if instructions else []
    return FlowMap(ranges, "scan")

_CACHE: dict[tuple[str, float], FlowMap] = {}

def cached_map(profile: BinaryProfile, instructions=None) -> FlowMap:
    key = (str(profile.path), float(profile.file_size))
    if key not in _CACHE:
        _CACHE[key] = function_map(profile, instructions)
    return _CACHE[key]
