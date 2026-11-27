from __future__ import annotations

import re
from dataclasses import dataclass

from xsolver import _vendor

_vendor.ensure_on_path()

import capstone

from xsolver.core.binary import BinaryProfile
from xsolver.core.elf import ElfSymbol, NotElfError, parse_elf, parse_elf_symbols
from xsolver.core.pe import NotPeError, parse_pe

_ELF_FLAG_EXEC = 0x4
_PE_CHAR_EXEC = 0x20000000

@dataclass
class CodeSection:
    name: str
    virtual_address: int
    data: bytes

def executable_sections(profile: BinaryProfile) -> list[CodeSection]:
    sections: list[CodeSection] = []
    try:
        info = parse_elf(profile.raw)
        for sec in info.sections:
            if sec.flags & _ELF_FLAG_EXEC and sec.size > 0 and sec.offset + sec.size <= len(profile.raw):
                body = profile.raw[sec.offset:sec.offset + sec.size]
                sections.append(CodeSection(sec.name or "(unnamed)", sec.addr, body))
        return sections
    except NotElfError:
        pass

    try:
        info = parse_pe(profile.raw)
        for sec in info.sections:
            if sec.characteristics & _PE_CHAR_EXEC and sec.raw_size > 0 and sec.raw_offset + sec.raw_size <= len(profile.raw):
                body = profile.raw[sec.raw_offset:sec.raw_offset + sec.raw_size]
                sections.append(CodeSection(sec.name or "(unnamed)", sec.virtual_address, body))
        return sections
    except NotPeError:
        pass

    return sections

def _all_sections(profile: BinaryProfile) -> list[CodeSection]:
    sections: list[CodeSection] = []
    try:
        info = parse_elf(profile.raw)
        for sec in info.sections:
            if sec.size > 0 and sec.addr and sec.offset + sec.size <= len(profile.raw):
                body = profile.raw[sec.offset:sec.offset + sec.size]
                sections.append(CodeSection(sec.name or "(unnamed)", sec.addr, body))
        return sections
    except NotElfError:
        pass

    try:
        info = parse_pe(profile.raw)
        for sec in info.sections:
            if sec.raw_size > 0 and sec.raw_offset + sec.raw_size <= len(profile.raw):
                body = profile.raw[sec.raw_offset:sec.raw_offset + sec.raw_size]
                sections.append(CodeSection(sec.name or "(unnamed)", sec.virtual_address, body))
        return sections
    except NotPeError:
        pass

    return sections

def _capstone_engine(profile: BinaryProfile) -> capstone.Cs | None:
    arch = profile.arch
    if "x86-64" in arch:
        engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif "x86" in arch:
        engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    else:
        return None
    engine.skipdata = True
    return engine

_SWEEP_CACHE: dict[tuple, list[capstone.CsInsn]] = {}
_SWEEP_CACHE_ORDER: list[tuple] = []
_SWEEP_CACHE_MAX = 4

def _sweep_key(profile: BinaryProfile) -> tuple:
    raw = profile.raw
    return (getattr(profile, "path", None), len(raw), hash(raw))

def disassemble(profile: BinaryProfile) -> list[capstone.CsInsn]:
    key = _sweep_key(profile)
    cached = _SWEEP_CACHE.get(key)
    if cached is not None:
        return cached
    engine = _capstone_engine(profile)
    if engine is None:
        return []
    instructions: list[capstone.CsInsn] = []
    for section in executable_sections(profile):
        instructions.extend(engine.disasm(section.data, section.virtual_address))
    _SWEEP_CACHE[key] = instructions
    _SWEEP_CACHE_ORDER.append(key)
    while len(_SWEEP_CACHE_ORDER) > _SWEEP_CACHE_MAX:
        _SWEEP_CACHE.pop(_SWEEP_CACHE_ORDER.pop(0), None)
    return instructions

class AddressSpace:
    def __init__(self, sections: list[CodeSection]):
        self._sections = sorted(sections, key=lambda s: s.virtual_address)

    def read(self, addr: int, length: int) -> bytes | None:
        for section in self._sections:
            start = section.virtual_address
            end = start + len(section.data)
            if start <= addr < end:
                offset = addr - start
                return section.data[offset:offset + length]
        return None

    def contains(self, addr: int) -> bool:
        for section in self._sections:
            if section.virtual_address <= addr < section.virtual_address + len(section.data):
                return True
        return False

_DIRECT_TARGET_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_JCC_PREFIXES = ("je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
                  "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns",
                  "jp", "jnp", "jcxz", "jecxz", "jrcxz")
_NO_SUCCESSOR_MNEMONICS = ("ret", "retn", "retf", "hlt", "ud2", "iret", "iretd", "iretq")

_MAX_INSN_LEN = 16

def _direct_target(insn: "capstone.CsInsn") -> int | None:
    if _DIRECT_TARGET_RE.match(insn.op_str.strip()):
        return int(insn.op_str, 16)
    return None

def _parse_imm_or_zero(token: str | None) -> int:
    if not token:
        return 0
    if token.lower().startswith("0x") or token.lower().startswith("-0x"):
        return int(token, 16)
    return int(token)

_SIB_SCALED_RE = re.compile(
    r"^\w+ ptr \[(?:(?P<base>\w+)\s*\+\s*)?(?P<index>\w+)\s*\*\s*(?P<scale>\d+)"
    r"(?:\s*\+\s*(?P<disp>-?0x[0-9a-fA-F]+|-?\d+))?\]$"
)
_RIP_LEA_RE = re.compile(r"^(?P<reg>\w+),\s*\[rip\s*\+\s*(?P<disp>0x[0-9a-fA-F]+)\]$")
_PTR_SIZE_WORDS = {"byte": 1, "word": 2, "dword": 4, "qword": 8}

def _resolve_jump_tables(
    instructions: list["capstone.CsInsn"],
    data_space: "AddressSpace",
    code_space: "AddressSpace",
    max_entries: int = 256,
) -> dict[int, list[int]]:
    by_addr = {insn.address: insn for insn in instructions}
    ordered = sorted(by_addr)
    index_of = {addr: i for i, addr in enumerate(ordered)}
    tables: dict[int, list[int]] = {}

    for addr in ordered:
        insn = by_addr[addr]
        if insn.mnemonic != "jmp":
            continue
        match = _SIB_SCALED_RE.match(insn.op_str)
        if not match:
            continue

        width_word = insn.op_str.split(" ptr", 1)[0].strip()
        entry_size = _PTR_SIZE_WORDS.get(width_word, 8)
        disp = _parse_imm_or_zero(match.group("disp"))
        base = match.group("base")

        table_addr: int | None = None
        if base is None:
            table_addr = disp
        else:
            idx = index_of.get(addr)
            if idx is not None:
                for lookback in range(idx - 1, max(-1, idx - 6), -1):
                    candidate = by_addr[ordered[lookback]]
                    if candidate.mnemonic != "lea":
                        continue
                    lea_match = _RIP_LEA_RE.match(candidate.op_str)
                    if lea_match and lea_match.group("reg") == base:
                        table_addr = candidate.address + candidate.size + _parse_imm_or_zero(lea_match.group("disp")) + disp
                        break

        if table_addr is None:
            continue

        entries: list[int] = []
        for i in range(max_entries):
            raw = data_space.read(table_addr + i * entry_size, entry_size)
            if raw is None or len(raw) < entry_size:
                break
            ptr = int.from_bytes(raw, "little")
            if not code_space.contains(ptr):
                break
            entries.append(ptr)
        if entries:
            tables[addr] = entries

    return tables

def _successors(insn: "capstone.CsInsn") -> list[int]:
    mnemonic = insn.mnemonic
    fallthrough = insn.address + insn.size

    if mnemonic in _NO_SUCCESSOR_MNEMONICS:
        return []
    if mnemonic == "jmp":
        target = _direct_target(insn)
        return [target] if target is not None else []
    if mnemonic in _JCC_PREFIXES:
        target = _direct_target(insn)
        return [fallthrough, target] if target is not None else [fallthrough]
    if mnemonic == "call":
        return [fallthrough]
    return [fallthrough]

def recursive_function_instructions(
    profile: BinaryProfile,
    func: "FunctionRange",
    address_space: AddressSpace | None = None,
    engine: "capstone.Cs | None" = None,
    data_space: AddressSpace | None = None,
) -> list["capstone.CsInsn"]:
    engine = engine or _capstone_engine(profile)
    if engine is None:
        return []
    address_space = address_space or AddressSpace(executable_sections(profile))
    data_space = data_space or AddressSpace(_all_sections(profile))

    visited: dict[int, capstone.CsInsn] = {}
    worklist = [func.start]
    tables_seen: set[int] = set()

    while True:
        while worklist:
            addr = worklist.pop()
            if addr in visited or addr < func.start or addr >= func.end:
                continue
            window = address_space.read(addr, _MAX_INSN_LEN)
            if not window:
                continue
            decoded = list(engine.disasm(window, addr, count=1))
            if not decoded:
                continue
            insn = decoded[0]
            visited[addr] = insn
            for target in _successors(insn):
                if target not in visited:
                    worklist.append(target)

        ordered = [visited[addr] for addr in sorted(visited)]
        tables = _resolve_jump_tables(ordered, data_space, address_space)
        new_targets = [
            target
            for jmp_addr, entries in tables.items()
            if jmp_addr not in tables_seen
            for target in entries
            if func.start <= target < func.end and target not in visited
        ]
        tables_seen.update(tables.keys())
        if not new_targets:
            break
        worklist.extend(new_targets)

    return [visited[addr] for addr in sorted(visited)]

def _seed_functions_without_symbols(
    profile: BinaryProfile,
    address_space: "AddressSpace",
    engine: "capstone.Cs | None",
) -> list[int]:
    seeds: list[int] = []
    window = address_space.read(profile.entry_point, 64)
    if window and engine is not None:
        for insn in engine.disasm(window, profile.entry_point):
            match = _RIP_LEA_RE.match(insn.op_str)
            if insn.mnemonic != "lea" or match is None or match.group("reg") != "rdi":
                continue
            target = insn.address + insn.size + _parse_imm_or_zero(match.group("disp"))
            if target != profile.entry_point:
                seeds.append(target)

    seeds.extend(insn.address for insn in disassemble(profile) if insn.mnemonic == "endbr64")
    return seeds

def disassemble_functions_recursive(profile: BinaryProfile) -> dict[str, list["capstone.CsInsn"]]:
    engine = _capstone_engine(profile)
    if engine is None:
        return {}
    sections = executable_sections(profile)
    address_space = AddressSpace(sections)
    data_space = AddressSpace(_all_sections(profile))
    code_bounds = [s.virtual_address + len(s.data) for s in sections]
    section_end = max(code_bounds) if code_bounds else 0

    known: dict[int, FunctionRange] = {}
    try:
        symbols = [s for s in parse_elf_symbols(profile.raw) if s.is_function and s.size > 0]
    except Exception:
        symbols = []

    for s in symbols:
        known[s.value] = FunctionRange(s.name, s.value, s.value + s.size)

    go_names: dict[int, str] = {}
    if not known:
        try:
            from xsolver.analysis import gopcln

            go_names = gopcln.function_names(profile)
        except Exception:
            go_names = {}

    def add_seed(start: int) -> None:
        if not address_space.contains(start) or start in known:
            return
        if any(rng.start <= start < rng.end for rng in known.values()):
            return
        starts = sorted(set(known) | {start})
        index = starts.index(start)
        end = starts[index + 1] if index + 1 < len(starts) else section_end
        known[start] = FunctionRange(go_names.get(start, f"sub_{start:x}"), start, end)

    for seed in _seed_functions_without_symbols(profile, address_space, engine):
        add_seed(seed)
    add_seed(profile.entry_point)

    if not known:
        linear = disassemble(profile)
        if linear:
            known[linear[0].address] = FunctionRange("(unknown)", linear[0].address, linear[-1].address + 16)

    results: dict[str, list[capstone.CsInsn]] = {}
    processed: set[int] = set()
    worklist = list(known.keys())

    while worklist:
        start = worklist.pop()
        if start in processed or start not in known:
            continue
        processed.add(start)
        func = known[start]
        insns = recursive_function_instructions(profile, func, address_space, engine, data_space)
        results[func.name] = insns

        for target in _call_targets(insns):
            if target in known or not address_space.contains(target):
                continue
            all_starts = sorted(known.keys() | {target})
            idx = all_starts.index(target)
            end = all_starts[idx + 1] if idx + 1 < len(all_starts) else section_end
            known[target] = FunctionRange(go_names.get(target, f"sub_{target:x}"), target, end)
            worklist.append(target)

    return results

@dataclass
class FunctionRange:
    name: str
    start: int
    end: int

def _call_targets(instructions: list[capstone.CsInsn]) -> set[int]:
    targets: set[int] = set()
    for insn in instructions:
        if insn.mnemonic == "call":
            target = _direct_target(insn)
            if target is not None:
                targets.add(target)
    return targets

def function_ranges(profile: BinaryProfile, instructions: list[capstone.CsInsn]) -> list[FunctionRange]:
    symbols: list[ElfSymbol] = []
    try:
        symbols = [s for s in parse_elf_symbols(profile.raw) if s.is_function and s.size > 0]
    except Exception:
        symbols = []

    if symbols:
        ranges = [FunctionRange(s.name, s.value, s.value + s.size) for s in symbols]
        known_starts = {r.start for r in ranges}
        code_bounds = [s.virtual_address + len(s.data) for s in executable_sections(profile)]
        section_end = max(code_bounds) if code_bounds else (instructions[-1].address + 16 if instructions else 0)

        extra_starts = sorted(t for t in _call_targets(instructions) if t not in known_starts)
        if extra_starts:
            all_starts = sorted(known_starts | set(extra_starts))
            for start in extra_starts:
                idx = all_starts.index(start)
                end = all_starts[idx + 1] if idx + 1 < len(all_starts) else section_end
                ranges.append(FunctionRange(f"sub_{start:x}", start, end))

        ranges.sort(key=lambda r: (r.name != "main", r.start))
        return ranges

    boundaries = [insn.address for insn in instructions if insn.mnemonic == "endbr64"]
    if not boundaries:
        if instructions:
            return [FunctionRange("(unknown)", instructions[0].address, instructions[-1].address + 16)]
        return []

    boundaries.append(instructions[-1].address + 16)
    return [
        FunctionRange(f"sub_{boundaries[i]:x}", boundaries[i], boundaries[i + 1])
        for i in range(len(boundaries) - 1)
    ]
