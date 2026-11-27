from __future__ import annotations

import re
from dataclasses import dataclass

from xsolver import _vendor

_vendor.ensure_on_path()

import z3

from xsolver.analysis.disasm import (
    AddressSpace,
    _all_sections,
    disassemble,
    disassemble_functions_recursive,
)
from xsolver.analysis.cmp_args import comparison_argument_strings
from xsolver.analysis.dispatch_table import find_dispatch_strings
from xsolver.core.binary import BinaryProfile

_LOOKAHEAD = 6
_DISPATCH_SCAN_LIMIT = 60000
_COMPARISON_RESERVE = 4
_MAX_BLOB_GAP = 48
_SELF_OP_RE = re.compile(r"^(\w+),\s*\1$")
_IMM_STORE_RE = re.compile(r"^(byte|word|dword|qword) ptr \[.+\],\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_IMM_ALU_RE = re.compile(r"^(\w+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_IMM_ALU_MEM_RE = re.compile(r"^((?:byte|word|dword|qword) ptr \[[^\]]+\]),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_UNARY_MEM_RE = re.compile(r"^(?:byte|word|dword|qword) ptr \[[^\]]+\]$")
_CHAIN_MNEMONICS = {"xor", "add", "sub", "rol", "ror"}
_UNARY_CHAIN_MNEMONICS = {"not"}

_WIDTH_BYTES = {"byte": 1, "word": 2, "dword": 4, "qword": 8}
_BYTE_REGISTERS = {
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
}
_CONDITION_CONSUMERS = {
    "sete", "setne", "setz", "setnz", "setg", "setge", "setl", "setle",
    "seta", "setae", "setb", "setbe", "seto", "setno", "sets", "setns",
    "cmove", "cmovne", "cmovz", "cmovnz", "cmovg", "cmovge", "cmovl", "cmovle",
    "cmova", "cmovae", "cmovb", "cmovbe",
}

def _parse_imm(token: str) -> int:
    if token.lower().startswith("0x") or token.lower().startswith("-0x"):
        return int(token, 16)
    return int(token)

@dataclass
class Transform:
    op: str
    immediate: int
    index: bool = False

_REG_REG_RE = re.compile(r"^([a-z][a-z0-9]*),\s*([a-z][a-z0-9]*)$")
_STACK_REGISTERS = ("rbp", "rsp", "ebp", "esp")

def _indexed_through_operand(insn, base_register: str) -> bool:
    if "ptr [" not in insn.op_str:
        return False
    bracket = insn.op_str.split("[", 1)[1]
    if base_register not in bracket:
        return False
    if any(stack in bracket for stack in _STACK_REGISTERS):
        return False
    return "+" in bracket
_LEA_RIP_RE = re.compile(r"^([a-z][a-z0-9]*),\s*\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]$")

def _chain_step(insn) -> tuple[str, Transform] | None:
    if insn.mnemonic in _CHAIN_MNEMONICS:
        if _SELF_OP_RE.match(insn.op_str):
            return None
        if insn.mnemonic in ("add", "sub"):
            regs = _REG_REG_RE.match(insn.op_str)
            if regs:
                return regs.group(1), Transform(insn.mnemonic, 0, index=True)
        match = _IMM_ALU_RE.match(insn.op_str) or _IMM_ALU_MEM_RE.match(insn.op_str)
        if not match:
            return None
        immediate = _parse_imm(match.group(2))
        if insn.mnemonic in ("xor", "add", "sub") and not (1 <= abs(immediate) <= 255):
            return None
        if insn.mnemonic in ("rol", "ror") and not (1 <= immediate <= 31):
            return None
        return match.group(1), Transform(insn.mnemonic, immediate)
    if insn.mnemonic in _UNARY_CHAIN_MNEMONICS:
        operand = insn.op_str.strip()
        if operand in _BYTE_REGISTERS or _UNARY_MEM_RE.match(operand):
            return operand, Transform(insn.mnemonic, 0)
    return None

def _find_transform_chains(instructions) -> list[list[Transform]]:
    chains: list[list[Transform]] = []
    index = 0
    while index < len(instructions):
        step = _chain_step(instructions[index])
        if step is None:
            index += 1
            continue

        target, transform = step
        chain = [transform]
        cursor = index + 1
        while cursor < len(instructions):
            next_step = _chain_step(instructions[cursor])
            if next_step is None or next_step[0] != target:
                break
            chain.append(next_step[1])
            cursor += 1

        has_cmp = False
        for lookahead in instructions[cursor:cursor + _LOOKAHEAD]:
            if lookahead.mnemonic == "cmp":
                has_cmp = True
                break
            if lookahead.mnemonic.startswith("j"):
                break
        if has_cmp:
            if any(step.index for step in chain):
                for offset, step in enumerate(chain):
                    if not step.index:
                        chains.append(chain[offset:])
                        break
            chains.append(chain)

        index = cursor if cursor > index else index + 1
    return chains

def _find_constant_blobs(instructions) -> list[bytes]:
    chunks: list[tuple[int, bytes]] = []
    for insn in instructions:
        if insn.mnemonic != "mov":
            continue
        match = _IMM_STORE_RE.match(insn.op_str)
        if not match:
            continue
        width = _WIDTH_BYTES[match.group(1)]
        value = _parse_imm(match.group(2)) & ((1 << (width * 8)) - 1)
        chunks.append((insn.address, value.to_bytes(width, "little")))

    chunks.sort(key=lambda item: item[0])

    blobs: list[bytes] = []
    current = bytearray()
    previous_addr: int | None = None
    for addr, chunk in chunks:
        if previous_addr is not None and addr - previous_addr > _MAX_BLOB_GAP:
            if current:
                blobs.append(bytes(current))
            current = bytearray()
        current += chunk
        previous_addr = addr
    if current:
        blobs.append(bytes(current))

    return [part for blob in blobs for part in blob.split(b"\x00") if part]

def _find_direct_byte_comparisons(instructions) -> bytes:
    bytes_found: list[int] = []
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "cmp":
            continue
        match = _IMM_ALU_RE.match(insn.op_str)
        if not match or match.group(1) not in _BYTE_REGISTERS:
            continue
        immediate = _parse_imm(match.group(2)) & 0xFF
        has_consumer = any(
            lookahead.mnemonic.startswith("j") or lookahead.mnemonic in _CONDITION_CONSUMERS
            for lookahead in instructions[index + 1:index + 1 + _LOOKAHEAD]
        )
        if not has_consumer:
            continue
        bytes_found.append(immediate)
    return bytes(bytes_found)

def _apply_chain_z3(blob: bytes, chain: list[Transform]) -> bytes:
    out = bytearray()
    for position, byte in enumerate(blob):
        secret = z3.BitVec("b", 8)
        expr = secret
        for step in chain:
            if step.index:
                term = position if step.op == "add" else -position
                expr = expr + (term & 0xFF)
                continue
            if step.op == "xor":
                expr = expr ^ (step.immediate & 0xFF)
            elif step.op == "add":
                expr = expr + (step.immediate & 0xFF)
            elif step.op == "sub":
                expr = expr - (step.immediate & 0xFF)
            elif step.op == "rol":
                expr = z3.RotateLeft(expr, step.immediate & 0x7)
            elif step.op == "ror":
                expr = z3.RotateRight(expr, step.immediate & 0x7)
            elif step.op == "not":
                expr = ~expr
        solver = z3.Solver()
        solver.add(expr == byte)
        if solver.check() != z3.sat:
            return b""
        model = solver.model()
        out.append(model[secret].as_long() & 0xFF)
    return bytes(out)

def _executable_ranges(profile: BinaryProfile) -> list[tuple[int, int]]:
    from xsolver.analysis.disasm import executable_sections

    return [
        (section.virtual_address, section.virtual_address + len(section.data))
        for section in executable_sections(profile)
    ]

def _find_data_tables(instructions, space, code_ranges, lengths) -> list[bytes]:
    tables: list[bytes] = []
    seen: set[bytes] = set()
    if not lengths:
        return tables
    for position, insn in enumerate(instructions):
        if insn.mnemonic != "lea":
            continue
        match = _LEA_RIP_RE.match(insn.op_str)
        if not match:
            continue
        window = instructions[position + 1:position + 12]
        destination = match.group(1)
        indexed = any(
            step.mnemonic in ("add", "sub")
            and destination in (part.strip() for part in step.op_str.split(","))
            for step in window
        ) or any(
            _indexed_through_operand(step, destination)
            for step in window
        )
        loads_byte = any(
            step.mnemonic in ("movzx", "movsx", "mov") and "byte ptr [" in step.op_str
            for step in window
        )
        if not (indexed and loads_byte):
            continue
        displacement = _parse_imm(match.group(3))
        if match.group(2) == "-":
            displacement = -displacement
        address = insn.address + insn.size + displacement
        if any(start <= address < end for start, end in code_ranges):
            continue
        for length in lengths[:3]:
            if not 2 <= length <= 64:
                continue
            raw = space.read(address, length)
            if not raw or len(raw) < length:
                continue
            raw = bytes(raw[:length])
            if raw in seen:
                continue
            seen.add(raw)
            tables.append(raw)
            if len(tables) >= 6:
                return tables
    return tables

def _self_modifying(profile: BinaryProfile) -> bool:
    from xsolver.analysis.selfmod import detect_self_modifying_code

    try:
        return bool(detect_self_modifying_code(profile))
    except Exception:
        return False

def _loop_lengths(instructions) -> list[int]:
    lengths: list[int] = []

    def remember(value: int):
        for candidate in (value, value + 1):
            if 2 <= candidate <= 64 and candidate not in lengths:
                lengths.append(candidate)

    for insn in instructions:
        if insn.mnemonic != "cmp":
            continue
        match = _IMM_ALU_RE.match(insn.op_str) or _IMM_ALU_MEM_RE.match(insn.op_str)
        if not match:
            continue
        remember(_parse_imm(match.group(2)))
    return lengths

def extract_candidate_keys(profile: BinaryProfile, max_candidates: int = 8) -> list[str]:
    functions = disassemble_functions_recursive(profile)
    if not functions:
        return []

    try:
        from xsolver.analysis import self_generator

        generated = self_generator.candidates(profile)
    except Exception:
        generated = []

    limit = max_candidates + _COMPARISON_RESERVE + min(len(generated), 96)
    candidates: list[str] = []
    seen: set[str] = set()

    def add(raw: bytes):
        if not raw or len(raw) < 3 or len(candidates) >= limit:
            return
        if not all(0x20 <= b <= 0x7e for b in raw):
            return
        text = raw.decode("latin-1")
        if text in seen:
            return
        seen.add(text)
        candidates.append(text)

    try:
        from xsolver.analysis import xor_table

        for text in xor_table.tables(profile):
            add(text.encode("latin-1"))
    except Exception:
        pass

    for text in generated:
        add(text.encode("latin-1"))

    try:
        from xsolver.analysis import gopcln

        if gopcln.is_go(profile):
            for text in gopcln.go_strings(profile):
                add(text.encode("latin-1"))
    except Exception:
        pass

    ordered_names = sorted(functions, key=lambda name: (name != "main", name))

    space = AddressSpace(_all_sections(profile))

    try:
        compared = comparison_argument_strings(profile, max_candidates=_COMPARISON_RESERVE)
    except Exception:
        compared = []
    for text in compared:
        add(text.encode("latin-1"))

    whole_file = disassemble(profile)
    if len(whole_file) <= _DISPATCH_SCAN_LIMIT:
        for text in find_dispatch_strings(whole_file, space.read):
            add(text.encode("latin-1"))

    for name in ordered_names:
        if len(candidates) >= limit:
            break
        if not functions[name]:
            continue
        for text in find_dispatch_strings(functions[name], space.read):
            add(text.encode("latin-1"))

    for name in ordered_names:
        if len(candidates) >= limit:
            break
        func_instructions = functions[name]
        if not func_instructions:
            continue

        blobs = _find_constant_blobs(func_instructions)
        direct = _find_direct_byte_comparisons(func_instructions)
        if direct:
            blobs.append(direct)

        chains = _find_transform_chains(func_instructions)
        seen_chains: set[tuple[tuple[str, int, bool], ...]] = set()
        unique_chains: list[list[Transform]] = []
        for chain in chains:
            key = tuple((step.op, step.immediate, step.index) for step in chain)
            if key in seen_chains:
                continue
            seen_chains.add(key)
            unique_chains.append(chain)
        indexed_chains = [chain for chain in unique_chains if any(step.index for step in chain)]

        plain_chains = [chain for chain in unique_chains if not any(step.index for step in chain)]
        for blob in blobs:
            add(blob)
            for chain in plain_chains:
                decoded = _apply_chain_z3(blob, chain)
                add(decoded)

        if indexed_chains and not _self_modifying(profile):
            code_ranges = _executable_ranges(profile)
            lengths = _loop_lengths(func_instructions)
            for table in _find_data_tables(func_instructions, space, code_ranges, lengths):
                add(table)
                for chain in indexed_chains:
                    add(_apply_chain_z3(table, chain))

    return candidates[:limit]
