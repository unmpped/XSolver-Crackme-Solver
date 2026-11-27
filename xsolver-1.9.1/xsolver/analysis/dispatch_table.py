from __future__ import annotations

import re
from typing import Callable

_TABLE_LOAD_RE = re.compile(
    r"^e?(?P<dst>[a-z0-9]+),\s*dword ptr \[(?P<base>[a-z0-9]+)"
    r"\s*\+\s*(?P<index>[a-z0-9]+)\*(?P<scale>[1248])"
    r"\s*(?P<sign>[+-])\s*(?P<disp>0x[0-9a-f]+|\d+)\]$"
)
_ADD_RE = re.compile(r"^(?P<dst>[a-z0-9]+),\s*(?P<base>[a-z0-9]+)$")
_LEA_RIP_RE = re.compile(r"^(?P<dst>[a-z0-9]+),\s*\[rip\s*(?P<sign>[+-])\s*(?P<disp>0x[0-9a-f]+|\d+)\]$")
_MOV_IMM_RE = re.compile(r"^(?P<dst>[a-z0-9]+),\s*(?P<imm>0x[0-9a-f]+|\d+)$")
_CMP_IMM_RE = re.compile(r"^(?P<dst>[a-z0-9]+),\s*(?P<imm>0x[0-9a-f]+|\d+)$")

_BYTE_REGISTERS = {
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
}
_REG64 = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}
_REG32_TO_64 = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
    "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
}

_LOOKBACK = 8
_LOOKAHEAD = 12
_MAX_ENTRIES = 256

def _int(token: str) -> int:
    token = token.strip()
    return int(token, 16) if token.lower().startswith("0x") else int(token)

def _reg64(name: str | None) -> str | None:
    if not name:
        return None
    if name in _REG64:
        return name
    return _REG32_TO_64.get(name)

def _find_table_base(instructions, position: int, base_reg: str, memo: dict) -> int | None:
    if base_reg in memo:
        return memo[base_reg]
    for previous in reversed(instructions[max(0, position - _LOOKBACK):position]):
        if previous.mnemonic != "lea":
            continue
        match = _LEA_RIP_RE.match(previous.op_str)
        if not match or match.group("dst") != base_reg:
            continue
        disp = _int(match.group("disp"))
        if match.group("sign") == "-":
            disp = -disp
        base = previous.address + previous.size + disp
        memo[base_reg] = base
        return base
    return None

def _follow_character(instructions, target: int, addresses: set[int]) -> int | None:
    try:
        start = next(i for i, insn in enumerate(instructions) if insn.address == target)
    except StopIteration:
        return None
    for insn in instructions[start:start + _LOOKAHEAD]:
        if insn.mnemonic == "mov":
            match = _MOV_IMM_RE.match(insn.op_str)
            if match and match.group("dst") in _BYTE_REGISTERS:
                return _int(match.group("imm")) & 0xFF
        if insn.mnemonic in ("ret", "retn", "int3", "ud2", "hlt"):
            return None
        if insn.mnemonic == "jmp" and insn.address != target:
            return None
    return None

def _entry_count(instructions, position: int, index_reg: str) -> int | None:
    for insn in instructions[position:position + 200]:
        if insn.mnemonic != "cmp":
            continue
        match = _CMP_IMM_RE.match(insn.op_str)
        if not match:
            continue
        if _reg64(match.group("dst")) != _reg64(index_reg):
            continue
        value = _int(match.group("imm"))
        if 1 <= value <= _MAX_ENTRIES:
            return value
    return None

def find_dispatch_strings(
    instructions,
    read_memory: Callable[[int, int], bytes],
) -> list[str]:
    if not instructions:
        return []

    addresses = {insn.address for insn in instructions}
    memo: dict[str, int] = {}
    found: list[str] = []

    for position, insn in enumerate(instructions):
        if insn.mnemonic != "jmp" or insn.op_str not in _REG64:
            continue
        jump_register = insn.op_str

        adder = None
        for previous in reversed(instructions[max(0, position - 4):position]):
            match = _ADD_RE.match(previous.op_str)
            if previous.mnemonic == "add" and match and _reg64(match.group("dst")) == jump_register:
                adder = match.group("base")
                break
        if adder is None:
            continue

        loader = None
        for previous in reversed(instructions[max(0, position - _LOOKBACK):position]):
            if previous.mnemonic != "mov":
                continue
            if _reg64(previous.op_str.split(",")[0].strip()) != jump_register:
                continue
            match = _TABLE_LOAD_RE.match(previous.op_str)
            if match and match.group("base") == adder:
                loader = match
            break
        if loader is None:
            continue

        base = _find_table_base(instructions, position, adder, memo)
        if base is None:
            continue
        index_reg = loader.group("index")
        scale = int(loader.group("scale"))
        dispatch = _int(loader.group("disp"))
        if loader.group("sign") == "-":
            dispatch = -dispatch
        count = _entry_count(instructions, position, index_reg)
        if not count:
            continue

        chars: list[int] = []
        for entry in range(count):
            try:
                raw = read_memory(base + dispatch + entry * scale, 4)
            except Exception:
                break
            if not raw or len(raw) < 4:
                break
            offset = int.from_bytes(raw[:4], "little")
            target = base + offset
            if target not in addresses:
                break
            char = _follow_character(instructions, target, addresses)
            if char is None:
                break
            chars.append(char)

        if len(chars) == count and chars:
            text = bytes(chars).decode("latin-1")
            if text not in found:
                found.append(text)

    return found
