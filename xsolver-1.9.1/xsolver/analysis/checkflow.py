from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from xsolver.core.binary import BinaryProfile

_ARCH_32 = ("x86", "i386", "i686", "ia32")
_ARCH_64 = ("x86-64", "amd64", "x64", "x86_64")
_LOADERS = {"lodsb", "lodsw", "lodsd", "mov", "movzx", "movsx", "movsxd", "lea", "pop"}
_BOUNDARIES = {"ret", "retn", "call", "jmp", "jz", "jnz", "je", "jne", "ja", "jb",
               "jae", "jbe", "jg", "jl", "jge", "jle", "loop", "loope", "loopne"}
_MAX_INSTRUCTIONS = 240_000
_MIN_RUN = 3

@dataclass
class _ByteFact:
    address: int
    index: int | None
    value: int
    transforms: tuple[tuple[str, int], ...] = ()
    group: str = ""

@dataclass
class _Group:
    name: str
    facts: list[_ByteFact] = field(default_factory=list)

def _engine(profile: BinaryProfile):
    import capstone

    arch = (profile.arch or "").lower()
    if any(tag in arch for tag in _ARCH_64):
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if any(tag in arch for tag in _ARCH_32) or "pe" in profile.format.lower():
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return None

def _sections(profile: BinaryProfile):
    try:
        import pefile
    except ImportError:
        return []
    try:
        pe = pefile.PE(str(profile.path), fast_load=True)
    except Exception:
        return []
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    out = []
    for section in pe.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        body = bytes(section.get_data() or b"")
        if body:
            out.append((base + int(section.VirtualAddress), body))
    return out

def _invert(value: int, transforms) -> int:
    result = value
    for name, operand in reversed(transforms):
        if name == "xor":
            result ^= operand
        elif name == "add":
            result = (result - operand) & 0xFF
        elif name == "sub":
            result = (result + operand) & 0xFF
        elif name == "not":
            result ^= 0xFF
        elif name == "rol":
            amount = operand % 8
            result = ((result >> amount) | (result << (8 - amount))) & 0xFF
        elif name == "ror":
            amount = operand % 8
            result = ((result << amount) | (result >> (8 - amount))) & 0xFF
        else:
            return -1
    return result

def _reg8(op) -> str | None:
    name = op.reg
    if name is None:
        return None
    text = op.reg
    try:
        import capstone.x86 as x86
        name = x86.X86_REG
        text = _REG_NAMES.get(op.reg)
    except Exception:
        pass
    return (text or "").lower() or None

def _build_reg_names(arch_64: bool) -> dict[int, str]:
    import capstone.x86 as x86

    mapping = {}
    for name in dir(x86):
        if not name.startswith("X86_REG_"):
            continue
        key = getattr(x86, name)
        if isinstance(key, int):
            mapping[key] = name[len("X86_REG_"):].lower()
    return mapping

_REG_NAMES: dict[int, str] = {}
for _bits in (False, True):
    try:
        _REG_NAMES.update(_build_reg_names(_bits))
    except Exception:
        pass

_EIGHT_BIT = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
              "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b",
              "r12b", "r13b", "r14b", "r15b"}

def _reg_name(op) -> str:
    return _REG_NAMES.get(op.reg, "") if op.type == 1 else ""

def _is_imm(op) -> bool:
    return op.type == 2 and _imm_value(op) is not None

def _imm_value(op) -> int | None:
    try:
        value = op.imm
    except Exception:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)) and len(value) in (1, 2, 4, 8):
        return int.from_bytes(bytes(value[:4 if op.size <= 4 else 8]), "little")
    return None

def _is_mem(op) -> bool:
    return op.type == 3

def recover_bytes(profile: BinaryProfile, limit: int = 12_000) -> list[str]:
    engine = _engine(profile)
    if engine is None:
        return []
    import capstone.x86 as x86

    engine.detail = True
    groups: dict[str, _Group] = defaultdict(lambda: _Group(name=""))
    transforms: dict[str, list[tuple[str, int]]] = defaultdict(list)
    counter: dict[str, int] = defaultdict(int)
    processed = 0

    for base, body in _sections(profile):
        for insn in engine.disasm(body, base):
            processed += 1
            if processed > _MAX_INSTRUCTIONS:
                break
            mnemonic = insn.mnemonic.lower()
            operands = insn.operands

            if mnemonic in ("xor", "add", "sub", "rol", "ror") and len(operands) == 2:
                target = _reg_name(operands[0])
                amount = _imm_value(operands[1]) if _is_imm(operands[1]) else None
                if target in _EIGHT_BIT and amount is not None:
                    transforms[target].append((mnemonic, amount & 0xFF))
                continue
            if mnemonic == "not" and len(operands) == 1:
                target = _reg_name(operands[0])
                if target in _EIGHT_BIT:
                    transforms[target].append(("not", 0))
                continue

            if mnemonic == "cmp" and len(operands) == 2 and _is_imm(operands[1]):
                immediate = _imm_value(operands[1]) or 0
                left = operands[0]
                if _is_mem(left):
                    key = f"mem:{_reg_name(left)}{left.mem.base and _REG_NAMES.get(left.mem.base, '')}" \
                          f"+{left.mem.index and _REG_NAMES.get(left.mem.index, '')}"
                    index = int(left.mem.disp)
                    width = left.size
                    if width != 1 or immediate > 0xFF:
                        transforms.clear()
                        continue
                    groups[key].facts.append(_ByteFact(insn.address, index, immediate,
                                                       tuple(transforms[_reg_name(left)]), key))
                elif left.type == 1:
                    reg = _reg_name(left)
                    if reg in _EIGHT_BIT:
                        group = f"reg:{reg}"
                        groups[group].facts.append(_ByteFact(insn.address, None,
                                                             immediate & 0xFF,
                                                             tuple(transforms[reg]), group))
                        counter[group] += 1
                    elif reg:
                        groups[f"reg:{reg}"].facts.append(_ByteFact(insn.address, None,
                                                                    immediate, (), f"reg:{reg}"))
                        counter[f"reg:{reg}"] += 1
                transforms.clear() if mnemonic in _BOUNDARIES else None
                continue

            if mnemonic in ("lodsb", "movsx", "movzx", "mov") and operands:
                first = _reg_name(operands[0])
                if first:
                    transforms[first] = []
                if len(operands) > 1 and _is_mem(operands[1]) and mnemonic == "mov" and operands[0].size == 1:
                    mem = operands[1].mem
                    base_reg = _REG_NAMES.get(mem.base, "")
                    key = f"copy:{base_reg}+{_REG_NAMES.get(mem.index, '')}"
                    counter[key] += 1
                continue

            if mnemonic in _BOUNDARIES:
                transforms.clear()

    keys: list[str] = []
    for name, group in groups.items():
        positions: dict[int, int] = {}
        for order, fact in enumerate(group.facts):
            index = fact.index if name.startswith("mem:") else order
            value = _invert(fact.value, fact.transforms)
            if index is None or value < 0 or value > 0xFF:
                continue
            positions.setdefault(index, value)
        if not positions:
            continue
        keys.extend(_runs(positions))
    return _rank(keys)[:limit]

def _runs(positions: dict[int, int], minimum: int = _MIN_RUN) -> list[str]:
    out: list[str] = []
    run: list[int] = []
    last = None
    for index in sorted(positions):
        value = positions[index]
        printable = 0x20 <= value <= 0x7E
        if printable and (last is None or index == last + 1):
            run.append(value)
        elif printable:
            if len(run) >= minimum:
                out.append(bytes(run).decode("latin-1"))
            run = [value]
        else:
            if len(run) >= minimum:
                out.append(bytes(run).decode("latin-1"))
            run = []
        last = index
    if len(run) >= minimum:
        out.append(bytes(run).decode("latin-1"))
    return out

_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")

def _rank(keys: list[str]) -> list[str]:
    scored = []
    seen = set()
    for text in keys:
        if text in seen or not _PRINTABLE.match(text):
            continue
        seen.add(text)
        score = len(text)
        if re.search(r"[A-Za-z]", text):
            score += 6
        if re.search(r"[0-9]", text):
            score += 2
        if text.isupper() or text.islower():
            score += 1
        if "\x00" in text:
            score -= 20
        scored.append((score, text))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [text for _score, text in scored]

def _plausible(text: str) -> bool:
    if not 3 <= len(text) <= 48:
        return False
    longest = 1
    run = 1
    for previous, current in zip(text, text[1:]):
        run = run + 1 if current == previous else 1
        longest = max(longest, run)
    if longest > 4:
        return False
    if len(text) >= 6 and len(set(text)) <= max(1, len(text) // 6):
        return False
    return True

def candidate_keys(profile: BinaryProfile, limit: int = 12) -> list[str]:
    out: list[str] = []
    sources: list[str] = []
    try:
        from xsolver.analysis import dataflow

        sources.extend(dataflow.byte_strings(profile, limit=limit))
    except Exception:
        pass
    try:
        from xsolver.analysis.ptr_strings import pointer_strings

        sources.extend(pointer_strings(profile, limit=limit))
    except Exception:
        pass
    sources.extend(recover_bytes(profile, limit=limit * 4))
    for text in sources:
        stripped = text.strip("\x00").strip()
        if not stripped or stripped in out or not _plausible(stripped):
            continue
        out.append(stripped)
        if len(out) >= limit:
            break
    return out
