from __future__ import annotations

import re

from xsolver.analysis.cmp_args import _image_base, pe_imports
from xsolver.analysis.disasm import disassemble
from xsolver.core.binary import BinaryProfile

_REG32 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_REG8 = {"al": ("eax", 0), "ah": ("eax", 8), "bl": ("ebx", 0), "bh": ("ebx", 8),
         "cl": ("ecx", 0), "ch": ("ecx", 8), "dl": ("edx", 0), "dh": ("edx", 8)}
_REG16 = {"ax": "eax", "bx": "ebx", "cx": "ecx", "dx": "edx"}
_MEM_PREFIX = ("byte ptr ", "word ptr ", "dword ptr ", "qword ptr ", "ptr ")
_STRCMP_NAMES = {"strcmp", "_strcmp", "lstrcmpA", "lstrcmpW", "wcscmp", "_stricmp", "strncmp"}
_PRINTABLE = range(0x21, 0x7F)
_MASK = 0xFFFFFFFF

def _size_of(token: str) -> int:
    head = token.strip().split(" ")[0]
    if head in ("byte", "word", "dword", "qword"):
        return {"byte": 1, "word": 2, "dword": 4, "qword": 8}[head]
    return 0

def _strip(token: str) -> str:
    text = token.strip()
    for prefix in _MEM_PREFIX:
        if text.startswith(prefix):
            return text[len(prefix):].strip()
    return text

def _split_operands(text: str) -> list[str]:
    parts, depth, current = [], 0, ""
    for char in text:
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current)
    return [part.strip() for part in parts]

class _Cpu:
    def __init__(self, insns, esp: int = 0x7FF000, ebp: int = 0x7FEF00):
        self.insns = insns
        self.regs = {name: 0 for name in _REG32}
        self.regs["esp"] = esp
        self.regs["ebp"] = ebp
        self.mem: dict[int, int] = {}
        self.zf = 0
        self.sf = 0
        self.steps = 0

    def read(self, addr: int, size: int) -> int:
        value = 0
        for offset in range(size):
            value |= (self.mem.get((addr + offset) & _MASK, 0) & 0xFF) << (8 * offset)
        return value

    def write(self, addr: int, size: int, value: int) -> None:
        for offset in range(size):
            self.mem[(addr + offset) & _MASK] = (value >> (8 * offset)) & 0xFF

    def read_reg(self, name: str) -> int:
        if name in _REG8:
            base, shift = _REG8[name]
            return (self.regs[base] >> shift) & 0xFF
        if name in _REG16:
            return self.regs[_REG16[name]] & 0xFFFF
        return self.regs.get(name, 0)

    def write_reg(self, name: str, value: int) -> None:
        if name in _REG8:
            base, shift = _REG8[name]
            mask = 0xFF << shift
            self.regs[base] = (self.regs[base] & ~mask & _MASK) | ((value & 0xFF) << shift)
            return
        if name in _REG16:
            base = _REG16[name]
            self.regs[base] = (self.regs[base] & 0xFFFF0000) | (value & 0xFFFF)
            return
        self.regs[name] = value & _MASK

    def address(self, spec: str) -> int:
        total = 0
        for part in spec.replace(" ", "").replace("-", "+-").split("+"):
            part = part.strip()
            if not part:
                continue
            if part in _REG32:
                total += self.regs[part]
            elif part in _REG16:
                total += self.regs[_REG16[part]] & 0xFFFF
            else:
                try:
                    total += int(part, 0)
                except ValueError:
                    raise _Unsupported(spec)
        return total & _MASK

    def operand(self, token: str) -> tuple[str, int]:
        text = _strip(token)
        if "[" in text:
            return "mem", self.address(text[text.index("[") + 1:text.rindex("]")])
        if text in _REG32 or text in _REG8 or text in _REG16:
            return "reg", 0
        try:
            return "imm", int(text, 0) & _MASK
        except ValueError:
            raise _Unsupported(token)

class _Unsupported(Exception):
    pass

def _flag(cpu: _Cpu, value: int, size: int) -> int:
    bits = size * 8
    cpu.zf = 1 if (value & ((1 << bits) - 1)) == 0 else 0
    cpu.sf = (value >> (bits - 1)) & 1
    return value & ((1 << bits) - 1)

def _condition(mnemonic: str, cpu: _Cpu, cf: int = 0) -> bool:
    if mnemonic in ("je", "jz"):
        return cpu.zf == 1
    if mnemonic in ("jne", "jnz"):
        return cpu.zf == 0
    if mnemonic in ("jl", "jnge"):
        return cpu.sf != cpu.of if hasattr(cpu, "of") else cpu.sf == 1
    if mnemonic in ("jle", "jng"):
        return cpu.zf == 1 or cpu.sf == 1
    if mnemonic in ("jg", "jnle"):
        return cpu.zf == 0 and cpu.sf == 0
    if mnemonic in ("jge", "jnl"):
        return cpu.sf == 0
    if mnemonic in ("jb", "jnae", "jc"):
        return cf == 1
    if mnemonic in ("jae", "jnb", "jnc"):
        return cf == 0
    if mnemonic in ("jbe", "jna"):
        return cf == 1 or cpu.zf == 1
    if mnemonic in ("ja", "jnbe"):
        return cf == 0 and cpu.zf == 0
    raise _Unsupported(mnemonic)

def _load(cpu: _Cpu, token: str, size: int) -> int:
    kind, value = cpu.operand(token)
    if kind == "imm":
        return value
    if kind == "reg":
        return cpu.read_reg(_strip(token))
    return cpu.read(value, size or 4)

def _store(cpu: _Cpu, token: str, size: int, value: int) -> None:
    kind, address = cpu.operand(token)
    if kind == "reg":
        cpu.write_reg(_strip(token), value)
        return
    if kind != "mem":
        raise _Unsupported(token)
    cpu.write(address, size or 4, value)

def _execute(cpu: _Cpu, insn) -> int | None:
    name, text = insn.mnemonic, insn.op_str
    ops = _split_operands(text) if text else []
    if name in ("nop", "int3", "cld", "std"):
        return None
    if name == "push":
        value = _load(cpu, ops[0], _size_of(ops[0]) or 4)
        cpu.write_reg("esp", cpu.regs["esp"] - 4)
        cpu.write(cpu.regs["esp"], 4, value)
        return None
    if name == "pop":
        value = cpu.read(cpu.regs["esp"], 4)
        cpu.write_reg("esp", cpu.regs["esp"] + 4)
        _store(cpu, ops[0], 4, value)
        return None
    if name == "leave":
        cpu.write_reg("esp", cpu.regs["ebp"])
        cpu.write_reg("ebp", cpu.read(cpu.regs["esp"], 4))
        cpu.write_reg("esp", cpu.regs["esp"] + 4)
        return None
    if name == "ret":
        raise _Finished()
    if name == "mov":
        size = _size_of(ops[0]) or _size_of(ops[1]) or 4
        _store(cpu, ops[0], size, _load(cpu, ops[1], size))
        return None
    if name in ("movzx", "movsx"):
        size = _size_of(ops[1]) or 1
        value = _load(cpu, ops[1], size)
        if name == "movsx" and value >> (size * 8 - 1):
            value |= _MASK << (size * 8) & _MASK
        _store(cpu, ops[0], _size_of(ops[0]) or 4, value & _MASK)
        return None
    if name == "lea":
        kind, address = cpu.operand(ops[1])
        if kind != "mem":
            raise _Unsupported(text)
        _store(cpu, ops[0], 4, address)
        return None
    if name in ("add", "sub", "xor", "and", "or", "shl", "shr", "sal", "sar"):
        size = _size_of(ops[0]) or _size_of(ops[1]) or 4
        left = _load(cpu, ops[0], size)
        right = _load(cpu, ops[1], size)
        if name == "add":
            result = left + right
        elif name == "sub":
            result = left - right
        elif name == "xor":
            result = left ^ right
        elif name == "and":
            result = left & right
        elif name == "or":
            result = left | right
        elif name in ("shl", "sal"):
            result = left << (right & 0x1F)
        else:
            result = left >> (right & 0x1F)
        _store(cpu, ops[0], size, _flag(cpu, result, size))
        return None
    if name in ("inc", "dec"):
        size = _size_of(ops[0]) or 4
        left = _load(cpu, ops[0], size)
        _store(cpu, ops[0], size, _flag(cpu, left + (1 if name == "inc" else -1), size))
        return None
    if name in ("cmp", "test"):
        size = _size_of(ops[0]) or _size_of(ops[1]) or 4
        left = _load(cpu, ops[0], size)
        right = _load(cpu, ops[1], size)
        _flag(cpu, (left - right) if name == "cmp" else (left & right), size)
        return None
    if name == "imul":
        size = _size_of(ops[0]) or 4
        if len(ops) == 2:
            _store(cpu, ops[0], size, _flag(cpu, _load(cpu, ops[0], size) * _load(cpu, ops[1], size), size))
            return None
        raise _Unsupported(text)
    if name == "jmp":
        target = cpu.operand(ops[0])
        if target[0] != "imm":
            raise _Unsupported(text)
        return target[1]
    if name.startswith("j"):
        cf = 0
        if not _condition(name, cpu, cf):
            return None
        target = cpu.operand(ops[0])
        if target[0] != "imm":
            raise _Unsupported(text)
        return target[1]
    raise _Unsupported(name)

class _Finished(Exception):
    pass

def _run(insns, argument: int, budget: int = 4000) -> dict[int, int]:
    by_addr = {insn.address: insn for insn in insns}
    start = insns[0].address
    cpu = _Cpu(insns)
    cpu.write(cpu.regs["esp"] + 4, 4, argument & _MASK)
    address = start
    while cpu.steps < budget:
        insn = by_addr.get(address)
        if insn is None:
            break
        cpu.steps += 1
        try:
            target = _execute(cpu, insn)
        except _Finished:
            break
        except _Unsupported:
            return {}
        address = target if target is not None else address + insn.size
    return cpu.mem

def _function_instructions(insns, index: int):
    out = []
    for insn in insns[index:]:
        if out and insn.mnemonic == "ret":
            out.append(insn)
            break
        if insn.mnemonic == "ret" and not out:
            out.append(insn)
            break
        out.append(insn)
        if len(out) > 200:
            break
    return out

def _import_name(slot: int, imports: dict[int, str], image_base: int) -> str | None:
    for key in (slot, slot - image_base, slot + image_base):
        name = imports.get(key)
        if name:
            return name.split("@")[0].lstrip("_").lower()
    return None

def _resolve_import(by_addr, target: int, imports, image_base: int, depth: int = 0) -> str | None:
    insn = by_addr.get(target)
    if insn is None or depth > 4:
        return None
    if insn.mnemonic != "jmp":
        return None
    spec = _strip(insn.op_str)
    if "[" in spec:
        inner = spec[spec.index("[") + 1:spec.rindex("]")]
        if "rip" in inner:
            displacement = 0
            for part in inner.replace(" ", "").replace("-", "+-").split("+"):
                part = part.strip()
                if not part or part in ("rip",):
                    continue
                try:
                    displacement += int(part, 0)
                except ValueError:
                    return None
            slot = (target + insn.size + displacement) & _MASK
        else:
            try:
                slot = int(inner, 0)
            except ValueError:
                return None
        return _import_name(slot, imports, image_base)
    try:
        return _resolve_import(by_addr, int(spec, 0), imports, image_base, depth + 1)
    except ValueError:
        return None

def _call_kind(by_addr, insn, imports, image_base: int) -> tuple[str, int]:
    if insn.mnemonic != "call":
        return "", 0
    spec = insn.op_str.strip()
    if not spec or "[" in spec or spec in _REG32:
        return "", 0
    try:
        target = int(spec, 0)
    except ValueError:
        return "", 0
    imported = _resolve_import(by_addr, target, imports, image_base)
    if imported:
        return "import", 0 if imported not in _STRCMP_NAMES else 1
    return "local", target

def _strings_from(memory: dict[int, int], limit: int = 48) -> list[str]:
    globals_seen = {address for address in memory if 0x10000 < address < 0x7F0000}
    found: list[str] = []
    for base in sorted(globals_seen):
        if base - 1 in globals_seen:
            continue
        raw = bytearray()
        for offset in range(limit):
            byte = memory.get(base + offset)
            if not byte:
                break
            raw.append(byte & 0xFF)
        if 4 <= len(raw) <= limit - 1 and all(0x20 <= byte < 0x7F for byte in raw):
            found.append(raw.decode("latin-1"))
    return found

def candidates(profile: BinaryProfile, limit: int = 64) -> list[str]:
    insns = disassemble(profile)
    if not insns:
        return []
    imports = pe_imports(profile.raw)
    image_base = _image_base(profile)
    by_addr = {insn.address: insn for insn in insns}
    indexes = {}
    for position, insn in enumerate(insns):
        indexes.setdefault(insn.address, position)
    results: list[str] = []
    for position, insn in enumerate(insns):
        if insn.mnemonic != "call":
            continue
        kind, target = _call_kind(by_addr, insn, imports, image_base)
        if kind != "import":
            continue
        spec = insn.op_str.strip()
        try:
            callee = int(spec, 0)
        except ValueError:
            continue
        imported = _resolve_import(by_addr, callee, imports, image_base)
        if imported not in _STRCMP_NAMES:
            continue
        seen: set[int] = set()
        for back in range(position - 1, max(position - 41, -1), -1):
            earlier = insns[back]
            kind2, local = _call_kind(by_addr, earlier, imports, image_base)
            if kind2 != "local" or local in seen:
                continue
            seen.add(local)
            index = indexes.get(local)
            if index is None:
                continue
            body = _function_instructions(insns, index)
            if any(item.mnemonic == "call" for item in body):
                continue
            produced: list[str] = []
            for value in _PRINTABLE:
                memory = _run(body, value)
                if not memory:
                    continue
                produced.extend(_strings_from(memory))
            for text in produced:
                if text not in results:
                    results.append(text)
            if len(results) >= limit:
                return results[:limit]
        return results
    return results
