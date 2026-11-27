from __future__ import annotations

from dataclasses import dataclass, field

from xsolver.core.binary import BinaryProfile

_MAX_INSTRUCTIONS = 300_000

_REG_NAMES: dict[int, str] = {}
try:
    import capstone.x86 as _x86

    for _name in dir(_x86):
        if _name.startswith("X86_REG_"):
            _value = getattr(_x86, _name)
            if isinstance(_value, int):
                _REG_NAMES[_value] = _name[len("X86_REG_"):].lower()
except Exception:
    pass

_EIGHT = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil",
          "spl", "bpl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"}
_ALIASES = {"al": "eax", "ah": "eax", "bl": "ebx", "bh": "ebx",
            "cl": "ecx", "ch": "ecx", "dl": "edx", "dh": "edx",
            "ax": "eax", "bx": "ebx", "cx": "ecx", "dx": "edx",
            "si": "esi", "di": "edi", "bp": "ebp", "sp": "esp",
            "rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
            "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp"}
_BYTE_TRANSFORMS = {"xor", "add", "sub", "rol", "ror", "neg"}

_KINDS = {"je": "eq", "jz": "eq", "jne": "ne", "jnz": "ne",
          "ja": "gt", "jnbe": "gt", "jg": "gt", "jnle": "gt",
          "jae": "ge", "jnb": "ge", "jnc": "ge", "jge": "ge", "jnl": "ge",
          "jb": "lt", "jc": "lt", "jnae": "lt", "jl": "lt", "jnge": "lt",
          "jbe": "le", "jna": "le", "jle": "le", "jng": "le"}
_SETCC = {"sete": "eq", "setz": "eq", "setne": "ne", "setnz": "ne",
          "seta": "gt", "setnbe": "gt", "setg": "gt", "setnle": "gt",
          "setae": "ge", "setnb": "ge", "setge": "ge", "setnl": "ge",
          "setb": "lt", "setnae": "lt", "setl": "lt", "setnge": "lt",
          "setbe": "le", "setna": "le", "setle": "le", "setng": "le"}
_NEGATE = {"eq": "ne", "ne": "eq", "gt": "le", "le": "gt", "ge": "lt", "lt": "ge"}

_INPUT_ARGS = {"readconsolea": 1, "readconsolew": 1, "readfile": 1,
               "fgets": 0, "_fgets": 0, "gets": 0, "_gets": 0,
               "scanf": 1, "_scanf": 1, "scanf_s": 1, "_scanf_s": 1,
               "getwindowtexta": 1, "getwindowtextw": 1,
               "getdlgitemtexta": 2, "getdlgitemtextw": 2}
_COMPARE_CRT = {"memcmp", "_memcmp", "strcmp", "_strcmp", "strncmp", "_strncmp",
                "lstrcmpa", "lstrcmp", "_stricmp", "stricmp"}

@dataclass
class Comparison:
    position: int | None
    order: int
    value: int
    width: int
    text: str | None = None
    reversed_operands: bool = False

@dataclass
class Finding:
    strings: list[str] = field(default_factory=list)
    byte_pairs: dict[str, dict[int, int]] = field(default_factory=dict)
    predicates: list[tuple[int, str, int]] = field(default_factory=list)
    buffers: list[int] = field(default_factory=list)

class _Image:
    def __init__(self, base: int, sections):
        self.base = base
        self.sections = sections
        self.stack_buffers: list[int] = []
        self.stack_constants: dict[int, tuple[int, int]] = {}

    def read(self, address: int, size: int) -> bytes:
        for start, body, _characteristics in self.sections:
            if start <= address < start + len(body):
                offset = address - start
                return body[offset:offset + size]
        return b""

    def in_image(self, address: int) -> bool:
        return any(start <= address < start + len(body) for start, body, _c in self.sections)

def _load(profile: BinaryProfile):
    import pefile

    pe = pefile.PE(str(profile.path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    sections = []
    code = []
    iat: dict[int, str] = {}
    for section in pe.sections:
        characteristics = int(section.Characteristics)
        start = base + int(section.VirtualAddress)
        body = bytes(section.get_data() or b"")
        sections.append((start, body, characteristics))
        if characteristics & 0x20000000:
            code.append((start, body))
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imported in getattr(entry, "imports", []) or []:
            if imported.name:
                iat[int(imported.address)] = imported.name.decode("latin-1")
    return base, base, sections, code, iat

def _reg(op) -> str:
    if op.type != 1:
        return ""
    return _REG_NAMES.get(op.reg, "")

def _canonical(name: str) -> str:
    return _ALIASES.get(name, name)

def _invert(byte: int, transforms) -> int:
    result = byte
    for name, operand in reversed(transforms):
        if name == "xor":
            result ^= operand
        elif name == "add":
            result = (result - operand) & 0xFF
        elif name == "sub":
            result = (result + operand) & 0xFF
        elif name == "rol":
            amount = operand % 8
            result = ((result >> amount) | (result << (8 - amount))) & 0xFF
        elif name == "ror":
            amount = operand % 8
            result = ((result << amount) | (result >> (8 - amount))) & 0xFF
        elif name == "neg":
            result = (-result) & 0xFF
        elif name == "not":
            result ^= 0xFF
        else:
            return -1
    return result

def analyse(profile: BinaryProfile) -> Finding:
    import capstone

    try:
        base, _b, sections, code_sections, iat = _load(profile)
    except Exception:
        return Finding()
    image = _Image(base, sections)
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    thunks = _thunk_map(engine, code_sections, iat)

    findings = Finding()
    input_buffers: set[int] = set()
    processed = 0

    for start, body in code_sections:
        slots: dict[str, tuple] = {}
        transforms: dict[str, list[tuple[str, int]]] = {}
        pushes: list[int | None] = []
        occurrence: dict[str, int] = {}
        last: Comparison | None = None
        stack_args: dict[int, tuple | None] = {}
        image.stack_buffers = []
        image.stack_constants = {}

        for insn in engine.disasm(body, start):
            processed += 1
            if processed > _MAX_INSTRUCTIONS:
                return findings
            mnemonic = insn.mnemonic.lower()
            operands = insn.operands

            if mnemonic == "push":
                value = None
                if operands and operands[0].type == 2 and isinstance(operands[0].imm, int):
                    value = ("bytes", operands[0].imm, 4)
                elif operands and operands[0].type == 1:
                    value = slots.get(_canonical(_reg(operands[0])))
                pushes.append(value)
                pushes = pushes[-12:]
                continue

            if mnemonic == "call" and operands:
                target = operands[0]
                name = ""
                if target.type == 3 and target.mem.base == 0 and target.mem.disp in iat:
                    name = iat[target.mem.disp].lower()
                elif target.type == 2 and isinstance(target.imm, int) and target.imm in thunks:
                    name = thunks[target.imm].lower()
                if name in _INPUT_ARGS:
                    slot = _INPUT_ARGS[name]
                    ordered = list(reversed(pushes))
                    if stack_args:
                        ordered = [stack_args.get(offset) for offset in sorted(stack_args)]
                    if slot < len(ordered):
                        buffer = ordered[slot]
                        if isinstance(buffer, tuple) and buffer[0] == "bytes" \
                                and image.in_image(buffer[1]):
                            input_buffers.add(buffer[1])
                        elif isinstance(buffer, tuple) and buffer[0] == "stack":
                            image.stack_buffers.append(buffer[1])
                        findings.buffers.append(buffer[1] if isinstance(buffer, tuple) else 0)
                if name in _COMPARE_CRT:
                    findings.strings.extend(_crt_strings(pushes, image))
                    findings.strings.extend(
                        _crt_strings([stack_args[offset] for offset in sorted(stack_args)], image))
                pushes = []
                stack_args = {}
                for register in ("eax", "ecx", "edx"):
                    slots.pop(register, None)
                last = None
                continue

            if mnemonic == "lea" and len(operands) == 2 and operands[1].type == 3:
                destination = _canonical(_reg(operands[0]))
                memory = operands[1].mem
                base_register = _canonical(_REG_NAMES.get(memory.base, "")) if memory.base else ""
                if destination:
                    if base_register in ("ebp", "esp") and not memory.index:
                        slots[destination] = ("stack", int(memory.disp))
                    elif not memory.base and not memory.index:
                        slots[destination] = ("literal", int(memory.disp))
                    else:
                        slots.pop(destination, None)
                continue

            if mnemonic == "lodsb":
                entry = slots.get("esi")
                if entry and entry[0] == "input":
                    slots["al"] = ("input", entry[1], 1)
                else:
                    slots.pop("al", None)
                _shift(slots, "esi", 1)
                transforms.pop("al", None)
                continue

            if mnemonic in ("mov", "movzx", "movsx") and len(operands) == 2:
                destination = _canonical(_reg(operands[0]))
                source = operands[1]
                if not destination:
                    target_memory = operands[0]
                    if target_memory.type == 3 and not target_memory.mem.index:
                        base_name = _canonical(_REG_NAMES.get(target_memory.mem.base, ""))
                        displacement = int(target_memory.mem.disp)
                        stored = _value(source, slots, image)
                        if base_name in ("esp", "ebp"):
                            if 0 <= displacement < 0x40:
                                stack_args[displacement] = stored
                            if stored is not None and stored[0] == "bytes":
                                image.stack_constants[displacement] = (stored[1], stored[2])
                    continue
                if source.type == 2 and isinstance(source.imm, int):
                    value = source.imm
                    if value in input_buffers:
                        slots[destination] = ("input", 0, 1)
                    elif image.in_image(value):
                        slots[destination] = ("literal", value)
                    else:
                        slots.pop(destination, None)
                    transforms.pop(_reg(operands[0]), None)
                    continue
                if source.type == 3:
                    resolved = _resolve(source, slots, image)
                    if resolved is not None:
                        slots[destination] = resolved
                    else:
                        slots.pop(destination, None)
                    transforms.pop(_reg(operands[0]), None)
                    continue
                if source.type == 1:
                    alias = _canonical(_reg(source))
                    if alias in slots:
                        slots[destination] = slots[alias]
                    else:
                        slots.pop(destination, None)
                    continue
                continue

            if mnemonic in _BYTE_TRANSFORMS and len(operands) == 2:
                register = _reg(operands[0])
                if register in _EIGHT and operands[1].type == 2 and isinstance(operands[1].imm, int):
                    transforms.setdefault(register, []).append((mnemonic, operands[1].imm & 0xFF))
                continue
            if mnemonic == "not" and operands:
                register = _reg(operands[0])
                if register in _EIGHT:
                    transforms.setdefault(register, []).append(("not", 0))
                continue

            if mnemonic in ("add", "sub", "inc", "dec") and operands:
                target = _canonical(_reg(operands[0]))
                amount = None
                if mnemonic == "inc":
                    amount = 1
                elif mnemonic == "dec":
                    amount = -1
                elif len(operands) == 2 and operands[1].type == 2 and isinstance(operands[1].imm, int):
                    amount = operands[1].imm if mnemonic == "add" else -operands[1].imm
                if amount is not None and target in slots:
                    _shift(slots, target, amount)
                register = _reg(operands[0])
                if register in _EIGHT and len(operands) == 2 and operands[1].type == 2:
                    if isinstance(operands[1].imm, int):
                        transforms.setdefault(register, []).append((mnemonic, operands[1].imm & 0xFF))
                continue

            if mnemonic == "cmp" and len(operands) == 2:
                last = _compare(insn, operands[0], operands[1], slots, image,
                                transforms, occurrence, findings)
                continue

            kind = _KINDS.get(mnemonic)
            if kind and last is not None:
                target_address = operands[0].imm if operands and operands[0].type == 2 else None
                backwards = isinstance(target_address, int) and target_address < insn.address
                if kind in ("eq", "ne"):
                    if last.reversed_operands:
                        kind = _NEGATE[kind]
                    if not backwards:
                        kind = "eq"
                else:
                    if last.reversed_operands:
                        kind = _NEGATE[kind]
                    if not backwards:
                        kind = _NEGATE[kind]
                _emit(findings, last, kind)
                last = None
                continue
            kind = _SETCC.get(mnemonic)
            if kind and last is not None:
                if last.reversed_operands:
                    kind = _NEGATE[kind]
                _emit(findings, last, kind)
                last = None
                continue

            if mnemonic in ("ret", "retn", "jmp"):
                slots.clear()
                transforms.clear()
                last = None
                continue

    return findings

def _thunk_map(engine, code_sections, iat) -> dict[int, str]:
    thunks: dict[int, str] = {}
    for start, body in code_sections:
        for insn in engine.disasm(body, start):
            if insn.mnemonic.lower() not in ("jmp", "jmpq"):
                continue
            operands = insn.operands
            if not operands or operands[0].type != 3:
                continue
            memory = operands[0].mem
            if memory.base or memory.index:
                continue
            name = iat.get(int(memory.disp))
            if name:
                thunks[insn.address] = name
    return thunks

def _shift(slots: dict, register: str, amount: int) -> None:
    entry = slots.get(register)
    if entry and entry[0] in ("input", "literal"):
        slots[register] = (entry[0], entry[1] + amount) + tuple(entry[2:])

def _resolve(operand, slots, image):
    memory = operand.mem
    size = operand.size or 1
    base_register = _canonical(_REG_NAMES.get(memory.base, "")) if memory.base else ""
    index_register = _canonical(_REG_NAMES.get(memory.index, "")) if memory.index else ""
    entry = slots.get(base_register) if base_register else None
    index_entry = slots.get(index_register) if index_register else None
    displacement = int(memory.disp)
    if index_entry and index_entry[0] == "literal":
        displacement += index_entry[1]
    elif index_entry:
        return None
    if entry is None:
        if base_register in ("ebp", "esp") and not index_register and image.stack_buffers:
            displacement_full = displacement
            matches = [base for base in image.stack_buffers if displacement_full >= base]
            if matches:
                return ("input", displacement_full - max(matches), size)
        if base_register in ("ebp", "esp") and not index_register and image.stack_constants:
            for start, (value, width) in image.stack_constants.items():
                if start <= displacement < start + width:
                    shift = (displacement - start) * 8
                    raw = (value >> shift) & (0xFFFFFFFF if size >= 4 else (0xFFFF if size == 2 else 0xFF))
                    return ("bytes", raw, size)
        if base_register or index_register:
            return None
        body = image.read(displacement, size)
        if body and len(body) == size:
            return ("bytes", int.from_bytes(body, "little"), size)
        return None
    if entry[0] == "input":
        return ("input", entry[1] + displacement, size)
    if entry[0] == "literal":
        body = image.read(entry[1] + displacement, size)
        if body and len(body) == size:
            return ("bytes", int.from_bytes(body, "little"), size)
    return None

def _compare(insn, left, right, slots, image, transforms, occurrence, findings):
    left_value = _value(left, slots, image)
    right_value = _value(right, slots, image)
    if left_value is None or right_value is None:
        return None

    if left_value[0] == "bytes" and right_value[0] == "input":
        expected, source, reversed_operands = left_value, right_value, False
    elif right_value[0] == "bytes" and left_value[0] == "input":
        expected, source, reversed_operands = right_value, left_value, True
    else:
        return None

    width = min(expected[2], source[2]) if expected[2] == source[2] else expected[2]
    raw = expected[1] & (0xFFFFFFFF if width >= 4 else (0xFFFF if width == 2 else 0xFF))
    position = source[1]
    if width == 1:
        register = _reg(left) if right_value[0] == "bytes" else _reg(right)
        value = _invert(raw, transforms.get(register, []))
        if value < 0:
            return None
        order = occurrence.get("seq", 0)
        occurrence["seq"] = order + 1
        findings.byte_pairs.setdefault("seq", {})[order] = value
        return Comparison(position, order, value, 1, None, reversed_operands)

    body = raw.to_bytes(width, "little")
    text = body.rstrip(b"\x00").decode("latin-1")
    if len(text) >= 3 and all(32 <= ord(char) < 127 for char in text):
        findings.strings.append(text)
    order = occurrence.get("seq", 0)
    occurrence["seq"] = order + 1
    return Comparison(position, order, raw, width, text, reversed_operands)

def _value(operand, slots, image):
    if operand.type == 2 and isinstance(operand.imm, int):
        return ("bytes", operand.imm, operand.size or 1)
    if operand.type == 1:
        name = _canonical(_reg(operand))
        entry = slots.get(name)
        if entry is None:
            return None
        if entry[0] == "literal":
            body = image.read(entry[1], operand.size or 1)
            if body and len(body) == operand.size:
                return ("bytes", int.from_bytes(body, "little"), operand.size)
            return None
        return entry
    if operand.type == 3:
        return _resolve(operand, slots, image)
    return None

def _emit(findings: Finding, comparison: Comparison, kind: str) -> None:
    if comparison.width != 1:
        return
    index = comparison.position if comparison.position is not None else comparison.order
    findings.predicates.append((int(index), kind, comparison.value))

def _runs(pairs: dict[int, int]) -> list[str]:
    out: list[str] = []
    run: list[int] = []
    previous = None
    for index in sorted(pairs):
        value = pairs[index]
        usable = value not in (0x00, 0xFF) and (previous is None or index == previous + 1)
        if usable:
            run.append(value)
        else:
            _flush(run, out)
            run = [value] if value not in (0x00, 0xFF) else []
        previous = index
    _flush(run, out)
    return out

def _flush(run: list[int], out: list[str]) -> None:
    if len(run) < 3:
        return
    printable = sum(1 for byte in run if 0x20 <= byte <= 0x7E)
    if printable / len(run) < 0.6:
        return
    out.append(bytes(run).decode("latin-1"))

def _crt_strings(pushes, image) -> list[str]:
    out: list[str] = []
    for value in reversed(pushes):
        address = None
        if isinstance(value, int):
            address = value
        elif isinstance(value, tuple) and value[0] == "literal":
            address = value[1]
        elif isinstance(value, tuple) and value[0] == "bytes":
            address = value[1]
        if address is None or not image.in_image(address):
            continue
        body = image.read(address, 64)
        if not body:
            continue
        text = body.split(b"\x00")[0]
        if 3 <= len(text) <= 48 and all(32 <= byte < 127 for byte in text):
            out.append(text.decode("latin-1"))
    return out

def byte_strings(profile: BinaryProfile, limit: int = 16) -> list[str]:
    finding = analyse(profile)
    for pairs in finding.byte_pairs.values():
        finding.strings[:0] = _runs(pairs)
    out: list[str] = []
    for text in finding.strings:
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out

def predicates(profile: BinaryProfile) -> dict[int, list[tuple[str, int]]]:
    finding = analyse(profile)
    grouped: dict[int, list[tuple[str, int]]] = {}
    for position, kind, value in finding.predicates:
        grouped.setdefault(position, []).append((kind, value))
    return grouped
