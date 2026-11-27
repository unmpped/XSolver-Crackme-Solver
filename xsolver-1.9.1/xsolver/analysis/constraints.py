from __future__ import annotations

from dataclasses import dataclass, field

from xsolver.core.binary import BinaryProfile

_MAX_INSTRUCTIONS = 200_000
_PALETTES = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "abcdefghijklmnopqrstuvwxyz0123456789",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "0123456789abcdef",
    "0123456789ABCDEF",
    "".join(chr(code) for code in range(0x20, 0x7F)),
)

_EQ = {"je", "jz"}
_NE = {"jne", "jnz"}
_GT = {"ja", "jnbe", "jg", "jnle"}
_GE = {"jae", "jnb", "jnc", "jge", "jnl"}
_LT = {"jb", "jc", "jnae", "jl", "jnge"}
_LE = {"jbe", "jna", "jle", "jng"}
_FLAGS = _EQ | _NE | _GT | _GE | _LT | _LE

_REG8 = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil",
         "spl", "bpl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"}
_REG16 = {"ax", "bx", "cx", "dx", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"}

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

@dataclass
class Constraint:
    kind: str
    value: int

    def accepts(self, byte: int) -> bool:
        if self.kind == "eq":
            return byte == self.value
        if self.kind == "ne":
            return byte != self.value
        if self.kind == "gt":
            return byte > self.value
        if self.kind == "ge":
            return byte >= self.value
        if self.kind == "lt":
            return byte < self.value
        if self.kind == "le":
            return byte <= self.value
        return False

@dataclass
class Plan:
    positions: dict[int, list[Constraint]] = field(default_factory=dict)
    order: list[int] = field(default_factory=list)

    def add(self, position: int, constraint: Constraint) -> None:
        if position not in self.positions:
            self.positions[position] = []
            self.order.append(position)
        self.positions[position].append(constraint)

    def clone(self) -> "Plan":
        copy = Plan()
        for position in self.order:
            copy.positions[position] = list(self.positions[position])
            copy.order.append(position)
        return copy

    def negate(self) -> "Plan":
        flip = {"eq": "ne", "ne": "eq", "gt": "le", "le": "gt",
                "ge": "lt", "lt": "ge"}
        copy = Plan()
        for position in self.order:
            copy.positions[position] = [Constraint(flip[item.kind], item.value)
                                        for item in self.positions[position]]
            copy.order.append(position)
        return copy

    def size(self) -> int:
        return len(self.order)

def _engine(profile: BinaryProfile):
    import capstone

    arch = (profile.arch or "").lower()
    mode = None
    if "64" in arch or "amd64" in arch or "x86-64" in arch:
        mode = capstone.CS_MODE_64
    else:
        mode = capstone.CS_MODE_32
    engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
    engine.detail = True
    return engine

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

def _register(op) -> str:
    if op.type != 1:
        return ""
    return _REG_NAMES.get(op.reg, "")

def _kind(mnemonic: str) -> str | None:
    if mnemonic in _EQ:
        return "eq"
    if mnemonic in _NE:
        return "ne"
    if mnemonic in _GT:
        return "gt"
    if mnemonic in _GE:
        return "ge"
    if mnemonic in _LT:
        return "lt"
    if mnemonic in _LE:
        return "le"
    return None

def _is_input_load(insn) -> tuple[str, int | None]:
    mnemonic = insn.mnemonic.lower()
    if mnemonic == "lodsb":
        return "al", None
    if mnemonic in ("mov", "movzx", "movsx") and len(insn.operands) == 2:
        target = _register(insn.operands[0])
        source = insn.operands[1]
        if not target or source.type != 3:
            return "", None
        if source.mem.base == 0 and source.mem.index == 0:
            return target, None
        return target, int(source.mem.disp)
    return "", None

def dataflow_plan(profile: BinaryProfile) -> Plan | None:
    from xsolver.analysis import dataflow

    try:
        grouped = dataflow.predicates(profile)
    except Exception:
        return None
    if not grouped:
        return None
    plan = Plan()
    for position in sorted(grouped):
        for kind, value in grouped[position]:
            plan.add(position, Constraint(kind, value))
    return plan if plan.size() >= 3 else None

def plans(profile: BinaryProfile, limit: int = 10) -> list[Plan]:
    engine = _engine(profile)
    collected: list[Plan] = []
    processed = 0
    for base, body in _sections(profile):
        instructions = []
        for insn in engine.disasm(body, base):
            instructions.append(insn)
            processed += 1
            if processed > _MAX_INSTRUCTIONS:
                break
        collected.extend(_plans_from(instructions))
        collected.extend(_memory_plans(instructions))
        if processed > _MAX_INSTRUCTIONS:
            break
    extra = dataflow_plan(profile)
    if extra is not None:
        collected.append(extra)
    collected = [plan for plan in collected if plan.size() >= 3]
    collected.sort(key=lambda plan: -plan.size())
    return collected[:limit]

def _plans_from(instructions) -> list[Plan]:
    sequence = Plan()
    dispatch = Plan()
    input_registers: dict[str, int] = {}
    local_index = 0
    selector: int | None = None
    max_selector: int | None = None
    pending: tuple[str, int] | None = None

    for position, insn in enumerate(instructions):
        mnemonic = insn.mnemonic.lower()
        operands = insn.operands

        loaded_reg, _disp = _is_input_load(insn)
        if loaded_reg:
            input_registers[loaded_reg] = local_index
            local_index += 1
            continue

        if mnemonic == "cmp" and len(operands) == 2 and operands[1].type == 2:
            register = _register(operands[0])
            immediate = operands[1].imm if isinstance(operands[1].imm, int) else None
            if not register or immediate is None:
                pending = None
                continue
            if register in _REG8:
                pending = (register, immediate & 0xFF)
            else:
                pending = None
            continue

        kind = _kind(mnemonic)
        if kind and pending is not None:
            register, value = pending
            pending = None
            if register in input_registers or (register == "al" and local_index):
                if selector is not None:
                    base = selector
                elif max_selector is not None and register in input_registers:
                    base = max_selector + 1
                else:
                    base = input_registers.get(register, local_index)
                dispatch.add(base, Constraint(kind, value))
                selector = None
            else:
                selector = value
                max_selector = value if max_selector is None else max(max_selector, value)
            continue

        if kind:
            pending = None
            continue
        if mnemonic in ("ret", "retn", "call", "jmp"):
            pending = None
            continue
    plans_out = [plan for plan in (sequence, dispatch) if plan.size() >= 3]
    return plans_out

def _memory_plans(instructions) -> list[Plan]:
    facts: list[tuple[str, int, str, int]] = []
    pending: tuple[str, int, int] | None = None
    for insn in instructions:
        mnemonic = insn.mnemonic.lower()
        operands = insn.operands
        if mnemonic == "cmp" and len(operands) == 2 and operands[1].type == 2:
            left, right = operands
            immediate = right.imm if isinstance(right.imm, int) else None
            if left.type != 3 or immediate is None or left.size != 1:
                pending = None
                continue
            base = _REG_NAMES.get(left.mem.base, "")
            if base in ("", "esp", "rsp", "ebp", "rbp") and _REG_NAMES.get(left.mem.base, "") != "ebp":
                if base in ("", "esp", "rsp"):
                    pending = None
                    continue
            pending = (base or "frame", int(left.mem.disp), immediate & 0xFF)
            continue
        kind = _kind(mnemonic)
        if kind and pending is not None:
            base, disp, value = pending
            facts.append((base, disp, kind, value))
            pending = None
            continue
        if kind:
            pending: tuple | None = None
            continue
    grouped: dict[str, list[tuple[int, str, int]]] = {}
    for base, disp, kind, value in facts:
        grouped.setdefault(base, []).append((disp, kind, value))
    out: list[Plan] = []
    for base, entries in grouped.items():
        if len(entries) < 4:
            continue
        order = sorted(entries, key=lambda item: item[0])
        for ascending in (True, False):
            sequence = order if ascending else list(reversed(order))
            plan = Plan()
            for rank, (_disp, kind, value) in enumerate(sequence):
                plan.add(rank, Constraint(kind, value))
            out.append(plan)
    return out

def _renumber(plan: Plan, base: int) -> Plan:
    copy = Plan()
    for position in plan.order:
        copy.positions[position - base] = list(plan.positions[position])
        copy.order.append(position - base)
    return copy

def variants(plan: Plan) -> list[Plan]:
    out: list[Plan] = []
    for candidate in (plan, _drop_first(plan)):
        if candidate is None or candidate.size() < 3:
            continue
        base = min(candidate.order)
        shifted = _renumber(candidate, base)
        out.append(shifted)
        negated = shifted.negate()
        out.append(_renumber(negated, min(negated.order)))
    return out

def _drop_first(plan: Plan) -> Plan | None:
    if plan.size() <= 3:
        return None
    copy = plan.clone()
    first = min(copy.order)
    copy.positions.pop(first)
    copy.order.remove(first)
    return copy if copy.size() >= 3 else None

def synthesise(plan: Plan, palette: str = _PALETTES[0]) -> str | None:
    if not plan.order:
        return None
    highest = max(plan.order)
    if highest > 256:
        return None
    out: list[str] = []
    for index in range(highest + 1):
        constraints = plan.positions.get(index) or []
        choice = None
        for char in palette:
            if all(item.accepts(ord(char)) for item in constraints):
                choice = char
                break
        if choice is None:
            return None
        out.append(choice)
    return "".join(out)

def _quality(plan: Plan) -> tuple[int, float]:
    eq = 0
    for constraints_at in plan.positions.values():
        for item in constraints_at:
            if item.kind in ("eq",):
                eq += 1
    total = plan.size()
    constrained = sum(1 for values in plan.positions.values() if values)
    return eq, constrained / max(1, total)

def _plausible(text: str) -> bool:
    if not text:
        return False
    if not 4 <= len(text) <= 40:
        return False
    longest = 1
    run = 1
    for previous, current in zip(text, text[1:]):
        run = run + 1 if current == previous else 1
        longest = max(longest, run)
    if len(set(text)) <= max(1, len(text) // 6):
        return False
    if longest > 4:
        return False
    return True

def candidates(profile: BinaryProfile, limit: int = 10) -> list[str]:
    scored: list[tuple[float, str]] = []
    for plan in plans(profile):
        for variant in variants(plan):
            if variant.size() < 4 or variant.size() > 40:
                continue
            eq, ratio = _quality(variant)
            if ratio < 0.5:
                continue
            for palette_index, palette in enumerate(_PALETTES[:4]):
                text = synthesise(variant, palette)
                if not text or not _plausible(text):
                    continue
                score = eq * 10 + ratio * 6 + min(len(text), 20) * 0.4 - palette_index
                scored.append((score, text))
    scored.sort(key=lambda item: (-item[0], item[1]))
    found: list[str] = []
    for _score, text in scored:
        if text in found:
            continue
        found.append(text)
        if len(found) >= limit:
            break
    return found
