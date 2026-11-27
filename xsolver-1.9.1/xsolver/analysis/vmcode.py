from __future__ import annotations

import re
import struct

from xsolver import _vendor

_vendor.ensure_on_path()

import z3

from xsolver.core.binary import BinaryProfile

_TABLE_RE = re.compile(
    r"^\w+, (?:byte|word|dword|qword) ptr \[([a-z][a-z0-9]*) \+ ([a-z][a-z0-9]*)\*4 \+ (0x[0-9a-f]+)\]$"
)
_FETCH_RE = re.compile(
    r"^(?:\w+), (?:byte|word|dword|qword) ptr \[([a-z][a-z0-9]*) \+ ([a-z][a-z0-9]*)(?:\*\d+)?(?: \+ (0x[0-9a-f]+))?\]$"
)
_REG_RE = re.compile(r"^[a-z][a-z0-9]*$")
_IMM_RE = re.compile(r"^\w+,\s*(0x[0-9a-f]+|\d+)$")
_STRIDE_RE = re.compile(r"\+ ([a-z][a-z0-9]*)\*2\]")
_SLOT_MEM_RE = re.compile(r"\[rbp \+ [a-z][a-z0-9]* [-+] 0x[0-9a-f]+\]|\[rbp [-+] 0x[0-9a-f]+ \+ [a-z][a-z0-9]*\]")
_WINDOW = 30
_STRIDE = 3
_MAX_LEN = 32
_STEP_LIMIT = 400

def _sections(profile: BinaryProfile):
    from xsolver.analysis import disasm

    return disasm._all_sections(profile)

def _read_rva(sections, rva: int, size: int) -> bytes | None:
    for section in sections:
        start = section.virtual_address
        if start <= rva < start + len(section.data):
            offset = rva - start
            data = section.data[offset:offset + size]
            if len(data) < size:
                return None
            return data
    return None

def _hints_in(sections, address: int) -> str | None:
    data = _read_rva(sections, address, 96)
    if not data:
        return None
    end = data.find(b"\x00")
    text = (data if end < 0 else data[:end]).lower()
    positive = (b"granted", b"congrat", b"success", b"correct", b"you win", b"access")
    negative = (b"denied", b"wrong", b"invalid", b"incorrect", b"try again")
    if any(hint in text for hint in positive):
        return "win"
    if any(hint in text for hint in negative):
        return "lose"
    return None

def _classify_handler(instructions, sections, start: int, boundaries: set[int]) -> str | None:
    slice_ = []
    for index, insn in enumerate(instructions):
        if insn.address != start:
            continue
        for other in instructions[index:index + 40]:
            if other.address != start and (other.address in boundaries or other.mnemonic == "ret"):
                break
            slice_.append(other)
        break
    if not slice_:
        return None
    for insn in slice_:
        if insn.mnemonic in ("sete", "setz", "setne", "setnz"):
            return "cmp_flag"
    for insn in slice_:
        if insn.mnemonic == "lea" and _STRIDE_RE.search(insn.op_str):
            return "jump_false"
    for insn in slice_:
        if insn.mnemonic != "lea" or "rip" not in insn.op_str:
            continue
        match = re.match(r"^(\w+), \[rip ([+-]) (0x[0-9a-f]+)\]$", insn.op_str)
        if not match:
            continue
        delta = int(match.group(3), 16)
        origin = insn.address + insn.size
        target = origin + delta if match.group(2) == "+" else origin - delta
        verdict = _hints_in(sections, target)
        if verdict == "win":
            return "halt_win"
        if verdict == "lose":
            return "halt_lose"
    for insn in slice_:
        if insn.mnemonic not in ("movzx", "movzbl", "movzx"):
            continue
        match = _FETCH_RE.match(insn.op_str)
        if not match:
            continue
        if "rbp" in match.group(1) or "rbp" in match.group(2):
            continue
        if any(s.mnemonic == "mov" and _SLOT_MEM_RE.search(s.op_str) for s in slice_):
            return "input_read"
    for insn in slice_:
        if insn.mnemonic == "add" and "byte ptr [" in insn.op_str:
            return "add"
    for insn in slice_:
        if insn.mnemonic == "xor" and "byte ptr [" in insn.op_str:
            has_slot_load = any(s.mnemonic.startswith("movzx") for s in slice_)
            return "xor_reg" if has_slot_load else "xor_imm"
    for insn in slice_:
        if (
            insn.mnemonic == "mov"
            and "byte ptr [" in insn.op_str
            and _SLOT_MEM_RE.search(insn.op_str)
        ):
            return "imm_load"
    return None

def find_vm(profile: BinaryProfile) -> dict | None:
    from xsolver.analysis import disasm

    instructions = disasm.disassemble(profile)
    if not instructions:
        return None
    sections = _sections(profile)
    window: list = []
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "jmp" or not _REG_RE.match(insn.op_str):
            window.append(insn)
            if len(window) > _WINDOW:
                window.pop(0)
            continue
        table = None
        fetch = None
        for step in window:
            table_match = _TABLE_RE.match(step.op_str)
            if step.mnemonic == "mov" and table_match:
                table = (step, table_match)
            fetch_match = _FETCH_RE.match(step.op_str)
            if (
                step.mnemonic in ("movzx", "mov")
                and fetch_match
                and fetch_match.group(3)
                and not _TABLE_RE.match(step.op_str)
            ):
                disp = int(fetch_match.group(3), 16)
                if disp >= 0x1000 and (fetch is None or disp < int(fetch[1].group(3), 16)):
                    fetch = (step, fetch_match)
        if table and fetch:
            result = _extract(instructions, sections, window, table, fetch, insn)
            if result is not None:
                return result
        window.append(insn)
        if len(window) > _WINDOW:
            window.pop(0)
    return None

def _extract(instructions, sections, window, table, fetch, jmp_insn) -> dict | None:
    table_insn, table_match = table
    fetch_insn, fetch_match = fetch
    bytecode_rva = int(fetch_match.group(3), 16)
    table_rva = int(table_match.group(3), 16)
    pos = instructions.index(table_insn) if table_insn in instructions else -1
    entries: int | None = None
    bound: int | None = None
    if pos >= 0:
        near = instructions[max(0, pos - 12):pos + 12]
        for step in near:
            if step.mnemonic != "dec":
                continue
            start = instructions.index(step)
            for other in instructions[start + 1:start + 5]:
                imm_match = _IMM_RE.match(other.op_str)
                if other.mnemonic == "cmp" and imm_match:
                    try:
                        value = _parse(imm_match.group(1))
                    except ValueError:
                        continue
                    if 1 <= value <= 64:
                        entries = value + 1
                    break
            if entries is not None:
                break
        for step in window:
            if step.mnemonic != "cmp":
                continue
            imm_match = _IMM_RE.match(step.op_str)
            if not imm_match:
                continue
            try:
                value = _parse(imm_match.group(1))
            except ValueError:
                continue
            if value >= _STRIDE * 3 and (bound is None or value > bound):
                bound = value
    if entries is None or bound is None or bound < _STRIDE * 2:
        return None
    table_data = _read_rva(sections, table_rva, entries * 4)
    bytecode = _read_rva(sections, bytecode_rva, bound)
    if table_data is None or bytecode is None:
        return None
    handlers = [struct.unpack_from("<I", table_data, i * 4)[0] for i in range(entries)]
    kinds: list[str | None] = []
    for handler in handlers:
        handler_addrs = {h for h in handlers if h}
        kinds.append(
            _classify_handler(instructions, sections, handler, handler_addrs)
        )
    if any(kind is None for kind in kinds):
        return None
    if "halt_win" not in kinds or "halt_lose" not in kinds:
        return None
    nreg: int | None = None
    for kind, handler in zip(kinds, handlers):
        if kind in ("halt_win", "halt_lose"):
            continue
        handler_pos = next(
            (i for i, insn in enumerate(instructions) if insn.address == handler), None
        )
        if handler_pos is None:
            continue
        for step in instructions[handler_pos:handler_pos + 8]:
            if step.mnemonic != "cmp":
                continue
            imm_match = _IMM_RE.match(step.op_str)
            if not imm_match:
                continue
            try:
                value = _parse(imm_match.group(1))
            except ValueError:
                continue
            if 2 <= value <= 16:
                nreg = value
                break
        if nreg is not None:
            break
    if nreg is None:
        nreg = 4
    return {
        "bytecode": bytecode,
        "handlers": handlers,
        "kinds": kinds,
        "nreg": nreg,
        "stride": _STRIDE,
    }

def _parse(token: str) -> int:
    return int(token, 16) if token.lower().startswith("0x") else int(token)

def solve_input(profile: BinaryProfile, max_candidates: int = 4) -> list[str]:
    vm = find_vm(profile)
    if vm is None:
        return []
    out: list[str] = []
    for length in range(1, _MAX_LEN + 1):
        candidate = _solve_length(vm, length)
        if candidate is not None and candidate not in out:
            out.append(candidate)
            if len(out) >= max_candidates:
                break
    return out

def _solve_length(vm: dict, length: int) -> str | None:
    bytecode: bytes = vm["bytecode"]
    kinds: list[str] = vm["kinds"]
    stride: int = vm["stride"]
    nreg: int = vm["nreg"]
    inputs = [z3.BitVec(f"in_{length}_{i}", 8) for i in range(length)]
    solver = z3.Solver()
    solver.set("timeout", 2000)
    for byte in inputs:
        solver.add(byte >= 0x20, byte <= 0x7E)

    def run(pc: int, idx: int, regs: list, flag, steps: int) -> str | None:
        while pc + stride <= len(bytecode) and steps < _STEP_LIMIT:
            steps += 1
            op = bytecode[pc]
            a1 = bytecode[pc + 1]
            a2 = bytecode[pc + 2]
            if op < 1 or op > len(kinds):
                return None
            kind = kinds[op - 1]
            nxt = pc + stride
            if kind == "input_read":
                if a1 < nreg:
                    regs = list(regs)
                    if idx < length:
                        regs[a1] = inputs[idx]
                        idx += 1
                    else:
                        regs[a1] = z3.BitVecVal(0, 8)
            elif kind == "imm_load":
                if a1 < nreg:
                    regs = list(regs)
                    regs[a1] = z3.BitVecVal(a2 & 0xFF, 8)
            elif kind == "add":
                if a1 < nreg and a2 < nreg:
                    regs = list(regs)
                    regs[a1] = regs[a1] + regs[a2]
            elif kind == "xor_reg":
                if a1 < nreg and a2 < nreg:
                    regs = list(regs)
                    regs[a1] = regs[a1] ^ regs[a2]
            elif kind == "xor_imm":
                if a1 < nreg:
                    regs = list(regs)
                    regs[a1] = regs[a1] ^ z3.BitVecVal(a2 & 0xFF, 8)
            elif kind == "cmp_flag":
                if a1 < nreg:
                    flag = regs[a1] == z3.BitVecVal(a2 & 0xFF, 8)
            elif kind == "jump_false":
                solver.push()
                solver.add(flag)
                if solver.check() == z3.sat:
                    found = run(nxt, idx, regs, flag, steps)
                    solver.pop()
                    if found is not None:
                        return found
                else:
                    solver.pop()
                solver.push()
                solver.add(z3.Not(flag))
                if solver.check() == z3.sat:
                    found = run(a2 * stride, idx, regs, flag, steps)
                    solver.pop()
                    if found is not None:
                        return found
                else:
                    solver.pop()
                return None
            elif kind == "halt_win":
                if solver.check() != z3.sat:
                    return None
                model = solver.model()
                try:
                    return "".join(chr(model[byte].as_long()) for byte in inputs)
                except Exception:
                    return None
            else:
                return None
            pc = nxt
        return None

    return run(0, 0, [z3.BitVecVal(0, 8) for _ in range(nreg)], z3.BoolVal(False), 0)

def _is_win(candidate: str, mode: str, result, success_detector) -> bool:
    text = str(getattr(result, "output", "") or "")
    if success_detector and success_detector(candidate, text):
        return True
    from xsolver.strategies.base import POSITIVE_HINTS

    low = text.lower()
    for hint in POSITIVE_HINTS:
        token = hint.decode("latin1") if isinstance(hint, (bytes, bytearray)) else str(hint)
        if token in low:
            return True
    return False
