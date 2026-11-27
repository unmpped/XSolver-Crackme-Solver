from __future__ import annotations

import re
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

MAGIC10 = 0x0CCCCCCCD
MAX_PREFIX = 40
MIN_PREFIX = 3
CALLER_WINDOW = 14
MAX_CANDIDATES = 60
FIELD_OFFSETS = (4, 0, 8, 12)

_TOP = object()
_THIS = object()

_REG_NAMES = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
_MEM_RE = re.compile(r"\[(.*?)\]")
_BRANCHES = frozenset((
    "jmp", "jne", "je", "jg", "jl", "jge", "jle", "ja", "jb", "jae", "jbe",
    "js", "jns", "jo", "jno", "jp", "jnp", "ret", "retn", "loop", "loope",
    "loopne",
))
_SSE = frozenset(("movups", "movaps", "movdqu", "movdqa", "movd", "movq", "xorps", "pxor"))
_NOPS = frozenset(("nop", "cld", "std", "pause", "endbr32", "endbr64", "fwait"))
_WIDTHS = ("byte", "word", "dword", "qword")

class _Abort(Exception):
    pass

def _s32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value

def _u32(value: int) -> int:
    return value & 0xFFFFFFFF

def _pe_image_base(data: bytes) -> int:
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 24)[0]
    if magic == 0x20B:
        return struct.unpack_from("<Q", data, e + 24 + 24)[0]
    return struct.unpack_from("<I", data, e + 24 + 28)[0]

def _pe_image_size(info) -> int:
    return max(
        (sec.virtual_address + max(sec.virtual_size, sec.raw_size)
         for sec in info.sections),
        default=0x10000,
    )

def _load_pe32(data: bytes):
    from xsolver.core.pe import parse_pe

    info = parse_pe(data)
    if info.is_64:
        return None
    return info

def _rva_to_off(info, rva: int) -> int | None:
    for sec in info.sections:
        span = max(sec.virtual_size, sec.raw_size)
        if sec.virtual_address <= rva < sec.virtual_address + span:
            delta = rva - sec.virtual_address
            if delta < sec.raw_size:
                return sec.raw_offset + delta
            return None
    return None

def _text_section(info):
    for sec in info.sections:
        if sec.characteristics & 0x20000000 and sec.raw_size:
            return sec
    return None

def _split_two(ops: str):
    if "," not in ops:
        return ops.strip(), None
    left, right = ops.split(",", 1)
    return left.strip(), right.strip()

def _is_prologue_pair(order, idx: int) -> bool:
    insn = order[idx]
    if insn.mnemonic == "push" and insn.op_str == "ebp":
        return True
    if insn.mnemonic == "push" and insn.op_str == "ebx":
        for nxt in order[idx + 1:idx + 3]:
            if nxt.mnemonic == "mov" and nxt.op_str.startswith("ebx, esp"):
                return True
            if nxt.mnemonic == "push":
                break
    return False

def _eval_mem(inner: str, regs: dict, this_offset: int):
    inner = inner.strip()
    if re.match(r"^(fs|gs|ss|cs|ds|es):", inner):
        return _TOP
    total = 0
    sign = 1
    saw = False
    saw_this = False
    for tok in re.split(r"([+-])", inner):
        tok = tok.strip()
        if tok in ("+", "-"):
            sign = 1 if tok == "+" else -1
            continue
        if not tok:
            continue
        m = re.match(r"^([a-z]{2,3})(?:\s*\*\s*(\d+))?$", tok)
        if m and m.group(1) in _REG_NAMES:
            val = regs.get(m.group(1), _TOP)
            if val is _THIS:
                saw_this = True
                saw = True
                continue
            if val is _TOP:
                return _TOP
            scaled = val * int(m.group(2)) if m.group(2) else val
            total += sign * scaled
            saw = True
            continue
        m = re.match(r"^(0x[0-9a-f]+|\d+)$", tok)
        if m:
            total += sign * int(m.group(1), 0)
            saw = True
            continue
        return _TOP
    if not saw:
        return _TOP
    if saw_this:
        return ("THIS", total, this_offset)
    return total

def _load_mem(text: str, regs: dict, field: int, offset: int,
              data: bytes, info, base: int, allow_this: bool = True):
    m = _MEM_RE.search(text)
    if not m:
        return _TOP
    value = _eval_mem(m.group(1), regs, offset)
    if isinstance(value, tuple):
        if not allow_this:
            raise _Abort("this read")
        if value[1] == offset:
            return _s32(field)
        raise _Abort("this field")
    if value is _TOP:
        return _TOP
    width = 4
    for name, size in (("byte", 1), ("word", 2), ("qword", 8)):
        if text.startswith(name):
            width = size
            break
    off = _rva_to_off(info, value - base)
    if off is None or off + width > len(data):
        return _TOP
    fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}[width]
    return struct.unpack_from(fmt, data, off)[0]

def _plain_value(text: str, regs: dict):
    text = text.strip()
    if text in _REG_NAMES:
        return regs.get(text, _TOP)
    try:
        return _s32(int(text, 0))
    except ValueError:
        return _TOP

def _operand_value(text: str, regs: dict, field: int, offset: int,
                   data: bytes, info, base: int, allow_this: bool = True):
    text = text.strip()
    if text.startswith(_WIDTHS):
        return _load_mem(text, regs, field, offset, data, info, base,
                         allow_this=allow_this)
    if text in _REG_NAMES:
        return regs.get(text, _TOP)
    try:
        return _s32(int(text, 0))
    except ValueError:
        return _TOP

def _do_mov(ops: str, regs: dict, field: int, offset: int,
            data: bytes, info, base: int) -> None:
    dst, src = _split_two(ops)
    if dst is None or src is None:
        raise _Abort("mov form")
    if dst.startswith(_WIDTHS):
        m = _MEM_RE.search(dst)
        if not m:
            raise _Abort("store")
        inner = m.group(1)
        if re.match(r"^(fs|gs|ss|cs|ds|es):", inner):
            return
        value = _eval_mem(inner, regs, offset)
        if isinstance(value, tuple):
            raise _Abort("this store")
        return
    if dst in _REG_NAMES:
        regs[dst] = _operand_value(src, regs, field, offset, data, info, base)
        return
    raise _Abort("mov dst")

def _do_movx(mn: str, ops: str, regs: dict, field: int, offset: int,
             data: bytes, info, base: int) -> None:
    dst, src = _split_two(ops)
    if dst is None or src is None or dst not in _REG_NAMES:
        raise _Abort("movx form")
    value = _operand_value(src, regs, field, offset, data, info, base)
    if not isinstance(value, int):
        regs[dst] = _TOP
        return
    if mn == "movzx":
        mask = 0xFF if "byte" in src else 0xFFFF
        regs[dst] = _u32(value) & mask
    else:
        if "byte" in src:
            regs[dst] = _s32(struct.unpack("<b", struct.pack("<B", _u32(value) & 0xFF))[0])
        else:
            regs[dst] = _s32(struct.unpack("<h", struct.pack("<H", _u32(value) & 0xFFFF))[0])

def _do_arith(mn: str, ops: str, regs: dict) -> None:
    dst, src = _split_two(ops)
    if dst is None or dst not in _REG_NAMES:
        raise _Abort("arith form")
    if mn == "imul" and src and "," in src:
        first, second = src.split(",", 1)
        left = _plain_value(first, regs)
        right = _plain_value(second, regs)
        if not isinstance(left, int) or not isinstance(right, int):
            regs[dst] = _TOP
            return
        regs[dst] = _s32(_s32(left) * _s32(right))
        return
    if mn == "imul" and src is None:
        eax = regs.get("eax", _TOP)
        rhs = regs.get(dst, _TOP)
        if not isinstance(eax, int) or not isinstance(rhs, int):
            regs["eax"] = _TOP
            regs["edx"] = _TOP
            return
        prod = _s32(eax) * _s32(rhs)
        regs["eax"] = _s32(prod)
        regs["edx"] = _s32(prod >> 32)
        return
    if src is None:
        raise _Abort("arith form")
    left = regs.get(dst, _TOP)
    right = _plain_value(src, regs)
    if not isinstance(left, int) or not isinstance(right, int):
        regs[dst] = _TOP
        return
    if mn == "add":
        regs[dst] = _s32(left + right)
    elif mn == "sub":
        regs[dst] = _s32(left - right)
    elif mn == "and":
        regs[dst] = _s32(_u32(left) & _u32(right))
    elif mn == "or":
        regs[dst] = _s32(_u32(left) | _u32(right))
    elif mn == "xor":
        regs[dst] = _s32(_u32(left) ^ _u32(right))
    elif mn == "imul":
        regs[dst] = _s32(_s32(left) * _s32(right))
    else:
        raise _Abort("arith op")

def _do_muldiv(ops: str, regs: dict, signed: bool) -> None:
    if "," in ops:
        raise _Abort("mul form")
    src = _plain_value(ops, regs)
    eax = regs.get("eax", _TOP)
    if not isinstance(src, int) or not isinstance(eax, int):
        regs["eax"] = _TOP
        regs["edx"] = _TOP
        return
    if signed:
        prod = _s32(eax) * _s32(src)
    else:
        prod = _u32(eax) * _u32(src)
    regs["eax"] = _s32(prod)
    regs["edx"] = _s32(prod >> 32)

def _do_shift(mn: str, ops: str, regs: dict) -> None:
    dst, src = _split_two(ops)
    if dst is None or src is None or dst not in _REG_NAMES:
        raise _Abort("shift form")
    count = _plain_value(src, regs)
    val = regs.get(dst, _TOP)
    if not isinstance(count, int) or not isinstance(val, int):
        regs[dst] = _TOP
        return
    count &= 0x1F
    if mn == "shl":
        regs[dst] = _s32(_u32(val) << count)
    elif mn == "shr":
        regs[dst] = _s32(_u32(val) >> count)
    else:
        regs[dst] = _s32(_s32(val) >> count)

def _run_interpret(order, entry_idx: int, call_idx: int, field: int,
                   offset: int, data: bytes, info, base: int):
    regs: dict = {name: _TOP for name in _REG_NAMES}
    regs["ecx"] = _THIS
    shadow: list = []
    idx = entry_idx
    while idx < call_idx:
        insn = order[idx]
        mn = insn.mnemonic
        ops = insn.op_str
        if mn in _BRANCHES:
            raise _Abort("branch")
        if mn in ("cmp", "test"):
            idx += 1
            continue
        if mn == "push":
            shadow.append(_operand_value(ops, regs, field, offset, data, info, base,
                                         allow_this=False))
            idx += 1
            continue
        if mn == "pop":
            raise _Abort("pop")
        if mn == "call":
            raise _Abort("nested call")
        if mn in _SSE:
            idx += 1
            continue
        if mn == "lea":
            dst, src = _split_two(ops)
            if dst is None or src is None or dst not in _REG_NAMES:
                raise _Abort("lea form")
            m = _MEM_RE.search(src)
            if not m:
                raise _Abort("lea non-mem")
            regs[dst] = _eval_mem(m.group(1), regs, offset)
            idx += 1
            continue
        if mn == "mov":
            _do_mov(ops, regs, field, offset, data, info, base)
            idx += 1
            continue
        if mn in ("movzx", "movsx"):
            _do_movx(mn, ops, regs, field, offset, data, info, base)
            idx += 1
            continue
        if mn in ("add", "sub", "and", "or", "xor", "imul"):
            _do_arith(mn, ops, regs)
            idx += 1
            continue
        if mn in ("mul", "div", "idiv"):
            _do_muldiv(ops, regs, signed=(mn == "idiv"))
            idx += 1
            continue
        if mn in ("neg", "not"):
            dst = ops.strip()
            val = regs.get(dst, _TOP)
            regs[dst] = _s32(-val if mn == "neg" else ~val) if isinstance(val, int) else _TOP
            idx += 1
            continue
        if mn in ("shl", "shr", "sar"):
            _do_shift(mn, ops, regs)
            idx += 1
            continue
        if mn == "cdq":
            val = regs.get("eax", _TOP)
            regs["edx"] = (-1 if _s32(val) < 0 else 0) if isinstance(val, int) else _TOP
            idx += 1
            continue
        if mn in _NOPS:
            idx += 1
            continue
        raise _Abort(f"insn {mn}")
    return regs, shadow

def _capture_numbers(regs: dict, shadow: list, base: int, size: int) -> list[int]:
    values: list[int] = []
    for name in ("edx", "eax", "ebx", "ecx", "esi", "edi", "ebp"):
        val = regs.get(name, _TOP)
        if isinstance(val, int):
            values.append(val)
    for item in reversed(shadow):
        if isinstance(item, int):
            values.append(item)
    seen: set[int] = set()
    out: list[int] = []
    for val in values:
        val = _s32(val)
        if val in seen:
            continue
        seen.add(val)
        if base <= _u32(val) < base + size:
            continue
        out.append(val)
    return out

def _is_magic10(insn) -> bool:
    if insn.mnemonic not in ("mov", "movabs"):
        return False
    _, src = _split_two(insn.op_str)
    if src is None:
        return False
    try:
        return int(src, 0) == MAGIC10
    except ValueError:
        return False

def _function_start(order, call_idx: int) -> int | None:
    start = None
    for i in range(call_idx - 1, -1, -1):
        mn = order[i].mnemonic
        if mn in ("ret", "retn", "jmp", "int3"):
            start = i + 1
            break
        if _is_prologue_pair(order, i):
            start = i
            if order[i].op_str == "ebp":
                for back in range(i - 1, max(-1, i - 7), -1):
                    if (order[back].mnemonic == "push" and order[back].op_str == "ebx"
                            and back + 1 < len(order)
                            and order[back + 1].mnemonic == "mov"
                            and order[back + 1].op_str.startswith("ebx, esp")):
                        start = back
            break
    if start is None or start >= call_idx:
        return None
    while start < call_idx and order[start].mnemonic in ("nop", "int3"):
        start += 1
    return start if start < call_idx else None

def _window_fields(order, start: int, end: int, offset: int) -> list[int]:
    fields: list[int] = []
    mats: list[tuple[str, int]] = []
    for w in order[max(0, start):end]:
        if w.mnemonic == "lea":
            dst, src = _split_two(w.op_str)
            if dst is None or src is None:
                continue
            m = re.fullmatch(r"\[([a-z]{2,3})(?: \+ (0x[0-9a-f]+|\d+))?\]",
                             src.strip())
            if m:
                disp = int(m.group(2), 0) if m.group(2) else 0
                mats.append((m.group(1), disp))
        elif w.mnemonic == "mov":
            dst, src = _split_two(w.op_str)
            if dst is None or src is None:
                continue
            if src.strip() in _REG_NAMES and dst.strip() in _REG_NAMES:
                mats.append((src.strip(), 0))
    if not mats:
        return fields
    for base_reg, base_disp in mats:
        target = base_disp + offset
        if target:
            pat = (r"(?:dword|byte|word) ptr \[" + re.escape(base_reg)
                   + r" \+ (0x[0-9a-f]+|\d+)\]")
        else:
            pat = (r"(?:dword|byte|word) ptr \[" + re.escape(base_reg)
                   + r"\]")
        for idx in range(max(0, start), end):
            insn = order[idx]
            if insn.mnemonic != "mov":
                continue
            dst, src = _split_two(insn.op_str)
            if dst is None or src is None:
                continue
            m = re.fullmatch(pat, dst.strip())
            if not m:
                continue
            if m.groups() and int(m.group(1), 0) != target:
                continue
            try:
                imm = _s32(int(src, 0))
            except ValueError:
                continue
            fields.append(imm)
    return list(dict.fromkeys(fields))

def _inlined_strings(order, call_idx: int) -> list[str]:
    stores: dict[str, list[tuple[int, str]]] = {}
    width_bytes = {"dword": 4, "word": 2, "byte": 1}
    for insn in order[call_idx:min(len(order), call_idx + 90)]:
        if insn.mnemonic != "mov":
            continue
        dst, src = _split_two(insn.op_str)
        if dst is None or src is None:
            continue
        m = re.fullmatch(r"(dword|word|byte) ptr \[([a-z]{2,3})"
                         r"(?: \+ (0x[0-9a-f]+|\d+))?\]", dst.strip())
        if not m:
            continue
        size_name, base_reg = m.group(1), m.group(2)
        off = int(m.group(3), 0) if m.group(3) else 0
        try:
            imm = int(src, 0)
        except ValueError:
            continue
        nbytes = width_bytes[size_name]
        imm &= (1 << (8 * nbytes)) - 1
        raw = imm.to_bytes(nbytes, "little")
        if not all(32 <= b <= 126 for b in raw):
            continue
        stores.setdefault(base_reg, []).append((off, raw.decode("ascii")))
    out: list[str] = []
    for items in stores.values():
        items.sort()
        chain_off, chain = None, ""
        for off, text in items:
            if chain_off is None:
                chain_off, chain = off, text
            elif off == chain_off + len(chain):
                chain += text
            else:
                if len(chain) >= MIN_PREFIX:
                    out.append(chain)
                chain_off, chain = off, text
        if chain and len(chain) >= MIN_PREFIX:
            out.append(chain)
    return out

def _prefixes(order, call_idx: int, data: bytes, info, base: int) -> list[str]:
    call_addr = order[call_idx].address
    found: list[tuple[int, str]] = []
    seen: set[str] = set()
    for text in _inlined_strings(order, call_idx):
        if text not in seen:
            seen.add(text)
            found.append((0, text))
    for insn in order[call_idx:min(len(order), call_idx + 90)]:
        for match in re.finditer(r"0x[0-9a-f]{5,8}", insn.op_str):
            addr = int(match.group(0), 16)
            if not (base <= addr < base + _pe_image_size(info)):
                continue
            exec_sec = False
            for sec in info.sections:
                span = max(sec.virtual_size, sec.raw_size)
                if sec.virtual_address <= addr - base < sec.virtual_address + span:
                    exec_sec = bool(sec.characteristics & 0x20000000)
                    break
            if exec_sec:
                continue
            off = _rva_to_off(info, addr - base)
            if off is None:
                continue
            end_off = data.find(b"\x00", off, off + MAX_PREFIX + 1)
            if end_off < 0:
                continue
            raw = data[off:end_off]
            if not (MIN_PREFIX <= len(raw) <= MAX_PREFIX):
                continue
            try:
                text = raw.decode("ascii")
            except UnicodeDecodeError:
                continue
            if not all(32 <= ord(ch) <= 126 for ch in text):
                continue
            if text in seen:
                continue
            seen.add(text)
            found.append((abs(addr - call_addr), text))
    found.sort()
    return [text for _, text in found]

def const_fold_candidates(path: str | Path) -> list[str]:
    data = Path(path).read_bytes()
    info = _load_pe32(data)
    if info is None:
        return []
    base = _pe_image_base(data)
    size = _pe_image_size(info)
    sec = _text_section(info)
    if sec is None:
        return []
    order = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for insn in md.disasm(data[sec.raw_offset:sec.raw_offset + sec.raw_size],
                          base + sec.virtual_address):
        order.append(insn)
    if not order:
        return []
    pros = [i for i in range(len(order)) if _is_prologue_pair(order, i)]
    d_starts: set[int] = set()
    for mi, insn in enumerate(order):
        if not _is_magic10(insn):
            continue
        p = None
        for cand in pros:
            if cand < mi:
                p = cand
            else:
                break
        if p is not None:
            d_starts.add(order[p].address)
    if not d_starts:
        return []
    results: list[str] = []
    seen: set[str] = set()
    for call_idx, insn in enumerate(order):
        if insn.mnemonic != "call":
            continue
        try:
            target = int(insn.op_str, 16)
        except ValueError:
            continue
        if target not in d_starts:
            continue
        entry_idx = _function_start(order, call_idx)
        if entry_idx is None or entry_idx >= call_idx:
            continue
        f_addr = order[entry_idx].address
        caller_idxs = []
        for idx, other in enumerate(order):
            if other.mnemonic != "call":
                continue
            try:
                t = int(other.op_str, 16)
            except ValueError:
                continue
            if t == f_addr and idx != call_idx:
                caller_idxs.append(idx)
        if not caller_idxs:
            continue
        prefixes = _prefixes(order, call_idx, data, info, base)
        numbers: list[int] = []
        got_number = False
        for offset in FIELD_OFFSETS:
            fields: list[int] = []
            for cidx in caller_idxs:
                fields.extend(_window_fields(order, max(0, cidx - CALLER_WINDOW),
                                             cidx, offset))
            fields = list(dict.fromkeys(fields))
            for field in fields:
                try:
                    regs, shadow = _run_interpret(order, entry_idx, call_idx,
                                                  field, offset, data, info, base)
                except _Abort:
                    continue
                got_number = True
                for num in _capture_numbers(regs, shadow, base, size):
                    if num not in numbers:
                        numbers.append(num)
            if got_number:
                break
        if not got_number:
            continue
        for num in numbers:
            text = str(num)
            for prefix in prefixes:
                for cand in (prefix + text, text + prefix):
                    if cand not in seen:
                        seen.add(cand)
                        results.append(cand)
            if text not in seen:
                seen.add(text)
                results.append(text)
    return results[:MAX_CANDIDATES]
