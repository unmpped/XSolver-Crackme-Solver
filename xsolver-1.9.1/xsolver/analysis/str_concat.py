from __future__ import annotations

import struct

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EAX,
    X86_REG_EBP,
    X86_REG_ECX,
    X86_REG_EDX,
    X86_REG_ESP,
    X86_REG_INVALID,
    X86_REG_RAX,
    X86_REG_RBP,
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RSP,
)

def _pe_sections(data: bytes) -> list[dict]:
    if data[:2] != b"MZ":
        return []
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e : e + 4] != b"PE\0\0":
        return []
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    magic = struct.unpack_from("<H", data, e + 24)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, e + 24 + 24)[0]
        mode = CS_MODE_64
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", data, e + 24 + 28)[0]
        mode = CS_MODE_32
    else:
        return []
    soff = e + 24 + optsz
    secs = []
    for i in range(nsec):
        o = soff + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, raw = struct.unpack_from("<IIII", data, o + 8)
        secs.append(
            {"name": name, "va": va, "vs": vs, "raw": raw, "rs": rs,
             "base": image_base, "mode": mode}
        )
    return secs

def _rva_to_off(secs: list[dict], rva: int) -> int | None:
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
            return s["raw"] + rva - s["va"]
    return None

def _read_cstr(data: bytes, secs: list[dict], va: int) -> str | None:
    base = secs[0]["base"]
    rva = va - base if va >= base else va
    off = _rva_to_off(secs, rva)
    if off is None or off >= len(data):
        return None
    try:
        end = data.index(b"\0", off)
    except ValueError:
        return None
    raw = data[off:end]
    if not (2 <= len(raw) <= 80):
        return None
    if not all(32 <= c < 127 for c in raw):
        return None
    return raw.decode("ascii")

def _is_bp(reg: int) -> bool:
    return reg in (X86_REG_EBP, X86_REG_RBP)

def str_concat_candidates(path) -> list[str]:
    data = path.read_bytes() if hasattr(path, "read_bytes") else open(path, "rb").read()
    secs = _pe_sections(data)
    if not secs:
        return []
    text = next((s for s in secs if s["name"] == ".text"), None)
    if text is None:
        return []
    md = Cs(CS_ARCH_X86, text["mode"])
    md.detail = True
    insns = list(md.disasm(
        data[text["raw"] : text["raw"] + text["rs"]], text["base"] + text["va"]
    ))
    if not insns:
        return []

    slot_str: dict[int, str] = {}
    reg_slot: dict[int, int] = {}
    acc: str | None = None
    results: list[str] = []
    last_cstr: str | None = None
    last_cstr_idx = -1

    for i, ins in enumerate(insns):
        if ins.mnemonic == "lea" and ins.operands and len(ins.operands) == 2:
            if ins.operands[0].type == X86_OP_REG and ins.operands[1].type == X86_OP_MEM:
                mem = ins.operands[1].mem
                if _is_bp(mem.base) and mem.index == X86_REG_INVALID:
                    reg_slot[ins.operands[0].reg] = mem.disp
                else:
                    reg_slot.pop(ins.operands[0].reg, None)
            continue

        if ins.mnemonic == "mov" and ins.operands and len(ins.operands) == 2:
            o0, o1 = ins.operands
            if o0.type == X86_OP_REG:
                reg_slot.pop(o0.reg, None)
            if (o0.type == X86_OP_MEM and o1.type == X86_OP_IMM
                    and o0.mem.base == X86_REG_ESP
                    and o0.mem.index == X86_REG_INVALID):
                s = _read_cstr(data, secs, o1.imm)
                if s is not None:
                    last_cstr = s
                    last_cstr_idx = i
            continue

        if ins.mnemonic != "push" or not ins.operands:
            continue

        op = ins.operands[0]
        pushed_slot = None
        pushed_lit = None
        if op.type == X86_OP_IMM:
            pushed_lit = _read_cstr(data, secs, op.imm)
            if pushed_lit is None:
                continue
            last_cstr = pushed_lit
            last_cstr_idx = i
        elif op.type == X86_OP_REG:
            if op.reg not in reg_slot:
                continue
            pushed_slot = reg_slot[op.reg]
        elif op.type == X86_OP_MEM:
            mem = op.mem
            if _is_bp(mem.base) and mem.index == X86_REG_INVALID:
                pushed_slot = mem.disp
            else:
                continue
        else:
            continue

        dest_slot = None
        left_slot = None
        call_idx = None
        esp_lit = None
        for j in range(i + 1, min(i + 14, len(insns))):
            y = insns[j]
            if y.mnemonic == "mov" and y.operands and len(y.operands) == 2:
                m0, m1 = y.operands
                if (m0.type == X86_OP_MEM and m1.type == X86_OP_IMM
                        and m0.mem.base == X86_REG_ESP
                        and m0.mem.index == X86_REG_INVALID):
                    s = _read_cstr(data, secs, m1.imm)
                    if s is not None:
                        esp_lit = s
                if (m0.type == X86_OP_REG
                        and m0.reg in (X86_REG_EDX, X86_REG_RDX)
                        and m1.type == X86_OP_REG
                        and m1.reg in (X86_REG_EAX, X86_REG_RAX)):
                    left_slot = -1
            if y.mnemonic == "lea" and y.operands and len(y.operands) == 2:
                if y.operands[0].type != X86_OP_REG or y.operands[1].type != X86_OP_MEM:
                    continue
                mem = y.operands[1].mem
                if not _is_bp(mem.base) or mem.index != X86_REG_INVALID:
                    continue
                dst = y.operands[0].reg
                if dst in (X86_REG_ECX, X86_REG_RCX):
                    dest_slot = mem.disp
                elif dst in (X86_REG_EDX, X86_REG_RDX):
                    left_slot = mem.disp
            if y.mnemonic == "call":
                call_idx = j
                break
            if y.mnemonic in ("ret", "retn"):
                break

        if call_idx is None:
            continue

        if dest_slot is None and left_slot is None:
            continue

        if pushed_lit is not None and left_slot is None and dest_slot is not None:
            slot_str[dest_slot] = pushed_lit
            continue

        left = None
        if left_slot == -1:
            left = acc
        elif left_slot is not None:
            left = slot_str.get(left_slot)
        right = None
        if pushed_slot is not None:
            right = slot_str.get(pushed_slot)
        elif pushed_lit is not None:
            right = pushed_lit
        if left is not None and right is not None:
            combined = left + right
            if dest_slot is not None:
                slot_str[dest_slot] = combined
            acc = combined
            results.append(combined)
            continue

        if esp_lit is not None and dest_slot is None:
            continue

    strcpy_mode = _strcpy_chains_indexed(insns, data, secs)
    results.extend(strcpy_mode)

    seen: list[str] = []
    for s in results:
        if s not in seen and len(s) >= 4:
            seen.append(s)
    seen.sort(key=len, reverse=True)
    return seen

def _strcpy_chains_indexed(insns, data, secs) -> list[str]:
    reg_buf: dict[int, tuple[str, int]] = {}
    buf_str: dict[tuple[str, int], str] = {}
    last_lit: str | None = None
    last_lit_idx = -1
    out: list[str] = []
    for i, ins in enumerate(insns):
        if ins.mnemonic == "lea" and ins.operands and len(ins.operands) == 2:
            if ins.operands[0].type == X86_OP_REG and ins.operands[1].type == X86_OP_MEM:
                mem = ins.operands[1].mem
                if mem.base in (X86_REG_EBP, X86_REG_RBP) and mem.index == X86_REG_INVALID:
                    reg_buf[ins.operands[0].reg] = ("bp", mem.disp)
                elif mem.base in (X86_REG_ESP, X86_REG_RSP) and mem.index == X86_REG_INVALID:
                    reg_buf[ins.operands[0].reg] = ("sp", mem.disp)
                else:
                    reg_buf.pop(ins.operands[0].reg, None)
            continue
        if ins.mnemonic == "mov" and ins.operands and len(ins.operands) == 2:
            o0, o1 = ins.operands
            if o0.type == X86_OP_REG:
                reg_buf.pop(o0.reg, None)
            if (o0.type == X86_OP_MEM and o1.type == X86_OP_IMM
                    and o0.mem.base in (X86_REG_ESP, X86_REG_RSP)
                    and o0.mem.index == X86_REG_INVALID):
                s = _read_cstr(data, secs, o1.imm)
                if s is not None:
                    last_lit = s
                    last_lit_idx = i
            continue
        if ins.mnemonic == "push" and ins.operands:
            if ins.operands[0].type == X86_OP_IMM:
                s = _read_cstr(data, secs, ins.operands[0].imm)
                if s is not None:
                    last_lit = s
                    last_lit_idx = i
            continue
        if ins.mnemonic != "call" or last_lit is None:
            continue
        dest = None
        for j in range(i - 1, last_lit_idx, -1):
            y = insns[j]
            if y.mnemonic == "mov" and y.operands and len(y.operands) == 2:
                m0, m1 = y.operands
                if (m0.type == X86_OP_MEM
                        and m0.mem.base in (X86_REG_ESP, X86_REG_RSP)
                        and m0.mem.index == X86_REG_INVALID
                        and m1.type == X86_OP_REG
                        and m1.reg in reg_buf):
                    dest = reg_buf[m1.reg]
                    break
        if dest is None:
            last_lit = None
            continue
        prev = buf_str.get(dest, "")
        if not prev:
            buf_str[dest] = last_lit
        else:
            combined = prev + last_lit
            buf_str[dest] = combined
            out.append(combined)
        last_lit = None
    return out
