from __future__ import annotations

import struct

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_INVALID,
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
            {"name": name, "va": va, "vs": vs, "raw": raw, "rs": rs, "base": image_base, "mode": mode}
        )
    return secs

def _rva_to_off(secs: list[dict], rva: int) -> int | None:
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
            return s["raw"] + rva - s["va"]
    return None

def _decode_blob(raw: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in raw)

def _printable_score(text: bytes) -> float:
    if not text:
        return -100.0
    letters = sum(chr(c).isalpha() for c in text)
    digits = sum(chr(c).isdigit() for c in text)
    vowels = sum(chr(c) in "aeiouAEIOU" for c in text)
    spaces = text.count(32)
    punct = sum(c in b"-_.'!?" for c in text)
    printable = sum(32 <= c < 127 for c in text)
    if printable != len(text):
        return -100.0
    if letters + digits + spaces + punct < len(text) * 0.8:
        return -50.0
    score = letters * 2.0 + digits * 1.5 + spaces * 2.0 + punct * 2.0
    score /= max(len(text), 1) ** 0.5
    if letters >= 4 and vowels == 0:
        score -= 6.0
    if letters:
        ratio = vowels / letters
        if ratio >= 0.30:
            score += 4.0
        if ratio >= 0.40:
            score += 2.0
    if any(chr(c).isupper() for c in text) and any(chr(c).islower() for c in text):
        score += 2.0
    if len(set(text)) < max(3, len(text) // 2):
        score -= 4.0
    return score

def xor_loop_candidates(data: bytes) -> list[tuple[str, int]]:
    secs = _pe_sections(data)
    if not secs:
        return []
    text = next((s for s in secs if s["name"] == ".text"), None)
    if text is None:
        return []
    mode = text["mode"]
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    code = data[text["raw"] : text["raw"] + text["rs"]]
    insns = list(md.disasm(code, text["base"] + text["va"]))
    if not insns:
        return []
    by_index = {i: ins for i, ins in enumerate(insns)}

    found: dict[str, tuple[int, int]] = {}

    for i, ins in enumerate(insns):
        if ins.mnemonic != "xor" or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if src.type != X86_OP_IMM:
            continue
        key = src.imm & 0xFF
        if key == 0:
            continue
        lo = i
        while lo > 0 and i - lo < 48:
            prev = insns[lo - 1]
            if prev.mnemonic in ("ret", "retn", "call"):
                break
            lo -= 1
        window = insns[lo : i + 5]
        cmp_len = None
        stores = False
        load_mem = None
        lea_targets: dict[int, int] = {}
        for w in window:
            if w.mnemonic == "cmp" and w.operands and w.operands[1].type == X86_OP_IMM:
                imm = w.operands[1].imm
                if 4 <= imm <= 64:
                    cmp_len = imm
            if w.mnemonic == "lea" and w.operands and len(w.operands) == 2 and w.operands[1].type == X86_OP_MEM:
                mem = w.operands[1].mem
                dst_reg = w.operands[0].reg
                if mem.base == X86_REG_INVALID and mem.index == X86_REG_INVALID and mem.disp:
                    lea_targets[dst_reg] = mem.disp
                elif mem.base != X86_REG_INVALID and mem.index == X86_REG_INVALID and mem.disp:
                    lea_targets[dst_reg] = (w.address + w.size + mem.disp) - text["base"]
                elif mem.base != X86_REG_INVALID and mem.index == X86_REG_INVALID and not mem.disp:
                    pass
                elif mem.index == X86_REG_INVALID and mem.base != X86_REG_INVALID and mem.disp == 0 and mem.base:
                    pass
                if mem.base != X86_REG_INVALID and mem.index == X86_REG_INVALID and mem.disp:
                    rip_rva = (w.address + w.size + mem.disp) - text["base"]
                    lea_targets[dst_reg] = rip_rva
            if w.mnemonic in ("mov", "movzx") and w.operands and len(w.operands) == 2:
                o0, o1 = w.operands
                if o1.type == X86_OP_MEM and o0.type == X86_OP_REG:
                    if w.mnemonic == "movzx" or (o0.size == o1.size and o0.size in (1, 2, 4, 8)):
                        load_mem = o1.mem
                if o0.type == X86_OP_MEM and o0.mem.base != X86_REG_INVALID:
                    stores = True
        if cmp_len is None or not stores or load_mem is None:
            continue
        src_va = None
        if load_mem.disp and load_mem.base != X86_REG_INVALID:
            src_va = load_mem.disp
        elif load_mem.base in lea_targets:
            src_va = lea_targets[load_mem.base]
        elif load_mem.index in lea_targets:
            src_va = lea_targets[load_mem.index]
        elif load_mem.disp and load_mem.base == X86_REG_INVALID:
            src_va = load_mem.disp
        if src_va is None:
            continue
        target_rva = src_va - text["base"] if src_va >= text["base"] else src_va
        off = _rva_to_off(secs, target_rva)
        if off is None:
            continue
        blob = data[off : off + cmp_len]
        if len(blob) != cmp_len:
            continue
        decoded = _decode_blob(blob, key)
        try:
            text_out = decoded.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not text_out or not all(32 <= ord(c) < 127 for c in text_out):
            continue
        text_out = text_out.rstrip("\0")
        if len(text_out) < 4:
            continue
        score = _printable_score(text_out.encode())
        if score < 0:
            continue
        prev = found.get(text_out)
        if prev is None or score > prev[1]:
            found[text_out] = (key, score)

    extra: dict[str, tuple[int, int]] = {}
    for text_out, (key, score) in found.items():
        stripped = text_out.strip()
        if stripped != text_out and len(stripped) >= 4:
            s_score = _printable_score(stripped.encode())
            if s_score >= 0:
                extra[stripped] = (key, s_score)
        for part in text_out.replace(":", " ").replace(",", " ").split():
            if len(part) >= 4 and part != text_out:
                p_score = _printable_score(part.encode())
                if p_score >= 0 and (part not in found):
                    extra.setdefault(part, (key, p_score))
    found.update({k: v for k, v in extra.items() if k not in found})

    ranked = sorted(found.items(), key=lambda kv: kv[1][1], reverse=True)
    return [(t, k) for t, (k, _s) in ranked]
