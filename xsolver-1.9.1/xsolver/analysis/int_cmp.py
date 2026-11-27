from __future__ import annotations

import struct

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

_MIN_IMM = 1000
_MAX_IMM = 999_999_999
_MAX_GAP = 16
_BRANCHES = {"je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe",
             "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns"}
_EXACT = {0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC,
          0x80000000, 0x55555555, 0xAAAAAAAA, 0xFFFF8000,
          0x5A4D, 0x4550, 0x1000, 0x2000, 0x3000, 0x4000, 0x5000}

def _pe_layout(data: bytes):
    if data[:2] != b"MZ":
        return None
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e : e + 4] != b"PE\0\0":
        return None
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
        return None
    soff = e + 24 + optsz
    secs = []
    for i in range(nsec):
        o = soff + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, raw = struct.unpack_from("<IIII", data, o + 8)
        secs.append({"name": name, "va": va, "vs": vs, "raw": raw, "rs": rs})
    return image_base, mode, secs

def _plausible(imm: int, image_base: int) -> bool:
    if imm < _MIN_IMM or imm > _MAX_IMM:
        return False
    if imm in _EXACT:
        return False
    if 0xC0000000 <= imm <= 0xCFFFFFFF:
        return False
    if image_base <= imm < image_base + 0x200000:
        return False
    if imm & 0xFFF == 0 and imm <= 0x100000:
        return False
    return True

def int_cmp_candidates(path) -> list[str]:
    data = path.read_bytes() if hasattr(path, "read_bytes") else open(path, "rb").read()
    layout = _pe_layout(data)
    if layout is None:
        return []
    image_base, mode, secs = layout
    text = next((s for s in secs if s["name"] == ".text"), None)
    if text is None:
        return []
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    insns = list(md.disasm(
        data[text["raw"] : text["raw"] + text["rs"]], image_base + text["va"]
    ))
    if not insns:
        return []

    found: list[str] = []
    seen: set[str] = set()
    last_call_idx = -1

    for i, ins in enumerate(insns):
        if ins.mnemonic == "call":
            last_call_idx = i
            continue
        if ins.mnemonic != "cmp" or not ins.operands or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if src.type != X86_OP_IMM or dst.type != X86_OP_REG:
            continue
        imm = src.imm
        if imm < 0:
            width = 64 if mode == CS_MODE_64 else 32
            imm = imm & ((1 << width) - 1)
        if not _plausible(imm, image_base):
            continue
        gap = i - last_call_idx
        if not (0 <= gap <= _MAX_GAP):
            continue
        has_branch = any(
            insns[j].mnemonic in _BRANCHES
            for j in range(i + 1, min(i + 4, len(insns)))
        )
        if not has_branch:
            continue
        text_val = str(imm)
        if text_val not in seen:
            seen.add(text_val)
            found.append(text_val)
    found.sort(key=lambda s: (len(s), s))
    return found
