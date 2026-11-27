from __future__ import annotations

import re

from xsolver.core.binary import BinaryProfile

_LEA_RIP = re.compile(r"^(\w+), \[rip ([+-]) (0x[0-9a-f]+)\]$")
_IMM = re.compile(r"^\w+, (0x[0-9a-f]+)$")
_MIN = 4
_MAX = 64
_WINDOW = 40
_AFFINE_WINDOW = 30
_AFFINE_SIZE_MIN = 8
_AFFINE_SIZE_MAX = 128
_BYTE_REG_RE = re.compile(
    r"^(al|bl|cl|dl|ah|bh|ch|dh|sil|dil|bpl|spl|r[0-9]+b),\s*(0x[0-9a-f]+|\d+)$"
)
_IMM_ANY_RE = re.compile(r"^\w+,\s*(0x[0-9a-f]+|-?\d+)$")
_HEX_RE = re.compile(r"0x[0-9a-f]+")
_BRACKET_CLEAN_RE = re.compile(r"0x[0-9a-f]+|\*\d+|\b\d+\b")
_BRACKET_TAIL_RE = re.compile(r"0x[0-9a-f]+|\b\d+\b")
_REG_RE = re.compile(r"[a-z][a-z0-9]+")
_RIP_TYPED_RE = re.compile(
    r"^(\w+), (?:byte|word|dword|qword|xmmword) ptr \[rip ([+-]) (0x[0-9a-f]+)\]$"
)
_XORB_IMM_RE = re.compile(r"^byte ptr \[[^\]]+\], (0x[0-9a-f]+|\d+)$")
_CALL_ABS_RE = re.compile(r"^(0x[0-9a-f]+)$")
_STACK_LEA_RE = re.compile(r"^\w+, \[(?:rbp|ebp) [-+] ")
_RIP_ANCHOR_MNEMS = {"mov", "movups", "movdqu", "movdqa", "movzx", "movzbl", "movzwl", "lea"}
_DECODE_WINDOW = 120
_MAX_NUL_READ = 64
_ABS_MEM_RE = re.compile(r"^\w+, (?:byte|word|dword|qword|xmmword) ptr \[(0x[0-9a-f]+)\]$")
_STACK_XMM_STORE_RE = re.compile(
    r"^(?:xmmword|dword) ptr \[(?:rbp|ebp) ([-+]) (0x[0-9a-f]+)\], (xmm\d+)$"
)
_IMM_STACK_STORE_RE = re.compile(
    r"^(dword|word|byte) ptr \[(?:rbp|ebp) ([-+]) (0x[0-9a-f]+)\], (0x[0-9a-f]+|\d+)$"
)
_PUSH_ABS_RE = re.compile(r"^(0x[0-9a-f]+)$")
_FORMAT_PREFIXES = (b"flag{", b"cmo{", b"ctf{")
_WIDTHS = {"dword": 4, "word": 2, "byte": 1}
_ABS_BASES = (0x400000, 0x10000000, 0x140000000, 0x1000000)

def _rip_delta(op_str: str) -> tuple[str, int] | None:
    match = _RIP_TYPED_RE.match(op_str) or _LEA_RIP.match(op_str)
    if not match:
        return None
    delta = int(match.group(3), 16)
    sign = match.group(2)
    return match.group(1), delta if sign == "+" else -delta

def _nul_string(space, address: int) -> bytes | None:
    data = space.read(address, _MAX_NUL_READ)
    if not data:
        return None
    end = data.find(b"\x00")
    if end < 0:
        end = len(data)
    data = data[:end]
    if not 3 <= len(data) <= _MAX_NUL_READ:
        return None
    return data

def _printable_text(raw: bytes) -> str | None:
    if not all(0x20 <= byte < 0x7F for byte in raw):
        return None
    text = raw.decode("latin-1")
    if len(set(text)) < 3:
        return None
    return text

def _multi_stack_reads(instructions) -> bool:
    counts: dict[str, int] = {}
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "call":
            continue
        target = _CALL_ABS_RE.match(insn.op_str)
        if not target:
            continue
        prior = instructions[max(0, index - 4):index]
        if not any(step.mnemonic == "lea" and _STACK_LEA_RE.match(step.op_str) for step in prior):
            continue
        counts[target.group(1)] = counts.get(target.group(1), 0) + 1
        if counts[target.group(1)] >= 2:
            return True
    return False

def _decoded_pairs(instructions, space, limit: int) -> list[str]:
    if limit <= 0:
        return []
    sizes: set[int] = set()
    for insn in instructions:
        if insn.mnemonic != "cmp":
            continue
        match = _IMM_ANY_RE.match(insn.op_str)
        if not match:
            continue
        try:
            bound = _parse_number(match.group(1))
        except ValueError:
            continue
        if 2 <= bound <= 64:
            sizes.add(bound)
    raw_texts: list[str] = []
    decoded_texts: list[str] = []
    seen: set[str] = set()
    seen_targets: set[int] = set()
    for index, insn in enumerate(instructions):
        if insn.mnemonic not in _RIP_ANCHOR_MNEMS:
            continue
        delta_info = _rip_delta(insn.op_str)
        if delta_info is None:
            continue
        origin = insn.address + insn.size
        window = instructions[max(0, index - _DECODE_WINDOW):index + _DECODE_WINDOW + 1]
        keys: set[int] = set()
        for step in window:
            if step.mnemonic != "xor":
                continue
            key_match = _XORB_IMM_RE.match(step.op_str)
            if key_match:
                keys.add(_parse_number(key_match.group(1)) & 0xFF)
        if not keys:
            continue
        targets: list[int] = [origin + delta_info[1]]
        for step in window:
            if step.mnemonic not in _RIP_ANCHOR_MNEMS:
                continue
            step_info = _rip_delta(step.op_str)
            if step_info is None:
                continue
            step_origin = step.address + step.size
            targets.append(step_origin + step_info[1])
        for target in targets:
            if target in seen_targets:
                continue
            seen_targets.add(target)
            data = _nul_string(space, target)
            if data is None:
                continue
            text = _printable_text(data)
            if text is not None and text not in seen:
                seen.add(text)
                raw_texts.append(text)
            for key in sorted(keys):
                decoded = _printable_text(bytes(byte ^ key for byte in data))
                if decoded is not None and decoded not in seen:
                    seen.add(decoded)
                    decoded_texts.append(decoded)
    pairs: list[str] = []
    if _multi_stack_reads(instructions):
        longs = [text for text in decoded_texts if len(text) >= 8]
        longs += [text for text in raw_texts if len(text) >= 8]
        shorts = [
            text
            for text in raw_texts + decoded_texts
            if 3 <= len(text) <= 12
        ]

        def rank(text: str) -> tuple[int, int]:
            return (0 if len(text) in sizes else 1, len(text))

        longs = sorted(dict.fromkeys(longs), key=rank)
        shorts = sorted(dict.fromkeys(shorts), key=rank)
        for long in longs:
            for short in shorts:
                if long == short:
                    continue
                pair = f"{long} {short}"
                if pair not in seen:
                    seen.add(pair)
                    pairs.append(pair)
                    if len(pairs) >= limit:
                        break
            if len(pairs) >= limit:
                break
    ordered = pairs + decoded_texts + raw_texts
    out: list[str] = []
    for text in ordered:
        if text in out:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out

def _parse_number(token: str) -> int:
    token = token.strip()
    if token.lower().startswith("0x") or token.lower().startswith("-0x"):
        return int(token, 16)
    return int(token)

def _table_bytes(space, table: int, size: int) -> bytes | None:
    data = space.read(table, size)
    if not data or len(data) < size:
        return None
    return data

def _affine_indexed(instructions, space, limit: int) -> list[str]:
    found: list[str] = []
    if limit <= 0:
        return found
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "imul":
            continue
        tokens = [token.strip() for token in insn.op_str.split(",")]
        if len(tokens) < 2:
            continue
        try:
            factor = _parse_number(tokens[-1])
        except ValueError:
            continue
        if not 1 <= factor <= 255:
            continue
        lo = max(0, index - _AFFINE_WINDOW)
        hi = min(len(instructions), index + _AFFINE_WINDOW + 1)
        window = instructions[lo:hi]
        offset = None
        for near in window:
            if near.mnemonic != "add":
                continue
            byte_match = _BYTE_REG_RE.match(near.op_str)
            if not byte_match:
                continue
            try:
                value = _parse_number(byte_match.group(2))
            except ValueError:
                continue
            if 0 <= value <= 255:
                offset = value
                break
        if offset is None:
            continue
        if not any(
            near.mnemonic == "xor" and "ptr [" in near.op_str for near in window
        ):
            continue
        lea_targets: dict[str, int] = {}
        for near in window:
            if near.mnemonic != "lea":
                continue
            lea_match = _LEA_RIP.match(near.op_str)
            if not lea_match:
                continue
            delta = int(lea_match.group(3), 16)
            origin = near.address + near.size
            lea_targets[lea_match.group(1)] = (
                origin + delta if lea_match.group(2) == "+" else origin - delta
            )
        if not lea_targets:
            continue
        sizes: dict[int, int] = {}
        table_disp: int | None = None
        base_regs: list[str] = []
        for near in window:
            if near.mnemonic != "cmp":
                continue
            if "ptr [" in near.op_str:
                if "[" not in near.op_str or "]" not in near.op_str:
                    continue
                bracket = near.op_str.split("[", 1)[1].split("]", 1)[0]
                tails = _BRACKET_TAIL_RE.findall(bracket)
                if not tails:
                    continue
                regs = [
                    reg
                    for reg in _REG_RE.findall(_BRACKET_CLEAN_RE.sub("", bracket))
                    if reg in lea_targets
                ]
                if regs:
                    table_disp = _parse_number(tails[-1])
                    base_regs = regs
                continue
            imm_match = _IMM_ANY_RE.match(near.op_str)
            if not imm_match:
                continue
            try:
                bound = _parse_number(imm_match.group(1))
            except ValueError:
                continue
            if _AFFINE_SIZE_MIN <= bound <= _AFFINE_SIZE_MAX:
                sizes[bound] = sizes.get(bound, 0) + 1
        if table_disp is None or not sizes:
            continue
        ordered = sorted(sizes.items(), key=lambda item: (-item[1], -item[0]))
        for size, _count in ordered:
            for reg in base_regs:
                data = _table_bytes(space, lea_targets[reg] + table_disp, size)
                if data is None:
                    continue
                decoded = bytes(
                    byte ^ ((position * factor + offset) & 0xFF)
                    for position, byte in enumerate(data)
                )
                if not all(0x20 <= byte < 0x7F for byte in decoded):
                    continue
                text = decoded.decode("latin-1")
                if len(set(text)) < 3 or text in found:
                    continue
                found.append(text)
                if len(found) >= limit:
                    return found
    return found

def _read_abs(space, address: int, length: int) -> bytes | None:
    candidates = [address]
    for base in _ABS_BASES:
        if address > base:
            candidates.append(address - base)
    for candidate in candidates:
        data = space.read(candidate, length)
        if data:
            return data
    return None

def _stack_buffer(instructions, index: int, space) -> bytes | None:
    anchor = instructions[index]
    anchor_match = _STACK_XMM_STORE_RE.match(anchor.op_str)
    if not anchor_match:
        return None
    sign, offset, reg = anchor_match.group(1), int(anchor_match.group(2), 16), anchor_match.group(3)
    base_offset = -offset if sign == "-" else offset
    head: bytes | None = None
    for step in instructions[max(0, index - 5):index]:
        if step.mnemonic not in ("movaps", "movups", "movdqu", "movdqa"):
            continue
        if not step.op_str.startswith(f"{reg}, "):
            continue
        source_match = _ABS_MEM_RE.match(step.op_str)
        if source_match:
            head = _read_abs(space, int(source_match.group(1), 16), 16)
        else:
            info = _rip_delta(step.op_str)
            if info is not None:
                head = space.read(step.address + step.size + info[1], 16)
        if head:
            break
    if not head or len(head) < 16:
        return None
    buffer = bytearray(head[:16])
    for step in instructions[index + 1:index + 16]:
        store_match = _IMM_STACK_STORE_RE.match(step.op_str)
        if not store_match:
            break
        width = _WIDTHS[store_match.group(1)]
        store_sign, store_offset = store_match.group(2), int(store_match.group(3), 16)
        store_position = -store_offset if store_sign == "-" else store_offset
        position = store_position - base_offset
        if position != len(buffer) or position + width > 64:
            break
        value_token = store_match.group(4)
        value = int(value_token, 16) if value_token.lower().startswith("0x") else int(value_token)
        buffer += value.to_bytes(width, "little")
    return bytes(buffer)

def _scanf_period(instructions, space) -> tuple[int, bytes] | None:
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "call" or not _CALL_ABS_RE.match(insn.op_str):
            continue
        fmt_address: int | None = None
        for step in instructions[max(0, index - 4):index]:
            if step.mnemonic != "push":
                continue
            push_match = _PUSH_ABS_RE.match(step.op_str)
            if push_match:
                fmt_address = int(push_match.group(1), 16)
        if fmt_address is None:
            continue
        fmt_data = _read_abs(space, fmt_address, 16)
        if not fmt_data or b"%" not in fmt_data:
            continue
        for offset, step in enumerate(instructions[index + 1:index + 7]):
            if step.mnemonic != "cmp":
                continue
            cmp_match = _IMM_ANY_RE.match(step.op_str)
            if not cmp_match:
                break
            try:
                period = _parse_number(cmp_match.group(1))
            except ValueError:
                break
            for tail in instructions[index + offset + 2:index + offset + 4]:
                if tail.mnemonic not in ("jb", "jbe", "jna", "jnae"):
                    continue
                try:
                    target = int(tail.op_str, 16)
                except ValueError:
                    continue
                if target <= insn.address and 1 <= period <= 32:
                    return period, fmt_data
            break
    return None

def _known_prefix(profile: BinaryProfile, instructions, space, limit: int) -> list[str]:
    if limit <= 0:
        return []
    buffers: list[bytes] = []
    for index, insn in enumerate(instructions):
        if insn.mnemonic not in ("movups", "movaps", "movdqu", "movdqa"):
            continue
        if "ptr [rbp -" not in insn.op_str and "ptr [ebp -" not in insn.op_str:
            continue
        data = _stack_buffer(instructions, index, space)
        if data and data not in buffers:
            buffers.append(data)
    if not buffers:
        return []
    period_scan = _scanf_period(instructions, space)
    if period_scan is None:
        return []
    period, fmt_data = period_scan
    raw = profile.raw
    prefixes: list[bytes] = []
    for pattern in _FORMAT_PREFIXES:
        position = raw.find(pattern)
        if position >= 0:
            prefixes.append(pattern)
    out: list[str] = []
    for buffer in buffers:
        if len(buffer) < period or period > 32:
            continue
        for prefix in prefixes:
            if period > len(prefix):
                continue
            key = bytes(buffer[i] ^ prefix[i] for i in range(period))
            decoded = bytes(buffer[i] ^ key[i % period] for i in range(len(buffer)))
            text = decoded.split(b"\x00")[0]
            if not text.startswith(prefix) or not text.rstrip(b"\r\n").endswith(b"}"):
                continue
            if b"d" in fmt_data:
                candidate = " ".join(str(byte) for byte in key)
            elif b"c" in fmt_data and all(0x20 <= byte < 0x7F for byte in key):
                candidate = key.decode("latin-1")
            else:
                continue
            if candidate not in out:
                out.append(candidate)
            if len(out) >= limit:
                return out
    return out

def tables(profile: BinaryProfile, instructions=None, limit: int = 8) -> list[str]:
    from xsolver.analysis import disasm

    instructions = instructions if instructions is not None else disasm.disassemble(profile)
    space = disasm.AddressSpace(disasm._all_sections(profile))
    found: list[str] = []
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "cmp":
            continue
        size_match = _IMM.match(insn.op_str)
        if not size_match:
            continue
        size = int(size_match.group(1), 16)
        if not _MIN <= size <= _MAX:
            continue
        window = instructions[max(0, index - _WINDOW):index + _WINDOW]
        keys: set[int] = set()
        for near in window:
            if near.mnemonic != "xor":
                continue
            value_match = _IMM.match(near.op_str)
            if value_match:
                value = int(value_match.group(1), 16)
                if 0 < value < 256:
                    keys.add(value)
        if not keys:
            continue
        bases: set[int] = set()
        for near in window:
            if near.mnemonic != "lea":
                continue
            lea_match = _LEA_RIP.match(near.op_str)
            if not lea_match:
                continue
            delta = int(lea_match.group(3), 16)
            origin = near.address + near.size
            bases.add(origin + delta if lea_match.group(2) == "+" else origin - delta)
        for base in bases:
            data = _table_bytes(space, base, size)
            if data is None:
                continue
            for key in keys:
                decoded = bytes(byte ^ key for byte in data)
                if not all(0x20 <= byte < 0x7F for byte in decoded):
                    continue
                text = decoded.decode("latin-1")
                if len(set(text)) < 3 or text in found:
                    continue
                found.append(text)
                if len(found) >= limit:
                    return found
    if len(found) < limit:
        found.extend(_affine_indexed(instructions, space, limit - len(found)))
    if len(found) < limit:
        found.extend(_decoded_pairs(instructions, space, limit - len(found)))
    if len(found) < limit:
        found.extend(_known_prefix(profile, instructions, space, limit - len(found)))
    return found
