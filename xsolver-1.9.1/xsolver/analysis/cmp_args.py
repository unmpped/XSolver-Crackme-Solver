from __future__ import annotations

import re
import struct

from xsolver.analysis.disasm import AddressSpace, _all_sections, disassemble
from xsolver.core.binary import BinaryProfile
from xsolver.core.elf import parse_elf
from xsolver.core.pe import parse_pe

_COMPARE_NAMES = {
    "strcmp", "strncmp", "stricmp", "_stricmp", "strcasecmp", "strncasecmp",
    "memcmp", "_memicmp", "memicmp", "lstrcmpa", "lstrcmpw", "comparestringa",
    "wcscmp", "wcsncmp", "_wcsicmp", "strcmpi", "_strcmpi", "memcmp_s",
}

_ARGUMENT_REGISTERS = {
    "win64": ("rcx", "rdx"),
    "win32": (),
    "sysv": ("rdi", "rsi"),
}

_LEA_RIP_RE = re.compile(r"^([a-z][a-z0-9]*),\s*\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]$")
_CALL_IAT_RE = re.compile(r"^qword ptr \[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]$")
_CALL_IAT32_RE = re.compile(r"^(?:dword ptr )?\[(?P<addr>0x[0-9a-fA-F]+|\d+)\]$")
_PUSH_IMM_RE = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")
_PUSH_SYM_RE = re.compile(r"^offset (?P<addr>0x[0-9a-fA-F]+|\d+)$")
_WINDOW = 18
_MAX_STRING = 128

def pe_imports(data: bytes) -> dict[int, str]:
    imports: dict[int, str] = {}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return imports
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return imports
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return imports
    coff = e_lfanew + 4
    try:
        _machine, _num_sections, _ts, _sym, _numsym, opt_size, _chars = \
            struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
    except struct.error:
        return imports
    is_64 = magic == 0x20B
    directory = opt + (112 if is_64 else 96)
    try:
        import_rva = struct.unpack_from("<I", data, directory + 8)[0]
    except struct.error:
        return imports
    if not import_rva:
        return imports

    sections = []
    table = opt + opt_size
    for index in range(_num_sections):
        off = table + index * 40
        if off + 40 > len(data):
            break
        vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
        sections.append((vaddr, max(vsize, raw_size), raw_off, raw_size))

    def offset_of(rva: int) -> int | None:
        for vaddr, size, raw_off, raw_size in sections:
            if vaddr <= rva < vaddr + size:
                delta = rva - vaddr
                if delta >= raw_size:
                    return None
                return raw_off + delta
        return None

    thunk_size = 8 if is_64 else 4
    descriptor = offset_of(import_rva)
    if descriptor is None:
        return imports
    for _ in range(256):
        if descriptor + 20 > len(data):
            break
        original, _ts, _fc, name_rva, first_thunk = struct.unpack_from("<IIIII", data, descriptor)
        if not name_rva and not first_thunk:
            break
        walker = offset_of(original or first_thunk)
        if walker is not None:
            for index in range(4096):
                entry_off = walker + index * thunk_size
                if entry_off + thunk_size > len(data):
                    break
                value = struct.unpack_from("<Q" if is_64 else "<I", data, entry_off)[0]
                if value == 0:
                    break
                if value & (1 << (63 if is_64 else 31)):
                    continue
                name_off = offset_of(value & 0x7FFFFFFF)
                if name_off is None or name_off + 2 > len(data):
                    continue
                end = data.find(b"\x00", name_off + 2, name_off + 2 + 128)
                if end < 0:
                    continue
                name = data[name_off + 2:end].decode("latin-1", "replace")
                imports[first_thunk + index * thunk_size] = name
        descriptor += 20
    return imports

def elf_plt_names(profile: BinaryProfile) -> dict[int, str]:
    data = profile.raw
    names: dict[int, str] = {}
    if not data or data[:4] != b"\x7fELF":
        return names
    is_64 = len(data) > 4 and data[4] == 2
    try:
        info = parse_elf(data)
    except Exception:
        return names

    sections = {section.name: section for section in info.sections}
    dynstr = sections.get(".dynstr")
    rela = sections.get(".rela.plt") or sections.get(".rela.dyn")
    rel = sections.get(".rel.plt") or sections.get(".rel.dyn")
    if dynstr is None or (rela is None and rel is None):
        return names

    def symbol_name(offset_in_dynstr: int) -> str | None:
        start = dynstr.offset + offset_in_dynstr
        if start >= len(data):
            return None
        end = data.find(b"\x00", start, start + 256)
        if end < 0:
            return None
        return data[start:end].decode("latin-1", "replace")

    dynsym = sections.get(".dynsym")
    slot_to_name: dict[int, str] = {}
    entries = rela if rela is not None else rel
    entry_size = 24 if rela is not None else 16
    count = entries.size // entry_size
    for index in range(count):
        offset = entries.offset + index * entry_size
        try:
            if rela is not None:
                r_offset, r_info = struct.unpack_from("<QQ", data, offset)
                symbol_index = r_info >> 32
            else:
                r_offset, r_info = struct.unpack_from("<II", data, offset)
                symbol_index = r_info >> 8
        except struct.error:
            continue
        if dynsym is None:
            continue
        symbol_offset = dynsym.offset + symbol_index * (24 if is_64 else 16)
        try:
            st_name = struct.unpack_from("<I", data, symbol_offset)[0]
        except struct.error:
            continue
        name = symbol_name(st_name)
        if name:
            slot_to_name[r_offset] = name.lower()

    if not slot_to_name:
        return names

    for section in info.sections:
        if not (section.flags & 0x4):
            continue
        if section.name not in (".plt", ".plt.sec", ".plt.got", ".iplt"):
            continue
        base = section.addr
        start = section.offset
        stop = start + section.size
        position = start
        while position + 6 <= stop and position + 6 <= len(data):
            if data[position] == 0xFF and data[position + 1] == 0x25:
                delta = struct.unpack_from("<i", data, position + 2)[0]
                stub_address = base + (position - start)
                slot = stub_address + 6 + delta
                name = slot_to_name.get(slot)
                if name:
                    names[stub_address] = name
                position += 16
            else:
                position += 16
    return names

def _string_at(space: AddressSpace, address: int, limit: int = _MAX_STRING) -> bytes | None:
    raw = space.read(address, limit)
    if not raw:
        return None
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    if len(raw) < 3:
        return None
    if not all(0x20 <= byte <= 0x7E for byte in raw):
        return None
    if len(set(raw)) < 3:
        return None
    return raw

_MEM_STORE_RE = re.compile(
    r"^(?:(byte|word|dword|qword) ptr )?\[(rbp|ebp)\s*-\s*(0x[0-9a-fA-F]+|\d+)\],\s*(-?0x[0-9a-fA-F]+|-?\d+)$"
)
_POINTER_LOAD_RE = re.compile(
    r"^([a-z][a-z0-9]*),\s*qword ptr \[rip \+ (0x[0-9a-fA-F]+|\d+)\]$"
)
_LEA_ABS_RE = re.compile(r"^([a-z][a-z0-9]*),\s*\[(?P<addr>0x[0-9a-fA-F]+|\d+)\]$")
_MEM_LEA_RE = re.compile(r"^([a-z][a-z0-9]*),\s*\[(rbp|ebp)\s*-\s*(0x[0-9a-fA-F]+|\d+)\]$")
_REG_MOV_RE = re.compile(r"^([a-z][a-z0-9]*),\s*([a-z][a-z0-9]*)$")
_IMM_TO_REG_RE = re.compile(r"^([a-z][a-z0-9]*),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_WIDTH = {"byte": 1, "word": 2, "dword": 4, "qword": 8}

_MEM_REG_STORE_RE = re.compile(
    r"^(?:(byte|word|dword|qword) ptr )?\[(rbp|ebp)\s*-\s*(0x[0-9a-fA-F]+|\d+)\],\s*([a-z][a-z0-9]*)$"
)

def _stack_string(instructions, index: int, offset: int, limit: int = 128) -> bytes | None:
    buffer = bytearray(limit)
    pending: dict[str, tuple[bytes, int]] = {}
    seen = False

    window = []
    for back in range(1, 200):
        position = index - back
        if position < 0:
            break
        insn = instructions[position]
        if insn.mnemonic in ("ret", "leave") or (
            insn.mnemonic == "mov" and insn.op_str.replace(" ", "") in ("rbp,rsp", "ebp,esp")
        ):
            break
        window.append(insn)
    window.reverse()

    for insn in window:
        if insn.mnemonic not in ("mov", "movabs"):
            continue

        imm_reg = _IMM_TO_REG_RE.match(insn.op_str)
        if imm_reg:
            width = 8 if insn.mnemonic == "movabs" else 4
            value = int(imm_reg.group(2), 0) & ((1 << (8 * width)) - 1)
            pending[imm_reg.group(1)] = (value.to_bytes(width, "little"), width)
            continue

        match = _MEM_STORE_RE.match(insn.op_str)
        if match:
            width = _WIDTH.get(match.group(1) or "", 8 if insn.mnemonic == "movabs" else None)
            if width is None:
                continue
            target = int(match.group(3), 0)
            value = int(match.group(4), 0) & ((1 << (8 * width)) - 1)
            if _place(buffer, offset, target, value.to_bytes(width, "little"), limit):
                seen = True
            continue

        reg_store = _MEM_REG_STORE_RE.match(insn.op_str)
        if reg_store and reg_store.group(4) in pending:
            target = int(reg_store.group(3), 0)
            raw, width = pending[reg_store.group(4)]
            named = _WIDTH.get(reg_store.group(1) or "", width)
            if _place(buffer, offset, target, raw[:named], limit):
                seen = True

    if not seen:
        return None
    raw = bytes(buffer).split(b"\x00", 1)[0]
    if len(raw) < 3 or not all(0x20 <= byte <= 0x7E for byte in raw):
        return None
    if len(set(raw)) < 3:
        return None
    return raw

def _place(buffer: bytearray, base: int, target: int, data: bytes, limit: int) -> bool:
    delta = base - target
    if delta < 0 or delta + len(data) > limit:
        return False
    buffer[delta:delta + len(data)] = data
    return True

def _image_base(profile: BinaryProfile) -> int:
    raw = profile.raw
    try:
        offset = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[offset:offset + 4] != b"PE\x00\x00":
            return 0
        optional = offset + 24
        magic = struct.unpack_from("<H", raw, optional)[0]
        if magic == 0x20B:
            return struct.unpack_from("<Q", raw, optional + 24)[0]
        if magic == 0x10B:
            return struct.unpack_from("<I", raw, optional + 28)[0]
    except (struct.error, IndexError):
        return 0
    return 0

def elf_relative_pointers(profile: BinaryProfile) -> dict[int, int]:
    pointers: dict[int, int] = {}
    try:
        info = parse_elf(profile.raw)
    except Exception:
        return pointers
    raw = profile.raw
    for section in info.sections:
        if section.name not in (".rela.dyn", ".rel.dyn"):
            continue
        entry_size = 24 if section.name.endswith("rela.dyn") else 16
        with_addend = section.name.endswith("rela.dyn")
        for offset in range(0, section.size - entry_size + 1, entry_size):
            start = section.offset + offset
            chunk = raw[start:start + entry_size]
            if len(chunk) < entry_size:
                break
            slot = int.from_bytes(chunk[0:8], "little")
            info_word = int.from_bytes(chunk[8:16], "little")
            relocation_type = info_word & 0xFFFFFFFF
            addend = int.from_bytes(chunk[16:24], "little", signed=True) if with_addend else 0
            if relocation_type == 8 and addend > 0:
                pointers[slot] = addend
    return pointers

def _pointer_target(space: AddressSpace, pointers: dict[int, int], slot: int,
                    image_base: int = 0) -> int | None:
    if slot in pointers:
        return pointers[slot]
    raw = space.read(slot, 8)
    if not raw or len(raw) < 8:
        return None
    value = int.from_bytes(raw, "little")
    if value == 0:
        return None
    if image_base and space.read(value, 1) is None and space.read(value - image_base, 1):
        return value - image_base
    return value

def _stack_pushed_addresses(instructions, index: int, space: AddressSpace,
                            image_base: int = 0, limit: int = 2) -> list[bytes]:
    found: list[bytes] = []
    staged: dict[str, int] = {}
    for back in range(1, _WINDOW + 1):
        position = index - back
        if position < 0:
            break
        insn = instructions[position]
        if insn.mnemonic in ("call", "ret", "retn"):
            break
        if insn.mnemonic == "mov":
            match = _IMM_TO_REG_RE.match(insn.op_str)
            if match:
                staged[match.group(1)] = int(match.group(2), 0)
            continue
        if insn.mnemonic == "lea":
            match = _LEA_ABS_RE.match(insn.op_str)
            if match:
                staged[match.group(1)] = int(match.group(2), 0)
            continue
        if insn.mnemonic != "push":
            continue
        operand = insn.op_str.strip()
        address = None
        imm = _PUSH_IMM_RE.match(operand)
        sym = _PUSH_SYM_RE.match(operand)
        if imm:
            address = int(imm.group(1), 0)
        elif sym:
            address = int(sym.group("addr"), 0)
        elif operand in staged:
            address = staged[operand]
        if address is None:
            continue
        for candidate in (address, address - image_base):
            if candidate <= 0:
                continue
            text = _string_at(space, candidate)
            if text and len(text) >= 2:
                if text not in found:
                    found.append(text)
                break
        if len(found) >= limit:
            break
    return found

_PRINTABLE_BYTES = bytes(range(0x20, 0x7F))

def _printable(text: bytes, minimum: float = 0.85) -> bool:
    if len(text) < 4:
        return False
    good = sum(1 for byte in text if byte in _PRINTABLE_BYTES)
    return good / len(text) >= minimum

def _text_word(chunk: bytes) -> bool:
    return all(byte in _PRINTABLE_BYTES for byte in chunk.rstrip(b"\x00")) and chunk[0] != 0

def _stack_literals(instructions, index: int, window: int = 24) -> list[str]:
    words: list[int] = []
    for back in range(1, window + 1):
        position = index - back
        if position < 0:
            break
        insn = instructions[position]
        if insn.mnemonic in ("call", "ret", "retn"):
            break

        if insn.mnemonic != "push":
            if not words:
                continue
            if insn.mnemonic in ("mov", "lea") and "esp" in insn.op_str:
                continue
            break

        operand = insn.op_str.strip()
        match = _PUSH_IMM_RE.match(operand)
        if not match:
            if words:
                break
            continue
        value = int(match.group(1), 0) & 0xFFFFFFFF
        chunk = value.to_bytes(4, "little")
        if not words:
            if all(byte in _PRINTABLE_BYTES for byte in chunk):
                words.append(value)
            continue
        if chunk == b"\x00\x00\x00\x00" or _text_word(chunk):
            words.append(value)
            continue
        break

    if not words:
        return []
    blob = b"".join(word.to_bytes(4, "little") for word in words)
    end = blob.find(b"\x00")
    if end >= 0:
        blob = blob[:end]
    if not _printable(blob):
        return []
    return [blob.decode("latin-1")]

def _stack_arguments(instructions, index: int, space: AddressSpace,
                     image_base: int = 0, limit: int = 3) -> list[bytes]:
    found = _stack_pushed_addresses(instructions, index, space, image_base,
                                    limit=limit)
    for text in _stack_literals(instructions, index):
        raw = text.encode("latin-1", "replace")
        if raw not in found:
            found.append(raw)
    return found[:limit]

def _argument_strings(instructions, index: int, space: AddressSpace,
                      registers: tuple[str, str],
                      pointers: dict[int, int] | None = None,
                      image_base: int = 0) -> list[bytes]:
    found: list[bytes] = []
    values: dict[str, bytes | tuple[str, int]] = {}

    for back in range(1, _WINDOW + 1):
        position = index - back
        if position < 0:
            break
        insn = instructions[position]
        if insn.mnemonic == "call":
            break

        if insn.mnemonic == "lea":
            reg_match = _LEA_RIP_RE.match(insn.op_str)
            if reg_match:
                delta = int(reg_match.group(3), 0)
                target = insn.address + insn.size + (delta if reg_match.group(2) == "+" else -delta)
                if reg_match.group(1) not in values:
                    text = _string_at(space, target)
                    values[reg_match.group(1)] = text if text else b""
                continue
            stack_match = _MEM_LEA_RE.match(insn.op_str)
            if stack_match and stack_match.group(1) not in values:
                values[stack_match.group(1)] = ("stack", int(stack_match.group(3), 0))
            continue

        if insn.mnemonic in ("mov", "movabs"):
            pointer_match = _POINTER_LOAD_RE.match(insn.op_str)
            if pointer_match:
                delta = int(pointer_match.group(2), 0)
                slot = insn.address + insn.size + delta
                if pointer_match.group(1) not in values:
                    target = _pointer_target(space, pointers or {}, slot, image_base)
                    text = _string_at(space, target) if target else None
                    values[pointer_match.group(1)] = text if text else b""
                continue
            reg_match = _REG_MOV_RE.match(insn.op_str)
            if reg_match and reg_match.group(1) not in values:
                values[reg_match.group(1)] = values.get(
                    reg_match.group(2), ("reg", reg_match.group(2))
                )
                continue
            imm_match = _IMM_TO_REG_RE.match(insn.op_str)
            if imm_match and imm_match.group(1) not in values:
                value = int(imm_match.group(2), 0)
                text = _string_at(space, value) if value > 0x1000 else None
                values[imm_match.group(1)] = text if text else b""
            continue

    for register in registers:
        value = values.get(register)
        for _ in range(8):
            if isinstance(value, tuple) and value[0] == "reg":
                value = values.get(value[1], b"")
            else:
                break
        if isinstance(value, bytes) and value:
            found.append(value)
        elif isinstance(value, tuple) and value[0] == "stack":
            text = _stack_string(instructions, index, value[1])
            if text:
                found.append(text)
    return found

def _resolve_thunk(imports: dict[int, str], instructions, target: int,
                   image_base: int = 0, by_addr: dict | None = None) -> str | None:
    if by_addr is not None:
        insn = by_addr.get(target)
        candidates = [insn] if insn is not None else []
    else:
        candidates = [item for item in instructions if item.address == target]
    for insn in candidates:
        if insn.mnemonic not in ("jmp", "call"):
            return None
        direct = insn.op_str.strip()
        match = _CALL_IAT_RE.match(direct)
        if match:
            delta = int(match.group(2), 0)
            slot = insn.address + insn.size + (delta if match.group(1) == "+" else -delta)
            return imports.get(slot)
        flat = _CALL_IAT32_RE.match(direct)
        if flat:
            slot = int(flat.group("addr"), 0)
            return imports.get(slot) or (imports.get(slot - image_base) if image_base else None)
        return None
    return None

def comparison_argument_strings(profile: BinaryProfile, max_candidates: int = 8) -> list[str]:
    instructions = disassemble(profile)
    if not instructions:
        return []

    imports: dict[int, str] = {}
    if profile.format.startswith("PE"):
        imports = {va: name.lower() for va, name in pe_imports(profile.raw).items()}
    else:
        imports = {va: name.lower() for va, name in elf_plt_names(profile).items()}

    space = AddressSpace(_all_sections(profile))
    pointers = {} if profile.format.startswith("PE") else elf_relative_pointers(profile)
    image_base = _image_base(profile) if profile.format.startswith("PE") else 0
    is_64 = "64" in profile.arch
    if profile.format.startswith("PE"):
        registers = _ARGUMENT_REGISTERS["win64" if is_64 else "win32"]
    else:
        registers = _ARGUMENT_REGISTERS["sysv"]

    by_addr = {insn.address: insn for insn in instructions}

    candidates: list[str] = []
    seen: set[str] = set()
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "call":
            continue
        target = None
        direct = insn.op_str.strip()
        if direct.startswith("0x"):
            try:
                target = int(direct, 16)
            except ValueError:
                target = None
        else:
            match = _CALL_IAT_RE.match(direct)
            if match:
                delta = int(match.group(2), 0)
                slot = insn.address + insn.size + (delta if match.group(1) == "+" else -delta)
                target = slot
            else:
                flat = _CALL_IAT32_RE.match(direct)
                if flat:
                    slot = int(flat.group("addr"), 0)
                    target = slot - image_base if image_base and slot > image_base else slot
        if target is None:
            continue
        name = imports.get(target)
        if name is None:
            name = _resolve_thunk(imports, instructions, target, image_base, by_addr)
        if name is None or name not in _COMPARE_NAMES:
            continue

        if registers:
            raws = _argument_strings(instructions, index, space, registers, pointers, image_base)
        else:
            raws = _stack_arguments(instructions, index, space, image_base)
        for raw in raws:
            text = raw.decode("latin-1")
            if text in seen:
                continue
            seen.add(text)
            candidates.append(text)
            if len(candidates) >= max_candidates:
                return candidates
    return candidates
