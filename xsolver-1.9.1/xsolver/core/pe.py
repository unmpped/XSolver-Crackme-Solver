from __future__ import annotations

import struct
from dataclasses import dataclass, field

class NotPeError(Exception):
    pass

@dataclass
class PeSection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int

@dataclass
class PeInfo:
    is_64: bool
    machine: str
    entry_point: int
    subsystem: int
    sections: list[PeSection] = field(default_factory=list)
    is_dll: bool = False

_MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

def parse_pe(data: bytes) -> PeInfo:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise NotPeError("Missing MZ magic bytes")

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error as exc:
        raise NotPeError(f"Truncated DOS header: {exc}") from exc
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise NotPeError("Missing PE signature")

    coff_off = e_lfanew + 4
    try:
        machine, num_sections, _timestamp, _symtab, _numsyms, opt_hdr_size, characteristics = \
            struct.unpack_from("<HHIIIHH", data, coff_off)
    except struct.error as exc:
        raise NotPeError(f"Truncated COFF header: {exc}") from exc

    is_dll = bool(characteristics & 0x2000)

    opt_off = coff_off + 20
    try:
        magic = struct.unpack_from("<H", data, opt_off)[0]
    except struct.error as exc:
        raise NotPeError(f"Truncated optional header: {exc}") from exc
    is_64 = magic == 0x20B

    if opt_off + 70 > len(data):
        raise NotPeError("optional header outside file")
    entry_point = struct.unpack_from("<I", data, opt_off + 16)[0]
    subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]

    section_table_off = opt_off + opt_hdr_size
    sections: list[PeSection] = []
    for i in range(num_sections):
        off = section_table_off + i * 40
        if off + 40 > len(data):
            break
        raw = data[off:off + 40]
        name_bytes = raw[0:8]
        name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", raw, 8)
        characteristics_s = struct.unpack_from("<I", raw, 36)[0]
        sections.append(PeSection(name, virtual_address, virtual_size, raw_size, raw_offset, characteristics_s))

    return PeInfo(
        is_64=is_64,
        machine=_MACHINE_NAMES.get(machine, f"unknown(0x{machine:x})"),
        entry_point=entry_point,
        subsystem=subsystem,
        sections=sections,
        is_dll=is_dll,
    )

def _rva_to_offset(info: PeInfo, rva: int) -> int | None:
    for section in info.sections:
        start = section.virtual_address
        size = max(section.virtual_size, section.raw_size)
        if start <= rva < start + size:
            delta = rva - start
            if delta >= section.raw_size:
                return None
            return section.raw_offset + delta
    return None

def imported_modules(data: bytes) -> list[str]:
    try:
        info = parse_pe(data)
    except NotPeError:
        return []
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        opt_off = e_lfanew + 4 + 20
        magic = struct.unpack_from("<H", data, opt_off)[0]
        dir_off = opt_off + (112 if magic == 0x20B else 96)
        import_rva, import_size = struct.unpack_from("<II", data, dir_off + 8)
    except struct.error:
        return []
    if not import_rva or not import_size:
        return []

    modules: list[str] = []
    cursor = _rva_to_offset(info, import_rva)
    if cursor is None:
        return []
    for _ in range(256):
        if cursor + 20 > len(data):
            break
        name_rva = struct.unpack_from("<I", data, cursor + 12)[0]
        if name_rva == 0:
            break
        offset = _rva_to_offset(info, name_rva)
        if offset is None:
            break
        end = data.find(b"\x00", offset, offset + 128)
        if end == -1:
            break
        name = data[offset:end].decode("latin-1", "replace")
        if name:
            modules.append(name)
        cursor += 20
    return modules
