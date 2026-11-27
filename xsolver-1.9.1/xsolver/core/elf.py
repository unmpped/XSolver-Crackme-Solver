from __future__ import annotations

import struct
from dataclasses import dataclass, field

class NotElfError(Exception):
    pass

@dataclass
class ElfSection:
    name: str
    sh_type: int
    addr: int
    offset: int
    size: int
    flags: int

@dataclass
class ElfInfo:
    is_64: bool
    is_little_endian: bool
    machine: str
    entry_point: int
    e_type: str
    sections: list[ElfSection] = field(default_factory=list)
    interpreter: str | None = None

    @property
    def arch_label(self) -> str:
        bits = "64-bit" if self.is_64 else "32-bit"
        return f"{self.machine} {bits}"

_MACHINE_NAMES = {
    0x03: "x86",
    0x3E: "x86-64",
    0x28: "ARM",
    0xB7: "AArch64",
    0x08: "MIPS",
    0xF3: "RISC-V",
}

_ETYPE_NAMES = {
    1: "relocatable",
    2: "executable",
    3: "shared/PIE",
    4: "core",
}

def _unpack_main_header(data: bytes, endian: str, is_64: bool):
    if is_64:
        return struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
    return struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)

def parse_elf(data: bytes) -> ElfInfo:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise NotElfError("Missing ELF magic bytes")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise NotElfError(f"Invalid ELF class {ei_class}")
    if ei_data not in (1, 2):
        raise NotElfError(f"Invalid ELF data encoding {ei_data}")

    is_64 = ei_class == 2
    is_little = ei_data == 1
    endian = "<" if is_little else ">"

    try:
        (e_type, e_machine, _e_version, e_entry, e_phoff, e_shoff, _e_flags,
         _e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            _unpack_main_header(data, endian, is_64)
    except struct.error as exc:
        raise NotElfError(f"Truncated ELF header: {exc}") from exc

    sections: list[ElfSection] = []
    if e_shoff and e_shnum and e_shstrndx != 0 and e_shstrndx < e_shnum:
        if e_shentsize <= 0 or e_shoff > len(data):
            raise NotElfError("section table outside file")
        raw_sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off < 0 or off + e_shentsize > len(data):
                raise NotElfError(f"Section header {i} lies outside the file")
            try:
                if is_64:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, \
                        sh_link, sh_info, sh_addralign, sh_entsize = \
                        struct.unpack_from(endian + "IIQQQQIIQQ", data, off)
                else:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, \
                        sh_link, sh_info, sh_addralign, sh_entsize = \
                        struct.unpack_from(endian + "IIIIIIIIII", data, off)
            except struct.error as exc:
                raise NotElfError(f"Malformed section header {i}: {exc}") from exc
            raw_sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size))

        strtab_off = raw_sections[e_shstrndx][4]
        strtab_size = raw_sections[e_shstrndx][5]
        if strtab_off > len(data):
            raise NotElfError("name table outside file")
        strtab_size = min(strtab_size, len(data) - strtab_off)
        strtab = data[strtab_off:strtab_off + strtab_size]

        for sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size in raw_sections:
            end = strtab.find(b"\x00", sh_name)
            name = strtab[sh_name:end].decode("utf-8", "replace") if end != -1 else ""
            sections.append(ElfSection(name, sh_type, sh_addr, sh_offset, sh_size, sh_flags))

    interpreter = None
    if e_phoff and e_phnum:
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off < 0 or off + e_phentsize > len(data):
                raise NotElfError(f"Program header {i} lies outside the file")
            try:
                if is_64:
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                        struct.unpack_from(endian + "IIQQQQQQ", data, off)
                else:
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                        struct.unpack_from(endian + "IIIIIIII", data, off)
            except struct.error as exc:
                raise NotElfError(f"Malformed program header {i}: {exc}") from exc
            if p_type == 3:
                raw = data[p_offset:p_offset + p_filesz]
                nul = raw.find(b"\x00")
                interpreter = raw[:nul].decode("utf-8", "replace") if nul != -1 else raw.decode("utf-8", "replace")

    return ElfInfo(
        is_64=is_64,
        is_little_endian=is_little,
        machine=_MACHINE_NAMES.get(e_machine, f"unknown(0x{e_machine:x})"),
        entry_point=e_entry,
        e_type=_ETYPE_NAMES.get(e_type, f"unknown({e_type})"),
        sections=sections,
        interpreter=interpreter,
    )

@dataclass
class ElfSymbol:
    name: str
    value: int
    size: int
    is_function: bool

def parse_elf_symbols(data: bytes) -> list[ElfSymbol]:
    info = parse_elf(data)
    is_64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    symbols: list[ElfSymbol] = []

    for symtab_name in (".symtab", ".dynsym"):
        symtab = next((s for s in info.sections if s.name == symtab_name), None)
        if symtab is None:
            continue
        strtab_name = ".strtab" if symtab_name == ".symtab" else ".dynstr"
        strtab_section = next((s for s in info.sections if s.name == strtab_name), None)
        if strtab_section is None:
            continue
        strtab = data[strtab_section.offset:strtab_section.offset + strtab_section.size]

        entry_size = 24 if is_64 else 16
        count = symtab.size // entry_size
        for i in range(count):
            off = symtab.offset + i * entry_size
            if is_64:
                st_name, st_info, _st_other, _st_shndx, st_value, st_size = \
                    struct.unpack_from(endian + "IBBHQQ", data, off)
            else:
                st_name, st_value, st_size, st_info, _st_other, _st_shndx = \
                    struct.unpack_from(endian + "IIIBBH", data, off)
            end = strtab.find(b"\x00", st_name)
            name = strtab[st_name:end].decode("utf-8", "replace") if end != -1 else ""
            symbol_type = st_info & 0xF
            if name and st_value:
                symbols.append(ElfSymbol(name=name, value=st_value, size=st_size, is_function=symbol_type == 2))
        if symbols:
            break

    return symbols
