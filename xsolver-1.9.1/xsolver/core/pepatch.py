from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

SECTION_NAME = b".adbg"
SECTION_CHARACTERISTICS = 0xE0000040
_COUNTER_SLOT = 0x10

_STUBS_32 = {
    "flag": bytes.fromhex("31c0c3"),
    "flag_out": bytes.fromhex("8b442408c70000000000b801000000c20800"),
    "ntstatus": bytes.fromhex("8b44240cc7000000000031d231c0c21400"),
    "ntstatus_nobuf": bytes.fromhex("31c0c21400"),
    "void1": bytes.fromhex("c20400"),
    "void0": bytes.fromhex("c3"),
    "zero1": bytes.fromhex("31c0c20400"),
    "zero2": bytes.fromhex("31c0c20800"),
    "qpc": bytes.fromhex("8b442404c70001000000c7400400000000b801000000c20400"),
    "qpf": bytes.fromhex("8b442404c700e8030000c7400400000000b801000000c20400"),
}

_STUBS_64 = {
    "flag": bytes.fromhex("31c0c3"),
    "flag_out": bytes.fromhex("c70200000000b801000000c3"),
    "ntstatus": bytes.fromhex("41c7000000000031c0c3"),
    "ntstatus_nobuf": bytes.fromhex("31c0c3"),
    "void1": bytes.fromhex("c3"),
    "void0": bytes.fromhex("c3"),
    "zero1": bytes.fromhex("31c0c3"),
    "zero2": bytes.fromhex("31c0c3"),
    "qpc": bytes.fromhex("c70101000000c7410400000000b801000000c3"),
    "qpf": bytes.fromhex("c701e8030000c7410400000000b801000000c3"),
}

_KIND_BY_API = {
    "isdebuggerpresent": "flag",
    "checkremotedebuggerpresent": "flag_out",
    "ntqueryinformationprocess": "ntstatus",
    "ntsetinformationthread": "ntstatus_nobuf",
    "ntquerysysteminformation": "ntstatus_nobuf",
    "ntyieldexecution": "flag",
    "outputdebugstringa": "void1",
    "outputdebugstringw": "void1",
    "debugbreak": "void0",
    "getthreadcontext": "zero2",
    "isprocessorfeaturepresent": "zero1",
    "gettickcount": "tick",
    "gettickcount64": "tick64",
    "timegettime": "tick",
    "queryperformancecounter": "qpc",
    "queryperformancefrequency": "qpf",
}

_TIMER_KINDS = {"tick", "tick64"}

@dataclass
class PatchResult:
    source: Path
    destination: Path | None
    patched: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    section_address: int = 0
    stub_addresses: dict[str, int] = field(default_factory=dict)
    code_references: int = 0
    rdtsc_sites: int = 0
    peb_stub: bool = False
    peb_entry_rva: int = 0
    arch: str = "x86"
    error: str | None = None

    @property
    def applied(self) -> bool:
        return bool(self.patched) and self.destination is not None

def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) // alignment * alignment

def _timer_stub_32(counter_address: int, wide: bool) -> bytes:
    body = bytearray()
    body += b"\xA1" + counter_address.to_bytes(4, "little")
    body += b"\xFF\x05" + counter_address.to_bytes(4, "little")
    if wide:
        body += b"\x31\xD2"
    body += b"\xC3"
    return bytes(body)

def _timer_stub_64(stub_address: int, counter_address: int, wide: bool) -> bytes:
    body = bytearray()
    disp = counter_address - (stub_address + 6)
    body += b"\x8B\x05" + (disp & 0xFFFFFFFF).to_bytes(4, "little")
    disp = counter_address - (stub_address + len(body) + 6)
    body += b"\xFF\x05" + (disp & 0xFFFFFFFF).to_bytes(4, "little")
    if wide:
        body += b"\x31\xD2"
    body += b"\xC3"
    return bytes(body)

def _stub_body(kind: str, arch: str, stub_address: int, counter_address: int) -> bytes:
    if kind in _TIMER_KINDS:
        if arch == "x86":
            return _timer_stub_32(counter_address, kind == "tick64")
        return _timer_stub_64(stub_address, counter_address, kind == "tick64")
    table = _STUBS_64 if arch == "x64" else _STUBS_32
    return table[kind]

def patch_file(source: str | Path, destination: str | Path, apis: list[str] | None = None,
               rdtsc: bool = True, peb: bool = True) -> PatchResult:
    source = Path(source)
    destination = Path(destination)
    result = PatchResult(source=source, destination=None)
    try:
        import pefile
    except ImportError:
        result.error = "pefile missing"
        return result

    try:
        pe = pefile.PE(str(source))
    except Exception as exc:
        result.error = f"cannot parse PE: {exc}"
        return result

    arch = "x64" if int(pe.OPTIONAL_HEADER.Magic) == 0x20B else "x86"
    result.arch = arch
    try:
        return _patch(pe, source, destination, result, apis or list(_KIND_BY_API), arch,
                      rdtsc=rdtsc, peb=peb)
    except Exception as exc:
        result.error = f"patch failed: {exc}"
        result.patched = []
        return result
    finally:
        try:
            pe.close()
        except Exception:
            pass

def _patch(pe, source: Path, destination: Path, result: PatchResult,
           apis: list[str], arch: str, rdtsc: bool = True, peb: bool = True) -> PatchResult:
    wanted = {name.lower() for name in apis}
    targets: list[tuple[str, int]] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imported in getattr(entry, "imports", []) or []:
            if not imported.name:
                continue
            name = imported.name.decode("latin-1")
            lowered = name.lower()
            if lowered not in wanted or lowered not in _KIND_BY_API:
                continue
            targets.append((name, int(imported.address)))

    if not targets and not rdtsc and not peb:
        result.error = "no anti-debug import to patch"
        return result

    kinds: list[str] = []
    unique: list[tuple[str, int]] = []
    seen: set[str] = set()
    for name, address in targets:
        lowered = name.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        unique.append((name, address))
        kinds.append(_KIND_BY_API[lowered])

    raw_bytes = source.read_bytes()
    data = bytearray(raw_bytes)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    file_alignment = max(0x200, int(pe.OPTIONAL_HEADER.FileAlignment))
    section_alignment = max(0x1000, int(pe.OPTIONAL_HEADER.SectionAlignment))
    e_lfanew = int(pe.DOS_HEADER.e_lfanew)
    optional_size = int(pe.FILE_HEADER.SizeOfOptionalHeader)
    sections = list(pe.sections)

    def rva_to_offset_stub(rva: int) -> int | None:
        for section in sections:
            start = int(section.VirtualAddress)
            size = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            if start <= rva < start + size:
                return int(section.PointerToRawData) + (rva - start)
        return None

    decoded: dict[int, tuple[str, int]] = {}
    if rdtsc and len(raw_bytes) <= 64 * 1024 * 1024:
        seeds = _code_seeds(pe, raw_bytes, arch)
        decoded = _walk_code(raw_bytes, sections, rva_to_offset_stub, image_base, seeds, arch)
    rdtsc_pattern_sites: list[int] = []
    if rdtsc:
        rdtsc_pattern_sites = _pattern_rdtsc_sites(raw_bytes, sections, image_base,
                                                   arch, set(decoded))
    rdtsc_total = sum(1 for mnemonic, _size in decoded.values()
                      if mnemonic in ("rdtsc", "rdtscp")) + len(rdtsc_pattern_sites)

    counters = sum(1 for kind in kinds if kind in _TIMER_KINDS)
    slots = max(counters, 1) + (1 if rdtsc else 0)
    import_stubs_size = 0x20 + 0x20 * len(kinds)
    peb_reserve = 0x40 if peb else 0
    rdtsc_reserve = 0x20 * min(rdtsc_total, 64)
    stub_size = (import_stubs_size + peb_reserve + rdtsc_reserve
                 + _COUNTER_SLOT * slots)
    stub_size = _align(stub_size, 0x20)

    physical = max(range(len(sections)),
                   key=lambda index: int(sections[index].PointerToRawData)
                   + int(sections[index].SizeOfRawData))
    target_section = sections[physical]
    virtual_start = _align(int(target_section.Misc_VirtualSize), 0x10)
    if int(target_section.SizeOfRawData) < virtual_start:
        virtual_start = _align(int(target_section.SizeOfRawData), 0x10)
    stub_rva = int(target_section.VirtualAddress) + virtual_start
    raw_offset = int(target_section.PointerToRawData) + virtual_start
    raw_size = _align(virtual_start + stub_size, file_alignment)
    result.section_address = image_base + stub_rva

    rdtsc_counter = image_base + stub_rva + stub_size - _COUNTER_SLOT
    cursor = 0
    counter_cursor = import_stubs_size + peb_reserve + rdtsc_reserve
    blobs: list[tuple[int, bytes]] = []
    plan: dict[str, int] = {}
    for name, _address in unique:
        lowered = name.lower()
        kind = _KIND_BY_API[lowered]
        stub_address = image_base + stub_rva + cursor
        counter_address = image_base + stub_rva + counter_cursor
        if kind in _TIMER_KINDS:
            counter_cursor += _COUNTER_SLOT
        body = _stub_body(kind, arch, stub_address, counter_address)
        blobs.append((cursor, body))
        plan[lowered] = stub_address
        cursor += _align(len(body) + 2, 0x10)

    stub_blob = bytearray(stub_size)
    for offset, body in blobs:
        stub_blob[offset:offset + len(body)] = body

    if len(data) < raw_offset:
        data.extend(b"\x00" * (raw_offset - len(data)))
    needed = raw_offset + raw_size
    if len(data) < needed:
        data.extend(b"\x00" * (needed - len(data)))
    data[raw_offset:raw_offset + stub_size] = stub_blob

    header_offset = e_lfanew + 24 + optional_size + physical * 40
    data[header_offset + 8:header_offset + 12] = int(virtual_start + stub_size).to_bytes(4, "little")
    data[header_offset + 16:header_offset + 20] = int(raw_size).to_bytes(4, "little")
    characteristics = int(target_section.Characteristics) | 0x20000000 | 0x40000000 | 0x80000000
    data[header_offset + 36:header_offset + 40] = characteristics.to_bytes(4, "little")

    size_of_image_offset = e_lfanew + 24 + 56
    new_image_size = _align(stub_rva + stub_size, section_alignment)
    current_image_size = int(pe.OPTIONAL_HEADER.SizeOfImage)
    if new_image_size > current_image_size:
        data[size_of_image_offset:size_of_image_offset + 4] = new_image_size.to_bytes(4, "little")

    def rva_to_offset(rva: int) -> int | None:
        for section in sections:
            start = int(section.VirtualAddress)
            size = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            if start <= rva < start + size:
                return int(section.PointerToRawData) + (rva - start)
        return None

    code_patched, unhandled = _patch_code_references(
        data, sections, targets, plan, rva_to_offset, image_base, arch)
    result.code_references = code_patched
    result.skipped.extend(sorted(unhandled))

    patched: list[str] = []
    skipped: list[str] = []
    for name, address in targets:
        lowered = name.lower()
        stub = plan.get(lowered)
        if stub is None:
            skipped.append(name)
            continue
        width = 8 if arch == "x64" else 4
        offset = rva_to_offset(address - image_base)
        if offset is None or offset + width > len(data):
            skipped.append(name)
            continue
        data[offset:offset + width] = int(stub).to_bytes(width, "little")
        if name not in patched:
            patched.append(name)
        result.stub_addresses[name] = stub

    if rdtsc:
        sites, rdtsc_skipped = _patch_rdtsc(
            data, sections, rva_to_offset, image_base, arch, decoded,
            rdtsc_counter, image_base + stub_rva + import_stubs_size + peb_reserve,
            rdtsc_reserve,
            raw_bytes, rdtsc_pattern_sites)
        result.rdtsc_sites = sites
        result.skipped.extend(rdtsc_skipped)
        if sites:
            patched.append(f"rdtsc x{sites}")

    if peb:
        entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        if entry_rva:
            stub_va = image_base + stub_rva + import_stubs_size
            body = _peb_stub(arch, stub_va, image_base + entry_rva)
            stub_offset = rva_to_offset(stub_rva + import_stubs_size)
            entry_field = e_lfanew + 24 + 16
            if (stub_offset is not None and stub_offset + len(body) <= len(data)
                    and entry_field + 4 <= len(data)):
                data[stub_offset:stub_offset + len(body)] = body
                data[entry_field:entry_field + 4] = int(stub_rva + import_stubs_size).to_bytes(4, "little")
                result.peb_stub = True
                result.peb_entry_rva = stub_rva + import_stubs_size
                patched.append("peb")

    if not patched:
        result.error = "nothing patched"
        return result

    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.write_bytes(bytes(data))
    except OSError as exc:
        result.error = f"cannot write: {exc}"
        return result

    result.patched = sorted(set(patched))
    result.skipped = sorted(set(result.skipped) | set(skipped))
    result.destination = destination
    return result

_RDTSC_PAD_BYTES = (0xCC, 0x00)
_RDTSC_PAD_MIN = 0x10

def _rel32(target: int, end: int) -> bytes:
    return ((target - end) & 0xFFFFFFFF).to_bytes(4, "little")

def _peb_stub(arch: str, stub_va: int, entry_va: int) -> bytes:
    body = bytearray()
    if arch == "x64":
        body += bytes.fromhex("65488b042560000000")
        body += bytes.fromhex("c6400200")
        body += bytes.fromhex("c780bc00000000000000")
        body += bytes.fromhex("488b4830")
        body += bytes.fromhex("4885c9")
        skip_at = len(body)
        body += b"\x74\x00"
        body += bytes.fromhex("c7411000000000")
        body += bytes.fromhex("c7411400000000")
    else:
        body += bytes.fromhex("64a130000000")
        body += bytes.fromhex("c6400200")
        body += bytes.fromhex("c7406800000000")
        body += bytes.fromhex("8b4818")
        body += bytes.fromhex("85c9")
        skip_at = len(body)
        body += b"\x74\x00"
        body += bytes.fromhex("c7411000000000")
        body += bytes.fromhex("c7411400000000")
    body[skip_at + 1] = (len(body) - (skip_at + 2)) & 0xFF
    body += b"\xE9" + _rel32(entry_va, stub_va + len(body) + 5)
    return bytes(body)

def _rdtsc_trampoline(cave: int, counter_address: int, back: int, arch: str,
                      advance: bool = True) -> bytes:
    body = bytearray()
    if arch == "x64":
        body += b"\x8B\x05" + _rel32(counter_address, cave + 6)
        if advance:
            body += b"\xFF\x05" + _rel32(counter_address, cave + 12)
    else:
        body += b"\xA1" + counter_address.to_bytes(4, "little")
        if advance:
            body += b"\xFF\x05" + counter_address.to_bytes(4, "little")
    body += b"\x31\xD2"
    body += b"\xE9" + _rel32(back, cave + len(body) + 5)
    return bytes(body)

def _engine(arch: str, detail: bool = True):
    import capstone

    mode = capstone.CS_MODE_64 if arch == "x64" else capstone.CS_MODE_32
    engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
    engine.detail = detail
    return engine

def _executable_sections(pe) -> list:
    return [section for section in pe.sections
            if int(section.Characteristics) & 0x20000000]

def _imm_of(operand) -> int | None:
    value = getattr(operand, "imm", None)
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, "little")
    return None

def _branch_target(op_str: str) -> int | None:
    text = op_str.strip()
    if text.startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    return None

def _walk_code(data: bytes, sections, rva_to_offset, image_base: int, seeds: list[int],
               arch: str, limit: int = 80_000) -> dict[int, tuple[str, int]]:
    from collections import deque

    engine = _engine(arch, detail=False)
    decoded: dict[int, tuple[str, int]] = {}
    queue = deque(seeds)
    while queue and len(decoded) < limit:
        address = queue.popleft()
        budget = 2000
        while budget > 0:
            budget -= 1
            if address in decoded:
                break
            offset = rva_to_offset(address - image_base)
            if offset is None or offset < 0 or offset + 16 > len(data):
                break
            decoded_one = next(engine.disasm_lite(data[offset:offset + 16], address, 1), None)
            if decoded_one is None:
                break
            start_va, size, mnemonic, op_str = decoded_one
            decoded[start_va] = (mnemonic, size)
            if mnemonic in ("jmp", "call", "lcall") or mnemonic.startswith("j") \
                    or mnemonic.startswith("loop"):
                target = _branch_target(op_str)
                if target:
                    queue.append(target)
            if mnemonic in ("ret", "retf", "iret", "iretd", "iretq", "jmp", "hlt", "ud2"):
                break
            if mnemonic == "int3" or mnemonic.startswith("int "):
                break
            address = start_va + size
    return decoded

def _padding_seeds(pe, data: bytes, image_base: int) -> list[int]:
    seeds: list[int] = []
    for section in pe.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        raw_start = int(section.PointerToRawData)
        base = image_base + int(section.VirtualAddress)
        body = data[raw_start:raw_start + int(section.SizeOfRawData)]
        index = 0
        length = len(body)
        while index < length:
            value = body[index]
            if value not in (0xCC, 0x90, 0x00):
                index += 1
                continue
            start = index
            while index < length and body[index] == value:
                index += 1
            if index - start >= 2 and index < length:
                seeds.append(base + index)
    return seeds

def _code_seeds(pe, data: bytes, arch: str) -> list[int]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    seeds = [image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)]
    for entry in getattr(pe, "DIRECTORY_ENTRY_EXPORT", None) and pe.DIRECTORY_ENTRY_EXPORT.symbols or []:
        if entry.address:
            seeds.append(image_base + int(entry.address))
    try:
        if pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct:
            callbacks = int(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
            if callbacks:
                offset = None
                for section in pe.sections:
                    start = image_base + int(section.VirtualAddress)
                    if start <= callbacks < start + int(section.SizeOfRawData):
                        offset = int(section.PointerToRawData) + (callbacks - start)
                if offset:
                    for index in range(16):
                        chunk = data[offset + index * 4: offset + index * 4 + 4]
                        if len(chunk) < 4:
                            break
                        value = int.from_bytes(chunk, "little")
                        if not value:
                            break
                        seeds.append(value)
    except Exception:
        pass
    try:
        for reloc in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []) or []:
            for entry in reloc.entries:
                seeds.append(image_base + int(entry.rva))
    except Exception:
        pass
    seeds.extend(_padding_seeds(pe, data, image_base))
    return [seed for seed in dict.fromkeys(seeds) if seed]

def _cave_runs(body: bytes) -> list[tuple[int, int]]:
    runs: list[tuple[int, int]] = []
    index = 0
    length = len(body)
    while index < length:
        value = body[index]
        if value not in _RDTSC_PAD_BYTES:
            index += 1
            continue
        start = index
        while index < length and body[index] == value:
            index += 1
        if index - start >= _RDTSC_PAD_MIN:
            runs.append((start, index))
    return runs

_RDTSC_NEXT_OK = {
    "mov", "movzx", "movsx", "movsxd", "lea", "sub", "add", "cmp", "test", "xor",
    "and", "or", "shl", "shr", "sar", "sal", "imul", "mul", "push", "pop", "cdq",
    "shld", "shrd", "bswap", "neg", "not",
}

def _pattern_rdtsc_sites(data: bytes, sections, image_base: int, arch: str,
                         known: set[int]) -> list[int]:
    engine = _engine(arch, detail=False)
    sites: list[int] = []
    for section in sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        raw_start = int(section.PointerToRawData)
        base = image_base + int(section.VirtualAddress)
        body = bytes(data[raw_start:raw_start + int(section.SizeOfRawData)])
        index = body.find(b"\x0f\x31")
        while index >= 0:
            if index >= 3 and index + 10 < len(body):
                window = body[index - 3:index]
                text_like = sum(1 for byte in window if byte == 0x00 or 0x20 <= byte < 0x7F) >= 3
                address = base + index
                if not text_like and address not in known:
                    following = next(engine.disasm_lite(body[index + 2:index + 12],
                                                        address + 2, 1), None)
                    if following is not None and following[2] in _RDTSC_NEXT_OK:
                        sites.append(address)
            index = body.find(b"\x0f\x31", index + 1)
    return sites

def _five_bytes_aligned(data: bytes, rva_to_offset, image_base: int, back: int,
                       arch: str) -> bool:
    engine = _engine(arch, detail=False)
    address = back
    for _guard in range(4):
        offset = rva_to_offset(address - image_base)
        if offset is None or offset + 16 > len(data):
            return False
        decoded = next(engine.disasm_lite(data[offset:offset + 16], address, 1), None)
        if decoded is None:
            return False
        address += decoded[1]
        if address == back + 3:
            return True
        if address > back + 3:
            return False
    return False

def _patch_rdtsc(data: bytearray, sections, rva_to_offset, image_base: int, arch: str,
                 decoded: dict[int, tuple[str, int]], counter_address: int,
                 stub_free_start: int, stub_reserve: int,
                 raw_source: bytes = b"", pattern_sites: list[int] | None = None
                 ) -> tuple[int, list[str]]:
    patched = 0
    skipped: set[str] = set()
    used_caves: list[tuple[int, int]] = []
    runs_by_section: dict[int, list[tuple[int, int]]] = {}
    for section in sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        raw_start = int(section.PointerToRawData)
        body = bytes(data[raw_start:raw_start + int(section.SizeOfRawData)])
        runs_by_section[id(section)] = _cave_runs(body)

    stub_cursor = stub_free_start
    stub_limit = stub_free_start + stub_reserve

    def section_of(rva: int):
        for section in sections:
            start = int(section.VirtualAddress)
            size = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            if start <= rva < start + size:
                return section
        return None

    sites = {address: width for address, (mnemonic, width) in decoded.items()
             if mnemonic == "rdtsc"}
    for extra in (pattern_sites if pattern_sites is not None
                  else _pattern_rdtsc_sites(raw_source, sections, image_base, arch, set(decoded))):
        sites.setdefault(extra, 2)

    for address, width in sorted(sites.items()):
        site_offset = rva_to_offset(address - image_base)
        if site_offset is None or site_offset + width > len(data):
            skipped.add("rdtsc outside the file")
            continue
        back = address + width
        section = section_of(address - image_base)
        runs = runs_by_section.get(id(section), []) if section is not None else []
        base_rva = int(section.VirtualAddress) if section is not None else 0
        raw_start = int(section.PointerToRawData) if section is not None else 0
        placed = False
        for run_start, run_end in runs:
            cave_va = image_base + base_rva + run_start
            if not -128 <= cave_va - (address + 2) <= 127:
                continue
            advance = True
            length = len(_rdtsc_trampoline(cave_va, counter_address, back, arch, advance))
            if run_end - run_start < length + 1:
                advance = False
                length = len(_rdtsc_trampoline(cave_va, counter_address, back, arch, advance))
                if run_end - run_start < length + 1:
                    continue
            slot = -1
            for candidate in range(run_start, run_end - length):
                if any(not (candidate + length <= used[0] or candidate >= used[1])
                       for used in used_caves):
                    continue
                slot = candidate
                break
            if slot < 0:
                continue
            cave_va = image_base + base_rva + slot
            delta = cave_va - (address + 2)
            if not -128 <= delta <= 127:
                continue
            body = _rdtsc_trampoline(cave_va, counter_address, back, arch, advance)
            cave_offset = raw_start + slot
            if cave_offset + len(body) > len(data):
                continue
            data[site_offset] = 0xEB
            data[site_offset + 1] = delta & 0xFF
            if width > 2:
                data[site_offset + 2] = 0x90
            data[cave_offset:cave_offset + len(body)] = body
            used_caves.append((slot, slot + len(body)))
            patched += 1
            placed = True
            break
        if placed:
            continue
        if (width == 2 and _five_bytes_aligned(data, rva_to_offset, image_base,
                                               back, arch)):
            body = _rdtsc_trampoline(stub_cursor, counter_address, address + 5, arch)
            if stub_cursor + len(body) > stub_limit:
                skipped.add("rdtsc: stub area full")
                continue
            cave_offset = rva_to_offset(stub_cursor - image_base)
            if cave_offset is None or cave_offset + len(body) > len(data):
                skipped.add("rdtsc: no stub room")
                continue
            data[cave_offset:cave_offset + len(body)] = body
            data[site_offset] = 0xE9
            data[site_offset + 1:site_offset + 5] = _rel32(stub_cursor, address + 5)
            stub_cursor += _align(len(body) + 2, 0x10)
            patched += 1
            continue
        skipped.add("rdtsc: no reachable cave")
    return patched, sorted(skipped)

def _register_index_table() -> dict[int, int]:
    try:
        import capstone.x86 as x86
    except Exception:
        return {}
    names = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
    table: dict[int, int] = {}
    for index, name in enumerate(names):
        value = getattr(x86, "X86_REG_" + name.upper(), None)
        if isinstance(value, int):
            table[value] = index
    return table

_REG32_INDEX = _register_index_table()

def _register_modrm_table() -> dict[int, int]:
    try:
        import capstone.x86 as x86
    except Exception:
        return {}
    names = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
    table: dict[int, int] = {}
    for index, name in enumerate(names):
        value = getattr(x86, "X86_REG_" + name.upper(), None)
        if isinstance(value, int):
            table[value] = index
    return table

_REG64_MODRM = _register_modrm_table()
try:
    import capstone.x86 as _x86

    _RIP = _x86.X86_REG_RIP
except Exception:
    _RIP = 41

def _slot_of(insn, arch: str) -> int | None:
    operands = insn.operands
    memory = None
    for operand in operands:
        if operand.type == 3:
            memory = operand.mem
    if memory is None:
        return None
    if arch == "x64":
        if memory.base == _RIP and not memory.index:
            return insn.address + insn.size + memory.disp
        return None
    if memory.base or memory.index:
        return None
    return int(memory.disp)

def _patch_code_references(data: bytearray, sections, targets, plan, rva_to_offset,
                           image_base: int, arch: str = "x86") -> tuple[int, list[str]]:
    import capstone

    wanted: dict[int, int] = {}
    for name, address in targets:
        stub = plan.get(name.lower())
        if stub is not None:
            wanted[address] = stub
    if not wanted:
        return 0, []
    mode = capstone.CS_MODE_64 if arch == "x64" else capstone.CS_MODE_32
    engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
    engine.detail = True
    patched = 0
    unhandled: set[str] = set()

    def redirect(insn, following) -> None:
        nonlocal patched
        slot = _slot_of(insn, arch)
        if slot is None:
            return
        stub = wanted.get(slot)
        if stub is None:
            return
        offset = rva_to_offset(insn.address - image_base)
        if offset is None or offset + insn.size > len(data):
            unhandled.add("out-of-file reference")
            return
        if insn.mnemonic in ("jmp", "call") and len(insn.operands) == 1:
            if insn.size < 5:
                unhandled.add(f"{insn.mnemonic} too short")
                return
            opcode = b"\xE8" if insn.mnemonic == "call" else b"\xE9"
            displacement = stub - (insn.address + 5)
            data[offset:offset + 5] = opcode + (displacement & 0xFFFFFFFF).to_bytes(4, "little")
            for extra in range(5, insn.size):
                data[offset + extra] = 0x90
            patched += 1
            return
        if insn.mnemonic == "mov" and arch == "x64":
            destination = insn.operands[0].reg if insn.operands else 0
            if (insn.size == 7
                    and following is not None
                    and following.mnemonic in ("call", "jmp")
                    and len(following.operands) == 1
                    and following.operands[0].type == 1
                    and following.operands[0].reg == destination
                    and destination in _REG64_MODRM):
                modrm = 0x05 | (_REG64_MODRM[destination] << 3)
                displacement = stub - (insn.address + 7)
                data[offset:offset + 7] = (b"\x48\x8D" + bytes([modrm])
                                           + (displacement & 0xFFFFFFFF).to_bytes(4, "little"))
                patched += 1
                return
            unhandled.add("mov load of IAT slot (not redirected)")
            return
        if insn.mnemonic == "mov" and arch == "x86" and insn.size >= 5:
            register = _REG32_INDEX.get(insn.operands[0].reg)
            if register is None:
                unhandled.add("mov into unknown register")
                return
            data[offset:offset + 5] = bytes([0xB8 + register]) + int(stub).to_bytes(4, "little")
            for extra in range(5, insn.size):
                data[offset + extra] = 0x90
            patched += 1
            return
        unhandled.add(f"{insn.mnemonic} load of IAT slot (not redirected)")

    for section in sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        start = int(section.VirtualAddress)
        body = bytes(data[int(section.PointerToRawData):
                          int(section.PointerToRawData) + int(section.SizeOfRawData)])
        if not body:
            continue
        iterator = engine.disasm(body, image_base + start)
        current = next(iterator, None)
        while current is not None:
            following = next(iterator, None)
            redirect(current, following)
            current = following
    return patched, sorted(unhandled)

def patched_copy(source: str | Path, root: str | Path | None = None,
                 apis: list[str] | None = None, rdtsc: bool = True,
                 peb: bool = True) -> PatchResult:
    source = Path(source)
    try:
        digest = hashlib.sha256(source.read_bytes()).hexdigest()[:16]
    except OSError as exc:
        return PatchResult(source=source, destination=None, error=str(exc))
    fingerprint = f"-{int(bool(rdtsc))}{int(bool(peb))}" if not (rdtsc and peb) else ""
    root = Path(root or os.path.join(os.environ.get("TMPDIR", "/tmp"), "xsolver-patched"))
    folder = root / (digest + fingerprint)
    destination = folder / source.name
    manifest = folder / "patched.json"
    if destination.exists():
        names: list[str] = []
        meta: dict = {}
        if manifest.exists():
            try:
                meta = json.loads(manifest.read_text())
                names = list(meta.get("patched", []))
            except Exception:
                meta, names = {}, []
        return PatchResult(
            source=source,
            destination=destination,
            patched=names,
            arch=meta.get("arch", "x86"),
            code_references=int(meta.get("code_references", 0)),
            rdtsc_sites=int(meta.get("rdtsc_sites", 0)),
            peb_stub=bool(meta.get("peb_stub", False)),
            peb_entry_rva=int(meta.get("peb_entry_rva", 0)),
            stub_addresses={k: int(v) for k, v in (meta.get("stub_addresses") or {}).items()},
        )
    folder.mkdir(parents=True, exist_ok=True)
    for sibling in source.parent.iterdir():
        if sibling == source or not sibling.is_file():
            continue
        try:
            if sibling.stat().st_size > 64 * 1024 * 1024:
                continue
            shutil.copyfile(sibling, folder / sibling.name)
        except OSError:
            pass
    result = patch_file(source, destination, apis=apis, rdtsc=rdtsc, peb=peb)
    if result.applied:
        try:
            manifest.write_text(json.dumps({"patched": result.patched,
                                            "code_references": result.code_references,
                                            "rdtsc_sites": result.rdtsc_sites,
                                            "peb_stub": result.peb_stub,
                                            "peb_entry_rva": result.peb_entry_rva,
                                            "stub_addresses": result.stub_addresses,
                                            "arch": result.arch}))
        except OSError:
            pass
    return result

def verify_patch(path: str | Path, result: PatchResult) -> bool:
    if not result.applied:
        return False
    try:
        import pefile

        pe = pefile.PE(str(path))
    except Exception:
        return False
    try:
        if result.peb_stub and result.peb_entry_rva:
            if int(pe.OPTIONAL_HEADER.AddressOfEntryPoint) != result.peb_entry_rva:
                return False
        for _name, stub in result.stub_addresses.items():
            body = pe.get_data(stub - int(pe.OPTIONAL_HEADER.ImageBase), 4)
            if not body or body == b"\x00\x00\x00\x00":
                return False
        return True
    finally:
        try:
            pe.close()
        except Exception:
            pass
