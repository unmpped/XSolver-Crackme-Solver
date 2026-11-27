from __future__ import annotations

import math
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from xsolver.core.elf import ElfInfo, NotElfError, parse_elf
from xsolver.core.pe import NotPeError, PeInfo, parse_pe

class UnsupportedFormatError(Exception):
    pass

@dataclass
class SectionSummary:
    name: str
    size: int
    entropy: float
    executable: bool

@dataclass
class BinaryProfile:
    path: Path
    format: str
    arch: str
    entry_point: int
    file_size: int
    overall_entropy: float
    sections: list[SectionSummary] = field(default_factory=list)
    is_executable_elf: bool = True
    packer_suspected: bool = False
    raw: bytes = field(repr=False, default=b"")

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter

    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def load_binary(path: str | Path) -> BinaryProfile:
    path = Path(path)
    data = path.read_bytes()

    try:
        info = parse_elf(data)
        return _profile_from_elf(path, data, info)
    except NotElfError:
        pass

    try:
        info = parse_pe(data)
        return _profile_from_pe(path, data, info)
    except NotPeError:
        pass

    raise UnsupportedFormatError(f"{path} is not ELF or PE")

def _profile_from_elf(path: Path, data: bytes, info: ElfInfo) -> BinaryProfile:
    sections = []
    for sec in info.sections:
        if sec.size == 0 or sec.offset + sec.size > len(data):
            continue
        body = data[sec.offset:sec.offset + sec.size]
        sections.append(SectionSummary(
            name=sec.name or "(unnamed)",
            size=sec.size,
            entropy=shannon_entropy(body),
            executable=bool(sec.flags & 0x4),
        ))

    packer_suspected = any(s.entropy > 7.2 and s.size > 2048 for s in sections)

    mode = os.stat(path).st_mode
    is_executable = bool(mode & stat.S_IXUSR)

    return BinaryProfile(
        path=path,
        format=f"ELF ({info.e_type})",
        arch=info.arch_label,
        entry_point=info.entry_point,
        file_size=len(data),
        overall_entropy=shannon_entropy(data),
        sections=sections,
        is_executable_elf=is_executable,
        packer_suspected=packer_suspected,
        raw=data,
    )

def _profile_from_pe(path: Path, data: bytes, info: PeInfo) -> BinaryProfile:
    sections = []
    for sec in info.sections:
        if sec.raw_size == 0 or sec.raw_offset + sec.raw_size > len(data):
            continue
        body = data[sec.raw_offset:sec.raw_offset + sec.raw_size]
        sections.append(SectionSummary(
            name=sec.name or "(unnamed)",
            size=sec.raw_size,
            entropy=shannon_entropy(body),
            executable=bool(sec.characteristics & 0x20000000),
        ))

    packer_suspected = any(s.entropy > 7.2 and s.size > 2048 for s in sections)
    bits = "64-bit" if info.is_64 else "32-bit"

    return BinaryProfile(
        path=path,
        format="PE (DLL)" if info.is_dll else "PE (EXE)",
        arch=f"{info.machine} {bits}",
        entry_point=info.entry_point,
        file_size=len(data),
        overall_entropy=shannon_entropy(data),
        sections=sections,
        is_executable_elf=False,
        packer_suspected=packer_suspected,
        raw=data,
    )
