from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from xsolver.analysis.disasm import _direct_target, disassemble_functions_recursive
from xsolver.core.binary import BinaryProfile
from xsolver.core.elf import NotElfError, parse_elf
from xsolver.core.pe import NotPeError, parse_pe

_TIMING_MNEMONICS = ("rdtsc", "rdtscp")
_LOOKAHEAD = 8

@dataclass
class PatchedCheck:
    function: str
    branch_address: int
    detail: str

def _vaddr_to_file_offset(profile: BinaryProfile, vaddr: int) -> int | None:
    try:
        info = parse_elf(profile.raw)
        for sec in info.sections:
            if sec.addr and sec.addr <= vaddr < sec.addr + sec.size:
                return sec.offset + (vaddr - sec.addr)
    except NotElfError:
        pass

    try:
        info = parse_pe(profile.raw)
        for sec in info.sections:
            if sec.virtual_address <= vaddr < sec.virtual_address + sec.raw_size:
                return sec.raw_offset + (vaddr - sec.virtual_address)
    except NotPeError:
        pass

    return None

def _functions_using_timing(functions: dict[str, list]) -> set[str]:
    direct = set()
    for name, insns in functions.items():
        if any(i.mnemonic in _TIMING_MNEMONICS for i in insns):
            direct.add(name)
    return direct

def _function_start_by_address(functions: dict[str, list]) -> dict[int, str]:
    starts: dict[int, str] = {}
    for name, insns in functions.items():
        if insns:
            starts[insns[0].address] = name
    return starts

def _calls_timing_function(insns: list, timing_starts: set[int]) -> list[int]:
    call_indices = []
    for index, insn in enumerate(insns):
        if insn.mnemonic == "call":
            target = _direct_target(insn)
            if target is not None and target in timing_starts:
                call_indices.append(index)
    return call_indices

def _is_quick_exit_block(insns: list, start_index: int, window: int = 10) -> bool:
    by_addr = {i.address: i for i in insns}
    ordered = sorted(by_addr)

    for insn in insns[start_index:start_index + window]:
        if insn.mnemonic in ("ret", "retn", "retf"):
            return True
        if insn.mnemonic == "jmp":
            target = _direct_target(insn)
            if target is not None and target in by_addr:
                target_index = ordered.index(target)
                for follow in insns[target_index:target_index + 8]:
                    if follow.mnemonic in ("ret", "retn", "retf"):
                        return True
    return False

def detect_timing_checks(profile: BinaryProfile) -> list[PatchedCheck]:
    functions = disassemble_functions_recursive(profile)
    if not functions:
        return []

    timing_funcs = _functions_using_timing(functions)
    timing_starts = {
        insns[0].address
        for name, insns in functions.items()
        if name in timing_funcs and insns
    }

    findings: list[PatchedCheck] = []
    for name, insns in functions.items():
        if not insns:
            continue
        if name in timing_funcs:
            findings.append(PatchedCheck(name, insns[0].address, "timing-source: reads rdtsc"))
            continue

        call_sites = _calls_timing_function(insns, timing_starts)
        if len(call_sites) < 2:
            continue

        for index, insn in enumerate(insns):
            if not insn.mnemonic.startswith("j") or insn.mnemonic == "jmp":
                continue
            if index <= call_sites[-1]:
                continue
            target = _direct_target(insn)
            if target is None:
                continue

            by_addr = {i.address: i for i in insns}
            ordered = sorted(by_addr)
            target_index = ordered.index(target) if target in by_addr else None
            fallthrough_index = index + 1

            if target_index is not None and _is_quick_exit_block(insns, target_index):
                findings.append(PatchedCheck(
                    name, insn.address,
                    f"branch at 0x{insn.address:x} timing check -> early return",
                ))
            elif fallthrough_index < len(insns) and _is_quick_exit_block(insns, fallthrough_index):
                findings.append(PatchedCheck(
                    name, insn.address,
                    f"branch at 0x{insn.address:x} timing check -> early return",
                ))
            break

    return findings

def _patch_force_jump(patched: bytearray, offset: int, insn_size: int) -> bool:
    if insn_size == 2:
        patched[offset] = 0xEB
        return True
    if insn_size == 6:
        old_disp = int.from_bytes(bytes(patched[offset + 2:offset + 6]), "little", signed=True)
        new_disp = old_disp + 1
        patched[offset] = 0xE9
        patched[offset + 1:offset + 5] = new_disp.to_bytes(4, "little", signed=True)
        patched[offset + 5] = 0x90
        return True
    return False

def _patch_force_fallthrough(patched: bytearray, offset: int, insn_size: int) -> bool:
    patched[offset:offset + insn_size] = b"\x90" * insn_size
    return True

def _instructions_to_exit(insns: list, start_index: int | None, limit: int = 32) -> int | None:
    if start_index is None or start_index >= len(insns):
        return None
    by_addr = {insn.address: insn for insn in insns}
    ordered = sorted(by_addr)
    for step, insn in enumerate(insns[start_index:start_index + limit]):
        if insn.mnemonic in ("ret", "retn", "retf"):
            return step
        if insn.mnemonic == "jmp":
            target = _direct_target(insn)
            if target is not None and target in by_addr:
                tail_index = ordered.index(target)
                for follow_step, follow in enumerate(insns[tail_index:tail_index + limit]):
                    if follow.mnemonic in ("ret", "retn", "retf"):
                        return step + follow_step
    return None

def neutralize_timing_checks(profile: BinaryProfile) -> tuple[bytes, list[PatchedCheck]] | None:
    functions = disassemble_functions_recursive(profile)
    if not functions:
        return None

    timing_funcs = _functions_using_timing(functions)
    timing_starts = {
        insns[0].address
        for name, insns in functions.items()
        if name in timing_funcs and insns
    }
    if not timing_starts:
        return None

    patched = bytearray(profile.raw)
    applied: list[PatchedCheck] = []

    for name, insns in functions.items():
        if name in timing_funcs or not insns:
            continue
        call_sites = _calls_timing_function(insns, timing_starts)
        if len(call_sites) < 2:
            continue

        by_addr = {i.address: i for i in insns}
        ordered = sorted(by_addr)

        for index, insn in enumerate(insns):
            if not insn.mnemonic.startswith("j") or insn.mnemonic == "jmp":
                continue
            if index <= call_sites[-1]:
                continue
            target = _direct_target(insn)
            if target is None:
                continue

            target_index = ordered.index(target) if target in by_addr else None
            fallthrough_index = index + 1
            target_exit = _instructions_to_exit(insns, target_index)
            fallthrough_exit = _instructions_to_exit(insns, fallthrough_index)

            if target_exit is None and fallthrough_exit is None:
                continue
            if target_exit is not None and fallthrough_exit is not None and target_exit == fallthrough_exit:
                continue

            fallthrough_is_bad = fallthrough_exit is not None and (
                target_exit is None or fallthrough_exit < target_exit
            )
            take_branch_is_bad = not fallthrough_is_bad

            offset = _vaddr_to_file_offset(profile, insn.address)
            if offset is None or offset + insn.size > len(patched):
                break

            if fallthrough_is_bad:
                ok = _patch_force_jump(patched, offset, insn.size)
                reason = "branch forced taken (timing check)"
            else:
                ok = _patch_force_fallthrough(patched, offset, insn.size)
                reason = "branch NOPed (timing check)"

            if ok:
                applied.append(PatchedCheck(name, insn.address, f"0x{insn.address:x}: {reason}"))
            break

    if not applied:
        return None
    return bytes(patched), applied

def write_patched_copy(profile: BinaryProfile, patched_bytes: bytes) -> Path:
    suffix = profile.path.suffix or ""
    fd, tmp_path = tempfile.mkstemp(prefix=f"xsolver_patched_{profile.path.stem}_", suffix=suffix)
    with os.fdopen(fd, "wb") as handle:
        handle.write(patched_bytes)
    path = Path(tmp_path)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path
