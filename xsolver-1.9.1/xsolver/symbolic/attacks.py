from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .engine import SymbolicEngine, SymbolicOutcome, symbolic_available
from .win32io import (
    CompareOracle,
    GuestReadLine,
    HexGroupHook,
    install_io_hooks,
    install_readline_hook,
)

HEX_DIGITS = b"0123456789abcdefABCDEF"

@dataclass
class ReadSpec:
    template: str
    call: int = 1
    address: int | None = None
    alphabet: bytes = HEX_DIGITS

    def to_spec(self) -> dict:
        length = len(self.template)

        def symbolic(index: int) -> bool:
            char = self.template[index]
            if char in "?#":
                return True
            if char in "XYZ":
                return True
            run = 1
            while index + run < length and self.template[index + run] == char:
                run += 1
            left = 1
            while index - left >= 0 and self.template[index - left] == char:
                left += 1
            return char.isalpha() and max(run, left) >= 3

        fixed = {
            i: ord(char)
            for i, char in enumerate(self.template)
            if not symbolic(i)
        }
        spec = {
            "call": self.call,
            "length": length,
            "alphabet": self.alphabet,
            "name": "serial",
        }
        if fixed:
            spec["fixed"] = fixed
        return spec

@dataclass
class KeygenmeResult:
    outcome: SymbolicOutcome | None = None
    serial: bytes | None = None
    verified: bool = False
    output: str = ""
    detail: str = ""
    hooks: dict = field(default_factory=dict)

def _text_sections(project):
    sections = []
    for obj in project.loader.all_objects:
        for sec in getattr(obj, "sections", []):
            if not getattr(sec, "is_executable", False) or not sec.min_addr:
                continue
            try:
                data = project.loader.memory.load(sec.min_addr, sec.memsize)
            except Exception:
                continue
            if data:
                sections.append((sec.min_addr, bytes(data)))
    return sections

def _iter_text(project):
    for base, data in _text_sections(project):
        yield base, data

def _import_addresses(project, name: str) -> set[int]:
    found: set[int] = set()
    for obj in project.loader.all_objects:
        imports = getattr(obj, "imports", None) or {}
        for key, sym in imports.items():
            if key != name and getattr(sym, "name", None) != name:
                continue
            if True:
                for attr in ("rebased_addr", "linked_addr", "resolvedby"):
                    value = getattr(sym, attr, None)
                    if isinstance(value, int):
                        found.add(value)
                resolver = getattr(sym, "resolvedby", None)
                addr = getattr(resolver, "rebased_addr", None) if resolver else None
                if isinstance(addr, int):
                    found.add(addr)
        plt = getattr(obj, "plt", None) or {}
        for key, value in plt.items():
            address = value if isinstance(key, str) else key
            stub_name = key if isinstance(key, str) else value
            if stub_name == name and isinstance(address, int):
                found.add(address)
    try:
        stub = project.loader.find_symbol(name)
        if stub is not None:
            found.add(stub.rebased_addr)
    except Exception:
        pass
    return found

def _find_call_sites(project, targets: set[int]) -> list[int]:
    if not targets:
        return []
    sites = []
    for base, data in _iter_text(project):
        for offset in range(len(data) - 5):
            if data[offset] == 0xE8:
                rel = int.from_bytes(data[offset + 1: offset + 5], "little", signed=True)
                dest = base + offset + 5 + rel
                if dest in targets:
                    sites.append(base + offset)
    return sites

def _cfg(project):
    cfg = getattr(project, "_xsolver_cfg", None)
    if cfg is None:
        cfg = project.analyses.CFGFast(normalize=True, data_references=False)
        setattr(project, "_xsolver_cfg", cfg)
    return cfg

def _function_start(project, call_site: int, window: int = 0x400) -> int | None:
    try:
        func = _cfg(project).kb.functions.floor_func(call_site)
        if func is not None and func.addr:
            return func.addr
    except Exception:
        pass

    for base, data in _iter_text(project):
        if not (base <= call_site <= base + len(data)):
            continue
        offset = call_site - base
        start = max(0, offset - window)
        best = -1
        for prologue in (b"\x55\x48\x89\xe5", b"\xf3\x0f\x1e\xfa"):
            position = data.rfind(prologue, start, offset)
            if position > best:
                best = position
        if best >= 0:
            return base + best
    return None

def _call_target_for(project, function_start: int, span: int = 0x20) -> int:
    low, high = function_start - span, function_start + 4
    targets: dict[int, int] = {}
    for base, data in _iter_text(project):
        if not (base <= function_start <= base + len(data)):
            continue
        for offset in range(max(0, low - base), min(len(data) - 5, high - base)):
            if data[offset] == 0xE8:
                rel = int.from_bytes(data[offset + 1: offset + 5], "little", signed=True)
                dest = base + offset + 5 + rel
                if low <= dest <= high:
                    targets[dest] = targets.get(dest, 0) + 1
    if not targets:
        return function_start
    return max(targets.items(), key=lambda item: item[1])[0]

def find_readline_candidates(project, limit: int = 6,
                             apis=("ReadFile", "fgets", "fread", "read", "scanf", "__isoc99_scanf")):
    found: list[tuple[int, int]] = []
    for api in apis:
        targets = _import_addresses(project, api)
        if not targets:
            continue
        thunks = set()
        for base, data in _iter_text(project):
            for offset in range(len(data) - 6):
                if data[offset] == 0xFF and data[offset + 1] == 0x25:
                    disp = int.from_bytes(data[offset + 2: offset + 6], "little", signed=True)
                    slot = base + offset + 6 + disp
                    if slot in targets:
                        thunks.add(base + offset)
        sites = _find_call_sites(project, set(targets) | thunks)
        for site in sites:
            start = _function_start(project, site)
            if start is None or site - start < 16:
                continue
            found.append((site - start, _call_target_for(project, start)))
    unique = []
    for _, address in sorted(found):
        if address not in unique:
            unique.append(address)
    return unique[:limit]

def find_readline_function(project, **kwargs):
    candidates = find_readline_candidates(project, **kwargs)
    return candidates[0] if candidates else None

def find_hex_candidates(project, limit: int = 6):
    from .win32io import find_hex_group_parser

    candidates = []
    try:
        cfg = project.analyses.CFGFast(normalize=True, data_references=False)
    except Exception:
        return candidates
    wanted = {0x30, 0x39, 0x41, 0x46}
    for func in cfg.functions.values():
        constants = set()
        try:
            for block in func.blocks:
                for ins in block.capstone.insns:
                    if ins.mnemonic.startswith("cmp"):
                        for op in ins.operands:
                            if getattr(op, "type", None) == 2:
                                constants.add(op.imm & 0xFF)
        except Exception:
            continue
        size = func.size or 0
        if wanted <= constants and 16 <= size < 0x300:
            candidates.append((size, func.addr))
    candidates.sort()
    out = []
    for _, addr in candidates:
        target = _call_target_for(project, addr)
        if target not in out:
            out.append(target)
    return out[:limit]

def find_repeated_callees(project, limit: int = 6):
    from collections import Counter

    counts: Counter = Counter()
    for base, data in _iter_text(project):
        for offset in range(len(data) - 5):
            if data[offset] == 0xE8:
                rel = int.from_bytes(data[offset + 1: offset + 5], "little", signed=True)
                counts[base + offset + 5 + rel] += 1
    candidates = []
    for target, count in counts.items():
        if count < 2:
            continue
        start = _function_start(project, target) if target > base else None
        size = (target - start) if start else 0
        if start and 0 < size <= 0x100:
            candidates.append((size, target))
    candidates.sort()
    return [target for _, target in candidates[:limit]]

def find_template_parser(project, limit: int = 3):
    from collections import Counter

    results = []
    try:
        cfg = project.analyses.CFGFast(normalize=True, data_references=False)
    except Exception:
        return results
    for func in cfg.functions.values():
        dashes = False
        calls: Counter = Counter()
        try:
            for block in func.blocks:
                for ins in block.capstone.insns:
                    if ins.mnemonic == "cmp":
                        for op in ins.operands:
                            if getattr(op, "type", None) == 2 and (op.imm & 0xFF) == 0x2D:
                                dashes = True
                    elif ins.mnemonic == "call" and ins.operands:
                        op = ins.operands[0]
                        if getattr(op, "type", None) == 2:
                            calls[op.imm] += 1
        except Exception:
            continue
        if not dashes:
            continue
        for target, count in calls.most_common():
            if count >= 2 and target not in results:
                results.append(target)
    return results[:limit]

def find_hex_parser(project):
    from .win32io import find_hex_group_parser

    start = find_hex_group_parser(project)
    if start is None:
        return None
    return _call_target_for(project, start)

_attempt_budget = 40.0
_max_states = 200
_max_steps = 6000

def _explore_one(project, engine, prefix, read_address, spec, hex_address, compare,
                 compare_pairs, win, avoid, budget):
    from .engine import _Timeout, _deadline

    if hex_address:
        project.hook(hex_address, HexGroupHook(digits=4, out_bits=16), length=0)
    if compare and compare_pairs:
        project.hook(compare, CompareOracle(pairs=compare_pairs, return_value=0), length=0)
    project.hook(read_address, GuestReadLine(spec), length=0)

    state = project.factory.full_init_state(
        stdin=(prefix + b"\n").ljust(256, b"\x00"),
        add_options=engine._base_options(),
    )
    state.globals["xsolver_readline_count"] = 0
    simgr = project.factory.simgr(state)

    find, avoid = set([win]), set(avoid)
    steps = 0
    try:
        with _deadline(budget):
            while steps < _max_steps:
                steps += 1
                simgr.step()
                found = simgr.stashes.setdefault("found", [])
                for current in list(simgr.active):
                    if current.addr in find:
                        simgr.active.remove(current)
                        if current.globals.get("xsolver_symread_data") is not None:
                            found.append(current)
                    elif current.addr in avoid:
                        simgr.active.remove(current)
                if len(simgr.stashes.get("found", [])) >= 3 or not simgr.active:
                    break
                if len(simgr.active) > _max_states:
                    return [], f"state explosion ({len(simgr.active)}) after {steps} steps"
    except _Timeout:
        return [], "timeout during exploration"
    except Exception as exc:
        return [], f"exploration error: {type(exc).__name__}: {exc}"

    states = simgr.stashes.get("found", [])
    if not states:
        return [], (f"branch 0x{win:x} not reached ({len(simgr.active)} active / "
                    f"{len(simgr.stashes.get('deadended', []))} finished)")
    return states, "success reached"

def _run_attempt(engine, read_address, spec, hex_address, compare, compare_pairs,
                 prefix, deadline, refs_win, refs_lose):
    import time

    notes: list[str] = []
    targets = refs_win or [0]
    for index, win in enumerate(targets):
        remaining = deadline - time.monotonic()
        if remaining <= 2:
            notes.append("time budget exhausted")
            break
        avoid = list(refs_lose)
        budget = min(_attempt_budget, max(6.0, remaining / max(1, len(targets) - index)))
        project = engine._project()
        install_io_hooks(project)
        states, message = _explore_one(
            project, engine, prefix, read_address, spec, hex_address, compare,
            compare_pairs, win, avoid, budget,
        )
        if not states:
            notes.append(f"0x{win:x}: {message}")
            continue
        produced: list[bytes] = []
        for state in states:
            try:
                serial = state.solver.eval(state.globals["xsolver_symread_data"], cast_to=bytes)
            except Exception:
                continue
            if serial not in produced:
                produced.append(serial)
        if produced:
            return f"success 0x{win:x}, {len(produced)} candidate(s)", produced
        notes.append(f"0x{win:x}: no candidate")
    return " | ".join(notes[-2:]), []

def solve_keygenme(
    path,
    *,
    template,
    prefix=b"",
    read=None,
    hex_parser=None,
    compare=None,
    compare_pairs=None,
    timeout=180.0,
    verify=None,
    max_attempts=14,
    verbose=False,
):
    import time

    if not symbolic_available():
        return KeygenmeResult(detail="angr unavailable")

    read_spec = read or ReadSpec(template=template)
    spec = read_spec.to_spec()
    deadline = time.monotonic() + timeout
    attempts = 0
    notes = []
    result = KeygenmeResult()

    engine = SymbolicEngine(path, max_len=max(64, len(template) + 8))
    project = engine._project()

    read_candidates = [read_spec.address] if read_spec.address else find_readline_candidates(project)
    if hex_parser:
        hex_candidates = [hex_parser]
    else:
        hex_candidates = []
        ordered = (find_template_parser(project) + find_hex_candidates(project)
                   + find_repeated_callees(project))
        for candidate in ordered:
            if candidate not in hex_candidates:
                hex_candidates.append(candidate)
        hex_candidates.append(None)
    call_indices = [read_spec.call] + [i for i in (1, 0) if i != read_spec.call]

    from .strings_xref import CodeDataReferences

    refs = CodeDataReferences(project)
    wins, lose = [], refs.lose_addresses()
    for addr in refs.win_addresses() + refs.infer_win_addresses():
        if addr not in wins:
            wins.append(addr)

    result.hooks = {
        "read_candidates": read_candidates,
        "hex_candidates": hex_candidates,
        "win": wins,
        "lose": lose,
    }
    if not read_candidates:
        result.detail = "no read function"
        return result

    for read_address in read_candidates:
        for hex_address in hex_candidates:
            for call_index in call_indices:
                if attempts >= max_attempts or time.monotonic() >= deadline:
                    break
                attempts += 1
                label = (f"read=0x{read_address:x} "
                         f"hex={hex(hex_address) if hex_address else '-'} call={call_index}")
                message, produced = _run_attempt(
                    engine, read_address, dict(spec, call=call_index), hex_address,
                    compare, compare_pairs, prefix, deadline, wins, lose,
                )
                if not produced:
                    notes.append(f"{label}: {message}")
                    continue
                notes.append(f"{label}: {len(produced)} candidate(s)")
                for serial in produced:
                    if verify is not None and not verify(serial):
                        continue
                    result.serial = serial
                    result.verified = verify is not None
                    result.detail = f"{attempts} tries; {label} ; serial {serial!r}"
                    result.hooks.update(read=read_address, hex=hex_address, call=call_index)
                    return result

    result.detail = " | ".join(notes[-6:])
    return result
