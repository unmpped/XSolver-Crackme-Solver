from __future__ import annotations

import time

try:
    import claripy
except Exception:
    claripy = None

def trace_loop_heads(project, stdin_data: bytes, limit: int = 40000) -> set[int]:
    try:
        state = project.factory.full_init_state(stdin=stdin_data)
    except Exception:
        return set()
    simgr = project.factory.simgr(state)
    counts: dict[int, int] = {}
    for _ in range(limit):
        if not simgr.active:
            break
        addr = simgr.active[0].addr
        counts[addr] = counts.get(addr, 0) + 1
        if counts[addr] > 200:
            break
        try:
            simgr.step()
        except Exception:
            break
    return {addr for addr, count in counts.items() if count >= 3}

def _state_key(state, heads: set[int]):
    if state.addr not in heads:
        return None
    parts = []
    for register in state.arch.register_list:
        name = register.name
        if not name or name.startswith(("ymm", "zmm", "xmm", "fs", "gs", "ds", "es", "cs", "ss")):
            continue
        try:
            value = state.registers.load(name)
        except Exception:
            continue
        try:
            parts.append(int(state.solver.eval(value)))
        except Exception:
            continue
    return (state.addr, tuple(parts))

_SKIP_PREFIXES = ("ymm", "zmm", "xmm", "fs", "gs", "ds", "es", "cs", "ss", "flags", "ip", "sp")

def fork_concrete_registers(state, heads: set[int], max_forks: int = 24) -> list:
    if state.addr not in heads:
        return [state]
    results = [state]
    for register in state.arch.register_list:
        name = register.name
        if not name or name.startswith(_SKIP_PREFIXES):
            continue
        try:
            value = state.registers.load(name)
        except Exception:
            continue
        if not state.solver.symbolic(value):
            continue
        try:
            options = state.solver.eval_upto(value, max_forks + 1)
        except Exception:
            continue
        if len(options) > max_forks:
            continue
        forked = []
        for current in results:
            for option in options:
                try:
                    copy = current.copy()
                    expression = copy.registers.load(name)
                    copy.solver.add(expression == option)
                    copy.registers.store(name, claripy.BVV(int(option), register.bits))
                except Exception:
                    continue
                forked.append(copy)
        if forked:
            results = forked[:max_forks]
    return results

def explore_dedup(
    project,
    state,
    find: list[int],
    avoid: list[int],
    heads: set[int],
    budget: float = 120.0,
    beam: int = 64,
):
    simgr = project.factory.simgr(state)
    find_set, avoid_set = set(find), set(avoid)
    deadline = time.monotonic() + budget
    found = None
    while True:
        if time.monotonic() > deadline:
            break
        active = [s for s in simgr.active if s.addr not in avoid_set]
        winners = [s for s in active if s.addr in find_set]
        if winners:
            found = winners[0]
            break
        if not active:
            break
        simgr.active = active
        try:
            simgr.step()
        except Exception:
            break
        forked = []
        for candidate in simgr.active:
            if candidate.addr in heads:
                forked.extend(fork_concrete_registers(candidate, heads))
            else:
                forked.append(candidate)
        kept: dict = {}
        others = []
        for candidate in forked:
            if candidate.addr in avoid_set:
                continue
            key = _state_key(candidate, heads)
            if key is None:
                others.append(candidate)
                continue
            kept.setdefault(key, candidate)
        merged = list(kept.values()) + others
        if len(merged) > beam:
            merged.sort(key=lambda s: len(s.solver.constraints), reverse=True)
            merged = merged[:beam]
        simgr.active = merged
    return found
