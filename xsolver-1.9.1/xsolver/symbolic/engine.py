from __future__ import annotations

import os
import re
import signal
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from xsolver.symbolic.strings_xref import CodeDataReferences

_ANGR_IMPORT_ERROR: str | None = None
try:
    import angr
    try:
        import claripy
    except ImportError:
        from angr import claripy
except Exception as exc:
    angr = None
    claripy = None
    _ANGR_IMPORT_ERROR = str(exc)

def symbolic_available() -> bool:
    return angr is not None

def symbolic_unavailable_reason() -> str:
    if angr is not None:
        return ""
    return f"angr missing ({_ANGR_IMPORT_ERROR}). pip install angr"

@dataclass
class SymbolicOutcome:
    found: bool
    input_data: bytes | None = None
    input_mode: str = "stdin"
    length: int | None = None
    win_addresses: list[int] = field(default_factory=list)
    lose_addresses: list[int] = field(default_factory=list)
    elapsed: float = 0.0
    detail: str = ""
    attempts: int = 0
    symbolic_output: str | None = None

class _ReturnZero(angr.SimProcedure if angr else object):
    def run(self, *args, **kwargs):
        return claripy.BVV(0, self.state.arch.bits)

class _ReturnOne(angr.SimProcedure if angr else object):
    def run(self, *args, **kwargs):
        return claripy.BVV(1, self.state.arch.bits)

def _hook_anti_debug(project) -> list[str]:
    hooks: list[str] = []
    for name in ("ptrace", "ptrace64", "prctl"):
        try:
            project.hook_symbol(name, _ReturnZero())
            hooks.append(name)
        except Exception:
            pass
    for name in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                 "NtQueryInformationProcess", "OutputDebugStringA"):
        try:
            project.hook_symbol(name, _ReturnZero())
            hooks.append(name)
        except Exception:
            pass
    for name in ("GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
                 "clock", "gettimeofday", "time"):
        try:
            project.hook_symbol(name, _ReturnZero())
            hooks.append(name)
        except Exception:
            pass

    try:
        import capstone

        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64
                         if project.arch.bits == 64 else capstone.CS_MODE_32)
        for sec in project.loader.main_object.sections:
            if not getattr(sec, "is_executable", False) or not sec.memsize:
                continue
            code = project.loader.memory.load(sec.vaddr, sec.memsize)
            for insn in cs.disasm(code, sec.vaddr):
                if insn.mnemonic in ("rdtsc", "rdtscp"):
                    project.hook(insn.address, _ReturnZero(), length=insn.size)
                    hooks.append(f"{insn.mnemonic}@0x{insn.address:x}")
    except Exception:
        pass
    return hooks

def _hook_windows_io(project) -> None:
    try:
        from xsolver.symbolic.win32io import install_io_hooks

        install_io_hooks(project)
    except Exception:
        pass

def guess_input_lengths(path: str | Path, limit: int = 40) -> list[int]:
    try:
        import capstone

        data = Path(path).read_bytes()
    except Exception:
        return [16, 8, 4, 12, 20, 24, 32, 6, 5, 10]

    found: list[int] = []
    memory_hits: list[int] = []
    try:
        import angr as _angr

        proj = _angr.Project(str(path), auto_load_libs=False)
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64
                         if proj.arch.bits == 64 else capstone.CS_MODE_32)
        for sec in proj.loader.main_object.sections:
            if not getattr(sec, "is_executable", False) or not sec.memsize:
                continue
            code = proj.loader.memory.load(sec.vaddr, sec.memsize)
            insns = list(cs.disasm(code, sec.vaddr))
            for i, insn in enumerate(insns):
                if insn.mnemonic != "cmp":
                    continue
                m = re.match(r"^[^,]+, (0x[0-9a-f]+|\d+)$", insn.op_str)
                if not m:
                    continue
                value = int(m.group(1), 0)
                if 1 <= value <= limit:
                    window = insns[i + 1:i + 4]
                    if any(w.mnemonic.startswith("j") and w.mnemonic != "jmp" for w in window):
                        left = insn.op_str.split(",")[0]
                        if any(marker in left for marker in ("[", "PTR")):
                            memory_hits.append(value)
                        else:
                            found.append(value)
    except Exception:
        pass

    ordered: list[int] = []
    for value in memory_hits + [v for v in found if v >= 4] + found:
        if value not in ordered:
            ordered.append(value)
    for default in (16, 8, 12, 20, 4, 24, 32, 6, 10, 5, 3, 7, 9, 14, 18):
        if default not in ordered:
            ordered.append(default)
    return ordered

class SymbolicEngine:
    def __init__(self, path: str | Path, *, max_len: int = 64, verbose: bool = False,
                 string_oracle: bool = True):
        self.path = str(path)
        self.max_len = max_len
        self.string_oracle = string_oracle
        self.verbose = verbose

    def _project(self):
        project = angr.Project(
            self.path,
            auto_load_libs=False,
            load_options={"auto_load_libs": False},
        )
        _hook_windows_io(project)
        self.hooks = _hook_anti_debug(project)
        try:
            from xsolver.symbolic.wincrt import install_win_crt_hooks

            self.hooks += install_win_crt_hooks(project)
        except Exception:
            pass
        try:
            from .win32io import install_stdio_hooks, install_string_length_hooks

            self.hooks += install_stdio_hooks(project)
            self.hooks += install_string_length_hooks(project)
        except Exception:
            pass
        try:
            from .cppio import install_cpp_hooks

            self.hooks += install_cpp_hooks(project)
        except Exception:
            pass
        if self.string_oracle:
            from .win32io import install_string_hooks

            self.hooks += install_string_hooks(project)
        return project

    @staticmethod
    def _base_options():
        options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.LAZY_SOLVES,
        }
        return options

    def solve(
        self,
        *,
        prefix: bytes = b"",
        suffix: bytes = b"\n",
        lengths: list[int] | None = None,
        timeout: float = 120.0,
        mode: str = "auto",
        verify=None,
        extra_constraints=None,
        symbolic_read: dict | None = None,
        concrete_stdin: bytes | None = None,
    ) -> SymbolicOutcome:
        if angr is None:
            return SymbolicOutcome(False, detail=symbolic_unavailable_reason())

        started = time.monotonic()
        project = self._project()
        refs = CodeDataReferences(project)
        lose = refs.lose_addresses()

        explicit = refs.win_addresses()
        inferred = refs.infer_win_addresses()
        targets: list[int] = []
        for addr in explicit + inferred:
            if addr not in targets:
                targets.append(addr)
        if not targets:
            targets = [0]

        if mode == "auto":
            mode = self._detect_input_mode(project)

        plans = self._plans(lengths)
        attempts = 0
        last_detail = "no satisfying state"
        tried: list[str] = []

        if symbolic_read is not None:
            for target in targets:
                budget = timeout - (time.monotonic() - started)
                if budget <= 1.0:
                    last_detail = "budget spent before read attack"
                    break
                attempts += 1
                find = [target] if target else []
                outcome, detail = self._attempt_reads(
                    project, symbolic_read, concrete_stdin or prefix + suffix,
                    find, lose, budget, extra_constraints=extra_constraints,
                )
                if detail:
                    last_detail = detail
                if outcome is None:
                    continue
                outcome.elapsed = time.monotonic() - started
                outcome.attempts = attempts
                outcome.win_addresses = targets
                outcome.lose_addresses = lose
                if verify is not None and not verify(outcome.input_data):
                    tried.append(f"read rejected at 0x{target:x}: {outcome.input_data!r}")
                    continue
                return outcome

            return SymbolicOutcome(
                False, input_mode=mode, win_addresses=targets, lose_addresses=lose,
                elapsed=time.monotonic() - started, attempts=attempts,
                detail=last_detail + ((" | " + " ; ".join(tried)) if tried else ""),
            )

        if targets == [0]:
            for plan in plans[:6]:
                budget = timeout - (time.monotonic() - started)
                if budget <= 1.0:
                    break
                attempts += 1
                model, detail = self._attempt_inject_noanchor(
                    project, plan["length"], min(budget, 45.0),
                    prefix=prefix, suffix=suffix, printable=plan["printable"],
                    verify=verify,
                )
                if detail:
                    last_detail = detail
                if model is not None:
                    return SymbolicOutcome(
                        True,
                        input_data=model,
                        input_mode="stdin",
                        length=plan["length"],
                        detail=detail,
                        elapsed=time.monotonic() - started,
                        attempts=attempts,
                        win_addresses=[],
                        lose_addresses=lose,
                    )

        for target in targets:
            for plan in plans:
                budget = timeout - (time.monotonic() - started)
                if budget <= 1.0:
                    last_detail = "budget spent during injection"
                    break
                attempts += 1
                find = [target] if target else []
                outcome, detail = self._attempt_inject(
                    project, plan["length"], find, lose,
                    min(budget, plan.get("slice", 30.0)),
                    prefix=prefix, suffix=suffix, printable=plan["printable"],
                )
                if detail:
                    last_detail = detail
                if outcome is None:
                    continue
                outcome.elapsed = time.monotonic() - started
                outcome.attempts = attempts
                outcome.win_addresses = targets
                outcome.lose_addresses = lose
                if verify is not None and not verify(outcome.input_data):
                    tried.append(
                        f"injection rejected at 0x{target:x}: {outcome.input_data!r}"
                    )
                    continue
                return outcome
            if time.monotonic() - started >= timeout:
                break

        for target in targets:
            for plan in plans:
                budget = timeout - (time.monotonic() - started)
                if budget <= 1.0:
                    last_detail = "budget spent during exploration"
                    break
                attempts += 1
                find = [target] if target else []
                outcome, detail = self._attempt(
                    project, mode, prefix, suffix, plan["length"], find, lose,
                    min(budget, plan["slice"]),
                    printable=plan["printable"],
                    extra_constraints=extra_constraints,
                )
                if detail:
                    last_detail = detail
                if outcome is None:
                    continue
                outcome.elapsed = time.monotonic() - started
                outcome.attempts = attempts
                outcome.win_addresses = targets
                outcome.lose_addresses = lose
                if verify is not None and not verify(outcome.input_data):
                    tried.append(
                        f"candidate rejected at 0x{target:x}: {outcome.input_data!r}"
                    )
                    continue
                return outcome
            if time.monotonic() - started >= timeout:
                break

        return SymbolicOutcome(
            False,
            input_mode=mode,
            win_addresses=targets,
            lose_addresses=lose,
            elapsed=time.monotonic() - started,
            attempts=attempts,
            detail=last_detail + ((" | " + " ; ".join(tried)) if tried else ""),
        )

    def _plans(self, lengths: list[int] | None) -> list[dict]:
        guessed = lengths or guess_input_lengths(self.path)
        plans: list[dict] = []
        for length in guessed[:10]:
            if 1 <= length <= self.max_len:
                plans.append({"length": length, "printable": True, "slice": 25.0})
        for length in (24, 32, 16, 48, 20, 64):
            if length <= self.max_len:
                plans.append({"length": length, "printable": False, "slice": 40.0})
        return plans

    def _detect_input_mode(self, project) -> str:
        names = set()
        try:
            for sym in project.loader.main_object.symbols:
                names.add(sym.name)
            for _, sym in getattr(project.loader.main_object, "imports", {}).items():
                names.add(getattr(sym, "name", ""))
        except Exception:
            pass
        names = {n for n in names if n}

        stdin_markers = {
            "fgets", "gets", "scanf", "__isoc99_scanf", "getchar", "read",
            "ReadFile", "getline", "fread", "std::getline", "cin",
        }
        if names & stdin_markers:
            return "stdin"
        try:
            if "ReadFile" in names or project.loader.main_object.__class__.__name__ == "PE":
                return "stdin"
        except Exception:
            return "stdin"
        return "stdin"

    def _attempt(self, project, mode, prefix, suffix, length, find, lose, budget,
                 printable=True, extra_constraints=None):
        sym = claripy.BVS(f"xs_{mode}", length * 8)
        parts = [claripy.BVV(b, 8) for b in prefix]
        parts += [sym.get_byte(i) for i in range(length)]
        parts += [claripy.BVV(b, 8) for b in suffix]
        payload = claripy.Concat(*parts) if len(parts) > 1 else parts[0]

        try:
            state = project.factory.full_init_state(
                stdin=payload,
                add_options=self._base_options(),
            )
        except Exception as exc:
            return None, f"state failed: {exc}"

        state.globals["xs_inject"] = {
            "length": length,
            "prefix": prefix,
            "suffix": suffix,
            "printable": printable,
        }
        try:
            from xsolver.symbolic.cppio import prepare_cin_objects

            prepare_cin_objects(project, state)
        except Exception:
            pass

        if printable:
            for i in range(length):
                byte = sym.get_byte(i)
                state.solver.add(byte >= 0x20, byte <= 0x7E)
        if extra_constraints is not None:
            extra_constraints(state, sym, length)

        avoid = list(lose)

        simgr = project.factory.simgr(state)

        def body():
            if find:
                simgr.explore(find=find, avoid=avoid, num_find=1)
                if simgr.found:
                    return self._extract(simgr.found[0], length, prefix, suffix, mode), None
                detail = (
                    f"[len={length}] no state reached success "
                    f"({len(simgr.active)} live, {len(simgr.errored)} errors)"
                )
                return None, detail
            return self._differential(simgr, length, prefix, suffix, mode, budget)

        try:
            return _bounded(budget, body)
        except _Timeout:
            return None, f"[len={length}] timeout during exploration"
        except Exception as exc:
            return None, f"[len={length}] exploration error: {type(exc).__name__}: {exc}"

    def _failure_output(self, project, length, prefix, suffix) -> bytes:
        dummy = bytes(prefix) + b"A" * length + bytes(suffix)
        try:
            state = project.factory.full_init_state(stdin=dummy, add_options=self._base_options())
        except Exception:
            return b""
        simgr = project.factory.simgr(state)
        try:
            simgr.run(n=4000)
        except Exception:
            pass
        blobs = []
        for st in list(simgr.deadended) + list(simgr.active):
            try:
                blobs.append(st.posix.dumps(1))
            except Exception:
                continue
        return max(blobs, key=len) if blobs else b""

    def _attempt_inject_noanchor(self, project, length, budget, prefix=b"", suffix=b"\n",
                                 printable=True, verify=None, attempts=0):
        import time as _time

        started = _time.monotonic()
        failure = self._failure_output(project, length, prefix, suffix)
        failure_key = b" ".join(failure.lower().split())

        dummy = bytes(prefix) + b"A" * length + bytes(suffix)
        try:
            state = project.factory.full_init_state(stdin=dummy, add_options=self._base_options())
        except Exception as exc:
            return None, f"[no anchor len={length}] impossible state: {exc}"
        state.globals["xs_inject"] = {
            "length": length,
            "prefix": bytes(prefix),
            "suffix": bytes(suffix),
            "printable": printable,
        }
        simgr = project.factory.simgr(state)
        deadline = started + budget
        while simgr.active and _time.monotonic() < deadline:
            try:
                simgr.step()
            except Exception:
                break
            if len(simgr.active) > 6:
                simgr.active.sort(key=lambda s: len(s.solver.constraints), reverse=True)
                simgr.active = simgr.active[:6]

        seen = set()
        for st in list(simgr.deadended) + list(simgr.active):
            variables = st.globals.get("xs_vars") or []
            if not variables:
                continue
            try:
                model = bytes(int(st.solver.eval(v)) & 0xFF for v in variables)
            except Exception:
                continue
            if len(model) < 3 or model in seen:
                continue
            seen.add(model)
            try:
                output = b" ".join(st.posix.dumps(1).lower().split())
            except Exception:
                output = b""
            if not output or output == failure_key:
                continue
            if verify is not None and not verify(model):
                continue
            return model, f"[no anchor len={length}] output differs, {len(seen)} tested"
        return None, f"[no anchor len={length}] no conclusive model ({len(seen)} tested)"

    def _attempt_inject(self, project, length, find, lose, budget,
                        prefix=b"", suffix=b"\n", printable=True):
        dummy = bytes(prefix) + b"A" * length + bytes(suffix)
        try:
            state = project.factory.full_init_state(
                stdin=dummy, add_options=self._base_options()
            )
        except Exception as exc:
            return None, f"[inject len={length}] impossible state: {exc}"
        state.globals["xs_inject"] = {
            "length": length,
            "prefix": bytes(prefix),
            "suffix": bytes(suffix),
            "printable": printable,
        }
        simgr = project.factory.simgr(state)
        def body():
            if find:
                simgr.explore(find=find, avoid=list(lose), num_find=1)
                if simgr.found:
                    return self._extract_injected(simgr.found[0], length, prefix, suffix), None
                return None, (
                    f"[inject len={length}] no state reached success "
                    f"({len(simgr.active)} active, {len(simgr.errored)} errors)"
                )
            return self._differential(simgr, length, prefix, suffix, "inject", budget)

        try:
            return _bounded(budget, body)
        except _Timeout:
            return None, f"[inject len={length}] timeout"
        except Exception as exc:
            return None, f"[inject len={length}] error: {type(exc).__name__}: {exc}"

    def _extract_injected(self, state, length, prefix, suffix) -> SymbolicOutcome:
        variables = state.globals.get("xs_vars") or []
        middle = bytes(state.solver.eval(v) for v in variables) if variables else b""
        data = bytes(prefix) + middle + bytes(suffix).rstrip(b"\n")
        try:
            output = state.posix.dumps(1).decode("latin-1", "replace")
        except Exception:
            output = None
        return SymbolicOutcome(
            True,
            input_data=data,
            input_mode="stdin",
            length=length,
            detail=f"key by injection (len {length})",
            symbolic_output=output,
        )

    def _attempt_reads(self, project, spec, concrete_stdin, find, lose, budget,
                       extra_constraints=None):
        index = int(spec.get("start", spec.get("index", 0)))
        buffered = bytearray(concrete_stdin)
        if len(buffered) < 512:
            buffered.extend(b"\x00" * (512 - len(buffered)))
        try:
            state = project.factory.full_init_state(
                stdin=bytes(buffered), add_options=self._base_options()
            )
        except Exception as exc:
            return None, f"state failed: {exc}"

        state.globals["xsolver_symbolic_reads"] = {index: dict(spec)}
        state.globals["xsolver_read_count"] = 0
        if extra_constraints is not None:
            extra_constraints(state, None, int(spec["length"]))

        simgr = project.factory.simgr(state)
        def body():
            target = state
            if find:
                simgr.explore(find=find, avoid=list(lose), num_find=1)
                if not simgr.found:
                    return None, (
                        f"[read#{index} len={spec['length']}] success branch "
                        f"not reached ({len(simgr.active)} active states, "
                        f"{len(simgr.errored)} errors)"
                    )
                target = simgr.found[0]
            else:
                outcome, detail = self._differential(
                    simgr, int(spec["length"]), b"", b"", "read", budget
                )
                if outcome is None:
                    return None, detail
                target = outcome

            data = target.globals.get("xsolver_symread_data")
            if data is None:
                return None, f"[read#{index}] buffer not found"
            raw = target.solver.eval(data, cast_to=bytes)
            try:
                output = target.posix.dumps(1).decode("latin-1", "replace")
            except Exception:
                output = None
            return SymbolicOutcome(
                True, input_data=raw, input_mode="read",
                length=len(raw),
                detail=f"read #{index} solved ({len(raw)} bytes)",
                symbolic_output=output,
            ), None

        try:
            return _bounded(budget, body)
        except _Timeout:
            return None, f"[read#{index} len={spec['length']}] timeout"
        except Exception as exc:
            return None, f"[read#{index}] exploration error: {type(exc).__name__}: {exc}"

    def _differential(self, simgr, length, prefix, suffix, mode, budget):
        lose_snippets = (b"denied", b"wrong", b"incorrect", b"invalid", b"fail")
        seen = 0
        while simgr.active and seen < 400:
            simgr.step()
            seen += len(simgr.active)
            for state in list(simgr.deadended):
                try:
                    out = state.posix.dumps(1).lower()
                except Exception:
                    out = b""
                if out and not any(s in out for s in lose_snippets):
                    return self._extract(state, length, prefix, suffix, mode), None
        return None, f"[len={length}] no conclusive state"

    def _extract(self, state, length, prefix, suffix, mode) -> SymbolicOutcome:
        data = state.solver.eval(
            state.posix.stdin.load(0, len(prefix) + length + len(suffix)),
            cast_to=bytes,
        )
        try:
            output = state.posix.dumps(1).decode("latin-1", "replace")
        except Exception:
            output = None
        return SymbolicOutcome(
            True,
            input_data=data,
            input_mode=mode,
            length=length,
            detail=f"key by symbolic exec (len {length})",
            symbolic_output=output,
        )

class _Timeout(Exception):
    pass

_HAS_ALARM = (hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer")
              and not os.environ.get("XSOLVER_THREAD_TIMEOUT"))

def _bounded(seconds: float, body):
    if _HAS_ALARM:
        with _deadline(seconds):
            return body()
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = body()
        except BaseException as exc:
            box["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(max(1.0, seconds))
    if worker.is_alive():
        raise _Timeout()
    if "error" in box:
        raise box["error"]
    return box.get("value")

class _deadline:
    def __init__(self, seconds: float):
        self.seconds = max(1.0, seconds)
        self.previous = None

    def __enter__(self):
        def handler(signum, frame):
            raise _Timeout()

        self.previous = signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, self.seconds)
        return self

    def __exit__(self, exc_type, exc, tb):
        signal.setitimer(signal.ITIMER_REAL, 0)
        if self.previous is not None:
            signal.signal(signal.SIGALRM, self.previous)
        return False
