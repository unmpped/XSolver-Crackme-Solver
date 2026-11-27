from __future__ import annotations

import angr
from angr import claripy

STD_INPUT_HANDLE = 0x100
STD_OUTPUT_HANDLE = 0x101
STD_ERROR_HANDLE = 0x102

class ReadFile(angr.SimProcedure):
    def run(self, hFile, lpBuffer, nBytesToRead, lpNumberOfBytesRead, lpOverlapped):
        st = self.state
        specs = st.globals.get("xsolver_symbolic_reads")
        index = st.globals.get("xsolver_read_count", 0)
        st.globals["xsolver_read_count"] = index + 1
        if st.globals.get("xs_inject"):
            capacity = 0x200 if st.solver.symbolic(nBytesToRead) else max(2, st.solver.eval(nBytesToRead))
            written = _inject_into(st, lpBuffer, capacity)
            if written:
                if lpNumberOfBytesRead is not None and not st.solver.symbolic(lpNumberOfBytesRead):
                    try:
                        st.memory.store(lpNumberOfBytesRead, claripy.BVV(written, 32),
                                        endness=st.arch.memory_endness, disable_actions=True)
                    except Exception:
                        pass
                return 1
        spec = self._spec_for(specs, index)
        if spec is not None:
            return self._symbolic_read(spec, lpBuffer, lpNumberOfBytesRead, index)

        offset = self.state.globals.get("xsolver_stdin_offset", 0)
        if self.state.solver.symbolic(nBytesToRead):
            count = min(1024, self.state.solver.max(nBytesToRead))
        else:
            count = self.state.solver.eval(nBytesToRead)
        count = max(0, min(count, 4096))

        data = self.state.posix.stdin.load(offset, count)
        self.state.memory.store(
            lpBuffer, data, endness=self.state.arch.memory_endness, disable_actions=True
        )
        if lpNumberOfBytesRead is not None and self.state.solver.is_true(lpNumberOfBytesRead != 0):
            self.state.memory.store(
                lpNumberOfBytesRead,
                claripy.BVV(count, 32),
                endness=self.state.arch.memory_endness,
                disable_actions=True,
            )
        self.state.globals["xsolver_stdin_offset"] = offset + count
        return 1 if count else 0

    @staticmethod
    def _spec_for(specs, index):
        if not isinstance(specs, dict):
            return None
        if index in specs:
            return specs[index]
        for spec in specs.values():
            start = int(spec.get("start", 0))
            if start <= index < start + int(spec.get("length", 0)):
                return spec
        return None

    def _symbolic_read(self, spec, lpBuffer, lpNumberOfBytesRead, index):
        st = self.state
        length = int(spec["length"])
        start = int(spec.get("start", 0))
        data = st.globals.get("xsolver_symread_data")
        if data is None:
            data = claripy.BVS(spec.get("name", "xs_read"), length * 8)
            st.globals["xsolver_symread_data"] = data
            st.globals["xsolver_symread_len"] = length
            alphabet = spec.get("alphabet")
            fixed = spec.get("fixed") or {}
            for i in range(length):
                byte = data.get_byte(i)
                if i in fixed:
                    st.solver.add(byte == claripy.BVV(fixed[i], 8))
                elif alphabet:
                    st.solver.add(
                        claripy.Or(*(byte == claripy.BVV(c, 8) for c in alphabet))
                    )

        pos = index - start
        if pos < 0:
            byte = claripy.BVV(0, 8)
        elif pos < length:
            byte = data.get_byte(pos)
        else:
            byte = claripy.BVV(0, 8)
        st.memory.store(lpBuffer, byte, disable_actions=True)
        if lpNumberOfBytesRead is not None and st.solver.is_true(lpNumberOfBytesRead != 0):
            st.memory.store(lpNumberOfBytesRead, claripy.BVV(1, 32),
                            endness=st.arch.memory_endness, disable_actions=True)
        return 1

class WriteFile(angr.SimProcedure):
    def run(self, hFile, lpBuffer, nBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
        if self.state.solver.symbolic(nBytesToWrite):
            count = min(4096, self.state.solver.max(nBytesToWrite))
        else:
            count = self.state.solver.eval(nBytesToWrite)
        count = max(0, min(count, 4096))

        data = self.state.memory.load(lpBuffer, count)
        chunks = self.state.globals.get("xsolver_stdout")
        if chunks is None:
            chunks = []
            self.state.globals["xsolver_stdout"] = chunks
        chunks.append(data)

        try:
            self.state.posix.stdout.write(0, data)
        except Exception:
            pass

        if lpNumberOfBytesWritten is not None and self.state.solver.is_true(lpNumberOfBytesWritten != 0):
            self.state.memory.store(
                lpNumberOfBytesWritten,
                claripy.BVV(count, 32),
                endness=self.state.arch.memory_endness,
                disable_actions=True,
            )
        return 1

class WriteConsole(angr.SimProcedure):
    def __init__(self, wide: bool = False):
        super().__init__()
        self.wide = wide

    def run(self, hConsole, lpBuffer, nChars, lpCharsWritten=None, *rest):
        st = self.state
        if st.solver.symbolic(nChars):
            count = min(4096, st.solver.max(nChars))
        else:
            count = st.solver.eval(nChars)
        count = max(0, min(count, 4096))
        if self.wide:
            data = claripy.Concat(*[
                st.memory.load(lpBuffer + 2 * index, 1, endness="Iend_LE") for index in range(count)
            ]) if count else claripy.BVV(b"")
        else:
            data = st.memory.load(lpBuffer, count)
        try:
            st.posix.stdout.write(0, data)
        except Exception:
            pass
        if lpCharsWritten is not None and not st.solver.symbolic(lpCharsWritten):
            try:
                st.memory.store(lpCharsWritten, claripy.BVV(count, 32),
                                endness=st.arch.memory_endness, disable_actions=True)
            except Exception:
                pass
        return 1

class ConstantTime(angr.SimProcedure):
    def __init__(self, value: int = 0):
        super().__init__(None)
        self._value = value

    def run(self, *args, **kwargs):
        return claripy.BVV(self._value, self.state.arch.bits)

class AlwaysFalse(angr.SimProcedure):
    def run(self, *args, **kwargs):
        if len(args) >= 2 and args[1] is not None and self.state.solver.is_true(args[1] != 0):
            self.state.memory.store(args[1], claripy.BVV(0, 32), disable_actions=True)
        return 0

def install_io_hooks(project) -> None:
    for name in ("ReadFile",):
        project.hook_symbol(name, ReadFile())
    for name, wide in (("ReadConsoleA", False), ("ReadConsoleW", True)):
        try:
            if project.loader.find_symbol(name) is not None:
                project.hook_symbol(name, ReadConsole(wide=wide))
        except Exception:
            pass
    for name in ("WriteFile",):
        project.hook_symbol(name, WriteFile())
    for name, wide in (("WriteConsoleA", False), ("WriteConsoleW", True)):
        try:
            if project.loader.find_symbol(name) is not None:
                project.hook_symbol(name, WriteConsole(wide=wide))
        except Exception:
            pass

    for name in ("GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
                 "GetSystemTimeAsFileTime", "timeGetTime", "clock"):
        try:
            project.hook_symbol(name, ConstantTime(0))
        except Exception:
            pass

    for name in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                 "NtQueryInformationProcess"):
        try:
            project.hook_symbol(name, AlwaysFalse())
        except Exception:
            pass

def _inject_into(state, buffer, capacity: int, wide: bool = False):
    spec = state.globals.get("xs_inject")
    if not spec:
        return None
    prefix = spec.get("prefix", b"")
    suffix = spec.get("suffix", b"\n")
    length = spec["length"]
    printable = spec.get("printable", True)
    variables = []

    if wide:
        cursor = 0
        for index in range(length):
            variable = claripy.BVS(f"xsw_{index}", 16)
            variables.append(variable)
            state.memory.store(buffer + cursor, variable, endness="Iend_LE")
            if printable:
                state.solver.add(variable >= 0x20, variable <= 0x7E)
            cursor += 2
        state.memory.store(buffer + cursor, claripy.BVV(0, 16), endness="Iend_LE")
        cursor += 2
        state.globals["xs_vars"] = variables
        return cursor

    cursor = 0
    for byte in prefix:
        state.memory.store(buffer + cursor, claripy.BVV(byte, 8))
        cursor += 1
    for index in range(length):
        variable = claripy.BVS(f"xs_{index}", 8)
        variables.append(variable)
        state.memory.store(buffer + cursor, variable)
        if printable:
            state.solver.add(variable >= 0x20, variable <= 0x7E)
        cursor += 1
    if cursor < capacity:
        for byte in suffix:
            state.memory.store(buffer + cursor, claripy.BVV(byte, 8))
            cursor += 1
    state.memory.store(buffer + cursor, claripy.BVV(0, 8))
    state.globals["xs_vars"] = variables
    return cursor

class ReadConsole(angr.SimProcedure):
    def __init__(self, wide: bool = False):
        super().__init__()
        self.wide = wide

    def run(self, hConsole, lpBuffer, nChars, lpNumberOfCharsRead=None, *rest):
        st = self.state
        if st.solver.symbolic(nChars):
            capacity = 0x100
        else:
            capacity = max(2, st.solver.eval(nChars)) * (2 if self.wide else 1)
        written = _inject_into(st, lpBuffer, capacity, wide=self.wide)
        if written is None:
            return 1
        count = len(st.globals.get("xs_vars") or [])
        if lpNumberOfCharsRead is not None and not st.solver.symbolic(lpNumberOfCharsRead):
            try:
                st.memory.store(lpNumberOfCharsRead, claripy.BVV(count, 32),
                                endness=st.arch.memory_endness, disable_actions=True)
            except Exception:
                pass
        return 1

class GuestReadLine(angr.SimProcedure):
    def __init__(self, spec: dict):
        super().__init__(None)
        self.spec = spec

    def run(self, *args):
        st = self.state
        buf, maxlen, errptr = st.regs.rcx, st.regs.rdx, st.regs.r8
        if args and len(args) >= 2:
            buf, maxlen = args[0], args[1]
            errptr = args[2] if len(args) >= 3 else None
        index = st.globals.get("xsolver_readline_count", 0)
        st.globals["xsolver_readline_count"] = index + 1
        if index != int(self.spec.get("call", 1)):
            return self._concrete_line(buf, maxlen, errptr)

        length = int(self.spec["length"])
        data = st.globals.get("xsolver_symread_data")
        if data is None:
            data = claripy.BVS(self.spec.get("name", "xs_read"), length * 8)
            st.globals["xsolver_symread_data"] = data
            st.globals["xsolver_symread_len"] = length
            alphabet = self.spec.get("alphabet")
            fixed = self.spec.get("fixed") or {}
            for i in range(length):
                byte = data.get_byte(i)
                if i in fixed:
                    st.solver.add(byte == claripy.BVV(fixed[i], 8))
                elif alphabet:
                    st.solver.add(claripy.Or(*(byte == claripy.BVV(c, 8) for c in alphabet)))
        st.memory.store(buf, data, disable_actions=True)
        st.memory.store(buf + length, claripy.BVV(0, 8), disable_actions=True)
        if errptr is not None and st.solver.is_true(errptr != 0):
            st.memory.store(errptr, claripy.BVV(0, 32), endness=st.arch.memory_endness,
                            disable_actions=True)
        return claripy.BVV(length, st.arch.bits)

    def _concrete_line(self, buf, maxlen, errptr=None):
        st = self.state
        try:
            limit = min(4096, max(1, st.solver.eval(maxlen)))
        except Exception:
            limit = 256
        written = 0
        for i in range(limit):
            offset = st.globals.get("xsolver_stdin_offset", 0)
            try:
                byte = st.posix.stdin.load(offset, 1)
                value = st.solver.eval(byte)
            except Exception:
                break
            st.globals["xsolver_stdin_offset"] = offset + 1
            if value in (0x00, 0x0A, 0x0D):
                break
            st.memory.store(buf + i, byte, disable_actions=True)
            written += 1
        st.memory.store(buf + written, claripy.BVV(0, 8), disable_actions=True)
        if errptr is not None and st.solver.is_true(errptr != 0):
            st.memory.store(errptr, claripy.BVV(0, 32), endness=st.arch.memory_endness,
                            disable_actions=True)
        return claripy.BVV(written, st.arch.bits)

def install_readline_hook(project, address: int, spec: dict) -> None:
    project.hook(address, GuestReadLine(spec), length=0)

class CompareOracle(angr.SimProcedure):
    def __init__(self, pairs=None, return_value=0, stack_slots=(0x28, 0x30, 0x38, 0x40)):
        super().__init__(None)
        self.pairs = pairs
        self.return_value = return_value
        self.stack_slots = stack_slots

    def _arguments(self):
        st = self.state
        values = [st.regs.rcx, st.regs.rdx, st.regs.r8, st.regs.r9]
        for offset in self.stack_slots:
            try:
                values.append(st.memory.load(st.regs.rsp + offset, 8,
                                             endness=st.arch.memory_endness))
            except Exception:
                break
        return values

    def run(self, *args):
        st = self.state
        values = self._arguments()
        pairs = self.pairs
        if pairs is None:
            half = len(values) // 2
            pairs = [(i, i + half) for i in range(half)]
        for left, right in pairs:
            if left < len(values) and right < len(values):
                st.solver.add(values[left] == values[right])
        return claripy.BVV(self.return_value, st.arch.bits)

def find_readline_wrapper(project, imports=("ReadFile", "fgets", "fread", "read")):
    targets = set()
    for name in imports:
        try:
            sym = project.loader.find_symbol(name)
        except Exception:
            sym = None
        if sym is not None:
            targets.add(sym.rebased_addr)
            for reloc in getattr(sym, "reverse_symbols", []) or []:
                try:
                    targets.add(reloc.rebased_addr)
                except Exception:
                    pass
    if not targets:
        return None

    best = None
    try:
        cfg = project.analyses.CFGFast(normalize=True, data_references=False,
                                       resolve_indirect_jumps=False)
    except Exception:
        return None
    for func in cfg.functions.values():
        try:
            block = project.factory.block(func.addr)
        except Exception:
            continue
        for ins in block.capstone.insns:
            if ins.mnemonic == "call" and ins.operands:
                op = ins.operands[0]
                if getattr(op, "type", None) == 2 and op.imm in targets:
                    size = func.size or 0x10000
                    if best is None or size < best[1]:
                        best = (func.addr, size)
    return best[0] if best else None

def _hex_value_of(byte):
    upper = byte - claripy.BVV(0x37, 8)
    lower = byte - claripy.BVV(0x57, 8)
    digit = byte - claripy.BVV(0x30, 8)
    return claripy.If(
        claripy.And(byte >= 0x30, byte <= 0x39), digit,
        claripy.If(
            claripy.And(byte >= 0x41, byte <= 0x46), upper,
            claripy.If(claripy.And(byte >= 0x61, byte <= 0x66), lower,
                       claripy.BVV(0xFF, 8)),
        ),
    )

class HexGroupHook(angr.SimProcedure):
    def __init__(self, digits: int = 4, out_bits: int = 16):
        super().__init__(None)
        self.digits = digits
        self.out_bits = out_bits

    def run(self, *args):
        st = self.state
        ptr, out_ptr = st.regs.rcx, st.regs.rdx
        if args and len(args) >= 2:
            ptr, out_ptr = args[0], args[1]
        value = claripy.BVV(0, self.out_bits)
        valid = claripy.BVV(1, 1)
        for i in range(self.digits):
            byte = st.memory.load(ptr + i, 1)
            nibble = claripy.ZeroExt(self.out_bits - 8, _hex_value_of(byte))
            value = (value << 4) | nibble
            valid = valid & claripy.If(
                claripy.Or(
                    claripy.And(byte >= 0x30, byte <= 0x39),
                    claripy.Or(
                        claripy.And(byte >= 0x41, byte <= 0x46),
                        claripy.And(byte >= 0x61, byte <= 0x66),
                    ),
                ),
                claripy.BVV(1, 1),
                claripy.BVV(0, 1),
            )
        if out_ptr is not None and st.solver.is_true(out_ptr != 0):
            st.memory.store(out_ptr, value, endness=st.arch.memory_endness,
                            disable_actions=True)
        return claripy.If(valid == 1, claripy.BVV(1, st.arch.bits),
                          claripy.BVV(0, st.arch.bits))

def find_hex_group_parser(project):
    candidates = []
    try:
        cfg = project.analyses.CFGFast(normalize=True, data_references=False)
    except Exception:
        return None
    wanted = {0x30, 0x39, 0x41, 0x46}
    for func in cfg.functions.values():
        seen = set()
        try:
            for block in func.blocks:
                for ins in block.capstone.insns:
                    if ins.mnemonic.startswith("cmp"):
                        for op in ins.operands:
                            if getattr(op, "type", None) == 2:
                                seen.add(op.imm & 0xFF)
        except Exception:
            continue
        if wanted <= seen and (func.size or 0) < 0x400:
            candidates.append((func.size or 0, func.addr))
    candidates.sort()
    return candidates[0][1] if candidates else None

class FixedReturn(angr.SimProcedure):
    def __init__(self, value: int = 0):
        super().__init__(None)
        self.value = value

    def run(self, *args, **kwargs):
        return claripy.BVV(self.value, self.state.arch.bits)

def install_win32_stubs(project) -> list[str]:
    installed = []
    stubs = {
        "GetModuleHandleA": 0x140000000,
        "GetModuleHandleW": 0x140000000,
        "GetModuleHandleExA": 1,
        "GetModuleHandleExW": 1,
        "GetProcAddress": 0,
        "LoadLibraryA": 0x140000000,
        "LoadLibraryW": 0x140000000,
        "VirtualProtect": 1,
        "VirtualQuery": 1,
        "GetCommandLineA": 0x140000000,
        "GetCommandLineW": 0x140000000,
    }
    for name, value in stubs.items():
        try:
            project.hook_symbol(name, FixedReturn(value))
            installed.append(name)
        except Exception:
            pass
    return installed

class StrCmpOracle(angr.SimProcedure):
    def __init__(self, limit: int = 256, fixed_length: int | None = None,
                 return_value: int = 0):
        super().__init__(None)
        self.limit = limit
        self.fixed_length = fixed_length
        self.return_value = return_value

    def run(self, *args):
        st = self.state
        left, right = st.regs.rcx, st.regs.rdx
        if args and len(args) >= 2:
            left, right = args[0], args[1]

        maximum = self.fixed_length or self.limit
        for index in range(maximum):
            low = st.memory.load(left + index, 1)
            high = st.memory.load(right + index, 1)
            st.solver.add(low == high)
            concrete_side = None
            for value in (high, low):
                if not st.solver.symbolic(value):
                    concrete_side = st.solver.eval(value)
                    break
            if concrete_side is not None and concrete_side == 0 and self.fixed_length is None:
                break
        return claripy.BVV(self.return_value, st.arch.bits)

def install_string_hooks(project) -> list[str]:
    installed = []
    for name in ("strcmp", "strncmp", "memcmp", "_strcmp", "_strncmp", "lstrcmpA"):
        try:
            if project.loader.find_symbol(name) is None:
                continue
            project.hook_symbol(name, StrCmpOracle())
            installed.append(name)
        except Exception:
            pass
    return installed

def _read_one(state, offset: int):
    stream = state.posix.stdin
    reader = getattr(stream, "read", None)
    if reader is not None:
        result = reader(offset, 1)
        if isinstance(result, tuple):
            return result[0], result[1]
        return result, 1
    result = stream.read_data(offset, 1)
    return result[0], result[1]

class WinFgets(angr.SimProcedure):
    def run(self, dst, size, stream=None):
        st = self.state
        spec = st.globals.get("xs_inject")
        if spec:
            prefix = spec.get("prefix", b"")
            suffix = spec.get("suffix", b"\n")
            length = spec["length"]
            variables = []
            cursor = 0
            for byte in prefix:
                st.memory.store(dst + cursor, claripy.BVV(byte, 8))
                cursor += 1
            for index in range(length):
                variable = claripy.BVS(f"xs_{index}", 8)
                variables.append(variable)
                st.memory.store(dst + cursor, variable)
                if spec.get("printable", True):
                    st.solver.add(variable >= 0x20, variable <= 0x7E)
                cursor += 1
            for byte in suffix:
                st.memory.store(dst + cursor, claripy.BVV(byte, 8))
                cursor += 1
            st.memory.store(dst + cursor, claripy.BVV(0, 8))
            st.globals["xs_vars"] = variables
            return dst
        limit = st.solver.eval(size) if not st.solver.symbolic(size) else 0x40
        count = 0
        while count < max(limit - 1, 1):
            try:
                data, real = _read_one(st, count)
            except Exception:
                break
            if st.solver.is_true(real == 0):
                break
            st.memory.store(dst + count, data)
            count += 1
            if st.solver.is_true(data == b"\n"):
                break
        st.memory.store(dst + count, claripy.BVV(0, 8))
        return dst

def install_stdio_hooks(project) -> list[str]:
    installed = []
    for name, proc in (
        ("fgets", WinFgets()),
        ("gets", WinFgets()),
    ):
        try:
            if project.loader.find_symbol(name) is None:
                continue
            project.hook_symbol(name, proc)
            installed.append(name)
        except Exception:
            pass
    return installed

def _proven_value(state, expr, hint: int):
    try:
        if not state.solver.symbolic(expr):
            return state.solver.eval(expr), True
        if state.solver.satisfiable() and state.solver.is_true(expr == state.solver.eval(expr)):
            return state.solver.eval(expr), True
    except Exception:
        pass
    return hint, False

class WinStrlen(angr.SimProcedure):
    def run(self, buf):
        st = self.state
        for index in range(512):
            try:
                byte = st.memory.load(buf + index, 1)
            except Exception:
                return claripy.BVV(0, st.arch.bits)
            if st.solver.is_true(byte == 0):
                return claripy.BVV(index, st.arch.bits)
            if st.solver.satisfiable(extra_constraints=[byte == 0]):
                if st.solver.satisfiable(extra_constraints=[byte != 0]):
                    st.solver.add(byte != 0)
                    continue
                return claripy.BVV(index, st.arch.bits)
        return claripy.BVV(512, st.arch.bits)

class WinStrCspn(angr.SimProcedure):
    def run(self, buf, reject=None):
        st = self.state
        separators = set()
        if reject is not None and not st.solver.symbolic(reject):
            try:
                pointer = st.solver.eval(reject)
                for offset in range(8):
                    byte = st.solver.eval(st.memory.load(pointer + offset, 1))
                    if byte == 0:
                        break
                    separators.add(byte)
            except Exception:
                separators = {0x0A, 0x0D}
        if not separators:
            separators = {0x0A, 0x0D}
        for index in range(512):
            try:
                byte = st.memory.load(buf + index, 1)
            except Exception:
                return claripy.BVV(index, st.arch.bits)
            if st.solver.is_true(byte == 0):
                return claripy.BVV(index, st.arch.bits)
            value, certain = _proven_value(st, byte, 0)
            if certain and value in separators:
                return claripy.BVV(index, st.arch.bits)
            if certain:
                continue
            st.solver.add(byte != 0x0A, byte != 0x0D)
        return claripy.BVV(512, st.arch.bits)

def install_string_length_hooks(project) -> list[str]:
    installed = []
    for name, proc in (("strlen", WinStrlen()), ("strcspn", WinStrCspn())):
        try:
            if project.loader.find_symbol(name) is None:
                continue
            project.hook_symbol(name, proc)
            installed.append(name)
        except Exception:
            pass
    return installed
