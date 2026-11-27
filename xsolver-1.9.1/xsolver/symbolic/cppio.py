from __future__ import annotations

import angr
from angr import claripy

_GETC_PATTERNS = ("?sgetc@", "sgetcEv", "5sgetc")
_NEXTC_PATTERNS = ("?snextc@", "snextcEv", "6snextc")
_PUTC_PATTERNS = ("?sputc@", "sputcEc", "5sputc")
_PUTN_PATTERNS = ("?sputn@", "sputnEPKc", "5sputn")
_BENIGN_HINTS = ("?flush@", "?setstate@", "?widen@", "?good@", "?eof@", "?fail@",
                 "?_Ipfx@", "?_Getcat@", "?uncaught_exception@",
                 "?init@", "?tie@", "?rdbuf@")

def _matches(name: str, patterns) -> bool:
    return any(pattern in name for pattern in patterns)

def _input_byte(state, index: int):
    spec = state.globals.get("xs_inject") or {}
    length = spec.get("length", 0)
    printable = spec.get("printable", True)
    variables = state.globals.get("xs_vars")
    if variables is None:
        variables = []
        state.globals["xs_vars"] = variables
    if index >= length:
        return claripy.BVV(-1, 32)
    while len(variables) <= index:
        position = len(variables)
        variable = claripy.BVS(f"xs_{position}", 8)
        variables.append(variable)
        if printable:
            state.solver.add(variable >= 0x20, variable <= 0x7E)
    return variables[index].zero_extend(24)

class StreambufGetc(angr.SimProcedure):
    def __init__(self, advance: bool = False):
        super().__init__()
        self.advance = advance

    def run(self, this=None, *args):
        state = self.state
        counter = "xs_cpp_pos"
        if self.advance:
            position = state.globals.get(counter, 0)
            state.globals[counter] = position + 1
            return _input_byte(state, position)
        return _input_byte(state, state.globals.get(counter, 0))

def _emit(state, data, width: int = 8) -> None:
    chunks = state.globals.get("xs_cpp_stdout")
    if chunks is None:
        chunks = []
        state.globals["xs_cpp_stdout"] = chunks
    chunks.append(data)
    try:
        state.posix.stdout.write(0, data)
    except Exception:
        pass

class StreambufPutc(angr.SimProcedure):
    def run(self, this=None, char=None, *args):
        state = self.state
        if char is None:
            char = _argument(self, 1)
        if char is None:
            return claripy.BVV(0, 32)
        try:
            value = state.memory.load(char, 1) if state.solver.symbolic(char) else char
            _emit(state, value if value.size() == 8 else value[:8])
        except Exception:
            pass
        return claripy.BVV(0, 32)

class StreambufPutn(angr.SimProcedure):
    def run(self, this=None, buffer=None, count=None, *args):
        state = self.state
        if buffer is None:
            buffer = _argument(self, 1)
        if count is None:
            count = _argument(self, 2)
        if buffer is None or count is None:
            return claripy.BVV(0, state.arch.bits)
        try:
            size = state.solver.eval(count) if not state.solver.symbolic(count) else 0
            if size:
                data = state.memory.load(buffer, size)
                _emit(state, data)
        except Exception:
            pass
        return count

class BenignStub(angr.SimProcedure):
    def __init__(self, value: int = 0):
        super().__init__()
        self.value = value

    def run(self, *args, **kwargs):
        return claripy.BVV(self.value, self.state.arch.bits)

def install_cpp_hooks(project) -> list[str]:
    installed: list[str] = []
    names: list[str] = []
    try:
        for name in list(project.loader.main_object.imports.keys()):
            names.append(name)
    except Exception:
        pass
    try:
        for symbol in project.loader.main_object.symbols:
            if symbol.name:
                names.append(symbol.name)
    except Exception:
        pass

    hooked = set()
    for name in names:
        if not name or name in hooked:
            continue
        try:
            if _matches(name, _GETC_PATTERNS):
                project.hook_symbol(name, StreambufGetc(advance=False))
            elif _matches(name, _NEXTC_PATTERNS):
                project.hook_symbol(name, StreambufGetc(advance=True))
            elif _matches(name, _PUTN_PATTERNS):
                project.hook_symbol(name, StreambufPutn())
            elif _matches(name, _PUTC_PATTERNS):
                project.hook_symbol(name, StreambufPutc())
            elif "?getloc@" in name:
                project.hook_symbol(name, GetLoc())
            elif any(hint in name for hint in _BENIGN_HINTS):
                ready = ("good" in name) or ("_Ipfx" in name)
                project.hook_symbol(name, BenignStub(1 if ready else 0))
            else:
                continue
            hooked.add(name)
            installed.append(name)
        except Exception:
            continue
    _install_high_level_hooks(project, installed)
    return installed

_GETLINE_PATTERNS = ("_ZSt7getline", "?getline@")
_EXTRACT_STRING_PATTERNS = ("_ZStrsIcSt11char_traitsIcESaIcEE", "??5?$basic_istream@DU")
_PUTS_PATTERNS = ("_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc", "??6?$basic_ostream@DU")
_MANIPULATOR_PATTERNS = ("_ZNSolsEPFRSoS_E", "?operator<<")

_STRING_LAYOUTS = {
    "libstdcxx": (0, 8, 16, 15),
    "msvc": (0x0, 0x10, 0x0, 15),
}

def _argument(procedure, index: int):
    try:
        value = procedure.cc.arg(procedure.state, index)
        if value is not None:
            return value
    except Exception:
        pass
    state = procedure.state
    try:
        if state.arch.name == "AMD64":
            registers = (state.regs.rdi, state.regs.rsi, state.regs.rdx,
                         state.regs.rcx, state.regs.r8, state.regs.r9)
            return registers[index]
        if state.arch.name == "X86":
            pointer = state.regs.esp + 4 + 4 * index
            return state.memory.load(pointer, state.arch.bits // 8)
    except Exception:
        pass
    return None

def _plan_bytes(state) -> list:
    spec = state.globals.get("xs_inject") or {}
    length = spec.get("length", 0)
    printable = spec.get("printable", True)
    variables = state.globals.get("xs_vars")
    if variables is None:
        variables = []
        state.globals["xs_vars"] = variables
    while len(variables) < length:
        position = len(variables)
        variable = claripy.BVS(f"xs_{position}", 8)
        variables.append(variable)
        if printable:
            state.solver.add(variable >= 0x20, variable <= 0x7E)
    return list(variables[:length])

def _bvv(value, bits: int):
    return value if hasattr(value, "size") else claripy.BVV(value, bits)

def _store_string(state, string_ptr, data: list, layout: str) -> None:
    pointer_offset, size_offset, local_offset, local_capacity = _STRING_LAYOUTS[layout]
    endness = state.arch.memory_endness
    count = len(data)
    payload = claripy.Concat(*data) if count else claripy.BVV(0, 8)

    if count <= local_capacity:
        buffer_address = string_ptr + local_offset
        if layout == "msvc":
            state.memory.store(string_ptr + size_offset, _bvv(count, state.arch.bits), endness=endness)
            state.memory.store(string_ptr + size_offset + 8, _bvv(local_capacity, state.arch.bits), endness=endness)
            state.memory.store(buffer_address, payload)
            state.memory.store(buffer_address + count, claripy.BVV(0, 8))
            return
    else:
        try:
            buffer_address = state.heap.allocate(count + 1)
        except Exception:
            buffer_address = string_ptr + local_offset

    state.memory.store(string_ptr + pointer_offset, _bvv(buffer_address, state.arch.bits), endness=endness)
    state.memory.store(string_ptr + size_offset, _bvv(count, state.arch.bits), endness=endness)
    if layout == "msvc":
        state.memory.store(string_ptr + size_offset + 8, _bvv(count, state.arch.bits), endness=endness)
    state.memory.store(buffer_address, payload)
    state.memory.store(buffer_address + count, claripy.BVV(0, 8))

class StdGetline(angr.SimProcedure):
    def __init__(self, layout: str = "libstdcxx"):
        super().__init__()
        self.layout = layout

    def run(self, istream=None, string_ptr=None, delimiter=None, *args):
        state = self.state
        if istream is None:
            istream = _argument(self, 0)
        if string_ptr is None:
            string_ptr = _argument(self, 1)
        if string_ptr is None:
            return istream if istream is not None else claripy.BVV(0, state.arch.bits)
        try:
            data = _plan_bytes(state)
            _store_string(state, string_ptr, data, self.layout)
        except Exception:
            pass
        return istream if istream is not None else claripy.BVV(0, state.arch.bits)

class StdExtractString(angr.SimProcedure):
    def __init__(self, layout: str = "libstdcxx"):
        super().__init__()
        self.layout = layout

    def run(self, istream=None, string_ptr=None, *args):
        state = self.state
        if istream is None:
            istream = _argument(self, 0)
        if string_ptr is None:
            string_ptr = _argument(self, 1)
        if string_ptr is None:
            return istream if istream is not None else claripy.BVV(0, state.arch.bits)
        try:
            spec = state.globals.get("xs_inject") or {}
            data = _plan_bytes(state)
            if spec.get("printable", True):
                kept = []
                for byte in data:
                    if state.solver.symbolic(byte):
                        kept.append(byte)
                    else:
                        break
                data = kept
            _store_string(state, string_ptr, data, self.layout)
        except Exception:
            pass
        return istream if istream is not None else claripy.BVV(0, state.arch.bits)

class OstreamPutString(angr.SimProcedure):
    def run(self, ostream=None, text=None, *args):
        state = self.state
        if ostream is None:
            ostream = _argument(self, 0)
        if text is None:
            text = _argument(self, 1)
        if text is not None:
            try:
                chunks = []
                for offset in range(0, 512):
                    byte = state.memory.load(text + offset, 1)
                    if state.solver.symbolic(byte):
                        break
                    value = state.solver.eval(byte)
                    if value == 0:
                        break
                    chunks.append(byte)
                if chunks:
                    _emit(state, claripy.Concat(*chunks))
            except Exception:
                pass
        return ostream if ostream is not None else claripy.BVV(0, state.arch.bits)

class OstreamManipulator(angr.SimProcedure):
    def run(self, ostream=None, manipulator=None, *args):
        state = self.state
        if manipulator is None:
            manipulator = _argument(self, 1)
        try:
            if manipulator is not None and not state.solver.symbolic(manipulator):
                _emit(state, claripy.BVV(0x0A, 8))
        except Exception:
            pass
        return ostream if ostream is not None else claripy.BVV(0, state.arch.bits)

def _string_layout(project) -> str:
    try:
        for name in project.loader.main_object.imports:
            if name.startswith("?") or "msvcp" in name.lower():
                return "msvc"
    except Exception:
        pass
    return "libstdcxx"

def _install_high_level_hooks(project, installed: list[str]) -> None:
    layout = _string_layout(project)
    try:
        names = list(project.loader.main_object.imports.keys())
    except Exception:
        names = []
    for name in names:
        try:
            if _matches(name, _GETLINE_PATTERNS):
                project.hook_symbol(name, StdGetline(layout))
            elif _matches(name, _EXTRACT_STRING_PATTERNS):
                project.hook_symbol(name, StdExtractString(layout))
            elif _matches(name, _PUTS_PATTERNS):
                project.hook_symbol(name, OstreamPutString())
            elif _matches(name, _MANIPULATOR_PATTERNS):
                project.hook_symbol(name, OstreamManipulator())
            else:
                continue
            installed.append(name)
        except Exception:
            continue

_MSVC_VB_OFFSET = 0x100

class _NoOp(angr.SimProcedure):
    def __init__(self, value: int = 0):
        super().__init__()
        self.value = value

    def run(self, *args):
        return claripy.BVV(self.value, self.state.arch.bits)

def _is_msvc_binary(project) -> bool:
    try:
        return any(name.startswith("?") for name in project.loader.main_object.imports)
    except Exception:
        return False

def _import_slot(project, fragment: str) -> int | None:
    try:
        for name, reloc in project.loader.main_object.imports.items():
            if fragment in name:
                return getattr(reloc, "rebased_addr", None)
    except Exception:
        pass
    return None

def _write(state, address: int, value: int, size: int = 8) -> None:
    state.memory.store(
        address,
        claripy.BVV(value & ((1 << (size * 8)) - 1), size * 8),
        endness=state.arch.memory_endness,
    )

def _ctype_table(state, address: int) -> None:
    for code in range(256):
        mask = 0
        if code in (0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D):
            mask = 0x0048
        elif 0x21 <= code <= 0x7E:
            mask = 0x0400 | 0x0200
            if 0x30 <= code <= 0x39:
                mask |= 0x0084
            elif 0x41 <= code <= 0x5A:
                mask |= 0x0101
            elif 0x61 <= code <= 0x7A:
                mask |= 0x0102
        elif code < 0x20:
            mask = 0x0010
        _write(state, address + code * 2, mask, size=2)

def prepare_cin_objects(project, state) -> dict | None:
    existing = state.globals.get("xs_cpp_objects")
    if existing:
        return existing
    if not _is_msvc_binary(project):
        return None

    base = (project.loader.main_object.mapped_base + 0x200000) & ~0xFFF
    vbtable_cin = base + 0x000
    vbtable_cout = base + 0x020
    cin = base + 0x100
    cout = base + 0x300
    buffer_cin = base + 0x500
    buffer_cout = base + 0x580
    vtable = base + 0x600
    locale = base + 0x700
    locimp = base + 0x740
    facets = base + 0x7A0
    facet = base + 0x9A0
    ctype = base + 0xA00
    stub = base + 0x1000

    try:
        if not project.is_hooked(stub):
            project.hook(stub, _NoOp(0))
    except Exception:
        return None

    try:
        _write(state, vbtable_cin, 0, size=8)
        _write(state, vbtable_cin + 4, _MSVC_VB_OFFSET, size=4)
        _write(state, vbtable_cout, 0, size=8)
        _write(state, vbtable_cout + 4, _MSVC_VB_OFFSET, size=4)

        for slot in range(32):
            _write(state, vtable + slot * 8, stub)

        for buffer in (buffer_cin, buffer_cout):
            _write(state, buffer, vtable)
            _write(state, buffer + 8, 0)

        for stream, vbtable, buffer in (
            (cin, vbtable_cin, buffer_cin),
            (cout, vbtable_cout, buffer_cout),
        ):
            _write(state, stream, vbtable)
            ios = stream + _MSVC_VB_OFFSET
            _write(state, ios, vtable)
            _write(state, ios + 0x28, 0)
            _write(state, ios + 0x30, 0)
            _write(state, ios + 0x48, buffer)
            _write(state, ios + 0x50, 0)

        _write(state, locale + 0, locimp)
        _write(state, locale + 8, locimp)
        _write(state, locimp + 0x00, vtable)
        _write(state, locimp + 0x10, facets)
        _write(state, locimp + 0x18, 512)
        for index in range(64):
            _write(state, facets + index * 8, facet)
        _write(state, facet + 0x00, vtable)
        _write(state, facet + 0x18, ctype)
        _ctype_table(state, ctype)

        info = {
            "base": base,
            "cin": cin,
            "cout": cout,
            "locale": locale,
            "locimp": locimp,
            "vtable": vtable,
            "stub": stub,
        }
        for fragment, stream in (("?cin@", cin), ("?cout@", cout)):
            slot = _import_slot(project, fragment)
            if slot is not None:
                _write(state, slot, stream)
                info[fragment] = slot
        state.globals["xs_cpp_objects"] = info
        return info
    except Exception:
        return None

class GetLoc(angr.SimProcedure):
    def run(self, ios=None, *args):
        state = self.state
        buffer = _argument(self, 0)
        try:
            info = state.globals.get("xs_cpp_objects")
            if info is None:
                if ios is None:
                    ios = _argument(self, 1)
                info = prepare_cin_objects(self.project, state)
            if info is not None and buffer is not None:
                _write(state, buffer + 0, info["locimp"])
                _write(state, buffer + 8, info["locimp"])
                return buffer
        except Exception:
            pass
        return buffer if buffer is not None else claripy.BVV(0, state.arch.bits)
