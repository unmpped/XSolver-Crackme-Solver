from __future__ import annotations

import angr
from angr import claripy

_BITS = 64

_SUCCESS_HINTS = (
    "_initterm_e",
    "_initterm",
    "_set_app_type",
    "_set_fmode",
    "_configthreadlocale",
    "_crt_atexit",
    "_register_onexit_function",
    "_initialize_narrow_environment",
    "_initialize_onexit_table",
    "_execute_onexit_table",
    "_set_new_handler",
    "_set_invalid_parameter_handler",
    "__crt_initialize_winrt",
    "_controlfp_s",
    "_fpreset",
    "__setusermatherr",
    "__std_exception_copy",
    "__std_exception_destroy",
)

_CELL_HINTS = {
    "__p___argc": 0x01,
    "__p___argv": 0x02,
    "__p__environ": 0x03,
    "_get_initial_narrow_environment": 0x04,
}

class Success0(angr.SimProcedure):
    def run(self, *args):
        return claripy.BVV(0, self.state.arch.bits)

class CellPointer(angr.SimProcedure):
    def __init__(self, kind: int):
        super().__init__()
        self.kind = kind

    def run(self, *args):
        state = self.state
        cells = state.globals.get("xs_crt_cells")
        if cells is None:
            cells = {}
            state.globals["xs_crt_cells"] = cells
        if self.kind not in cells:
            try:
                address = state.heap.allocate(0x80)
            except Exception:
                return claripy.BVV(0, state.arch.bits)
            if self.kind == 0x01:
                state.memory.store(address, claripy.BVV(0, 32), endness=state.arch.memory_endness)
            elif self.kind == 0x02:
                for offset in range(0, 0x20, 8):
                    state.memory.store(address + offset, claripy.BVV(0, 64),
                                       endness=state.arch.memory_endness)
            cells[self.kind] = address
        return claripy.BVV(cells[self.kind], state.arch.bits)

def install_win_crt_hooks(project) -> list[str]:
    installed: list[str] = []
    try:
        names = list(project.loader.main_object.imports.keys())
    except Exception:
        return installed
    for name in names:
        try:
            if name in _CELL_HINTS:
                project.hook_symbol(name, CellPointer(_CELL_HINTS[name]))
            elif any(hint == name or hint in name for hint in _SUCCESS_HINTS):
                project.hook_symbol(name, Success0())
            else:
                continue
            installed.append(name)
        except Exception:
            continue
    return installed
