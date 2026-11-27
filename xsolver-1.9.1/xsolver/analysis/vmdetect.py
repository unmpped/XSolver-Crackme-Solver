from __future__ import annotations

import re

from xsolver.analysis.disasm import (
    AddressSpace,
    _all_sections,
    _resolve_jump_tables,
    disassemble_functions_recursive,
    executable_sections,
)
from xsolver.core.binary import BinaryProfile

_SCALED_INDEX_RE = re.compile(r"\*\s*[248]\s*\]")
_BARE_REG_RE = re.compile(r"^\w+$")

def detect_vm_dispatchers(profile: BinaryProfile) -> list[str]:
    functions = disassemble_functions_recursive(profile)
    if not functions:
        return []

    code_space = AddressSpace(executable_sections(profile))
    data_space = AddressSpace(_all_sections(profile))

    findings: list[str] = []
    for name, insns in functions.items():
        if not insns:
            continue

        has_backward_branch = any(
            insn.mnemonic.startswith("j")
            and insn.op_str.strip().startswith("0x")
            and int(insn.op_str, 16) < insn.address
            for insn in insns
        )
        if not has_backward_branch:
            continue

        has_scaled_table_read = any(_SCALED_INDEX_RE.search(insn.op_str) for insn in insns)

        bare_indirect_transfers = [
            insn for insn in insns
            if insn.mnemonic in ("call", "jmp")
            and _BARE_REG_RE.match(insn.op_str.strip())
            and not insn.op_str.strip().lower().startswith("0x")
        ]

        tables = _resolve_jump_tables(insns, data_space, code_space)

        if tables:
            widest = max(tables.values(), key=len)
            findings.append(
                f"[{name}] {len(widest)}-entry jump table in a loop"
            )
        elif has_scaled_table_read and bare_indirect_transfers:
            findings.append(
                f"[{name}] handler from a table, indirect jump"
            )
        else:
            continue

        findings[-1] += " ; instruction-count-oracle can still walk it byte by byte"

    return findings
