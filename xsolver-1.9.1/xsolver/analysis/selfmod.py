from __future__ import annotations

import re

from xsolver.analysis.disasm import disassemble_functions_recursive
from xsolver.core.binary import BinaryProfile

_REG_ONLY_RE = re.compile(r"^(\w+)$")

_BYTE_SUBREGS = {
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
}

def detect_self_modifying_code(profile: BinaryProfile) -> list[str]:
    functions = disassemble_functions_recursive(profile)
    findings: list[str] = []

    for name, insns in functions.items():
        has_backward_branch = False
        has_byte_store_to_computed_address = False
        indirect_transfers: list["object"] = []

        for insn in insns:
            if insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
                target_match = re.match(r"^0x[0-9a-fA-F]+$", insn.op_str.strip())
                if target_match and int(insn.op_str, 16) < insn.address:
                    has_backward_branch = True

            if insn.mnemonic == "mov" and insn.op_str.startswith("byte ptr ["):
                source = insn.op_str.split(",", 1)[1].strip() if "," in insn.op_str else ""
                if source in _BYTE_SUBREGS:
                    has_byte_store_to_computed_address = True

            if insn.mnemonic in ("call", "jmp"):
                operand = insn.op_str.strip()
                if _REG_ONLY_RE.match(operand) and not operand.lower().startswith("0x"):
                    indirect_transfers.append(insn)

        if has_backward_branch and has_byte_store_to_computed_address and indirect_transfers:
            targets = ", ".join(f"0x{i.address:x} ({i.mnemonic} {i.op_str})" for i in indirect_transfers)
            findings.append(
                f"[{name}] memory writes then indirect jump ({targets}): likely runtime decryption"
            )

    return findings
