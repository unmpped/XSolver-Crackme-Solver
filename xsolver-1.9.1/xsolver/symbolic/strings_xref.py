from __future__ import annotations

from dataclasses import dataclass, field

import capstone

WIN_KEYWORDS = (
    "granted", "correct", "success", "congrat", "well done", "welldone",
    "unlocked", "you win", "winner", "solved", "nice work", "good job",
    "access ok", "authenticated", "valid", "bravo", "bien joue", "felicidades",
    "flag", "yea", "yep", "flag{", "flag :", "flag:", "discord", "eureka",
    "perfect", "awesome", "excellent", "welcome", "cracked", "unlocked",
    "right answer", "password ok", "accepted", "access granted", "you did it",
    "the moth lands", "lantern", " lands", "token", "imrate", "level",
)
LOSE_KEYWORDS = (
    "denied", "wrong", "incorrect", "invalid", "fail", "error", "nope",
    "try again", "scoff", "overflow", "not a night serial", "does not land",
    "ignores that name", "goes out", "bad name", "bad length", "mauvais",
    "incorrecto", "sorry", "not today", "not quite", "close but", "no luck",
    "better luck", "please try", "nah", "nope", "rejected", "refus",
)
PROMPT_KEYWORDS = ("serial", "password", "pass", "key", "name", "input", "code", ">", ":")

@dataclass
class StringRef:
    address: int
    text: str
    code_addrs: list[int] = field(default_factory=list)

    @property
    def kind(self) -> str:
        low = self.text.lower()
        if any(k in low for k in LOSE_KEYWORDS):
            return "lose"
        if any(k in low for k in WIN_KEYWORDS):
            return "win"
        return "other"

class CodeDataReferences:
    def __init__(self, project, max_string_len: int = 200):
        self.project = project
        self.obj = project.loader.main_object
        self.max_string_len = max_string_len
        self.refs: dict[int, StringRef] = {}
        self.instructions: list = []
        self._by_addr: dict[int, object] = {}
        self._collect()

    def _readable(self, addr: int) -> bool:
        for sec in self.obj.sections:
            if not sec.memsize or not getattr(sec, "is_readable", True):
                continue
            if sec.vaddr <= addr < sec.vaddr + sec.memsize:
                return True
        return False

    def read(self, addr: int, size: int) -> bytes:
        try:
            return self.project.loader.memory.load(addr, size)
        except Exception:
            return b""

    def cstring_at(self, addr: int) -> str:
        data = self.read(addr, self.max_string_len)
        end = data.find(b"\x00")
        if end < 0:
            end = len(data)
        return data[:end].decode("latin-1", "replace")

    def _collect(self) -> None:
        engine = _capstone_for(self.project)
        if engine is None:
            return
        targets: dict[int, list[int]] = {}
        for sec in self.obj.sections:
            if not sec.memsize or not getattr(sec, "is_executable", False):
                continue
            code = self.read(sec.vaddr, sec.memsize)
            if not code:
                continue
            for insn in engine.disasm(code, sec.vaddr):
                self.instructions.append(insn)
                self._by_addr[insn.address] = insn
                target = _operand_target(insn)
                if target is None or not self._readable(target):
                    continue
                targets.setdefault(target, []).append(insn.address)

        for address, code_addrs in targets.items():
            text = self.cstring_at(address)
            if not (3 <= len(text) <= self.max_string_len):
                continue
            if not any(0x20 <= ord(c) < 0x7F for c in text):
                continue
            self.refs[address] = StringRef(address, text, code_addrs)
        self._drop_suffix_duplicates()

    def by_kind(self, kind: str) -> list[StringRef]:
        return [r for r in self.refs.values() if r.kind == kind]

    def _drop_suffix_duplicates(self) -> None:
        addresses = sorted(self.refs)
        for index, address in enumerate(addresses):
            ref = self.refs.get(address)
            if ref is None:
                continue
            lower = index - 1
            while lower >= 0:
                previous = self.refs.get(addresses[lower])
                if previous is None:
                    lower -= 1
                    continue
                gap = address - previous.address
                if gap > len(previous.text):
                    break
                if previous.text.endswith(ref.text):
                    self.refs.pop(address, None)
                    break
                lower -= 1

    def win_addresses(self) -> list[int]:
        return sorted({a for r in self.by_kind("win") for a in r.code_addrs})

    def lose_addresses(self) -> list[int]:
        return sorted({a for r in self.by_kind("lose") for a in r.code_addrs})

    def prompts(self) -> list[StringRef]:
        return [
            r for r in self.refs.values()
            if any(k in r.text.lower() for k in PROMPT_KEYWORDS)
        ]

    def infer_win_addresses(self, lookback: int = 40) -> list[int]:
        if not self.instructions:
            return []
        wins: set[int] = set()
        ordered = sorted(self._by_addr)
        position = {addr: i for i, addr in enumerate(ordered)}

        for ref in self.by_kind("lose"):
            for code_addr in ref.code_addrs:
                if code_addr not in position:
                    continue
                start = position[code_addr]
                for index in range(start - 1, max(-1, start - lookback), -1):
                    insn = self._by_addr[ordered[index]]
                    if insn.mnemonic == "jmp":
                        continue
                    if not insn.mnemonic.startswith("j"):
                        continue
                    try:
                        target = int(insn.op_str, 16)
                    except ValueError:
                        break
                    fallthrough = insn.address + insn.size
                    if target == code_addr:
                        wins.add(fallthrough)
                    else:
                        wins.add(target)
                    break
        return sorted(a for a in wins if a in self._by_addr)

    def summary(self) -> str:
        lines = []
        for ref in sorted(self.refs.values(), key=lambda r: (r.kind, r.address)):
            if ref.kind == "other":
                continue
            lines.append(
                f"{ref.kind:4} 0x{ref.address:08x} {ref.text!r} "
                f"<- {[hex(a) for a in ref.code_addrs]}"
            )
        return "\n".join(lines)

def _capstone_for(project):
    import angr

    arch = project.arch
    if arch.name in ("AMD64", "X86"):
        mode = capstone.CS_MODE_64 if arch.bits == 64 else capstone.CS_MODE_32
        return capstone.Cs(capstone.CS_ARCH_X86, mode)
    if arch.name == "ARMEL" or arch.name.startswith("ARM"):
        mode = capstone.CS_MODE_ARM if arch.bits == 32 else capstone.CS_MODE_ARM
        return capstone.Cs(capstone.CS_ARCH_ARM, mode)
    if arch.name == "AARCH64":
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    return None

def _operand_target(insn) -> int | None:
    op = insn.op_str
    if "[rip" in op:
        try:
            disp = op.split("[rip")[1]
            disp = disp.split("+")[1].split("]")[0] if "+" in disp else disp.split("-")[1].split("]")[0]
            value = int(disp.strip(), 16)
            sign = -1 if "-" in op.split("[rip")[1].split("]")[0] else 1
            return insn.address + insn.size + sign * value
        except Exception:
            return None
    if insn.mnemonic in ("mov", "lea", "push", "cmp"):
        last = op.split(",")[-1].strip()
        if last.startswith("0x") and "[" not in last and "(" not in last:
            try:
                return int(last, 16)
            except ValueError:
                return None
    return None
