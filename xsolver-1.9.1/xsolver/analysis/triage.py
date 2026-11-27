from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from xsolver.analysis.strings import StringCandidate, extract_strings
from xsolver.core.binary import BinaryProfile, load_binary

@dataclass
class TriageResult:
    profile: BinaryProfile
    strings: list[StringCandidate] = field(default_factory=list)
    likely_input_mode: str = "unknown"
    notes: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    go_version: str = ""
    go_functions: int = 0

def triage(path: str | Path) -> TriageResult:
    profile = load_binary(path)
    strings = extract_strings(profile.raw)

    notes: list[str] = []
    if profile.packer_suspected:
        notes.append("high entropy, packed?")
    if not profile.is_executable_elf and "ELF" in profile.format:
        notes.append("not executable, chmod +x applied")

    prompts = [s.value.strip() for s in strings
               if 3 <= len(s.value.strip()) <= 40
               and s.value.strip()[-1] in ":>?"
               and sum(ch.isalpha() for ch in s.value) >= 3][:8]

    lowered_strings = " ".join(s.value.lower() for s in strings[:400])
    likely_mode = "argv"
    if "scanf" in lowered_strings or "gets" in lowered_strings or "fgets" in lowered_strings:
        likely_mode = "stdin"
    if "argv" in lowered_strings or "usage" in lowered_strings:
        likely_mode = "argv"

    go_version = ""
    go_functions = 0
    try:
        from xsolver.analysis import gopcln

        table = gopcln.find_table(profile)
        if table is not None:
            go_version = table.version
            go_functions = len(gopcln.function_names(profile, table))
            notes.append(f"go {go_version}, {go_functions} functions via pclntab")
    except Exception:
        pass

    return TriageResult(
        profile=profile,
        strings=strings,
        likely_input_mode=likely_mode,
        notes=notes,
        prompts=prompts,
        go_version=go_version,
        go_functions=go_functions,
    )
