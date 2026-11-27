from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from xsolver.core.binary import BinaryProfile, load_binary

DEBUG_APIS = {
    "isdebuggerpresent": "flag",
    "checkremotedebuggerpresent": "flag_out",
    "ntqueryinformationprocess": "ntstatus",
    "ntsetinformationthread": "ntstatus",
    "ntquerysysteminformation": "ntstatus",
    "ntyieldexecution": "ntstatus",
    "outputdebugstringa": "void",
    "outputdebugstringw": "void",
    "debugbreak": "void",
    "getthreadcontext": "zero",
    "isprocessorfeaturepresent": "zero",
}

TIMING_APIS = {
    "gettickcount": "tick",
    "gettickcount64": "tick64",
    "timegettime": "tick",
    "queryperformancecounter": "qpc",
    "queryperformancefrequency": "qpf",
}

_PATTERNS = {
    "peb_access": b"\x64\xa1\x30\x00\x00\x00",
    "peb_access64": b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00",
    "rdtsc": b"\x0f\x31",
    "rdtscp": b"\x0f\x01\xf9",
    "int3": b"\xcc",
    "int_2d": b"\xcd\x2d",
    "popf_trap": b"\x9c\x58\x35\x00\x01",
}

@dataclass
class AntiDebugReport:
    apis: dict[str, list[int]] = field(default_factory=dict)
    patterns: dict[str, int] = field(default_factory=dict)

    @property
    def detected(self) -> bool:
        return bool(self.apis or self.patterns)

    @property
    def names(self) -> list[str]:
        return sorted(self.apis)

    @property
    def patchable(self) -> bool:
        return bool(self.apis)

    def summary(self) -> str:
        parts = []
        if self.apis:
            parts.append(", ".join(sorted(self.apis)))
        if self.patterns:
            parts.append("patterns: " + ", ".join(sorted(self.patterns)))
        return " / ".join(parts)

def scan(profile: BinaryProfile | str | Path) -> AntiDebugReport:
    if not isinstance(profile, BinaryProfile):
        try:
            profile = load_binary(profile)
        except Exception:
            return AntiDebugReport()
    report = AntiDebugReport()
    try:
        import pefile

        pe = pefile.PE(str(profile.path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        return report
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imported in getattr(entry, "imports", []) or []:
            if not imported.name:
                continue
            name = imported.name.decode("latin-1")
            lowered = name.lower()
            if lowered in DEBUG_APIS or lowered in TIMING_APIS:
                report.apis.setdefault(name, []).append(int(imported.address))
    try:
        blob = Path(profile.path).read_bytes()
    except OSError:
        return report
    for name, pattern in _PATTERNS.items():
        count = blob.count(pattern)
        if count:
            report.patterns[name] = count
    if report.patterns.get("int3", 0) > 400:
        report.patterns.pop("int3", None)
    return report

def patchable_imports(profile: BinaryProfile | str | Path) -> list[str]:
    report = scan(profile)
    wanted = []
    for name in report.apis:
        lowered = name.lower()
        if lowered in DEBUG_APIS or lowered in TIMING_APIS:
            wanted.append(name)
    return sorted(set(wanted))
