from __future__ import annotations

import os
import re
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from xsolver.core.binary import BinaryProfile, load_binary
from xsolver.core.pe import NotPeError, parse_pe
from xsolver.core.runtime import RuntimeUnavailable, TargetRuntime

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_MAPS_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$"
)

@dataclass
class MappedRegion:
    address: int
    data: bytes
    permissions: str
    changed_bytes: int = 0

    @property
    def executable(self) -> bool:
        return "x" in self.permissions

    @property
    def changed(self) -> bool:
        return self.changed_bytes > 0

@dataclass
class UnpackedImage:
    path: Path
    image_base: int
    image_size: int
    regions: list[MappedRegion] = field(default_factory=list)

    @property
    def changed_regions(self) -> list[MappedRegion]:
        return [r for r in self.regions if r.changed]

    @property
    def changed_bytes(self) -> int:
        return sum(r.changed_bytes for r in self.regions)

    @property
    def code_changed_bytes(self) -> int:
        return sum(r.changed_bytes for r in self.regions if r.executable)

    def read(self, address: int, size: int) -> bytes | None:
        for region in self.regions:
            if region.address <= address and address + size <= region.address + len(region.data):
                offset = address - region.address
                return region.data[offset:offset + size]
        return None

    def image(self) -> bytes:
        if not self.regions:
            return b""
        buffer = bytearray(self.image_size)
        for region in self.regions:
            offset = region.address - self.image_base
            if offset < 0:
                continue
            end = min(len(buffer), offset + len(region.data))
            buffer[offset:end] = region.data[: end - offset]
        return bytes(buffer)

    def strings(self, min_length: int = 4, only_changed: bool = True) -> list[tuple[int, str]]:
        found: list[tuple[int, str]] = []
        for region in self.regions if not only_changed else self.changed_regions:
            for match in _PRINTABLE.finditer(region.data):
                if len(match.group(0)) < min_length:
                    continue
                found.append((region.address + match.start(), match.group(0).decode("ascii")))
        return found

    def code_referenced_strings(self, max_window: int = 6) -> list[tuple[str, int]]:
        try:
            import capstone
        except ImportError:
            return []

        known = {address: text for address, text in self.strings(min_length=3)}
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = False
        decoder.skipdata = True
        scores: dict[str, int] = {}

        for region in self.changed_regions:
            if not region.executable:
                continue
            instructions = list(decoder.disasm(region.data, region.address))
            for index, instruction in enumerate(instructions):
                if instruction.mnemonic != "lea":
                    continue
                match = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", instruction.op_str)
                if not match:
                    continue
                delta = int(match.group(2), 16)
                target = instruction.address + instruction.size + (delta if match.group(1) == "+" else -delta)
                text = known.get(target)
                if not text:
                    continue
                score = 1
                window = instructions[index + 1:index + 1 + max_window]
                for following in window:
                    length_match = re.match(r"^(e[a-z0-9]+), (0x[0-9a-f]+|\d+)$", following.op_str)
                    if length_match and following.mnemonic == "mov":
                        value = int(length_match.group(2), 0)
                        if value == len(text):
                            score = 2
                            break
                scores[text] = max(scores.get(text, 0), score)
        return sorted(scores.items(), key=lambda item: (-item[1], -len(item[0])))

    def candidate_passwords(self, limit: int = 60) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()

        def add(text: str) -> None:
            if text and text not in seen and "\n" not in text and "\r" not in text:
                seen.add(text)
                ordered.append(text)

        referenced = sorted(
            self.code_referenced_strings(),
            key=lambda item: (-item[1], " " in item[0], -len(item[0])),
        )
        for text, _score in referenced:
            add(text)
        for _address, text in sorted(self.strings(min_length=4), key=lambda item: -len(item[1])):
            add(text)
        return ordered[:limit]

def _image_layout(profile: BinaryProfile) -> tuple[int, int, bytes | None]:
    if not profile.format.startswith("PE"):
        return 0, 0, None
    data = profile.raw
    try:
        info = parse_pe(data)
    except NotPeError:
        return 0, 0, None

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
    base = (
        struct.unpack_from("<Q", data, opt_off + 24)[0]
        if magic == 0x20B
        else struct.unpack_from("<I", data, opt_off + 28)[0]
    )

    image = bytearray(size_of_image)
    size_of_headers = min(struct.unpack_from("<I", data, opt_off + 60)[0], size_of_image)
    image[0:size_of_headers] = data[0:size_of_headers]
    for section in info.sections:
        start = section.virtual_address
        if start >= size_of_image:
            continue
        span = min(section.raw_size, section.virtual_size) if section.virtual_size else section.raw_size
        raw = data[section.raw_offset:section.raw_offset + span]
        raw = raw[: max(0, size_of_image - start)]
        image[start:start + len(raw)] = raw
    return base, size_of_image, bytes(image)

def _process_tree(root_pid: int) -> list[int]:
    pids = {root_pid}
    frontier = [root_pid]
    while frontier:
        parent = frontier.pop()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid in pids:
                continue
            try:
                stat = Path(f"/proc/{pid}/stat").read_bytes()
            except OSError:
                continue
            try:
                ppid = int(stat.rsplit(b")", 1)[1].split()[1])
            except (IndexError, ValueError):
                continue
            if ppid == parent:
                pids.add(pid)
                frontier.append(pid)
    return sorted(pids)

def _snapshot_pid(pid: int, image_base: int, image_size: int,
                  expected: bytes | None) -> list[MappedRegion]:
    regions: list[MappedRegion] = []
    try:
        maps = Path(f"/proc/{pid}/maps").read_text().splitlines()
    except OSError:
        return regions
    try:
        handle = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except OSError:
        return regions
    with handle:
        for line in maps:
            match = _MAPS_RE.match(line)
            if not match:
                continue
            start, end, perms = int(match.group(1), 16), int(match.group(2), 16), match.group(3)
            if end <= image_base or start >= image_base + image_size:
                continue
            try:
                handle.seek(start)
                data = handle.read(end - start)
            except OSError:
                continue
            if not data:
                continue
            changed = 0
            if expected is not None:
                offset = start - image_base
                reference = expected[max(0, offset): max(0, offset) + len(data)] if offset >= 0 else b""
                if offset < 0:
                    reference = b""
                    data = data[-offset:]
                    start = image_base
                limit = min(len(data), len(reference))
                changed = sum(1 for i in range(limit) if data[i] != reference[i])
                changed += max(0, len(data) - len(reference))
            regions.append(MappedRegion(start, data, perms, changed))
    return regions

def _kill_tree(process: subprocess.Popen) -> None:
    try:
        import psutil

        parent = psutil.Process(process.pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except psutil.Error:
                pass
        parent.kill()
    except Exception:
        try:
            process.kill()
        except OSError:
            pass

def _observe(
    runtime: TargetRuntime,
    image_base: int,
    image_size: int,
    expected: bytes | None,
    feed: bytes | None,
    timeout: float,
    poll: float,
    min_changed: int,
) -> list[MappedRegion] | None:
    env = runtime.environment()
    try:
        process = subprocess.Popen(
            runtime.command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd="/tmp",
        )
    except OSError:
        return None

    try:
        if feed:
            try:
                process.stdin.write(feed)
                process.stdin.flush()
            except OSError:
                pass
        deadline = time.monotonic() + timeout
        best: list[MappedRegion] | None = None
        best_changed = -1
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            for pid in _process_tree(process.pid):
                regions = _snapshot_pid(pid, image_base, image_size, expected)
                changed = sum(region.changed_bytes for region in regions)
                if changed > best_changed:
                    best_changed, best = changed, regions
                if changed >= min_changed:
                    time.sleep(0.25)
                    for stable_pid in _process_tree(process.pid):
                        stable = _snapshot_pid(stable_pid, image_base, image_size, expected)
                        if sum(r.changed_bytes for r in stable) >= min_changed:
                            return stable
                    return regions
            time.sleep(poll)
        return best
    finally:
        _kill_tree(process)

def capture(
    path: str | Path,
    timeout: float = 6.0,
    poll: float = 0.01,
    min_changed: int = 256,
    feeds: tuple[bytes | None, ...] = (None, b"test123\n"),
) -> UnpackedImage | None:
    path = Path(path)
    try:
        runtime = TargetRuntime.for_path(path)
    except Exception:
        return None
    if not runtime.executable:
        return None

    profile = runtime.profile
    image_base, image_size, expected = _image_layout(profile)
    if not image_size:
        return None

    for feed in feeds:
        regions = _observe(runtime, image_base, image_size, expected, feed,
                           timeout, poll, min_changed)
        if not regions:
            continue
        changed = sum(region.changed_bytes for region in regions)
        if changed >= min_changed:
            return UnpackedImage(path=path, image_base=image_base,
                                 image_size=image_size, regions=regions)
    return None
