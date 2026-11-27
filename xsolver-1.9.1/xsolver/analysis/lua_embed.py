from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

_LH_SIGS = (b"PK\x03\x04", b"LK\x03\x04")
_CD_SIG = b"PK\x01\x02"
_EOCD_SIG = b"PK\x05\x06"
_RANDOM_RE = re.compile(
    rb"math\.random\(\s*(\d+)\s*,\s*(\d+)\s*\)"
)
_READ_RE = re.compile(rb"io\.read\s*\(")

@dataclass(frozen=True)
class LuaEmbedEntry:
    name: str
    offset: int
    method: int
    flags: int
    crc: int
    csize: int
    usize: int
    data_offset: int
    source: bytes

@dataclass(frozen=True)
class RandomPasswordPlan:
    entry: str
    low: int
    high: int
    source: bytes
    patched_source: bytes
    password: str

def _find_eocd(raw: bytes) -> int:
    return raw.rfind(_EOCD_SIG)

def _walk_cd(raw: bytes, cd_start: int, ntotal: int) -> list[tuple[str, int, int, int, int, int, int]] | None:
    entries: list[tuple[str, int, int, int, int, int, int]] = []
    off = cd_start
    for _ in range(ntotal):
        if off + 46 > len(raw) or raw[off:off + 4] != _CD_SIG:
            return None
        fields = struct.unpack_from("<IHHHHHHIIIHHHHHII", raw, off)
        crc, cs, us = fields[7], fields[8], fields[9]
        nlen, elen, cln = fields[10], fields[11], fields[12]
        lho = fields[16]
        name = raw[off + 46:off + 46 + nlen].decode("utf-8", "replace")
        entries.append((name, lho, fields[4], fields[3], crc, cs, us))
        off += 46 + nlen + elen + cln
    return entries

def _read_local(raw: bytes, lh: int, csize: int) -> tuple[int, int, bytes] | None:
    if lh < 0 or lh + 30 > len(raw):
        return None
    if raw[lh:lh + 4] not in _LH_SIGS:
        return None
    _ver, flags, method, _mt, _md, _crc, _cs, _us, nlen, elen = struct.unpack_from(
        "<HHHHHIIIHH", raw, lh + 4
    )
    data_off = lh + 30 + nlen + elen
    cdata = raw[data_off:data_off + csize]
    if len(cdata) < csize:
        return None
    return method, data_off, cdata

def _inflate(method: int, cdata: bytes) -> bytes | None:
    if method == 0:
        return cdata
    if method == 8:
        try:
            return zlib.decompress(cdata, -15)
        except zlib.error:
            return None
    return None

def extract_embedded_lua(raw: bytes) -> dict[str, LuaEmbedEntry]:
    eocd = _find_eocd(raw)
    if eocd < 0 or eocd + 22 > len(raw):
        return {}
    _disk, _cddisk, _nthis, ntotal, cdsize, cdoff, _clen = struct.unpack_from(
        "<HHHHIIH", raw, eocd + 4
    )
    if not ntotal or not cdsize:
        return {}

    idx = eocd
    candidates: list[int] = []
    while len(candidates) < 8:
        idx = raw.rfind(_CD_SIG, 0, idx)
        if idx < 0:
            break
        candidates.append(idx)
        idx -= 1

    for cd_start in candidates:
        zip_base = cd_start - cdoff
        if zip_base < 0:
            continue
        walked = _walk_cd(raw, cd_start, ntotal)
        if not walked:
            continue
        out: dict[str, LuaEmbedEntry] = {}
        ok = True
        for name, lho, method, flags, crc, cs, us in walked:
            lh = zip_base + lho
            parsed = _read_local(raw, lh, cs)
            if parsed is None:
                ok = False
                break
            lmethod, data_off, cdata = parsed
            source = _inflate(lmethod, cdata)
            if source is None or len(source) != us:
                ok = False
                break
            if zlib.crc32(source) & 0xFFFFFFFF != crc:
                ok = False
                break
            out[name] = LuaEmbedEntry(
                name=name,
                offset=lh,
                method=lmethod,
                flags=flags,
                crc=crc,
                csize=cs,
                usize=us,
                data_offset=data_off,
                source=source,
            )
        if ok and out:
            return out
    return {}

def _deflate(source: bytes, level: int) -> bytes:
    co = zlib.compressobj(level, zlib.DEFLATED, -15)
    return co.compress(source) + co.flush()

def _compress_exact(source: bytes, target_csize: int) -> tuple[bytes, bytes] | None:
    for level in range(10):
        blob = _deflate(source, level)
        if len(blob) == target_csize:
            return blob, source
    for pad in range(0, 4096):
        candidate = source + b"\n--" + b"a" * pad
        for level in (9, 6, 3, 1, 0):
            blob = _deflate(candidate, level)
            if len(blob) == target_csize:
                return blob, candidate
    return None

def plan_random_password(raw: bytes) -> RandomPasswordPlan | None:
    entries = extract_embedded_lua(raw)
    for name, entry in entries.items():
        if not name.endswith(".lua"):
            continue
        if not _READ_RE.search(entry.source):
            continue
        match = _RANDOM_RE.search(entry.source)
        if not match:
            continue
        low = int(match.group(1))
        high = int(match.group(2))
        if high < low:
            low, high = high, low

        original = match.group(0)
        comma_at = original.index(b",")
        after_comma = original[comma_at + 1:]
        pad_ws = after_comma[:len(after_comma) - len(after_comma.lstrip())]
        fixed = str(low).encode()
        rebuilt = b"math.random(" + match.group(1) + b"," + pad_ws + fixed + b")"
        if len(rebuilt) > len(original):
            continue
        if len(rebuilt) < len(original):
            rebuilt = rebuilt[:-1] + b" " * (len(original) - len(rebuilt)) + b")"
        if len(rebuilt) != len(original):
            continue
        patched_source = entry.source[:match.start()] + rebuilt + entry.source[match.end():]
        if len(patched_source) != len(entry.source):
            continue
        password = str(low)
        return RandomPasswordPlan(
            entry=name,
            low=low,
            high=high,
            source=entry.source,
            patched_source=patched_source,
            password=password,
        )
    return None

def patch_lua_random(raw: bytes, plan: RandomPasswordPlan | None = None) -> tuple[bytes, str] | None:
    plan = plan or plan_random_password(raw)
    if plan is None:
        return None
    entries = extract_embedded_lua(raw)
    entry = entries.get(plan.entry)
    if entry is None:
        return None
    packed = _compress_exact(plan.patched_source, entry.csize)
    if packed is None:
        return None
    blob, final_source = packed
    if len(blob) != entry.csize:
        return None
    data = bytearray(raw)
    data[entry.data_offset:entry.data_offset + entry.csize] = blob
    new_crc = zlib.crc32(final_source) & 0xFFFFFFFF

    dd = entry.data_offset + entry.csize
    if entry.flags & 0x8 and data[dd:dd + 4] == b"PK\x07\x08":
        struct.pack_into("<III", data, dd + 4, new_crc, entry.csize, len(final_source))
    elif entry.flags & 0x8:

        if dd + 16 <= len(data) and data[dd:dd + 4] != b"PK\x01\x02":
            struct.pack_into("<III", data, dd + 4, new_crc, entry.csize, len(final_source))

    lh = entry.offset
    _ver, flags, method, mt, md, lcrc, lcs, lus, nlen, elen = struct.unpack_from(
        "<HHHHHIIIHH", data, lh + 4
    )
    if not (flags & 0x8):
        struct.pack_into("<III", data, lh + 14, new_crc, entry.csize, len(final_source))

    eocd = bytes(data).rfind(_EOCD_SIG)
    if eocd >= 0:
        _d, _cd, _nt, ntotal, cdsize, cdoff, _cl = struct.unpack_from(
            "<HHHHIIH", data, eocd + 4
        )
        idx = eocd
        for _ in range(8):
            idx = bytes(data).rfind(_CD_SIG, 0, idx)
            if idx < 0:
                break
            walked = _walk_cd(bytes(data), idx, ntotal)
            if walked and any(name == plan.entry for name, *_rest in walked):
                off = idx
                for name, lho, _m, _f, _crc, _cs, _us in walked:
                    if name == plan.entry:

                        struct.pack_into("<I", data, off + 16, new_crc)
                        struct.pack_into("<I", data, off + 20, entry.csize)
                        struct.pack_into("<I", data, off + 24, len(final_source))
                        break
                    nlen, elen, cln = struct.unpack_from("<HHH", data, off + 28)
                    off += 46 + nlen + elen + cln
                break
            idx -= 1

    return bytes(data), plan.password

def is_lua_random_target(path: str | Path) -> bool:
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return False
    if not raw.startswith(b"MZ"):
        return False
    return plan_random_password(raw) is not None
