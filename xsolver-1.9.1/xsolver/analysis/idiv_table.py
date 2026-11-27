from __future__ import annotations

import struct
from pathlib import Path

MIN_RUN = 6

def _trunc_divmod(value: int, divisor: int) -> tuple[int, int]:
    if value >= 0:
        quotient = value // divisor
    else:
        quotient = -((-value) // divisor)
    return quotient, value - quotient * divisor

def _data_spans(data: bytes) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    try:
        from xsolver.core.pe import parse_pe

        info = parse_pe(data)
    except Exception:
        info = None
    if info is not None:
        for sec in info.sections:
            if sec.raw_size <= 0 or sec.characteristics & 0x20000000:
                continue
            start = sec.raw_offset
            end = min(sec.raw_offset + sec.raw_size, len(data))
            if end > start:
                spans.append((start, end))
        return spans
    try:
        from xsolver.core.elf import parse_elf

        info = parse_elf(data)
    except Exception:
        return spans
    for sec in info.sections:
        if sec.size <= 0 or sec.flags & 0x4 or sec.sh_type == 8:
            continue
        start = sec.offset
        end = min(sec.offset + sec.size, len(data))
        if end > start:
            spans.append((start, end))
    return spans

def _decode_run(data: bytes, start: int, limit: int) -> str | None:
    chars: list[str] = []
    pos = start
    index = 0
    while pos + 4 <= limit:
        (value,) = struct.unpack_from("<i", data, pos)
        quotient, remainder = _trunc_divmod(value, index + 1)
        if remainder != 0 or not (32 <= quotient <= 126):
            break
        chars.append(chr(quotient))
        pos += 4
        index += 1
    if len(chars) < MIN_RUN:
        return None
    return "".join(chars)

def find_idiv_tables(path: str | Path) -> list[str]:
    data = Path(path).read_bytes()
    found: list[str] = []
    seen: set[tuple[int, int]] = set()
    for start, end in _data_spans(data):
        offset = start if start % 4 == 0 else start + (4 - start % 4)
        while offset < end:
            text = _decode_run(data, offset, end)
            if text is None:
                offset += 4
                continue
            span = (offset, offset + 4 * len(text))
            if span not in seen:
                seen.add(span)
                found.append(text)
            offset = span[1]
    found.sort(key=len, reverse=True)
    return found
