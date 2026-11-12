"""Minimal DEX (Android dalvik bytecode) string-pool extraction.

An APK's classes.dex carries the app's identifiers: class names, method
names, URLs, secrets.  Pulling the string pool is the 80% of APK static
analysis.  Pure stdlib: header offsets + uleb128 lengths + MUTF-8 decoding.

This is NOT a dex disassembler — it reads the string table only.
"""

from __future__ import annotations

import struct
from typing import Any

DEX_MAGIC = b"dex\n"


def _read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("uleb128 runs past end of data")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("uleb128 too long")


def _mutf8_to_str(raw: bytes) -> str:
    """Decode dex MUTF-8 (modified UTF-8: NUL as 0xC0 0x80, surrogates
    encoded as two 3-byte sequences).  Best effort — undecodable runs are
    kept as latin-1 so the analyst still sees bytes."""
    try:
        # standard UTF-8 handles most real-world dex strings
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        # MUTF-8 quirks: 0xC0 0x80 = NUL; lone surrogates → replace
        out = bytearray()
        i = 0
        while i < len(raw):
            b = raw[i]
            if b == 0xC0 and i + 1 < len(raw) and raw[i + 1] == 0x80:
                out.append(0x00)
                i += 2
                continue
            out.append(b)
            i += 1
        return out.decode("utf-8", errors="replace")


def dex_info(data: bytes) -> dict[str, Any]:
    """Header summary for a classes.dex blob. Raises ValueError if not dex."""
    if len(data) < 0x70 or data[:4] != DEX_MAGIC:
        raise ValueError("not a dex file (bad magic)")
    version = data[4:7].decode("ascii", "replace")  # e.g. "035"
    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
    type_ids_size = struct.unpack_from("<I", data, 0x40)[0]
    method_ids_size = struct.unpack_from("<I", data, 0x48)[0]
    return {
        "version": version,
        "string_count": string_ids_size,
        "type_count": type_ids_size,
        "method_count": method_ids_size,
        "size": len(data),
    }


def dex_strings(data: bytes, limit: int = 0) -> list[str]:
    """Extract the string pool, in file order (roughly = first-use order).

    limit: optional cap on returned strings (0 = all).  Malformed entries
    are skipped, not fatal — CTF dex blobs are often tampered with.
    """
    info = dex_info(data)
    string_ids_size = info["string_count"]
    string_ids_off = info["string_count"] and int.from_bytes(data[0x3C:0x40], "little")

    out: list[str] = []
    skipped = 0
    for i in range(string_ids_size):
        if limit and len(out) >= limit:
            break
        off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
        if off >= len(data):
            skipped += 1
            continue
        try:
            strlen, pos = _read_uleb128(data, off)
            raw = data[pos : pos + strlen]
            # MUTF-8 strings are NUL-terminated — strip the terminator
            if raw.endswith(b"\x00"):
                raw = raw[:-1]
            out.append(_mutf8_to_str(raw))
        except (ValueError, struct.error):
            skipped += 1
            continue
    return out


def looks_like_dex(data: bytes) -> bool:
    return len(data) >= 0x70 and data[:4] == DEX_MAGIC
