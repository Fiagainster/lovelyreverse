"""Decoder Lab: a small, chainable bag of encoding/decoding operations.

Inspired by CyberChef's "recipe" model: an ordered list of ops, each taking
bytes in and emitting bytes out. Pure Python, stdlib only.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import string
import zlib
from typing import Any, Callable

PRINTABLE = set(string.printable.encode()) - {0x0B, 0x0C}


class OpError(ValueError):
    """Raised when a single op in a chain fails; message names the op."""

    def __init__(self, op: str, detail: str):
        super().__init__(f"[{op}] {detail}")
        self.op = op


# ---------------------------------------------------------------- text/bytes

def _to_text(data: bytes) -> str:
    return data.decode("utf-8", errors="strict")


def op_to_hex(data: bytes, sep: str = "", upper: bool = False) -> bytes:
    h = data.hex(sep=sep) if sep else data.hex()
    return h.upper().encode() if upper else h.encode()


def op_from_hex(data: bytes) -> bytes:
    s = _to_text(data).strip()
    s = s.replace("0x", "").replace("0X", "")
    s = "".join(c for c in s if c not in " \t\r\n:-,.")
    if len(s) % 2:
        raise OpError("from_hex", "odd number of hex digits")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise OpError("from_hex", f"invalid hex: {e}") from e


def op_to_base64(data: bytes, urlsafe: bool = False) -> bytes:
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return enc(data)


def op_from_base64(data: bytes) -> bytes:
    s = _to_text(data).strip().replace("-", "+").replace("_", "/")
    s = "".join(c for c in s if not c.isspace())
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + "=" * pad, validate=False)
    except (binascii.Error, ValueError) as e:
        raise OpError("from_base64", f"invalid base64: {e}") from e


def op_to_base32(data: bytes) -> bytes:
    return base64.b32encode(data)


def op_from_base32(data: bytes) -> bytes:
    s = _to_text(data).strip().upper()
    pad = (-len(s)) % 8
    try:
        return base64.b32decode(s + "=" * pad)
    except (binascii.Error, ValueError) as e:
        raise OpError("from_base32", f"invalid base32: {e}") from e


def op_to_ascii85(data: bytes) -> bytes:
    return base64.a85encode(data)


def op_from_ascii85(data: bytes) -> bytes:
    try:
        return base64.a85decode(_to_text(data).strip())
    except (binascii.Error, ValueError) as e:
        raise OpError("from_ascii85", f"invalid ascii85: {e}") from e


def op_url_encode(data: bytes) -> bytes:
    import urllib.parse

    return urllib.parse.quote_from_bytes(data).encode()


def op_url_decode(data: bytes) -> bytes:
    import urllib.parse

    try:
        return urllib.parse.unquote_to_bytes(_to_text(data))
    except UnicodeDecodeError as e:
        raise OpError("url_decode", f"not text: {e}") from e


# -------------------------------------------------------------------- cipher

def op_rot(data: bytes, n: int = 13) -> bytes:
    """ROT-n over letters, bytes preserved for non-letters."""
    n %= 26

    def shift(b: int, base: int) -> int:
        return (b - base + n) % 26 + base

    out = bytearray()
    for b in data:
        if 0x41 <= b <= 0x5A:
            out.append(shift(b, 0x41))
        elif 0x61 <= b <= 0x7A:
            out.append(shift(b, 0x61))
        else:
            out.append(b)
    return bytes(out)


def op_rot47(data: bytes, n: int = 47) -> bytes:
    n %= 94
    return bytes(
        (b - 0x21 + n) % 94 + 0x21 if 0x21 <= b <= 0x7E else b for b in data
    )


def _parse_key(key: str, force_hex: bool | None = None) -> bytes:
    """Key interpretation rules (a classic CTF footgun, so be explicit):

    - 2 chars of hex digits  -> one byte          ("17" -> 0x17)
    - even length >= 4, all hex digits, and force_hex -> hex
    - otherwise              -> ascii/utf-8 text  ("ATRI" -> b"ATRI")

    ``force_hex`` (op arg ``hex``) overrides detection either way.
    """
    if not key:
        raise OpError("xor", "key is empty")
    k = key.strip()
    is_hexish = len(k) % 2 == 0 and k != "" and all(c in string.hexdigits for c in k)
    as_hex = force_hex if force_hex is not None else (
        (len(k) == 2 and is_hexish) or (len(k) >= 4 and is_hexish)
    )
    if as_hex:
        try:
            return bytes.fromhex(k)
        except ValueError as e:
            raise OpError("xor", f"invalid hex key: {e}") from e
    return k.encode("utf-8")


def op_xor(data: bytes, key: str = "00", hex: bool | None = None) -> bytes:
    kb = _parse_key(key, hex)
    if not data:
        return b""
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))


def op_xor_pos(data: bytes, key: str = "00", offset: int = 0, hex: bool | None = None) -> bytes:
    """XOR where the key index also advances on skipped bytes (offset)."""
    kb = _parse_key(key, hex)
    return bytes(b ^ kb[(i + offset) % len(kb)] for i, b in enumerate(data))


def op_rc4(data: bytes, key: str = "") -> bytes:
    kb = _parse_key(key) if key else b""
    if not kb:
        raise OpError("rc4", "key is empty")
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + kb[i % len(kb)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


# -------------------------------------------------------------------- binary

def op_reverse(data: bytes) -> bytes:
    return data[::-1]


def op_bit_not(data: bytes) -> bytes:
    return bytes(~b & 0xFF for b in data)


def op_upper(data: bytes) -> bytes:
    return _to_text(data).upper().encode("utf-8", errors="replace")


def op_lower(data: bytes) -> bytes:
    return _to_text(data).lower().encode("utf-8", errors="replace")


def op_utf8_decode(data: bytes) -> bytes:
    """Bytes -> valid UTF-8 text bytes, replacing bad sequences visibly."""
    return _to_text(data).encode("utf-8", errors="replace") if _looks_text(data) else data


def op_utf8_encode(data: bytes) -> bytes:
    return data  # input is already bytes; identity kept for recipe clarity


def op_c_escape(data: bytes) -> bytes:
    out = "".join(f"\\x{b:02x}" if b < 0x20 or b > 0x7E or b in (0x22, 0x5C) else chr(b) for b in data)
    return out.encode()


def op_c_unescape(data: bytes) -> bytes:
    s = _to_text(data)
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            c = s[i + 1]
            if c == "x" and i + 3 < len(s) + 1:
                try:
                    out.append(int(s[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            mapping = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, "'": 39, '"': 34, "a": 7, "b": 8, "f": 12, "v": 11}
            if c in mapping:
                out.append(mapping[c])
                i += 2
                continue
        out.extend(s[i].encode("utf-8", errors="replace"))
        i += 1
    return bytes(out)


def op_hexdump(data: bytes, width: int = 16) -> bytes:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asciipart = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(lines).encode()


# ---------------------------------------------------------------- compression

def op_gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)


def op_gzip_decompress(data: bytes) -> bytes:
    try:
        return gzip.decompress(data)
    except (OSError, EOFError, zlib.error) as e:
        raise OpError("gzip_decompress", f"bad gzip: {e}") from e


def op_zlib_compress(data: bytes) -> bytes:
    return zlib.compress(data)


def op_zlib_decompress(data: bytes) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error as e:
        raise OpError("zlib_decompress", f"bad zlib: {e}") from e


def op_raw_inflate(data: bytes) -> bytes:
    try:
        return zlib.decompress(data, -15)
    except zlib.error as e:
        raise OpError("raw_inflate", f"bad deflate: {e}") from e


# ---------------------------------------------------------------------- hash

def _hash_op(algo: str) -> Callable[..., bytes]:
    def h(data: bytes) -> bytes:
        return hashlib.new(algo, data).hexdigest().encode()

    h.__name__ = f"op_{algo}"
    h.__doc__ = f"Hash input with {algo.upper()}, output hex text."
    return h


# ------------------------------------------------------------------ registry

def _looks_text(data: bytes) -> bool:
    if not data:
        return True
    return all(b in PRINTABLE or b in (9, 10, 13) for b in data[:4096])


OPS: dict[str, dict[str, Any]] = {
    "to_hex":      {"fn": op_to_hex, "args": {"sep": "str", "upper": "bool"}, "label": "Hex → Encode"},
    "from_hex":    {"fn": op_from_hex, "args": {}, "label": "Hex → Decode"},
    "to_base64":   {"fn": op_to_base64, "args": {"urlsafe": "bool"}, "label": "Base64 → Encode"},
    "from_base64": {"fn": op_from_base64, "args": {}, "label": "Base64 → Decode"},
    "to_base32":   {"fn": op_to_base32, "args": {}, "label": "Base32 → Encode"},
    "from_base32": {"fn": op_from_base32, "args": {}, "label": "Base32 → Decode"},
    "to_ascii85":  {"fn": op_to_ascii85, "args": {}, "label": "Ascii85 → Encode"},
    "from_ascii85": {"fn": op_from_ascii85, "args": {}, "label": "Ascii85 → Decode"},
    "url_encode":  {"fn": op_url_encode, "args": {}, "label": "URL → Encode"},
    "url_decode":  {"fn": op_url_decode, "args": {}, "label": "URL → Decode"},
    "rot":         {"fn": op_rot, "args": {"n": "int"}, "label": "ROT-n"},
    "rot47":       {"fn": op_rot47, "args": {"n": "int"}, "label": "ROT47"},
    "xor":         {"fn": op_xor, "args": {"key": "str", "hex": "bool"}, "label": "XOR (repeating key)"},
    "xor_pos":     {"fn": op_xor_pos, "args": {"key": "str", "offset": "int", "hex": "bool"}, "label": "XOR (with index offset)"},
    "rc4":         {"fn": op_rc4, "args": {"key": "str"}, "label": "RC4"},
    "reverse":     {"fn": op_reverse, "args": {}, "label": "Reverse bytes"},
    "bit_not":     {"fn": op_bit_not, "args": {}, "label": "NOT (bit flip)"},
    "upper":       {"fn": op_upper, "args": {}, "label": "UPPERCASE"},
    "lower":       {"fn": op_lower, "args": {}, "label": "lowercase"},
    "c_escape":    {"fn": op_c_escape, "args": {}, "label": "C escape"},
    "c_unescape":  {"fn": op_c_unescape, "args": {}, "label": "C unescape"},
    "hexdump":     {"fn": op_hexdump, "args": {}, "label": "Hexdump"},
    "gzip_compress":   {"fn": op_gzip_compress, "args": {}, "label": "GZip compress"},
    "gzip_decompress": {"fn": op_gzip_decompress, "args": {}, "label": "GZip decompress"},
    "zlib_compress":   {"fn": op_zlib_compress, "args": {}, "label": "Zlib compress"},
    "zlib_decompress": {"fn": op_zlib_decompress, "args": {}, "label": "Zlib decompress"},
    "raw_inflate":     {"fn": op_raw_inflate, "args": {}, "label": "Raw inflate"},
    "md5":    {"fn": _hash_op("md5"), "args": {}, "label": "MD5"},
    "sha1":   {"fn": _hash_op("sha1"), "args": {}, "label": "SHA-1"},
    "sha256": {"fn": _hash_op("sha256"), "args": {}, "label": "SHA-256"},
}


def run_chain(data: bytes, recipe: list[dict[str, Any]]) -> tuple[bytes, list[str]]:
    """Apply a recipe (list of {"op": name, "args": {...}}) to data.

    Returns (result_bytes, log_lines). Raises OpError on the failing op.
    """
    log: list[str] = []
    for i, step in enumerate(recipe):
        name = step.get("op", "")
        spec = OPS.get(name)
        if spec is None:
            raise OpError(name or f"step#{i}", "unknown operation")
        kwargs = {k: v for k, v in (step.get("args") or {}).items() if k in spec["args"]}
        try:
            data = spec["fn"](data, **kwargs)
        except OpError:
            raise
        except Exception as e:  # surface any op crash as an op-scoped error
            raise OpError(name, f"{type(e).__name__}: {e}") from e
        log.append(f"{i + 1:02d}. {spec['label']}  ({len(data)} bytes)")
    return data, log
