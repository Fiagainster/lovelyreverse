"""XOR helpers: single-byte brute force with scoring, and known-plaintext key derivation.

The classic CTF moves: "try every single-byte key", and "we know it starts
with flag{ — what's the key?".
"""

from __future__ import annotations

import string
from typing import Any

# Chars that make a decode look "intended": letters, digits, common punctuation.
_COMMON = set((string.ascii_letters + string.digits + " {}_-!@#$%^&*()+=[]:;'\",.<>/?\\|`~ ").encode())
_PRINTABLE = set((string.printable).encode()) - {0x0B, 0x0C}

_BONUS = {c: w for c, w in zip(b"etaoin shrdlu", [3] * 13)}
_BONUS.update({c: 2 for c in b"ETAOIN"})


def _score(data: bytes) -> float:
    """0..100 quality score for a candidate plaintext."""
    if not data:
        return 0.0
    sample = data[:1024]
    printable = sum(1 for b in sample if b in _PRINTABLE)
    if printable / len(sample) < 0.7:
        return printable / len(sample) * 30.0
    score = printable / len(sample) * 60.0
    score += sum(_BONUS.get(b, 0) for b in sample) / len(sample) * 10.0
    common = sum(1 for b in sample if b in _COMMON)
    score += common / len(sample) * 30.0
    return min(score, 100.0)


def _preview(data: bytes, limit: int = 64) -> str:
    chunk = data[:limit]
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)


def xor_single_brute(data: bytes, top: int = 16, min_score: float = 45.0) -> list[dict[str, Any]]:
    """Try every single-byte key; return scored candidates, best first."""
    results = []
    for k in range(256):
        dec = bytes(b ^ k for b in data[:1024])
        s = _score(dec)
        if s >= min_score:
            results.append({
                "key": k,
                "key_hex": f"{k:02x}",
                "score": round(s, 1),
                "preview": _preview(dec),
                "decoded_hex": None,
            })
    results.sort(key=lambda r: (-r["score"], r["key"]))
    return results[:top]


def xor_full_decode(data: bytes, key: int) -> dict[str, Any]:
    """Decode entire buffer with one byte key, with a text preview + hex fallback."""
    dec = bytes(b ^ key for b in data)
    return {
        "key": key,
        "key_hex": f"{key:02x}",
        "preview": _preview(dec, 4096),
        "is_printable": all(b in _PRINTABLE or b in (9, 10, 13) for b in dec[:4096]),
        "length": len(dec),
    }


def xor_derive(data: bytes, prefix: str | bytes, max_key_len: int = 64) -> list[dict[str, Any]]:
    """Derive repeating-XOR key candidates from a known plaintext prefix.

    Given data ^ key == prefix for the first len(prefix) bytes, the raw
    keystream is ks[i] = data[i] ^ prefix[i].  If the real key has length d
    dividing len(prefix), then ks must be periodic with period d; we test every
    divisor and return every consistent candidate.
    """
    if isinstance(prefix, str):
        prefix = prefix.encode("utf-8")
    n = min(len(prefix), len(data), max_key_len * 4)
    if n == 0:
        return []
    ks = bytes(d ^ p for d, p in zip(data[:n], prefix[:n]))
    out: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for d in range(1, n + 1):
        if len(out) >= 8:
            break
        cand = ks[:d]
        if cand in seen:
            continue
        if all(ks[i] == cand[i % d] for i in range(n)):
            seen.add(cand)
            printable_key = all(0x20 <= b < 0x7F for b in cand)
            out.append({
                "key_bytes": cand.hex(),
                "key_ascii": cand.decode("ascii") if printable_key else None,
                "key_display": cand.decode("ascii") if printable_key else cand.hex(),
                "length": d,
                "periodic": d < n,
            })
    # Prefer short, human-readable keys.
    out.sort(key=lambda c: (not c["key_ascii"], c["length"]))
    return out
