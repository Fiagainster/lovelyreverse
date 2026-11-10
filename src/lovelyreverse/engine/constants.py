"""Crypto constant signatures (FindCrypt-style) and the memory scanner.

Byte-order-sensitive constants are expanded into big- and little-endian
variants automatically, so the table only states each constant once.
"""

from __future__ import annotations

from typing import Any


def _b(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr.replace(" ", ""))


def _words(words: list[int], size: int) -> dict[str, bytes]:
    """Expand a word list into both byte orders."""
    return {
        "be": b"".join(w.to_bytes(size, "big") for w in words),
        "le": b"".join(w.to_bytes(size, "little") for w in words),
    }


def _build() -> list[dict[str, Any]]:
    sigs: list[dict[str, Any]] = []

    def add_raw(name: str, category: str, data: bytes, note: str = "") -> None:
        sigs.append({"name": name, "category": category, "data": data, "note": note})

    def add_words(name: str, category: str, words: list[int], size: int, note: str = "") -> None:
        variants = _words(words, size)
        for tag, blob in variants.items():
            suffix = " (BE)" if tag == "be" else " (LE)"
            add_raw(name + suffix, category, blob, note)

    # ------------------------------------------------------------ block ciphers
    add_raw("AES S-box", "block-cipher", _b(
        "637c777bf26b6fc53001672bfed7ab76"), "AES (Rijndael) substitution box")
    add_raw("AES inverse S-box", "block-cipher", _b(
        "52096ad53036a538bf40a39e81f3d7fb"), "AES inverse substitution box")
    add_words("AES Te0 T-table", "block-cipher", [0xC66363A5, 0xF87C7C84], 4,
              "AES encryption T-table head")
    add_words("AES Rcon[1..4]", "block-cipher", [0x01020408], 4,
              "AES key-schedule round constants (byte order agnostic)")
    add_raw("SM4 S-box", "block-cipher", _b(
        "d690e9fecce13db716b614c228fb2c05"), "SM4 (Chinese standard) substitution box")
    add_words("SM4 FK", "block-cipher", [0xA3B1BAC6, 0x56AA3350], 4, "SM4 system parameter")
    add_raw("DES IP table", "block-cipher", _b("58504234261a1002"),
            "DES initial permutation head (58,50,42,34,26,18,10,2)")
    add_raw("DES PC1 table", "block-cipher", _b("5749413325170901"),
            "DES permuted-choice-1 head (57,49,41,33,25,17,9,1)")
    add_words("Blowfish P-array[0..3]", "block-cipher",
              [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344], 4,
              "Blowfish P-array (hex digits of pi)")
    add_raw("CAST-128 S-box S1 head", "block-cipher", _b("30fb40d4"), "CAST-128 S1[0] = 0x30FB40D4")
    add_words("Camellia Sigma", "block-cipher",
              [0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2], 4, "Camellia key-schedule sigma")
    add_words("SEED key constants", "block-cipher", [0x9E3779B9, 0xE4BC7A0D], 4, "KISA SEED deltas")

    # ------------------------------------------------------------ stream ciphers
    add_raw("ChaCha/Salsa sigma", "stream-cipher", b"expand 32-byte k", "ChaCha20 / Salsa20 constant")
    add_raw("ChaCha sigma (128-bit key)", "stream-cipher", b"expand 16-byte k", "ChaCha variant constant")

    # -------------------------------------------------------------------- hashes
    md_iv = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    add_words("MD4/MD5/SHA-1/RIPEMD IV", "hash", md_iv, 4,
              "shared init vector of the MD family")
    add_words("MD5 T-table[0..3]", "hash",
              [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE], 4, "MD5 sine table")
    add_words("SHA-256 IV[0..3]", "hash",
              [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A], 4, "SHA-224/256 init vector")
    add_words("SHA-512 IV[0..2]", "hash",
              [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B], 8, "SHA-384/512 init vector")
    add_words("SHA-256 K[0..3]", "hash",
              [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5], 4, "SHA-256 round constants")
    add_words("SHA-512 K[0..2]", "hash",
              [0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F], 8, "SHA-512 round constants")
    add_words("SM3 IV[0..2]", "hash", [0x7380166F, 0x4914B2B9, 0x172442D7], 4,
              "SM3 (Chinese standard) init vector")
    add_raw("Whirlpool C0[0]", "hash", _b("1823c6e887b8014f"), "Whirlpool C0 table head (64-bit)")
    add_words("CRC-32 poly", "hash", [0xEDB88320], 4, "CRC-32 reflected polynomial")
    add_words("CRC-32 table[0..3]", "hash", [0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA], 4,
              "CRC-32 lookup table head")
    add_words("CRC-32C table[0..3]", "hash", [0x00000000, 0xF26B8303, 0xE13B70F7, 0x8E06A179], 4,
              "CRC-32C (Castagnoli) table head")
    add_raw("CRC-16 CCITT table[0..3]", "hash", _b("0000c0c1c181c300"),
            "CRC-16/CCITT-FALSE table head (byte order agnostic)")

    # ---------------------------------------------------------------------- misc
    add_words("TEA/XTEA delta", "misc", [0x9E3779B9], 4, "TEA family delta (derived from golden ratio)")
    add_words("XTEA decrypt sum", "misc", [0x61C88647], 4, "XTEA -delta, decrypt direction")

    # ------------------------------------------------------------------ encodings
    add_raw("Base64 alphabet", "encoding",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "standard base64 alphabet (RFC 4648)")
    add_raw("Base64url alphabet", "encoding",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            "URL-safe base64 alphabet")
    add_raw("Base32 alphabet", "encoding", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            "base32 alphabet (RFC 4648)")
    add_raw("Uuencode alphabet", "encoding",
            b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_",
            "uuencode 64-char alphabet")

    # ----------------------------------------------------------------------- ecc
    # Field primes are computed, not hand-copied — zero transcription risk.
    def _prime_hex(value: int, size: int, endian: str) -> str:
        return value.to_bytes(size, endian).hex().upper()

    p256 = 2**256 - 2**224 + 2**192 + 2**96 - 1
    p384 = 2**384 - 2**128 - 2**96 + 2**32 - 1
    p521 = 2**521 - 1
    k25519 = 2**255 - 19
    secp256k1 = 2**256 - 2**32 - 977

    add_raw("P-256 prime p", "ecc", _b(_prime_hex(p256, 32, "big")), "NIST P-256 field prime")
    add_raw("P-384 prime p", "ecc", _b(_prime_hex(p384, 48, "big")), "NIST P-384 field prime")
    add_raw("P-521 prime p", "ecc", _b(_prime_hex(p521, 66, "big")), "NIST P-521 field prime")
    add_raw("Curve25519 prime p", "ecc", _b(_prime_hex(k25519, 32, "little")),
            "X25519 field prime 2^255-19 (little-endian bytes)")
    add_raw("secp256k1 prime p", "ecc", _b(_prime_hex(secp256k1, 32, "big")),
            "Bitcoin curve field prime")

    return sigs


SIGNATURES: list[dict[str, Any]] = _build()


def scan_bytes(data: bytes, base_offset: int = 0, max_hits_per_sig: int = 32) -> list[dict[str, Any]]:
    """Scan a byte buffer for every signature; returns offset-sorted hits."""
    hits: list[dict[str, Any]] = []
    for sig in SIGNATURES:
        blob = sig["data"]
        start = 0
        count = 0
        while count < max_hits_per_sig:
            idx = data.find(blob, start)
            if idx < 0:
                break
            hits.append({
                "name": sig["name"],
                "category": sig["category"],
                "note": sig["note"],
                "length": len(blob),
                "offset": base_offset + idx,
            })
            start = idx + 1
            count += 1
    hits.sort(key=lambda h: h["offset"])
    return hits
