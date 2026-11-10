"""Tests for the crypto constant signature library and scanner."""

import os

import pytest

from lovelyreverse.engine.constants import SIGNATURES, scan_bytes

CATEGORIES = {"block-cipher", "stream-cipher", "hash", "encoding", "ecc", "misc"}


class TestSignatureTable:
    def test_names_unique(self):
        names = [s["name"] for s in SIGNATURES]
        assert len(names) == len(set(names))

    def test_categories_valid(self):
        assert all(s["category"] in CATEGORIES for s in SIGNATURES)

    def test_min_length(self):
        # signatures shorter than 4 bytes would be noise
        assert all(len(s["data"]) >= 4 for s in SIGNATURES)

    def test_table_size(self):
        # enough coverage to be useful (both-endian expansion included)
        assert len(SIGNATURES) >= 40


class TestScanner:
    def test_finds_aes_sbox(self):
        data = b"junk" + bytes.fromhex("637c777bf26b6fc53001672bfed7ab76") + b"more"
        hits = scan_bytes(data)
        match = [h for h in hits if h["name"] == "AES S-box"]
        assert match and match[0]["offset"] == 4

    def test_finds_tea_delta_both_endians(self):
        for blob in (b"\x9e\x37\x79\xb9", b"\xb9\x79\x37\x9e"):
            hits = scan_bytes(b"\x00" * 8 + blob)
            assert any("TEA" in h["name"] for h in hits)

    def test_finds_chacha_sigma(self):
        hits = scan_bytes(b"expand 32-byte k" + b"\x00" * 16)
        assert any(h["name"] == "ChaCha/Salsa sigma" for h in hits)

    def test_finds_base64_alphabet(self):
        hits = scan_bytes(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        assert any(h["category"] == "encoding" for h in hits)

    def test_offsets_are_absolute(self):
        blob = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
        hits = scan_bytes(b"\xff" * 100 + blob, base_offset=0x1000)
        assert hits[0]["offset"] == 0x1000 + 100

    def test_sorted_by_offset(self):
        data = (
            bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")     # AES sbox
            + b"\x00" * 5
            + b"expand 32-byte k"                                  # chacha
        )
        hits = scan_bytes(data)
        assert [h["offset"] for h in hits] == sorted(h["offset"] for h in hits)

    def test_hit_cap(self):
        data = b"\x9e\x37\x79\xb9" * 64
        hits = scan_bytes(data)
        tea_hits = [h for h in hits if "TEA" in h["name"]]
        assert len(tea_hits) <= 32

    def test_no_false_positives_on_zeros(self):
        assert scan_bytes(b"\x00" * 4096) == []
        assert scan_bytes(os.urandom(4096)) == []

    def test_realistic_program_image(self):
        # An .rdata section containing a compiled AES sbox reference
        image = b"\x90" * 0x200 + bytes.fromhex(
            "c66363a5f87c7c84ee777799f67b7b8d"   # Te0 head (BE)
        ) + b"\x00" * 16
        hits = scan_bytes(image)
        assert any("AES Te0" in h["name"] for h in hits)
