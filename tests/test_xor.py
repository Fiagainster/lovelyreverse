"""Tests for XOR brute force and known-plaintext key derivation."""

import os

from lovelyreverse.util.xor import xor_derive, xor_full_decode, xor_single_brute


class TestScoring:
    def test_printable_english_scores_high(self):
        from lovelyreverse.util.xor import _score

        english = b"the quick brown fox jumps over the lazy dog"
        noise = bytes(range(256)) * 2
        assert _score(english) > 80
        assert _score(noise) < 40

    def test_empty_scores_zero(self):
        from lovelyreverse.util.xor import _score

        assert _score(b"") == 0.0


class TestSingleByteBrute:
    def test_finds_correct_key(self):
        plain = (
            b"The flag is flag{xor_is_not_security}. Repeat: the flag is the flag. "
            b"More english text so the scoring has something to chew on. "
        )
        data = bytes(b ^ 0x42 for b in plain)
        results = xor_single_brute(data, top=8)
        assert results, "expected at least one candidate"
        assert results[0]["key"] == 0x42
        assert results[0]["preview"].startswith("The flag")

    def test_no_candidates_for_random_data(self):
        data = os.urandom(1024)
        results = xor_single_brute(data, min_score=90.0)
        assert results == []

    def test_results_sorted_by_score(self):
        plain = b"aaaaaaaa" * 32
        data = bytes(b ^ 0x10 for b in plain)
        results = xor_single_brute(data, top=16, min_score=0)
        scores = [r["score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_empty_input(self):
        assert xor_single_brute(b"") == []


class TestFullDecode:
    def test_decode_all(self):
        plain = b"hello world" * 10
        data = bytes(b ^ 0x5A for b in plain)
        res = xor_full_decode(data, 0x5A)
        assert res["is_printable"]
        assert res["preview"].startswith("hello world")
        assert res["length"] == len(plain)


class TestDerive:
    def test_derive_repeating_key(self):
        plain = b"flag{known_plaintext_attack_works}"
        key = b"ATRI"
        data = bytes(b ^ key[i % 4] for i, b in enumerate(plain))
        cands = xor_derive(data, "flag{")
        assert cands, "expected key candidates"
        best = cands[0]
        assert best["key_ascii"] == "ATRI"
        assert best["length"] == 4
        # A length-5 candidate also exists (prefix length), but short key wins.
        assert cands[0]["length"] <= cands[-1]["length"]

    def test_derive_single_byte(self):
        data = bytes(b ^ 0x2A for b in b"flag{single_byte}")
        cands = xor_derive(data, "flag{")
        assert any(c["key_bytes"] == "2a" and c["length"] == 1 for c in cands)

    def test_derive_prefix_longer_than_data(self):
        cands = xor_derive(b"ab", "flag{very_long_prefix}")
        assert cands == [] or all(c["length"] <= 2 for c in cands)

    def test_derive_empty(self):
        assert xor_derive(b"", "flag{") == []
