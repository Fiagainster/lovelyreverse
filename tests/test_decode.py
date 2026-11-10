"""Tests for the Decoder Lab ops and recipe chains."""

import pytest

from lovelyreverse.util.decode import OPS, OpError, run_chain


class TestSingleOps:
    def test_hex_roundtrip(self):
        out, _ = run_chain(b"hi there", [{"op": "to_hex"}])
        assert out == b"6869207468657265"
        back, _ = run_chain(out, [{"op": "from_hex"}])
        assert back == b"hi there"

    def test_hex_separator_upper(self):
        out, _ = run_chain(b"\xde\xad", [{"op": "to_hex", "args": {"sep": " ", "upper": True}}])
        assert out == b"DE AD"

    def test_from_hex_tolerant(self):
        out, _ = run_chain(b"0xDE, AD-be ef\n", [{"op": "from_hex"}])
        assert out == bytes.fromhex("deadbeef")

    def test_from_hex_odd_length(self):
        with pytest.raises(OpError, match="from_hex"):
            run_chain(b"abc", [{"op": "from_hex"}])

    def test_base64_roundtrip(self):
        out, _ = run_chain(b"flag{xor_master}", [{"op": "to_base64"}])
        assert out == b"ZmxhZ3t4b3JfbWFzdGVyfQ=="
        back, _ = run_chain(out, [{"op": "from_base64"}])
        assert back == b"flag{xor_master}"

    def test_from_base64_urlsafe_no_padding(self):
        # url-safe alphabet swap (- for +, _ for /), embedded whitespace
        out, _ = run_chain(b"-_-_", [{"op": "from_base64"}])
        assert out == b"\xfb\xff\xbf"
        out, _ = run_chain(b"aGkh\n", [{"op": "from_base64"}])
        assert out == b"hi!"

    def test_base32_roundtrip(self):
        out, _ = run_chain(b"data32", [{"op": "to_base32"}])
        back, _ = run_chain(out, [{"op": "from_base32"}])
        assert back == b"data32"

    def test_ascii85_roundtrip(self):
        out, _ = run_chain(b"payload!!", [{"op": "to_ascii85"}])
        back, _ = run_chain(out, [{"op": "from_ascii85"}])
        assert back == b"payload!!"

    def test_url_roundtrip(self):
        out, _ = run_chain(b"a b&c=d/\xc3\xa9", [{"op": "url_encode"}])
        back, _ = run_chain(out, [{"op": "url_decode"}])
        assert back == b"a b&c=d/\xc3\xa9"

    def test_rot13(self):
        out, _ = run_chain(b"Hello, World!", [{"op": "rot", "args": {"n": 13}}])
        assert out == b"Uryyb, Jbeyq!"

    def test_rot26_identity(self):
        out, _ = run_chain(b"Same", [{"op": "rot", "args": {"n": 26}}])
        assert out == b"Same"

    def test_rot47(self):
        out, _ = run_chain(b"ABC xyz 09", [{"op": "rot47"}])
        assert out == b"pqr IJK _h"
        # rot47 is its own inverse
        back, _ = run_chain(out, [{"op": "rot47"}])
        assert back == b"ABC xyz 09"

    def test_xor_repeating_key(self):
        # The ez_debug-style double encryption: ^0x17 then ^"ATRI"
        plain = b"flag{double_xor!!}"
        step1 = bytes(b ^ 0x17 for b in plain)
        cipher = bytes(b ^ step1_key for b, step1_key in zip(step1, (b"ATRI" * 10)))
        # decrypt: ^ATRI then ^0x17
        out, _ = run_chain(cipher, [{"op": "xor", "args": {"key": "ATRI"}}])
        out, _ = run_chain(out, [{"op": "xor", "args": {"key": "17"}}])  # 2 hex chars -> byte 0x17
        assert out == plain

    def test_xor_hex_key(self):
        out, _ = run_chain(b"\x00\x00\x00\x00", [{"op": "xor", "args": {"key": "deadbeef"}}])
        assert out == bytes.fromhex("deadbeef")

    def test_xor_hexish_word_forced_ascii(self):
        # "ABCD" is valid hex, but explicit hex=false forces ascii interpretation
        out, _ = run_chain(b"\x00" * 4, [{"op": "xor", "args": {"key": "ABCD", "hex": False}}])
        assert out == b"ABCD"

    def test_rc4_roundtrip(self):
        from lovelyreverse.util.decode import op_rc4

        enc = op_rc4(b"secret message", key="key")
        assert op_rc4(enc, key="key") == b"secret message"
        assert enc != b"secret message"

    def test_reverse_and_not(self):
        out, _ = run_chain(b"\x00\xff\x0f", [{"op": "reverse"}])
        assert out == b"\x0f\xff\x00"
        out, _ = run_chain(b"\x00\xff", [{"op": "bit_not"}])
        assert out == b"\xff\x00"

    def test_c_escape_unescape(self):
        raw = bytes(range(0, 16)) + b'A"B'
        out, _ = run_chain(raw, [{"op": "c_escape"}])
        back, _ = run_chain(out, [{"op": "c_unescape"}])
        assert back == raw

    def test_hexdump(self):
        out, _ = run_chain(b"AB", [{"op": "hexdump"}])
        assert out.startswith(b"00000000")

    def test_gzip_roundtrip(self):
        payload = b"compress me" * 100
        out, _ = run_chain(payload, [{"op": "gzip_compress"}])
        assert len(out) < len(payload)
        back, _ = run_chain(out, [{"op": "gzip_decompress"}])
        assert back == payload

    def test_zlib_and_raw_inflate(self):
        payload = b"zlib data" * 50
        out, _ = run_chain(payload, [{"op": "zlib_compress"}])
        back, _ = run_chain(out, [{"op": "zlib_decompress"}])
        assert back == payload
        # raw deflate stream (no zlib header) decompresses via raw_inflate
        import zlib as _z
        raw = _z.compressobj(9, _z.DEFLATED, -15)
        stream = raw.compress(payload) + raw.flush()
        back2, _ = run_chain(stream, [{"op": "raw_inflate"}])
        assert back2 == payload
        # ...but a zlib-wrapped stream is rejected by raw_inflate
        with pytest.raises(OpError, match="raw_inflate"):
            run_chain(out, [{"op": "raw_inflate"}])

    def test_md5_known_vector(self):
        out, _ = run_chain(b"", [{"op": "md5"}])
        assert out == b"d41d8cd98f00b204e9800998ecf8427e"

    def test_sha256_known_vector(self):
        out, _ = run_chain(b"abc", [{"op": "sha256"}])
        assert out == b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


class TestChain:
    def test_multistep_chain(self):
        # encode then decode returns original
        recipe = [{"op": "to_base64"}, {"op": "to_hex"}]
        out, _ = run_chain(b"round trip", recipe)
        back, _ = run_chain(out, [{"op": "from_hex"}, {"op": "from_base64"}])
        assert back == b"round trip"

    def test_log_lines(self):
        out, log = run_chain(b"x", [{"op": "to_hex"}, {"op": "reverse"}])
        assert len(log) == 2
        assert "01." in log[0] and "02." in log[1]

    def test_unknown_op(self):
        with pytest.raises(OpError, match="unknown operation"):
            run_chain(b"", [{"op": "nope"}])

    def test_bad_from_base64(self):
        # a single data char cannot decode
        with pytest.raises(OpError, match="from_base64"):
            run_chain(b"A", [{"op": "from_base64"}])

    def test_op_registry_labels_unique(self):
        labels = [spec["label"] for spec in OPS.values()]
        assert len(labels) == len(set(labels))
        assert len(OPS) >= 25
