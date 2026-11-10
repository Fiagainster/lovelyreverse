"""Tests for dependency-free PE/ELF triage: sections, overlay, entropy, sniffing."""

import os
import struct

from lovelyreverse.util.binfile import (
    entropy_profile,
    file_hashes,
    parse_elf,
    parse_pe,
    shannon_entropy,
    sniff_format,
    triage,
)


# ------------------------------------------------------------------- fixtures

def build_min_pe64(section_raw_size=0x200, section_raw_offset=0x200, cert=None, tail=b"") -> bytes:
    """Craft a minimal one-section PE32+ image for parser tests."""
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)  # e_lfanew

    pe = 0x40
    buf[pe : pe + 4] = b"PE\x00\x00"
    opt_size = 240  # PE32+: 112 fixed + 16 * 8 data dirs
    struct.pack_into(
        "<HHIIIHH", buf, pe + 4,
        0x8664,   # machine x86-64
        1,        # NumberOfSections
        0,        # TimeDateStamp
        0, 0,     # symbol table
        opt_size, # SizeOfOptionalHeader
        0x0022,   # Characteristics
    )
    opt = pe + 24
    struct.pack_into("<HBBIIIII", buf, opt,
                     0x20B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)  # magic..BaseOfCode
    struct.pack_into("<Q", buf, opt + 24, 0x140000000)           # ImageBase
    struct.pack_into("<I", buf, opt + 56, 0x3000)                # SizeOfImage
    struct.pack_into("<I", buf, opt + 60, 0x200)                 # SizeOfHeaders
    struct.pack_into("<I", buf, opt + 108, 16)                   # NumberOfRvaAndSizes
    if cert is not None:
        rva, size = cert
        struct.pack_into("<II", buf, opt + 112 + 8 * 4, rva, size)  # Security dir

    sh = opt + opt_size  # 0x40+24+240 = 328
    assert sh == 328
    sec = bytearray(40)
    sec[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", sec, 8, 0x1000, 0x1000, section_raw_size, section_raw_offset)
    struct.pack_into("<I", sec, 36, 0x60000020)  # characteristics
    buf[sh : sh + 40] = sec

    # padding up to section raw start
    if len(buf) < section_raw_offset:
        buf.extend(b"\x00" * (section_raw_offset - len(buf)))
    end = section_raw_offset + section_raw_size
    if len(buf) < end:
        buf.extend(b"\x00" * (end - len(buf)))
    buf.extend(tail)
    return bytes(buf)


def build_min_elf64(section_offset=0x100, section_size=0x100, tail=b"") -> bytes:
    """Craft a minimal 64-bit LE ELF: NULL section + one PROGBITS section."""
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4] = 2   # 64-bit
    eh[5] = 1   # little endian
    eh[6] = 1   # version
    struct.pack_into("<HH", eh, 16, 2, 62)      # ET_EXEC, EM_X86_64
    struct.pack_into("<Q", eh, 24, 0x401000)    # entry
    struct.pack_into("<Q", eh, 40, 0x40)        # e_shoff
    struct.pack_into("<HHHHHH", eh, 52, 64, 0, 0, 64, 2, 0)  # ehsize,phentsize,phnum,shentsize,shnum,shstrndx

    sh_null = bytearray(64)                     # section[0]: SHT_NULL
    sh_real = bytearray(64)
    struct.pack_into("<IIQQQQ", sh_real, 0, 0, 1, 0, 0x1000, section_offset, section_size)

    out = bytearray(eh)
    out.extend(sh_null)      # at 0x40
    out.extend(sh_real)      # at 0x80
    if len(out) < section_offset:
        out.extend(b"\x00" * (section_offset - len(out)))
    out.extend(b"\x90" * section_size)
    out.extend(tail)
    return bytes(out)


# --------------------------------------------------------------------- sniff

class TestSniff:
    def test_pe(self):
        assert sniff_format(b"MZ\x90\x00" + b"\x00" * 32)["format"] == "PE"

    def test_elf(self):
        assert sniff_format(b"\x7fELF\x02\x01\x01" + b"\x00" * 16)["format"] == "ELF"
        assert "64-bit" in sniff_format(b"\x7fELF\x02\x01\x01" + b"\x00" * 16)["detail"]

    def test_ar_archive(self):
        # The "Random Crackme" case: ELF wrapped in an ar archive
        assert sniff_format(b"!<arch>\nbleh")["format"] == "AR"

    def test_gzip_zip_7z(self):
        assert sniff_format(b"\x1f\x8b\x08\x00")["format"] == "GZIP"
        assert sniff_format(b"PK\x03\x04xxxx")["format"] == "ZIP"
        assert sniff_format(b"7z\xbc\xaf\x27\x1c")["format"] == "7z"

    def test_raw(self):
        assert sniff_format(b"\x00\x01\x02\x03")["format"] == "RAW"


# ------------------------------------------------------------------- entropy

class TestEntropy:
    def test_constant_bytes_zero(self):
        assert shannon_entropy(b"\x41" * 1000) == 0.0

    def test_random_near_eight(self):
        assert shannon_entropy(os.urandom(4096)) > 7.5

    def test_empty(self):
        assert shannon_entropy(b"") == 0.0

    def test_profile_shape(self):
        prof = entropy_profile(os.urandom(8192), chunks=16)
        assert 8 <= len(prof) <= 16
        assert all(0 <= v <= 8 for v in prof)

    def test_hashes(self):
        h = file_hashes(b"abc")
        assert h["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert h["size"] == 3


# ----------------------------------------------------------------------- PE

class TestPE:
    def test_basic_parse(self):
        data = build_min_pe64()
        info = parse_pe(data)
        assert info is not None
        assert info["bits"] == 64
        assert info["machine"] == "x86-64"
        assert info["sections"][0]["name"] == ".text"
        assert info["sections"][0]["raw_offset"] == 0x200
        assert info["overlay_size"] == 0
        assert not info["signed"]

    def test_overlay_detected(self):
        data = build_min_pe64(tail=b"SECRET_OVERLAY_DATA" * 10)
        info = parse_pe(data)
        assert info["overlay_size"] == len(b"SECRET_OVERLAY_DATA" * 10)
        assert info["overlay_offset"] == 0x400

    def test_cert_table_counts_as_tail(self):
        data = build_min_pe64(cert=(0x800, 0x100), tail=b"\x00" * 0x600)
        info = parse_pe(data)
        assert info["signed"]
        assert info["overlay_offset"] == 0x900
        assert info["overlay_size"] == 0x100  # only what lies past the cert table

    def test_not_pe(self):
        assert parse_pe(b"\x7fELF" + b"\x00" * 100) is None
        assert parse_pe(b"") is None
        assert parse_pe(b"MZ" + b"\x00" * 10) is None  # truncated

    def test_section_entropy_high_for_random_section(self):
        data = build_min_pe64()
        buf = bytearray(data)
        buf[0x200:0x400] = os.urandom(0x200)  # fill the whole raw section
        info = parse_pe(bytes(buf))
        assert info["sections"][0]["entropy"] > 7.0


# ---------------------------------------------------------------------- ELF

class TestELF:
    def test_basic_parse(self):
        info = parse_elf(build_min_elf64())
        assert info is not None
        assert info["bits"] == 64
        assert info["machine"] == "x86-64"
        assert info["endian"] == "little"
        assert info["sections"][1]["size"] == 0x100
        assert info["overlay_size"] == 0

    def test_overlay_detected(self):
        data = build_min_elf64(tail=b"APPENDED" * 32)
        info = parse_elf(data)
        assert info["overlay_size"] == 256
        assert info["overlay_offset"] == 0x100 + 0x100

    def test_32bit(self):
        # minimal 32-bit ELF header
        eh = bytearray(52)
        eh[0:4] = b"\x7fELF"
        eh[4] = 1
        eh[5] = 1
        struct.pack_into("<HH", eh, 16, 3, 3)      # ET_EXEC... wait EM_386=3, ET_EXEC=2
        struct.pack_into("<HH", eh, 16, 2, 3)
        struct.pack_into("<I", eh, 32, 0)           # e_phoff
        struct.pack_into("<I", eh, 0x20, 52)        # e_shoff
        struct.pack_into("<HHHHHH", eh, 40, 52, 32, 0, 40, 1, 0)
        sh = bytearray(40)
        struct.pack_into("<IIIIII", sh, 0, 0, 1, 0, 0x40, 0, 0)
        out = bytes(eh) + bytes(sh)
        info = parse_elf(out + b"\x00" * 64)
        assert info is not None
        assert info["bits"] == 32
        assert info["machine"] == "x86"

    def test_not_elf(self):
        assert parse_elf(b"MZ" + b"\x00" * 100) is None
        assert parse_elf(b"") is None


# ----------------------------------------------------------------- composite

class TestTriage:
    def test_triage_pe_with_overlay(self):
        data = build_min_pe64(tail=b"OVERLAY!" * 8)
        t = triage(data)
        assert t["sniff"]["format"] == "PE"
        assert t["overlay_present"] is True
        assert "sha256" in t["hashes"]
        assert t["entropy_profile"]

    def test_triage_raw(self):
        t = triage(os.urandom(2048))
        assert t["sniff"]["format"] == "RAW"
        assert t["overlay_present"] is False
