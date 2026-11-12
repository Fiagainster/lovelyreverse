"""Craft a minimal valid classes.dex for tests — header + string pool only.

Layout (little-endian):
  0x00  magic  "dex\n035\0"
  0x20  file_size
  0x38  string_ids_size
  0x3c  string_ids_off
  ...   string_ids: N * u32 offsets into data
  ...   string data: uleb128 byte-length + MUTF-8 bytes + 0x00
"""

import struct


def build_minidex(strings: list[str]) -> bytes:
    data = bytearray(0x70)
    data[0:8] = b"dex\n035\x00"

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    string_data_off = string_ids_off + string_ids_size * 4

    string_data = bytearray()
    offsets = []
    for s in strings:
        raw = s.encode("utf-8")
        offsets.append(string_data_off + len(string_data))
        # uleb128 length
        n = len(raw) + 1  # include the NUL terminator in the declared size
        while True:
            b7 = n & 0x7F
            n >>= 7
            if n:
                string_data.append(b7 | 0x80)
            else:
                string_data.append(b7)
                break
        string_data += raw + b"\x00"

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    string_data_off = string_ids_off + string_ids_size * 4

    out = bytearray(string_data_off + len(string_data))
    out[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", out, 0x20, len(out))               # file_size
    out[0x34:0x38] = b"\x78\x56\x34\x12"                      # checksum-ish
    struct.pack_into("<I", out, 0x38, string_ids_size)
    struct.pack_into("<I", out, 0x3C, string_ids_off)
    struct.pack_into("<I", out, 0x40, 3)                      # type_ids_size (fake)
    struct.pack_into("<I", out, 0x48, 5)                      # method_ids_size (fake)
    for i, off in enumerate(offsets):
        struct.pack_into("<I", out, string_ids_off + i * 4, off)
    out[string_data_off:] = string_data
    return bytes(out)


if __name__ == "__main__":
    import sys

    sys.path.insert(0, r"D:\Project\lovelyreverse\src")
    from lovelyreverse.util.dex import dex_info, dex_strings

    blob = build_minidex(["Lcom/ctf/MainActivity;", "flag{dex_strings_ftw}", "https://evil.example/submit"])
    print(dex_info(blob))
    for s in dex_strings(blob):
        print("  ", s)
