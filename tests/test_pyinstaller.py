"""PyInstaller unpacker tests — synthesizes a minimal CArchive, no fixture binaries."""

import marshal
import struct
import zlib

import pytest

from lovelyreverse.util.pyinstaller import NotPyInstaller, detect, unpack

MAGIC = b"MEI\014\013\012\013\016"
PY37_MAGIC = b"\x42\x0d\x0d\x0a"


def _entry(name, data, ctype, compress=False):
    payload = zlib.compress(data) if compress else data
    return {
        "name": name,
        "data": data,
        "ctype": ctype,
        "payload": payload,
        "cflag": 1 if compress else 0,
        "usize": len(data),
        "csize": len(payload),
    }


def _build(entries, pyver=37):
    """Layout: [entry blobs][toc][cookie] — cookie at EOF, overlay_pos = 0."""
    cookie_size = 24 + 64  # pyinstaller 2.1+
    blob_parts, toc_parts, offset = [], [], 0
    for e in entries:
        fixed = struct.pack("!IIIBc", offset, e["csize"], e["usize"], e["cflag"], e["ctype"])
        name_b = e["name"].encode()
        toc_parts.append(struct.pack("!i", 4 + len(fixed) + len(name_b)) + fixed + name_b)
        blob_parts.append(e["payload"])
        offset += e["csize"]
    toc_blob = b"".join(toc_parts)
    blob = b"".join(blob_parts)
    cookie = struct.pack(
        "!8sIIii64s", MAGIC, len(blob) + len(toc_blob) + cookie_size,
        len(blob), len(toc_blob), pyver, b"python37.dll\0",
    )
    return blob + toc_blob + cookie


SCRIPT = b"\xe3\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 8 + b"fake code object"


class TestDetect:
    def test_detects_cookie(self, tmp_path):
        exe = tmp_path / "packed.exe"
        exe.write_bytes(_build([_entry("run", SCRIPT, b"s", compress=True)]))
        out = detect(exe)
        assert out["python"] == "3.7"
        assert out["pyinstaller"] == "2.1+"

    def test_rejects_garbage(self, tmp_path):
        p = tmp_path / "plain.exe"
        p.write_bytes(b"MZ" + b"\x00" * 512)
        assert detect(p) is None


class TestUnpack:
    def _unpack(self, tmp_path, entries, pyver=37):
        exe = tmp_path / "packed.exe"
        exe.write_bytes(_build(entries, pyver))
        return unpack(exe, outdir=tmp_path / "out")

    def test_script_and_data(self, tmp_path):
        man = self._unpack(tmp_path, [
            _entry("run", SCRIPT, b"s", compress=True),
            _entry("config.json", b'{"a": 1}', b"x"),
        ])
        names = {e["name"]: e for e in man["entries"]}
        assert man["entry_points"] == ["run.pyc"]
        assert names["run.pyc"]["type"] == "script"
        assert names["config.json"]["type"] == "data"
        # bare pyc header fixed via python-version fallback (3.7 magic)
        pyc = (tmp_path / "out" / "run.pyc").read_bytes()
        assert pyc[:4] == PY37_MAGIC
        assert (tmp_path / "out" / "config.json").read_bytes() == b'{"a": 1}'

    def test_traversal_sanitized(self, tmp_path):
        man = self._unpack(tmp_path, [_entry("../evil.txt", b"x", b"x")])
        # ".." is defanged in-place, keeping the path inside the outdir
        assert man["entries"][0]["name"] == "__/evil.txt"
        assert (tmp_path / "out" / "__" / "evil.txt").is_file()
        assert not (tmp_path / "evil.txt").exists()

    def test_not_pyinstaller(self, tmp_path):
        bogus = tmp_path / "plain.exe"
        bogus.write_bytes(b"MZ" + b"\x00" * 512)
        with pytest.raises(NotPyInstaller):
            unpack(bogus, outdir=tmp_path / "out")

    def test_pyz_extracted(self, tmp_path):
        # mini PYZ: "PYZ\0" + pyc-magic + toc-pos + [module data] + [marshalled toc]
        pymod = zlib.compress(b"module-code")
        toc = {"os.path": (1, 12, len(pymod))}  # ispkg=1 -> __init__.pyc, data at pos 12
        toc_blob = marshal.dumps(toc)
        pyz = bytearray(b"PYZ\0" + PY37_MAGIC + struct.pack("!i", 12) + pymod + toc_blob)
        pyz[8:12] = struct.pack("!i", 12 + len(pymod))
        man = self._unpack(tmp_path, [_entry("PYZ-00.pyz", bytes(pyz), b"z")])
        assert man["pyz_modules"] == 1
        assert (tmp_path / "out" / "PYZ-00.pyz_extracted" / "os" / "path" / "__init__.pyc").is_file()
        # pyc magic inside PYZ extraction should match the PYZ's own magic
        init = (tmp_path / "out" / "PYZ-00.pyz_extracted" / "os" / "path" / "__init__.pyc").read_bytes()
        assert init[:4] == PY37_MAGIC
