"""PyInstaller archive unpacker (CArchive + PYZ), stdlib-only.

Ported from extremecoders-re/pyinstxtractor v2.0 (GPLv3) — that project's
notice is preserved here: https://github.com/extremecoders-re/pyinstxtractor

Adaptations for lovelyreverse:
* no chdir / no prints — returns a JSON-friendly manifest instead
* tolerant of malformed TOC entries (warn, don't assert)
* extraction goes into an explicit outdir with path-traversal guards
* PYZ extraction is attempted regardless of interpreter version; failures
  degrade to "archived as-is" warnings like the original
"""

from __future__ import annotations

import io
import marshal
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import Any, Callable

MAGIC = b"MEI\014\013\012\013\016"
PYINST20_COOKIE_SIZE = 24
PYINST21_COOKIE_SIZE = 24 + 64

TYPE_LABELS = {
    b"s": "script",
    b"m": "module",
    b"M": "package",
    b"z": "pyz",
    b"Z": "pyz",
    b"b": "binary",
    b"x": "data",
    b"o": "option",
    b"d": "dependency",
}

# Fallback pyc magic per CPython version, used when no PYZ/headered module
# reveals it. key = (major, minor) -> magic int (PEP 552 layout adds 8 bytes).
PYC_MAGIC = {
    (2, 7): 62211,
    (3, 6): 3379,
    (3, 7): 3394,
    (3, 8): 3413,
    (3, 9): 3425,
    (3, 10): 3439,
    (3, 11): 3495,
    (3, 12): 3531,
    (3, 13): 3571,
}


class NotPyInstaller(ValueError):
    pass


def _find_cookie(data: bytes) -> int:
    """Scan backwards for the CArchive cookie (it sits before cert padding)."""
    chunk = 8192
    end = len(data)
    while True:
        start = end - chunk if end >= chunk else 0
        if end - start < len(MAGIC):
            return -1
        offs = data.rfind(MAGIC, start, end)
        if offs != -1:
            return offs
        end = start + len(MAGIC) - 1
        if start == 0:
            return -1


def _parse_cookie(data: bytes, pos: int) -> dict[str, Any]:
    if b"python" in data[pos + PYINST20_COOKIE_SIZE : pos + PYINST20_COOKIE_SIZE + 64].lower():
        ver, size = 21, PYINST21_COOKIE_SIZE
    else:
        ver, size = 20, PYINST20_COOKIE_SIZE
    if ver == 20:
        _, lengthof_package, toc, toc_len, pyver = struct.unpack(
            "!8siiii", data[pos : pos + size]
        )
        pylibname = b""
    else:
        _, lengthof_package, toc, toc_len, pyver, pylibname = struct.unpack(
            "!8sIIii64s", data[pos : pos + size]
        )
    pymaj, pymin = (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
    tail = len(data) - pos - size
    overlay_size = lengthof_package + tail
    overlay_pos = len(data) - overlay_size
    return {
        "ver": ver,
        "pyver": pyver,
        "pymaj": pymaj,
        "pymin": pymin,
        "pylibname": pylibname.rstrip(b"\0").decode("utf-8", "replace"),
        "lengthof_package": lengthof_package,
        "toc": toc,
        "toc_len": toc_len,
        "overlay_pos": overlay_pos,
    }


def detect(path: str | Path) -> dict[str, Any] | None:
    """Return cookie info if `path` is a PyInstaller bundle, else None."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    pos = _find_cookie(data)
    if pos < 0:
        return None
    c = _parse_cookie(data, pos)
    return {
        "pyinstaller": "2.1+" if c["ver"] == 21 else "2.0",
        "python": f"{c['pymaj']}.{c['pymin']}",
        "pylibname": c["pylibname"],
        "overlay_size": len(data) - c["overlay_pos"],
    }


def unpack(
    path: str | Path,
    outdir: str | Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Extract a PyInstaller CArchive (and its PYZ) into outdir.

    Returns a manifest: {"outdir", "pyinstaller", "python", "entries",
    "total", "entry_points", "pyz_modules", "warnings"}.
    """
    src = Path(path)
    data = src.read_bytes()
    pos = _find_cookie(data)
    if pos < 0:
        raise NotPyInstaller("no PyInstaller cookie found (MEI\\x0c\\x0b\\x0a\\x0b\\x0e)")
    c = _parse_cookie(data, pos)

    if outdir is None:
        outdir = Path(__import__("tempfile").gettempdir()) / f"lvr_unpacked_{src.stem}_{int(time.time())}"
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out_res = outdir.resolve()

    warnings: list[str] = []
    entries: list[dict[str, Any]] = []
    entry_points: list[str] = []
    pyc_magic = b"\0" * 4
    bare_pycs: list[str] = []
    pyz_module_count = 0

    # parse TOC
    toc_bytes = data[c["overlay_pos"] + c["toc"] : c["overlay_pos"] + c["toc"] + c["toc_len"]]
    toc_off = 0
    toc_list: list[dict[str, Any]] = []
    while toc_off + 4 <= len(toc_bytes):
        (entry_size,) = struct.unpack_from("!i", toc_bytes, toc_off)
        if entry_size < 4 or toc_off + entry_size > len(toc_bytes):
            warnings.append(f"malformed TOC entry at offset {toc_off}, stopped parsing")
            break
        hdr = toc_bytes[toc_off + 4 : toc_off + entry_size]
        if len(hdr) < 14:
            warnings.append(f"short TOC entry at offset {toc_off}, skipped")
            toc_off += entry_size
            continue
        entry_pos, csize, usize, cflag, ctype = struct.unpack("!IIIBc", hdr[:14])
        name = hdr[14:].decode("utf-8", "replace").rstrip("\0")
        toc_off += entry_size

        if name.startswith("/"):
            name = name.lstrip("/")
        name = name.replace("\\", "/").replace("..", "__")
        if not name:
            name = f"unnamed_{len(toc_list)}"

        toc_list.append({
            "pos": c["overlay_pos"] + entry_pos,
            "csize": csize,
            "usize": usize,
            "cflag": cflag,
            "type": ctype,
            "name": name,
        })

    def prog(s: str) -> None:
        if progress:
            progress(s)

    def safe_target(rel: str) -> Path:
        t = (outdir / rel).resolve()
        t.relative_to(out_res)  # raises ValueError on traversal
        return t

    def write_pyc(rel: str, payload: bytes) -> None:
        t = safe_target(rel)
        t.parent.mkdir(parents=True, exist_ok=True)
        with t.open("wb") as f:
            f.write(pyc_magic)
            if c["pymaj"] >= 3 and c["pymin"] >= 7:  # PEP 552
                f.write(b"\0" * 4 + b"\0" * 8)
            else:
                f.write(b"\0" * 4)
                if c["pymaj"] >= 3 and c["pymin"] >= 3:
                    f.write(b"\0" * 4)
            f.write(payload)

    def write_raw(rel: str, payload: bytes) -> Path:
        t = safe_target(rel)
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_bytes(payload)
        return t

    total = len(toc_list)
    for i, e in enumerate(toc_list):
        if progress and (i % 50 == 0 or i == total - 1):
            prog(f"extracting {i + 1}/{total}")
        try:
            blob = data[e["pos"] : e["pos"] + e["csize"]]
            if e["cflag"] == 1:
                try:
                    blob = zlib.decompress(blob)
                except zlib.error:
                    warnings.append(f"failed to decompress {e['name']}, skipped")
                    continue
                if len(blob) != e["usize"]:
                    warnings.append(f"size mismatch on {e['name']} (header lied)")
            ctype = e["type"]
            if ctype in (b"d", b"o"):
                continue  # runtime options / dependencies, not files

            name = e["name"]
            if ctype == b"s":  # entry-point script
                rel = f"{name}.pyc"
                entry_points.append(rel)
                if pyc_magic == b"\0" * 4:
                    bare_pycs.append(rel)
                write_pyc(rel, blob)
                etype = "script"
            elif ctype in (b"M", b"m"):  # module/package, header maybe intact
                rel = f"{name}.pyc"
                if blob[2:4] == b"\r\n":  # < pyinstaller 5.3: full pyc header
                    if pyc_magic == b"\0" * 4:
                        pyc_magic = blob[0:4]
                    write_raw(rel, blob)
                else:
                    if pyc_magic == b"\0" * 4:
                        bare_pycs.append(rel)
                    write_pyc(rel, blob)
                etype = "package" if ctype == b"M" else "module"
            else:
                rel = name
                write_raw(rel, blob)
                etype = TYPE_LABELS.get(ctype, "data")
                if ctype in (b"z", b"Z"):
                    n, m = _extract_pyz(
                        safe_target(rel).read_bytes(),
                        outdir / f"{rel}_extracted",
                        out_res,
                        c,
                        progress,
                    )
                    pyz_module_count += n
                    if pyc_magic == b"\0" * 4 and m != b"\0" * 4:
                        pyc_magic = m  # PYZ reveals the true pyc magic
            entries.append({
                "name": rel,
                "type": etype,
                "size": len(blob),
                "zsize": e["csize"],
            })
            if len(entries) >= 5000:
                warnings.append("too many entries, manifest truncated at 5000")
                break
        except Exception as ex:  # noqa: BLE001 - one bad entry must not kill the job
            warnings.append(f"{e['name']}: {type(ex).__name__}: {ex}")

    # fix bare pycs once the real magic is known (PYZ usually provides it)
    if pyc_magic == b"\0" * 4 and (c["pymaj"], c["pymin"]) in PYC_MAGIC:
        pyc_magic = PYC_MAGIC[(c["pymaj"], c["pymin"])].to_bytes(2, "little") + b"\r\n"
        warnings.append(f"pyc magic guessed from python version {c['pymaj']}.{c['pymin']}")
    for rel in bare_pycs:
        try:
            t = safe_target(rel)
            if t.is_file():
                with t.open("r+b") as f:
                    f.write(pyc_magic)
        except Exception:  # noqa: BLE001
            pass

    prog("done")
    return {
        "outdir": str(outdir),
        "pyinstaller": "2.1+" if c["ver"] == 21 else "2.0",
        "python": f"{c['pymaj']}.{c['pymin']}",
        "pylibname": c["pylibname"],
        "total": len(entries),
        "pyz_modules": pyz_module_count,
        "entry_points": entry_points,
        "entries": entries,
        "warnings": warnings,
    }


def _extract_pyz(
    pyz: bytes,
    dest: Path,
    out_res: Path,
    cookie: dict[str, Any],
    progress: Callable[[str], None] | None,
) -> tuple[int, bytes]:
    """Extract PYZ archive bytes into dest; returns (module count, pyc magic)."""
    if len(pyz) < 12 or pyz[:4] != b"PYZ\0":
        return 0, b"\0" * 4
    pyc_magic = pyz[4:8]
    (toc_pos,) = struct.unpack_from("!i", pyz, 8)

    # reimplement write_pyc with the PYZ's own magic
    def wpyc(rel: str, payload: bytes) -> None:
        t = (dest / rel).resolve()
        t.relative_to(out_res)
        t.parent.mkdir(parents=True, exist_ok=True)
        with t.open("wb") as f:
            f.write(pyc_magic)
            if cookie["pymaj"] >= 3 and cookie["pymin"] >= 7:
                f.write(b"\0" * 4 + b"\0" * 8)
            else:
                f.write(b"\0" * 4)
                if cookie["pymaj"] >= 3 and cookie["pymin"] >= 3:
                    f.write(b"\0" * 4)
            f.write(payload)

    dest.mkdir(parents=True, exist_ok=True)
    try:
        toc = marshal.load(io.BytesIO(pyz[toc_pos:]))
    except Exception:
        # wrong interpreter version or encrypted PYZ — can't unmarshal TOC
        return 0, pyc_magic
    if isinstance(toc, list):
        toc = dict(toc)

    count = 0
    bio = io.BytesIO(pyz)
    for key, (ispkg, mpos, length) in toc.items():
        if isinstance(key, bytes):
            key = key.decode("utf-8", "replace")
        rel = key.replace("..", "__").replace(".", "/")
        rel = rel + ("/__init__.pyc" if ispkg else ".pyc")
        count += 1
        if progress and count % 100 == 0:
            progress(f"PYZ modules {count}")
        if length == 0:
            wpyc(rel, b"")
            continue
        try:
            bio.seek(mpos)
            payload = zlib.decompress(bio.read(length))
            wpyc(rel, payload)
        except Exception:  # noqa: BLE001 - encrypted or corrupt, dump as-is
            try:
                bio.seek(mpos)
                t = (dest / (rel + ".encrypted")).resolve()
                t.relative_to(out_res)
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(bio.read(length))
            except Exception:  # noqa: BLE001
                pass
    return count, pyc_magic


if __name__ == "__main__":  # quick manual use: python -m lovelyreverse.util.pyinstaller file.exe
    if len(sys.argv) < 2:
        print("usage: python -m lovelyreverse.util.pyinstaller <packed.exe>")
        sys.exit(2)
    info = detect(sys.argv[1])
    print("detect:", info)
    if info:
        man = unpack(sys.argv[1])
        print(f"extracted {man['total']} entries ({man['pyz_modules']} pyz modules) -> {man['outdir']}")
        print("entry points:", man["entry_points"])
        for w in man["warnings"][:10]:
            print("warn:", w)
