"""Engine integration tests — require a real Ghidra installation.

These are marked `engine` and skipped unless:
  * GHIDRA_INSTALL_DIR points at a Ghidra 11.x/12.x install, and
  * a C compiler (gcc) is available to build the crypto_demo fixture.

Run them explicitly with:  pytest -m engine -v
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.engine,
    pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="GHIDRA_INSTALL_DIR not set"),
]

FIXTURE_SRC = Path(__file__).parent / "fixtures" / "crypto_demo.c"


@pytest.fixture(scope="module")
def crypto_exe(tmp_path_factory):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available for building the fixture")
    out = tmp_path_factory.mktemp("fx") / "crypto_demo.exe"
    subprocess.run(
        [gcc, "-O0", "-o", str(out), str(FIXTURE_SRC)],
        check=True, capture_output=True,
    )
    return out


@pytest.fixture(scope="module")
def engine(crypto_exe, tmp_path_factory):
    from lovelyreverse.engine.manager import EngineManager

    # own project dir: the running workstation (if any) locks the default one
    em = EngineManager(
        Path(os.environ["GHIDRA_INSTALL_DIR"]),
        project_dir_path=tmp_path_factory.mktemp("engine-project"),
    )
    info = em.open(crypto_exe)
    yield em, info
    em.close()
    em.shutdown()


def test_open_and_program_info(engine):
    em, info = engine
    assert info["function_count"] > 5
    assert info["format"]
    assert info["image_base"].startswith("0x")


def test_functions_and_decompile(engine):
    em, _ = engine
    funcs = em.list_functions("", 0, 10_000)
    names = {f["name"] for f in funcs["items"]}
    assert "main" in names
    assert "tea_encrypt" in names
    main = next(f for f in funcs["items"] if f["name"] == "main")
    code = em.decompile(main["addr"])["code"]
    assert "tea_encrypt" in code  # decompiled C references the callee
    assert "int" in code


def test_strings_listing(engine):
    em, _ = engine
    strings = em.list_strings("", 0, 1000)
    values = " ".join(s["value"] for s in strings["items"])
    assert "sbox=" in values or "sbox" in values  # the printf format string


def test_constants_scan_finds_all(engine):
    em, _ = engine
    hits = em.constants_scan()
    names = " | ".join(h["name"] for h in hits)
    assert "AES S-box" in names
    assert "SHA-256 K" in names
    assert "TEA/XTEA delta" in names
    assert "Base64 alphabet" in names
    # function attribution works for the in-code delta
    tea_in_fn = [h for h in hits if "TEA" in h["name"] and h["function"]]
    assert tea_in_fn, "expected the TEA delta attributed to tea_encrypt()"


def test_callgraph_neighborhood(engine):
    em, _ = engine
    funcs = em.list_functions("", 0, 10_000)
    main = next(f for f in funcs["items"] if f["name"] == "main")
    g = em.callgraph(main["addr"], depth=2)
    names = {n["name"] for n in g["nodes"]}
    assert "main" in names
    assert "tea_encrypt" in names          # direct callee
    # the edge main -> tea_encrypt exists
    addr_of = {n["name"]: n["addr"] for n in g["nodes"]}
    assert [addr_of["main"], addr_of["tea_encrypt"]] in g["edges"]


def test_memory_read_and_search(engine):
    em, _ = engine
    blocks = em.memory_blocks()
    assert any(b["name"] == ".text" for b in blocks)
    data = em.read_memory(".text", 0, 16)
    assert len(data) == 16
    # x86-64 prologue: PUSH RBP (0x55) — mingw builds start .text with it
    assert data[0] == 0x55
    needle = "b979379e"  # TEA delta, little-endian in memory
    hits = em.search_hex(needle, limit=50)
    assert hits, "TEA delta should be findable in memory"
    assert any(h["function"] == "tea_encrypt" for h in hits)
