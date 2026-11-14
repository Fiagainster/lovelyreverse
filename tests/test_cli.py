"""CLI / deployment friendliness: Ghidra discovery, Java probing, doctor."""

from __future__ import annotations

from pathlib import Path

import pytest

import lovelyreverse.config as cfg
from lovelyreverse.config import (
    find_ghidra_install_dir,
    parse_java_version,
    resolve_ghidra_dir,
)


def make_ghidra_dir(tmp_path: Path, name: str = "ghidra_12.2_PUBLIC") -> Path:
    d = tmp_path / name
    (d / "Ghidra" / "Features").mkdir(parents=True)
    return d


class TestParseJavaVersion:
    @pytest.mark.parametrize(
        ("out", "major"),
        [
            ('openjdk version "21.0.2" 2024-01-16', 21),
            ('openjdk version "1.8.0_402"', 8),
            ('openjdk version "25"', 25),
            ('java version "17.0.9"', 17),
            ("openjdk version \"21.0.5\" 2024-10-15\nOpenJDK Runtime Environment Temurin-21.0.5+11 (build 21.0.5+11)", 21),
            ("no version here", None),
            ('garbage "abc.def"', None),
        ],
    )
    def test_parse(self, out: str, major: int | None):
        assert parse_java_version(out) == major


class TestResolveGhidraDir:
    def test_explicit_ok(self, tmp_path):
        d = make_ghidra_dir(tmp_path)
        p, warns = resolve_ghidra_dir(str(d))
        assert p == d
        assert warns == []

    def test_explicit_bad_is_error(self, tmp_path):
        p, warns = resolve_ghidra_dir(str(tmp_path / "nope"))
        assert p is None
        assert warns and "does not look like a Ghidra" in warns[0]

    def test_explicit_bad_with_ghidra_run_bat(self, tmp_path):
        d = tmp_path / "ghidra_11.3_PUBLIC"
        d.mkdir()
        (d / "ghidraRun.bat").write_text("", encoding="utf-8")
        p, warns = resolve_ghidra_dir(str(d))
        assert p == d
        assert warns == []

    def test_env_invalid_falls_back_to_scan(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "junk"))
        d = make_ghidra_dir(tmp_path)
        monkeypatch.setattr(cfg, "_hint_dirs", lambda: [str(tmp_path)])
        p, warns = resolve_ghidra_dir(None)
        assert p == d
        assert any("GHIDRA_INSTALL_DIR" in w for w in warns)

    def test_env_valid_short_circuits(self, tmp_path, monkeypatch):
        d = make_ghidra_dir(tmp_path)
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(d))
        # scan would find nothing (empty hint dirs) — env must win
        monkeypatch.setattr(cfg, "_hint_dirs", lambda: [])
        p, warns = resolve_ghidra_dir(None)
        assert p == d
        assert warns == []

    def test_nothing_found(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        monkeypatch.setattr(cfg, "_hint_dirs", lambda: [str(tmp_path)])
        p, warns = resolve_ghidra_dir(None)
        assert p is None
        assert warns == []


class TestScan:
    def test_scan_finds_ghidra_dir(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        d = make_ghidra_dir(tmp_path)
        monkeypatch.setattr(cfg, "_hint_dirs", lambda: [str(tmp_path)])
        assert find_ghidra_install_dir() == d

    def test_scan_picks_newest(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        make_ghidra_dir(tmp_path, "ghidra_11.3_PUBLIC")
        d2 = make_ghidra_dir(tmp_path, "ghidra_12.2_PUBLIC")
        monkeypatch.setattr(cfg, "_hint_dirs", lambda: [str(tmp_path)])
        assert find_ghidra_install_dir() == d2  # sorted() → lexicographic, 12.2 last


class TestNormalizeArgv:
    """A bare `python -m lovelyreverse` used to reach _cmd_serve without the
    serve subparser's defaults and crash with AttributeError: 'Namespace'
    object has no attribute 'ghidra'."""

    def test_bare_defaults_to_serve(self):
        from lovelyreverse.cli import _normalize_argv
        assert _normalize_argv([]) == ["serve"]
        assert _normalize_argv(["--no-browser"]) == ["serve", "--no-browser"]
        assert _normalize_argv(["--ghidra", "X"]) == ["serve", "--ghidra", "X"]
        assert _normalize_argv(["--host", "127.0.0.1", "--port", "9"]) == [
            "serve", "--host", "127.0.0.1", "--port", "9"]

    def test_explicit_subcommands_pass_through(self):
        from lovelyreverse.cli import _normalize_argv
        assert _normalize_argv(["serve"]) == ["serve"]
        assert _normalize_argv(["serve", "--port", "9"]) == ["serve", "--port", "9"]
        assert _normalize_argv(["doctor"]) == ["doctor"]
        assert _normalize_argv(["doctor", "--ghidra", "X"]) == ["doctor", "--ghidra", "X"]

    def test_top_level_flags_pass_through(self):
        from lovelyreverse.cli import _normalize_argv
        assert _normalize_argv(["--version"]) == ["--version"]
        assert _normalize_argv(["-h"]) == ["-h"]
        assert _normalize_argv(["--help"]) == ["--help"]

    def test_bare_main_parses_serve_defaults(self, monkeypatch):
        # main([]) must reach _cmd_serve with host/port/ghidra present —
        # stub out everything past parsing
        import lovelyreverse.cli as cli

        seen = {}
        monkeypatch.setattr(cli, "_cmd_serve", lambda args: seen.update(vars(args)) or 0)
        assert cli.main([]) == 0
        assert "ghidra" in seen and "host" in seen and "port" in seen
        assert seen["ghidra"] is None and seen["no_browser"] is False
