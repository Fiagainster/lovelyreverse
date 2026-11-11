"""Runtime configuration: Ghidra discovery, paths, server defaults."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

APP_NAME = "lovelyreverse"

# Default TCP port chosen to be memorable (leetspeak "7331").
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7331

# Where Ghidra projects (imported programs) live, per user.
def data_dir() -> Path:
    """Persistent app data directory (Ghidra projects, logs).

    Honors LVR_DATA_DIR (portable installs / test isolation).
    """
    env = os.environ.get("LVR_DATA_DIR")
    if env:
        d = Path(env)
    elif os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        d = Path(base) / APP_NAME
    else:
        d = Path.home() / f".{APP_NAME}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def project_dir() -> Path:
    """Fallback directory for Ghidra projects.

    Per-sample projects now live in `<sample dir>/_lvr/` (see
    EngineManager._project_for); this central dir only receives projects for
    samples in unwritable locations and file-picker uploads. Force it for
    everything with LVR_PROJECT_DIR.
    """
    d = data_dir() / "projects"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _hint_dirs() -> list[str]:
    """Directories scanned for ``ghidra_*`` installations (platform-aware)."""
    home = os.path.expanduser("~")
    dirs = [
        "D:/SecurityTools",  # author's own convention; harmless elsewhere
        "D:/Tools",
        "C:/ghidra",
        "C:/Tools",
        home,
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "tools"),
    ]
    if os.name == "nt":
        dirs += [os.environ.get("LOCALAPPDATA", ""), "C:/", "D:/"]
    else:
        dirs += ["/opt", "/usr/local"]
    return dirs


def find_ghidra_install_dir() -> Path | None:
    """Locate a Ghidra installation.

    Resolution order:
      1. GHIDRA_INSTALL_DIR environment variable (if it looks like Ghidra)
      2. Common directories scanned for ``ghidra_*`` folders
    """
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        p = Path(env)
        if _looks_like_ghidra(p):
            return p
    return _scan_hint_dirs()


def _scan_hint_dirs() -> Path | None:
    for root in _hint_dirs():
        if not root or not Path(root).is_dir():
            continue
        try:
            candidates = sorted(Path(root).glob("ghidra_*"), reverse=True)
        except OSError:
            continue
        for c in candidates:
            if _looks_like_ghidra(c):
                return c  # newest-looking first (lexicographic: 12.x > 11.x)
    return None


def resolve_ghidra_dir(explicit: str | None = None) -> tuple[Path | None, list[str]]:
    """Resolve the Ghidra install dir for CLI use.

    Returns ``(dir, warnings)``. An explicit ``--ghidra`` that does not look
    like Ghidra is an error (dir=None); an invalid GHIDRA_INSTALL_DIR only
    warns and falls through to the scan.
    """
    warns: list[str] = []
    if explicit:
        p = Path(explicit)
        if not _looks_like_ghidra(p):
            return None, [
                f"--ghidra path does not look like a Ghidra installation: {p}\n"
                f"  (expected ghidraRun.bat / Ghidra/Features inside)"
            ]
        return p, warns
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        p = Path(env)
        if _looks_like_ghidra(p):
            return p, warns
        warns.append(f"GHIDRA_INSTALL_DIR is set but not a Ghidra dir — ignoring: {p}")
    return _scan_hint_dirs(), warns


def parse_java_version(output: str) -> int | None:
    """Parse the major version out of ``java -version`` output.

    Handles both schemes: ``"21.0.2"`` → 21, ``"1.8.0_402"`` → 8.
    """
    m = re.search(r'version "([^"]+)"', output)
    if not m:
        return None
    parts = m.group(1).split(".")
    try:
        if parts[0] == "1" and len(parts) > 1:
            return int(parts[1])
        return int(parts[0])
    except ValueError:
        return None


def find_java(timeout: float = 10.0) -> tuple[str | None, int | None]:
    """Locate a java executable and its major version.

    Probes JAVA_HOME, the Ghidra-bundled JRE (``<ghidra>/.jre``) and PATH —
    mirroring how Ghidra itself finds Java. Returns ``(java_exe, major)``;
    either may be None.
    """
    exe: str | None = None
    jh = os.environ.get("JAVA_HOME")
    if jh:
        p = Path(jh) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if p.is_file():
            exe = str(p)
    if exe is None:
        env = os.environ.get("GHIDRA_INSTALL_DIR")
        if env:
            p = Path(env) / ".jre" / "bin" / ("java.exe" if os.name == "nt" else "java")
            if p.is_file():
                exe = str(p)
    if exe is None:
        exe = shutil.which("java")
    if exe is None:
        return None, None
    try:
        r = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return exe, None
    out = (r.stderr or "") + "\n" + (r.stdout or "")
    return exe, parse_java_version(out)


def _looks_like_ghidra(p: Path) -> bool:
    return p.is_dir() and (
        (p / "ghidraRun.bat").exists()
        or (p / "Ghidra" / "Features").is_dir()
    )
