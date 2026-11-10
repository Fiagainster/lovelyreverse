"""Runtime configuration: Ghidra discovery, paths, server defaults."""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "lovelyreverse"

# Default TCP port chosen to be memorable (leetspeak "7331").
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7331

# Where Ghidra projects (imported programs) live, per user.
def data_dir() -> Path:
    """Persistent app data directory (Ghidra projects, logs)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        d = Path(base) / APP_NAME
    else:
        d = Path.home() / f".{APP_NAME}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def project_dir() -> Path:
    """Directory holding Ghidra projects managed by lovelyreverse."""
    d = data_dir() / "projects"
    d.mkdir(parents=True, exist_ok=True)
    return d


_GHIDRA_HINT_DIRS = [
    "D:/SecurityTools",
    "D:/Tools",
    "D:/tools",
    "C:/ghidra",
    "C:/Tools",
    os.path.expanduser("~"),
    os.environ.get("LOCALAPPDATA", ""),
    os.environ.get("USERPROFILE", ""),
]


def find_ghidra_install_dir() -> Path | None:
    """Locate a Ghidra installation.

    Resolution order:
      1. GHIDRA_INSTALL_DIR environment variable
      2. Common directories scanned for ``ghidra_*`` folders containing ``ghidraRun.bat``
    """
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        p = Path(env)
        if _looks_like_ghidra(p):
            return p
    for root in _GHIDRA_HINT_DIRS:
        if not root or not Path(root).is_dir():
            continue
        try:
            candidates = sorted(Path(root).glob("ghidra_*"))
        except OSError:
            continue
        for c in candidates:
            if _looks_like_ghidra(c):
                return c
    return None


def _looks_like_ghidra(p: Path) -> bool:
    return p.is_dir() and (
        (p / "ghidraRun.bat").exists()
        or (p / "Ghidra" / "Features").is_dir()
    )
