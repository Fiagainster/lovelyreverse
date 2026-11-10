"""Command line entry: `lvr serve` (also `python -m lovelyreverse`)."""

from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from pathlib import Path

from lovelyreverse import __version__
from lovelyreverse.config import DEFAULT_HOST, DEFAULT_PORT, find_ghidra_install_dir
from lovelyreverse.engine.manager import EngineManager
from lovelyreverse.server.app import AppState, serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lvr",
        description="lovelyreverse — a hands-on reverse-engineering workstation powered by Ghidra.",
    )
    parser.add_argument("--version", action="version", version=f"lovelyreverse {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_serve = sub.add_parser("serve", help="start the workstation UI (default command)")
    p_serve.add_argument("--host", default=DEFAULT_HOST, help=f"bind address (default {DEFAULT_HOST})")
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})")
    p_serve.add_argument("--no-browser", action="store_true", help="do not auto-open the browser")
    p_serve.add_argument(
        "--ghidra",
        default=None,
        help="Ghidra install dir (defaults to GHIDRA_INSTALL_DIR or an auto-scan)",
    )

    args = parser.parse_args(argv)
    command = args.command or "serve"
    if command != "serve":
        parser.print_help()
        return 0

    ghidra_dir = Path(args.ghidra) if args.ghidra else find_ghidra_install_dir()
    if ghidra_dir is None:
        print(
            "error: could not locate a Ghidra installation.\n"
            "  set GHIDRA_INSTALL_DIR or pass --ghidra <path>\n"
            "  (download: https://github.com/NationalSecurityAgency/ghidra/releases)",
            file=sys.stderr,
        )
        return 2
    print(f"[*] ghidra install: {ghidra_dir}")

    engine = EngineManager(ghidra_dir)
    state = AppState(engine)
    httpd = serve(state, args.host, args.port)
    url = f"http://{args.host}:{args.port}"
    print(f"[*] lovelyreverse {__version__} serving at {url}")
    print("[*] JVM will boot on first use; opening a binary starts auto-analysis.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye ~")
    finally:
        engine.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
