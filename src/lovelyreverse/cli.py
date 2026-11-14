"""Command line entry: `lvr serve`, `lvr doctor` (also `python -m lovelyreverse`)."""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import webbrowser

from lovelyreverse import __version__
from lovelyreverse.config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    find_java,
    resolve_ghidra_dir,
)
from lovelyreverse.engine.manager import EngineManager
from lovelyreverse.server.app import AppState, serve


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to GBK/CP936 — gdb bridge console streams can
    # carry mojibake, and a GBK encode error inside a request thread would
    # kill it.  UTF-8 everywhere, non-representable chars replaced.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — non-standard streams
            pass
    parser = argparse.ArgumentParser(
        prog="lvr",
        description="lovelyreverse - a hands-on reverse-engineering workstation powered by Ghidra.",
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

    p_doc = sub.add_parser("doctor", help="check the environment: Python / Java / Ghidra / port")
    p_doc.add_argument("--ghidra", default=None, help="Ghidra install dir to verify explicitly")

    args = parser.parse_args(argv)
    command = args.command or "serve"
    if command == "doctor":
        return _cmd_doctor(args)
    if command != "serve":
        parser.print_help()
        return 0
    return _cmd_serve(args)


# --------------------------------------------------------------------- serve


def _cmd_serve(args: argparse.Namespace) -> int:
    ghidra_dir, warns = resolve_ghidra_dir(args.ghidra)
    for w in warns:
        print(f"[!] {w}", file=sys.stderr)
    if ghidra_dir is None:
        print(
            "error: could not locate a Ghidra installation.\n"
            "  run `lvr doctor` for a full environment check\n"
            "  set GHIDRA_INSTALL_DIR or pass --ghidra <path>\n"
            "  (download: https://github.com/NationalSecurityAgency/ghidra/releases)",
            file=sys.stderr,
        )
        return 2
    print(f"[*] ghidra install: {ghidra_dir}")

    java_exe, major = find_java()
    if java_exe is None:
        print(
            "error: no Java runtime found - Ghidra needs a JDK.\n"
            "  install JDK 21 or newer (https://adoptium.net) and re-run,\n"
            "  or point JAVA_HOME at an existing JDK.\n"
            "  (full check: lvr doctor)",
            file=sys.stderr,
        )
        return 2
    if major is None or major < 21:
        got = f"version unreadable at {java_exe}" if major is None else f"java {major} at {java_exe}"
        print(
            f"error: {got} - Ghidra 11.3+/12.x requires JDK 21+.\n"
            "  install a newer JDK (https://adoptium.net) and re-run.\n"
            "  (full check: lvr doctor)",
            file=sys.stderr,
        )
        return 2
    print(f"[*] java: {java_exe} (major {major})")

    engine = EngineManager(ghidra_dir)
    state = AppState(engine)
    try:
        httpd = serve(state, args.host, args.port)
    except OSError as e:
        print(
            f"error: cannot bind {args.host}:{args.port} - {e}\n"
            "  try: lvr serve --port <other>",
            file=sys.stderr,
        )
        return 2
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


# -------------------------------------------------------------------- doctor


def _cmd_doctor(args: argparse.Namespace) -> int:
    problems = 0
    print(f"lovelyreverse doctor - v{__version__}")

    v = sys.version_info
    if v >= (3, 10):
        print(f"  [ok]   python {v.major}.{v.minor}.{v.micro}")
    else:
        print(f"  [FAIL] python {v.major}.{v.minor}.{v.micro} - need >= 3.10")
        problems += 1

    java_exe, major = find_java()
    if java_exe is None:
        print("  [FAIL] java: not found - install JDK 21+ (https://adoptium.net),")
        print("         or point JAVA_HOME at an existing JDK")
        problems += 1
    elif major is None:
        print(f"  [FAIL] java: could not read version of {java_exe} - JDK 21+ required")
        problems += 1
    elif major < 21:
        print(f"  [FAIL] java {major} ({java_exe}) - Ghidra 11.3+/12.x needs JDK 21+")
        problems += 1
    else:
        print(f"  [ok]   java {major} ({java_exe})")

    ghidra_dir, warns = resolve_ghidra_dir(getattr(args, "ghidra", None))
    for w in warns:
        print(f"  [warn] {w}")
    if ghidra_dir is None:
        print("  [FAIL] ghidra: not found - set GHIDRA_INSTALL_DIR, pass --ghidra <path>,")
        print("         or extract Ghidra (folder name starting with 'ghidra_') into one of:")
        print("         ~/Downloads ~/Desktop ~/tools D:/Tools C:/ghidra /opt /usr/local")
        print("         (download: https://github.com/NationalSecurityAgency/ghidra/releases)")
        problems += 1
    else:
        print(f"  [ok]   ghidra {ghidra_dir}")

    s = socket.socket()
    try:
        s.bind((DEFAULT_HOST, DEFAULT_PORT))
        print(f"  [ok]   port {DEFAULT_PORT} free")
    except OSError:
        print(f"  [warn] port {DEFAULT_PORT} in use - start with: lvr serve --port <other>")
    finally:
        s.close()

    try:
        import pyghidra  # noqa: F401

        print("  [ok]   pyghidra importable")
    except Exception as e:  # noqa: BLE001 - report any import failure
        print(f"  [FAIL] pyghidra import failed: {e}\n         reinstall: pip install lovelyreverse")
        problems += 1

    if problems:
        print(f"{problems} problem(s) found - fix the [FAIL] lines above")
        return 1
    print("all good - run: lvr serve")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
