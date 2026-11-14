"""HTTP server: stdlib-only routing layer between the UI and the engine.

Zero third-party dependencies — ThreadingHTTPServer + regex routes.  The
engine is injectable so tests can exercise the whole HTTP surface with a
stub instead of a real JVM.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from lovelyreverse import __version__
from lovelyreverse.util.binfile import triage as file_triage
from lovelyreverse.util.decode import OpError, run_chain
from lovelyreverse.util.xor import xor_derive, xor_full_decode, xor_single_brute

STATIC_DIR = Path(__file__).parent.parent / "resources" / "static"

MAX_BODY = 32 * 1024 * 1024  # 32 MB cap on request bodies
RECENT_CAP = 20


# ---------------------------------------------------------------- recent list

def _recent_file() -> Path:
    from lovelyreverse.config import data_dir

    return data_dir() / "recent.json"


def _recent_load() -> list[dict[str, Any]]:
    try:
        items = json.loads(_recent_file().read_text(encoding="utf-8"))
        return items if isinstance(items, list) else []
    except Exception:  # noqa: BLE001 - missing/corrupt file just means empty
        return []


def _recent_record(path: str, size: int) -> None:
    items = [i for i in _recent_load() if i.get("path") != path]
    items.insert(0, {"path": path, "name": Path(path).name, "size": int(size), "ts": time.time()})
    try:
        _recent_file().write_text(
            json.dumps(items[:RECENT_CAP], ensure_ascii=False, indent=1), encoding="utf-8"
        )
    except Exception:  # noqa: BLE001 - persistence is best-effort
        pass


# ------------------------------------------------------------------- job farm

class Job:
    def __init__(self, job_id: str, kind: str):
        self.id = job_id
        self.kind = kind
        self.status = "running"  # running | done | error
        self.progress = ""
        self.log: list[str] = []
        self.result: Any = None
        self.error: str | None = None
        self.created = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "progress": self.progress,
            "log": self.log[-30:],
            "error": self.error,
            "result": self.result,
        }


class JobFarm:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._counter = 0
        self._lock = threading.Lock()

    def spawn(self, kind: str, target: Callable[[Job], Any]) -> str:
        with self._lock:
            self._counter += 1
            job = Job(f"j{self._counter}", kind)
            self._jobs[job.id] = job

        def run():
            try:
                job.result = target(job)
                job.status = "done"
            except BaseException as e:  # noqa: BLE001
                job.error = f"{type(e).__name__}: {e}"
                traceback.print_exc()
                job.status = "error"

        threading.Thread(target=run, name=f"lvr-job-{job.id}", daemon=True).start()
        return job.id

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)


# ------------------------------------------------------------------ app state

class AppState:
    """Everything mutable the handlers touch, in one injectable object."""

    def __init__(self, engine: Any):
        self.engine = engine
        self.jobs = JobFarm()
        self.file_bytes: bytes | None = None
        self.triage_info: dict[str, Any] | None = None
        self.source_path: str | None = None
        self.gdb_session: Any = None          # lovelyreverse.gdb.session.GdbSession
        self._gdb_env_cache: dict[str, Any] = {}
        self._gdb_probing = False

    # ---- gdb bridge helpers -------------------------------------------------

    def gdb_env(self, background: bool = True) -> dict[str, Any]:
        """Availability of both transports, probed once and cached.

        wsl.exe probes take 5-20s, far too slow for a request thread — the
        first call kicks off a daemon probe and returns {"probing": True}
        until it lands.  Call with background=False to probe inline (tests).
        """
        if not self._gdb_env_cache:
            if background and not self._gdb_probing:
                self._gdb_probing = True
                threading.Thread(target=self.gdb_env, kwargs={"background": False},
                                 daemon=True).start()
                return {"probing": True}
            self._gdb_probing = True
            from lovelyreverse.gdb.session import find_local_gdb

            local = find_local_gdb()
            wsl_ok = False
            distros: list[str] = []
            try:
                env = dict(os.environ, WSL_UTF8="1")
                out = subprocess.run(
                    ["wsl", "-l", "-q"], capture_output=True,
                    # wsl.exe writes UTF-8 even on zh-CN consoles (proxy warnings
                    # etc.); the default GBK locale decode raised inside Popen's
                    # own reader thread — untouchable from here.
                    encoding="utf-8", errors="replace",
                    timeout=20, env=env,
                )
                names = [ln.strip() for ln in out.stdout.replace("\x00", "").splitlines()
                         if ln.strip() and not ln.strip().startswith("wsl:")]
                distros = names
            except Exception:  # noqa: BLE001 — WSL missing entirely
                distros = []
            if distros:
                probe = distros[0]
                if any(d.startswith("Ubuntu") for d in distros):
                    probe = next(d for d in distros if d.startswith("Ubuntu"))
                try:
                    r = subprocess.run(
                        ["wsl", "-d", probe, "--", "gdb", "--version"],
                        capture_output=True, encoding="utf-8", errors="replace",
                        timeout=30, env=env,
                    )
                    wsl_ok = r.returncode == 0
                except Exception:  # noqa: BLE001
                    wsl_ok = False
            self._gdb_env_cache = {
                "probing": False,
                "local_gdb": local,
                "local_ok": bool(local),
                "wsl_ok": wsl_ok,
                "distros": distros,
            }
        return self._gdb_env_cache

    def gdb_start(self, transport: str, distro: str, args: str, stdin_text: str,
                  env_text: str = "") -> dict[str, Any]:
        from lovelyreverse.gdb.session import GdbSession, GdbError

        if self.gdb_session is not None:
            old_prog = None
            alive = False
            try:
                st = self.gdb_session.status()
                old_prog = st.get("program")
                alive = not st["dead"]
            except Exception:  # noqa: BLE001 — dead session object, replace it
                alive = False
            if alive and self.source_path and old_prog \
                    and os.path.normcase(os.path.abspath(old_prog)) \
                    != os.path.normcase(os.path.abspath(self.source_path)):
                # sample switched since the session was born — the old gdb is
                # still pointing at the previous file; restart on the new one
                # (a silent "already active" error here made the start button
                # look dead after switching samples)
                try:
                    self.gdb_session.exit()
                except Exception:  # noqa: BLE001
                    pass
                self.gdb_session = None
            elif alive:
                raise GdbError("a gdb session is already active — end it first")
            else:
                self.gdb_session = None
        if not self.source_path:
            raise GdbError("no program loaded — open a binary first")
        sess = GdbSession(transport=transport, distro=distro)
        sess.start(self.source_path)
        self.gdb_session = sess
        return sess.load(self.source_path, args=args, stdin_text=stdin_text,
                         env_text=env_text)

    # ---- shared handlers used by both routes and jobs

    def do_open(self, path: str, job: Job) -> dict[str, Any]:
        p = Path(path)
        if not p.is_file():
            raise ValueError(f"file not found: {path}")
        self.source_path = str(p)
        self.file_bytes = p.read_bytes()
        self.triage_info = file_triage(self.file_bytes)
        _recent_record(str(p), len(self.file_bytes))
        job.log.append(f"file: {p.name} ({len(self.file_bytes):,} bytes)")
        info = self.engine.open(str(p), progress=lambda s: setattr(job, "progress", s))
        return info


# --------------------------------------------------------------------- server

def make_handler(state: AppState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = f"lovelyreverse/{__version__}"

        # ---------------------------------------------------------- plumbing

        _t0 = 0.0

        def log_message(self, fmt: str, *args: Any) -> None:  # default chatter stays off
            pass

        def log_request(self, code: Any = "-", size: Any = "-") -> None:
            """Concise request log with latency; successful static hits stay quiet (B8)."""
            try:
                dt = (time.perf_counter() - self._t0) * 1000
            except Exception:  # noqa: BLE001
                dt = 0.0
            path = self.path.split("?", 1)[0] if isinstance(self.path, str) else "?"
            if path.startswith("/static/") and code == 200:
                return
            sys.stderr.write(f"[lvr] {self.command} {path} {code} {dt:.0f}ms\n")

        def _json(self, obj: Any, status: int = 200) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, message: str, status: int = 400) -> None:
            self._json({"error": str(message)}, status)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ValueError("body too large")
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def _static(self, rel: str) -> None:
            if rel in ("", "/"):
                rel = "/index.html"
            if rel.startswith("/static/"):
                rel = rel[len("/static"):]
            target = (STATIC_DIR / rel.lstrip("/")).resolve()
            if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
                self._error("not found", 404)
                return
            ctype = {
                ".html": "text/html; charset=utf-8",
                ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8",
                ".svg": "image/svg+xml",
                ".png": "image/png",
                ".ico": "image/x-icon",
                ".woff2": "font/woff2",
            }.get(target.suffix, "application/octet-stream")
            body = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)

        # ------------------------------------------------------------ routes

        def do_GET(self) -> None:  # noqa: N802
            self._t0 = time.perf_counter()
            try:
                self._route_get()
            except BrokenPipeError:
                pass
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                try:
                    self._error(f"{type(e).__name__}: {e}", 500)
                except Exception:  # noqa: BLE001
                    pass

        def do_POST(self) -> None:  # noqa: N802
            self._t0 = time.perf_counter()
            try:
                self._route_post()
            except BrokenPipeError:
                pass
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                try:
                    self._error(f"{type(e).__name__}: {e}", 500)
                except Exception:  # noqa: BLE001
                    pass

        def _route_get(self) -> None:
            url = urlparse(self.path)
            path, qs = url.path, parse_qs(url.query)

            if not path.startswith("/api/"):
                if path == "/lovelyreverse.js.map":  # never
                    self._error("not found", 404)
                    return
                self._static(path)
                return

            def q(name: str, default: str = "") -> str:
                return qs.get(name, [default])[0]

            def qi(name: str, default: int) -> int:
                try:
                    return int(qs.get(name, [str(default)])[0])
                except ValueError:
                    return default

            # ----- meta
            if path == "/api/status":
                engine_ready = bool(getattr(state.engine, "_thread", None))
                analyzing = getattr(state.engine, "open_state", "idle") == "opening"
                progress = getattr(state.engine, "open_progress", "") or ""
                # Lock-free program check: this endpoint is polled while an
                # open job runs, and every engine-thread call queues behind
                # that job — polling program_info() here would stall the UI
                # on the OLD project exactly when it should show progress.
                program_loaded = getattr(state.engine, "program", None) is not None
                return self._json({
                    "version": __version__,
                    "engine_ready": engine_ready,
                    "program_loaded": program_loaded,
                    "analyzing": analyzing,
                    "progress": progress,
                    "source_path": state.source_path,
                })

            if path == "/api/triage":
                if state.triage_info is None:
                    return self._error("no file loaded", 409)
                return self._json(state.triage_info)

            if path == "/api/program":
                info = state.engine.program_info()
                if info is None:
                    return self._error("no program loaded", 409)
                return self._json(info)

            # ----- listings
            if path == "/api/functions":
                return self._json(state.engine.list_functions(q("q"), qi("offset", 0), qi("limit", 300)))

            if path == "/api/strings":
                return self._json(state.engine.list_strings(q("q"), qi("offset", 0), qi("limit", 300)))

            if path == "/api/imports":
                return self._json({"items": state.engine.imports()})

            if path == "/api/exports":
                return self._json({"items": state.engine.exports()})

            # ----- recent opens
            if path == "/api/recent":
                return self._json({"items": _recent_load()})

            # ----- per-function
            m = re.fullmatch(r"/api/function/(\d+)/(decompile|disasm|xrefs|callgraph|comment)", path)
            if m:
                addr, what = int(m.group(1)), m.group(2)
                if what == "decompile":
                    return self._json(state.engine.decompile(addr))
                if what == "disasm":
                    return self._json(state.engine.disasm(addr, qi("limit", 500)))
                if what == "xrefs":
                    return self._json(state.engine.xrefs(addr))
                if what == "callgraph":
                    return self._json(state.engine.callgraph(addr, qi("depth", 2), qi("max", 250)))
                if what == "comment":
                    return self._json({"addr": addr, "comment": state.engine.function_comment(addr)})

            # ----- generic cross-references (works for data addresses too,
            # e.g. "who references this string")
            m = re.fullmatch(r"/api/xrefs/(\d+)", path)
            if m:
                return self._json(state.engine.xrefs(int(m.group(1))))

            # ----- gdb bridge (dynamic debugging)
            if path == "/api/gdb/env":
                return self._json(state.gdb_env())

            if path == "/api/gdb/state":
                sess = state.gdb_session
                if sess is None:
                    return self._json({"active": False, "env": state.gdb_env()})
                return self._json({"active": True, "status": sess.status()})

            if path == "/api/gdb/registers":
                if state.gdb_session is None:
                    return self._error("no gdb session", 409)
                return self._json({"registers": state.gdb_session.registers()})

            if path == "/api/gdb/breaks":
                if state.gdb_session is None:
                    return self._error("no gdb session", 409)
                return self._json({"items": state.gdb_session.list_breaks()})

            if path == "/api/gdb/stack":
                if state.gdb_session is None:
                    return self._error("no gdb session", 409)
                return self._json({"items": state.gdb_session.stack()})

            if path == "/api/gdb/log":
                if state.gdb_session is None:
                    return self._error("no gdb session", 409)
                return self._json({"items": state.gdb_session.console[-120:]})

            if path == "/api/gdb/memory":
                if state.gdb_session is None:
                    return self._error("no gdb session", 409)
                expr = q("expr")
                if not expr:
                    return self._error("expr required")
                import base64 as b64

                data = state.gdb_session.read_memory(expr, qi("len", 128))
                return self._json({"expr": expr, "len": len(data),
                                   "data_b64": b64.b64encode(data).decode()})

            # ----- memory
            if path == "/api/memory/blocks":
                return self._json({"items": state.engine.memory_blocks()})

            if path == "/api/memory/read":
                import base64 as b64

                data = state.engine.read_memory(q("block"), qi("offset", 0), qi("len", 4096))
                return self._json({"data_b64": b64.b64encode(data).decode()})

            # raw instruction-stream decode along the executed order (survives
            # overlapped instructions / jmp-calls that pollute Ghidra's listing)
            if path == "/api/disasm-raw":
                v = q("addr").strip()
                try:
                    a = int(v, 16) if v.lower().startswith("0x") else int(v)
                except ValueError:
                    return self._error("bad addr (want 0x… or decimal)")
                maxb = max(64, min(qi("max", 2048), 1 << 16))
                return self._json(state.engine.disasm_raw(a, maxb))

            if path == "/api/search":
                hits = state.engine.search_hex(q("hex"), qi("limit", 500))
                return self._json({"items": hits})

            if path == "/api/constants":
                return self._json({"items": state.engine.constants_scan()})

            # ----- jobs
            m = re.fullmatch(r"/api/job/(\w+)", path)
            if m:
                job = state.jobs.get(m.group(1))
                if job is None:
                    return self._error("no such job", 404)
                return self._json(job.to_dict())

            # ----- unpacked file viewer (PyInstaller)
            if path == "/api/unpack/file":
                job = state.jobs.get(q("job"))
                if not job or job.status != "done" or not isinstance(job.result, dict):
                    return self._error("unpack job not ready", 409)
                outdir = Path(job.result["outdir"]).resolve()
                target = (outdir / q("name")).resolve()
                try:
                    target.relative_to(outdir)  # traversal guard
                except ValueError:
                    return self._error("bad path", 400)
                if not target.is_file():
                    return self._error("no such file", 404)
                raw = target.read_bytes()
                shown = raw[: 2 * 1024 * 1024]
                return self._json({
                    "name": q("name"),
                    "size": target.stat().st_size,
                    "truncated": len(raw) > len(shown),
                    "data_b64": base64.b64encode(shown).decode(),
                })

            # ----- downloads
            m = re.fullmatch(r"/api/download/decompile/(\d+)\.c", path)
            if m:
                res = state.engine.decompile(int(m.group(1)))
                body = res["code"].encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/x-c; charset=utf-8")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{res["name"]}_{m.group(1):x}.c"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)

            m = re.fullmatch(r"/api/download/decompile-all\.zip", path)
            if m:
                job = state.jobs.get(q("job"))
                if not job or job.status != "done" or not isinstance(job.result, str):
                    return self._error("zip not ready", 409)
                data = Path(job.result).read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)

            return self._error("unknown api route", 404)

        def _route_gdb_post(self, path: str, body: dict[str, Any]) -> Any:
            """POST routes for the gdb bridge. Returns a response or None."""
            if path == "/api/gdb/start":
                transport = str(body.get("transport", "wsl"))
                if transport not in ("wsl", "local"):
                    return self._error("transport must be wsl|local")
                distro = str(body.get("distro", "Ubuntu-22.04"))
                args = str(body.get("args", ""))
                stdin_text = str(body.get("stdin", ""))
                env_text = str(body.get("env", ""))
                try:
                    info = state.gdb_start(transport, distro, args, stdin_text, env_text)
                except Exception as e:  # noqa: BLE001 — surface boot errors verbatim
                    return self._error(f"{type(e).__name__}: {e}", 500)
                return self._json({"ok": True, "info": info, "status": state.gdb_session.status()})

            if path == "/api/gdb/exec":
                sess = state.gdb_session
                if sess is None:
                    return self._error("no gdb session", 409)
                action = str(body.get("action", ""))
                if action == "console":
                    # raw gdb CLI command (e.g. "handle SIGTRAP nostop pass",
                    # "info proc mappings") — the escape hatch for everything
                    # the fixed exec buttons don't cover
                    text = str(body.get("cmd", ""))
                    try:
                        res = sess.console_cmd(text)
                    except Exception as e:  # noqa: BLE001
                        return self._error(f"{type(e).__name__}: {e}", 500)
                    return self._json({"ok": True, **res, "status": sess.status()})
                mapping = {"run": sess.run, "continue": sess.continue_,
                           "next": sess.next_, "step": sess.step_,
                           "nexti": sess.nexti_, "stepi": sess.stepi_,
                           "finish": sess.finish, "interrupt": sess.interrupt}
                if action not in mapping:
                    return self._error("action must be run|continue|next|step|nexti|stepi|finish|interrupt")
                try:
                    res = mapping[action]()
                except Exception as e:  # noqa: BLE001
                    return self._error(f"{type(e).__name__}: {e}", 500)
                return self._json({"ok": True, **res, "status": sess.status()})

            if path == "/api/gdb/break":
                sess = state.gdb_session
                if sess is None:
                    return self._error("no gdb session", 409)
                loc = str(body.get("loc", "")).strip()
                try:
                    return self._json({"ok": True, "bkpt": sess.insert_break(loc)})
                except Exception as e:  # noqa: BLE001
                    return self._error(f"{type(e).__name__}: {e}", 500)

            if path == "/api/gdb/break/delete":
                sess = state.gdb_session
                if sess is None:
                    return self._error("no gdb session", 409)
                try:
                    sess.delete_break(str(body.get("number", "")))
                except Exception as e:  # noqa: BLE001
                    return self._error(f"{type(e).__name__}: {e}", 500)
                return self._json({"ok": True})

            if path == "/api/gdb/set":
                sess = state.gdb_session
                if sess is None:
                    return self._error("no gdb session", 409)
                expr = str(body.get("expr", "")).strip()
                if not expr:
                    return self._error("expr required")
                try:
                    sess.cmd("-gdb-set " + expr)
                except Exception as e:  # noqa: BLE001
                    return self._error(f"{type(e).__name__}: {e}", 500)
                return self._json({"ok": True})

            if path == "/api/gdb/eval":
                sess = state.gdb_session
                if sess is None:
                    return self._error("no gdb session", 409)
                expr = str(body.get("expr", "")).strip()
                if not expr:
                    return self._error("expr required")
                try:
                    return self._json({"value": sess.evaluate(expr)})
                except Exception as e:  # noqa: BLE001
                    return self._error(f"{type(e).__name__}: {e}", 500)

            if path == "/api/gdb/exit":
                sess = state.gdb_session
                if sess is not None:
                    sess.exit()
                    state.gdb_session = None
                return self._json({"ok": True})

            return None

        def _route_post(self) -> None:
            url = urlparse(self.path)
            path = url.path

            # raw-bytes upload (drag & drop): /api/upload?name=foo.exe
            if path == "/api/upload":
                qs = parse_qs(url.query)
                name = (qs.get("name", ["sample.bin"])[0] or "sample.bin")[:120]
                safe = re.sub(r"[^\w.\- ()\[\]]", "_", name)
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    return self._error("file too large (32 MB limit)", 413)
                blob = self.rfile.read(length)
                from lovelyreverse.config import data_dir

                samples = data_dir() / "samples"
                samples.mkdir(parents=True, exist_ok=True)
                target = samples / f"{int(time.time())}_{safe}"
                target.write_bytes(blob)
                return self._json({"path": str(target)})

            body = self._body()

            # gdb bridge POST routes (start/exec/break/eval/exit)
            gdb_resp = self._route_gdb_post(path, body)
            if gdb_resp is not None:
                return gdb_resp

            if path == "/api/open":
                src = str(body.get("path", "")).strip()
                if not src:
                    return self._error("path required")
                state.source_path = src  # remembered even before the job finishes
                job_id = state.jobs.spawn("open", lambda job: state.do_open(src, job))
                return self._json({"job": job_id})

            if path == "/api/decode":
                data = base64.b64decode(body.get("input_b64", ""))
                recipe = body.get("recipe", [])
                if not isinstance(recipe, list):
                    return self._error("recipe must be a list")
                try:
                    out, log = run_chain(data, recipe)
                except OpError as e:
                    return self._error(str(e), 400)
                return self._json({
                    "result_b64": base64.b64encode(out).decode(),
                    "log": log,
                    "size": len(out),
                })

            if path == "/api/xor/brute":
                data = base64.b64decode(body.get("input_b64", ""))
                if not data:
                    return self._error("empty input")
                return self._json({"items": xor_single_brute(data, top=int(body.get("top", 16)))})

            if path == "/api/xor/decode":
                data = base64.b64decode(body.get("input_b64", ""))
                key = int(body.get("key", 0)) & 0xFF
                return self._json(xor_full_decode(data, key))

            if path == "/api/xor/derive":
                data = base64.b64decode(body.get("input_b64", ""))
                prefix = str(body.get("prefix", ""))
                return self._json({"items": xor_derive(data, prefix)})

            if path == "/api/export/decompile-all":
                if state.engine.program_info() is None:
                    return self._error("no program loaded", 409)

                def target(job: Job):
                    funcs = state.engine.list_functions("", 0, 1_000_000)
                    total = funcs["total"]
                    addrs = [f["addr"] for f in funcs["items"]]
                    name = Path(state.source_path or "program").stem

                    def progress(done: int, of: int) -> None:
                        job.progress = f"decompiling {done}/{of}"

                    results = state.engine.decompile_many(addrs, progress)
                    buf = io.BytesIO()
                    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                        for addr, fname, code in results:
                            safe = re.sub(r"[^\w.\-]", "_", fname)
                            zf.writestr(f"{safe}_{addr:x}.c", code)
                    out = Path(__import__("tempfile").gettempdir()) / f"lvr_{name}_{int(time.time())}.zip"
                    out.write_bytes(buf.getvalue())
                    job.progress = f"{len(results)} functions"
                    return str(out)
                return self._json({"job": state.jobs.spawn("decompile-all", target)})

            # ----- annotations (F1)
            m = re.fullmatch(r"/api/function/(\d+)/(rename|comment)", path)
            if m:
                if state.engine.program_info() is None:
                    return self._error("no program loaded", 409)
                addr = int(m.group(1))
                try:
                    if m.group(2) == "rename":
                        name = str(body.get("name", "")).strip()
                        if not name or len(name) > 200:
                            return self._error("name must be 1-200 chars")
                        return self._json(state.engine.rename_function(addr, name))
                    return self._json(state.engine.set_function_comment(addr, str(body.get("text", ""))))
                except Exception as e:  # noqa: BLE001 - engine errors -> client error
                    return self._error(f"{type(e).__name__}: {e}", 400)

            # ----- PyInstaller unpack (F5)
            if path == "/api/unpack/pyinstaller":
                src = str(body.get("path", "")).strip() or (state.source_path or "")
                if not src:
                    return self._error("path required")
                p = Path(src)
                if not p.is_file():
                    return self._error(f"file not found: {src}")

                def target(job: Job):
                    from lovelyreverse.util.pyinstaller import unpack

                    job.progress = "locating cookie"
                    # Unpack beside the sample (its _lvr/), not %TEMP% —
                    # nothing should accumulate on the system drive.
                    outdir = None
                    try:
                        outdir = p.parent / "_lvr" / "unpacked" / f"{p.stem}_{int(time.time())}"
                        outdir.mkdir(parents=True, exist_ok=True)
                    except OSError:
                        outdir = None  # unwritable location → util's tempdir default
                    return unpack(p, outdir=outdir, progress=lambda s: setattr(job, "progress", s))

                return self._json({"job": state.jobs.spawn("unpack-pyinstaller", target)})

            # ----- APK unpack (static: zip entries + dex string pools)
            if path == "/api/unpack/apk":
                src = str(body.get("path", "")).strip() or (state.source_path or "")
                if not src:
                    return self._error("path required")
                p = Path(src)
                if not p.is_file():
                    return self._error(f"file not found: {src}")

                def apk_target(job: Job):
                    import zipfile

                    from lovelyreverse.util.dex import dex_info, dex_strings, looks_like_dex

                    job.progress = "opening zip container"
                    outdir = p.parent / "_lvr" / "unpacked_apk" / f"{p.stem}_{int(time.time())}"
                    outdir.mkdir(parents=True, exist_ok=True)
                    entries: list[dict[str, Any]] = []
                    dex_strings_map: dict[str, list[str]] = {}
                    dex_meta: dict[str, Any] = {}
                    with zipfile.ZipFile(p) as zf:
                        infos = zf.infolist()
                        for i, zi in enumerate(infos):
                            job.progress = f"extracting {i + 1}/{len(infos)}"
                            name = zi.filename
                            if name.endswith("/") or "\\" in name or ".." in name.replace("\\", "/"):
                                continue  # dir entries / traversal guard
                            kind = ("dex" if name.endswith(".dex")
                                    else "manifest" if name == "AndroidManifest.xml"
                                    else "resource" if name == "resources.arsc"
                                    else "native" if name.endswith(".so")
                                    else "file")
                            entries.append({"name": name, "size": zi.file_size, "type": kind})
                            target_path = (outdir / name)
                            target_path.parent.mkdir(parents=True, exist_ok=True)
                            try:
                                target_path.write_bytes(zf.read(name))
                            except Exception:  # noqa: BLE001 — bad entry, keep going
                                continue
                            if kind == "dex":
                                try:
                                    blob = target_path.read_bytes()
                                    if looks_like_dex(blob):
                                        dex_meta[name] = dex_info(blob)
                                        dex_strings_map[name] = dex_strings(blob, limit=4000)
                                except Exception:  # noqa: BLE001 — tampered dex
                                    dex_meta[name] = {"error": "unparsable"}
                    job.progress = f"{len(entries)} entries"
                    return {
                        "outdir": str(outdir),
                        "entries": entries,
                        "dex": dex_meta,
                        "dex_strings": dex_strings_map,
                        "apk": True,
                    }

                return self._json({"job": state.jobs.spawn("unpack-apk", apk_target)})

            return self._error("unknown api route", 404)

    return Handler


def serve(state: AppState, host: str, port: int) -> ThreadingHTTPServer:
    handler = make_handler(state)
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd
