"""EngineManager: owns the JVM and serializes every Ghidra call.

Design notes
------------
* The JVM is booted inside one dedicated worker thread; *every* interaction
  with Ghidra happens on that thread (Ghidra's object model is not
  thread-safe). Callers submit callables and block on a boxed result.
* Program objects stay open for the server lifetime; opening a new binary
  closes the previous project entirely for a clean slate.
"""

from __future__ import annotations

import hashlib
import os
import queue
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable, TypeVar

from lovelyreverse.config import project_dir

T = TypeVar("T")


class EngineError(RuntimeError):
    pass


class _Box:
    """One-shot result container for a queued task."""

    __slots__ = ("event", "result", "error")

    def __init__(self):
        self.event = threading.Event()
        self.result: Any = None
        self.error: BaseException | None = None

    def wait(self, timeout: float | None = None) -> Any:
        if not self.event.wait(timeout):
            raise TimeoutError("engine task timed out")
        if self.error is not None:
            raise self.error
        return self.result


class EngineManager:
    def __init__(self, ghidra_install_dir: Path | None = None, project_dir_path: Path | None = None):
        self._ghidra_dir = ghidra_install_dir
        # Central project storage. With no explicit override, samples instead
        # get a per-binary `_lvr` project NEXT TO THE SAMPLE (reusable
        # analysis, nothing grows on the system drive); this dir is only the
        # fallback for unwritable locations and file-picker uploads.
        self._project_dir_path = project_dir_path or project_dir()
        self._project_forced = project_dir_path is not None
        if not self._project_forced:
            env = os.environ.get("LVR_PROJECT_DIR")
            if env:
                self._project_dir_path = Path(env)
                self._project_forced = True
        self._project_location: str | None = None
        self._queue: queue.Queue[tuple[Callable[[], Any], _Box] | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._boot_error: BaseException | None = None

        self.project: Any = None  # ghidra.base.project.GhidraProject
        self.program: Any = None
        self.program_name: str | None = None
        self.source_path: str | None = None

        # visible from HTTP threads without touching the engine queue
        self.open_state = "idle"  # idle | opening
        self.open_progress = ""

        self._decompiler: Any = None
        self._funcs_cache: list[dict[str, Any]] | None = None
        self._strings_cache: list[dict[str, Any]] | None = None
        self._imports_cache: list[dict[str, Any]] | None = None
        self._exports_cache: list[dict[str, Any]] | None = None
        self._blocks_cache: list[dict[str, Any]] | None = None

    # ------------------------------------------------------------ worker core

    def ensure_started(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._worker, name="lvr-engine", daemon=True)
            self._thread.start()
            # wait for JVM boot (or boot failure) before accepting work
            deadline = time.time() + 300
            while time.time() < deadline:
                if self._booted or self._boot_error:
                    break
                time.sleep(0.1)
            else:
                raise EngineError("JVM boot timed out after 300s")
            if self._boot_error:
                raise EngineError(f"JVM boot failed: {self._boot_error}") from self._boot_error

    _booted = False

    def _worker(self) -> None:
        try:
            import os

            if self._ghidra_dir is not None:
                os.environ["GHIDRA_INSTALL_DIR"] = str(self._ghidra_dir)
            import pyghidra

            pyghidra.start()
            self._booted = True
        except BaseException as e:  # noqa: BLE001 - must not kill the thread silently
            self._boot_error = e
            return
        while True:
            task = self._queue.get()
            if task is None:
                return
            fn, box = task
            try:
                box.result = fn()
            except BaseException as e:  # noqa: BLE001
                box.error = e
                traceback.print_exc()
            finally:
                box.event.set()

    def submit(self, fn: Callable[[], T], timeout: float | None = None) -> T:
        """Run fn on the engine thread and wait for its result."""
        self.ensure_started()
        box = _Box()
        self._queue.put((fn, box))
        return box.wait(timeout)

    # ------------------------------------------------------------- lifecycle

    def open(self, path: str | Path, progress: Callable[[str], None] | None = None) -> dict[str, Any]:
        """Import (or reuse) a binary and run auto-analysis. Returns program info."""
        self.open_state = "opening"

        def prog(s: str) -> None:
            self.open_progress = s
            if progress:
                progress(s)

        def job() -> dict[str, Any]:
            try:
                return self._open_job(path, prog)
            finally:
                self.open_state = "idle"
                self.open_progress = ""

        return self.submit(job, timeout=None)

    def _project_for(self, src: Path) -> tuple[Path, str]:
        """Where to put the Ghidra project for this sample.

        Default: `<sample dir>/_lvr/<name>` — analysis lives beside the
        binary and is reused verbatim on reopen (seconds instead of a full
        re-import), and nothing accumulates on the system drive. Falls back
        to the central dir when the sample's own location is not writable
        (read-only mounts, Program Files...), or when a central location is
        forced (explicit project_dir_path / LVR_PROJECT_DIR).

        Note: Ghidra rejects project paths containing dot-prefixed elements
        ("Path element starting with '.' is not permitted"), so the folder
        is `_lvr`, not `.lvr`.
        """
        if self._project_forced:
            return self._project_dir_path / "main", "main"
        pdir = src.parent / "_lvr"
        pname = _safe_project_name(src.stem)
        try:
            pdir.mkdir(parents=True, exist_ok=True)
            probe = pdir / ".write-test"
            probe.write_bytes(b"")
            probe.unlink()
        except OSError:
            return self._project_dir_path / "main", "main"
        return pdir, pname

    def _open_job(self, path: str | Path, progress: Callable[[str], None] | None) -> dict[str, Any]:
        def inner() -> dict[str, Any]:
            from ghidra.base.project import GhidraProject

            src = Path(path)
            if not src.is_file():
                raise EngineError(f"file not found: {src}")
            name = _safe_program_name(src.name)
            if progress:
                progress(f"importing {src.name}")

            pdir, pname = self._project_for(src)
            pdir.mkdir(parents=True, exist_ok=True)

            # Open the NEW project while the old program is still alive, and
            # only close the old one after the new import succeeds — a failed
            # open (unsupported file, malformed binary) must NOT leave the
            # engine with no program at all (every API would then 409 and the
            # whole UI dead-ends). Exception: reopening the SAME project must
            # close its previous handle first, or Ghidra's project lock
            # rejects the second open (LockException, poisoned engine).
            same_project = (
                self._project_location is not None
                and Path(self._project_location) == pdir.resolve()
            )
            old_project = self.project
            if same_project and old_project is not None:
                if progress:
                    progress("closing previous program")
                try:
                    old_project.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass
                self.project = None
                self.program = None
                old_project = None
            self._invalidate_caches()

            if (pdir / f"{pname}.rep").exists() or (pdir / f"{pname}.gpr").exists():
                project = GhidraProject.openProject(pdir, pname, True)
            else:
                project = GhidraProject.createProject(pdir, pname, False)

            try:
                program = None
                try:
                    existing = project.getRootFolder().getFile(name)
                    if existing is not None:
                        program = project.openProgram("/", name, False)
                except Exception:  # noqa: BLE001
                    program = None

                if program is None:
                    program = project.importProgram(src)
                    if program is None:
                        raise EngineError(
                            f"Ghidra failed to import '{src.name}' (unsupported or malformed)"
                        )
                    project.saveAs(program, "/", name, True)

                if progress:
                    progress("running auto-analysis (this can take a while)")

                import pyghidra

                pyghidra.analyze(program)

                project.save(program)
            except BaseException:
                # The project handle owns the on-disk project lock. If we leave
                # it open, EVERY later open dies with LockException (poisoned
                # engine) — close it before propagating. This is not yet
                # self.project, so the next open's cleanup can't see it.
                try:
                    project.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass
                raise

            # success — swap in the new program, THEN release the old project
            self.project = project
            self.program = program
            self.program_name = name
            self.source_path = str(src)
            self._project_location = str(pdir)
            if old_project is not None:
                try:
                    old_project.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass

            if progress:
                progress("collecting caches")
            info = self._program_info()
            # warm caches on the engine thread
            self._funcs()
            self._strings()
            self._imports_exports()
            self._blocks()
            if progress:
                progress("ready")
            return info

        return inner()

    def close(self) -> None:
        def job():
            if self.project is not None:
                try:
                    self.project.close()
                except Exception:  # noqa: BLE001
                    pass
            self.project = None
            self.program = None
            self._invalidate_caches()

        if self._thread is not None:
            self.submit(job, timeout=60)

    def shutdown(self) -> None:
        if self._thread is not None:
            self._queue.put(None)
            self._thread = None
        # Terminate the JVM so that embedding processes (pytest, short-lived
        # scripts) exit promptly — JPype leaves non-daemon threads behind.
        # Ghidra's analysis/worker threads are non-daemon and never stop, so
        # shutdownJVM() can block forever (observed in pytest teardown). Run
        # it on a helper thread with a grace budget; if it doesn't finish,
        # abandon teardown and let the JVM die with the process.
        import atexit

        done = threading.Event()

        def _kill() -> None:
            try:
                import jpype

                if jpype.isJVMStarted():
                    try:
                        atexit.unregister(jpype.shutdownJVM)
                    except Exception:  # noqa: BLE001
                        pass
                    # jpype registers its internal _JTerminate as the atexit
                    # hook (not shutdownJVM itself) - if it stays registered,
                    # interpreter exit blocks forever on Ghidra's non-daemon
                    # threads even after our bounded shutdown below.
                    try:
                        from jpype import _core

                        atexit.unregister(_core._JTerminate)
                    except Exception:  # noqa: BLE001
                        pass
                    jpype.shutdownJVM()
            except Exception:  # noqa: BLE001
                pass
            finally:
                done.set()

        threading.Thread(target=_kill, name="lvr-jvm-kill", daemon=True).start()
        done.wait(10.0)

    def _invalidate_caches(self) -> None:
        self._decompiler = None
        self._funcs_cache = None
        self._strings_cache = None
        self._imports_cache = None
        self._exports_cache = None
        self._blocks_cache = None

    # ---------------------------------------------------------------- helpers

    def _require_program(self) -> Any:
        if self.program is None:
            raise EngineError("no program loaded")
        return self.program

    def _to_addr(self, offset: int) -> Any:
        from ghidra.program.model.address import Address

        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def _program_info(self) -> dict[str, Any]:
        program = self._require_program()
        lang = program.getLanguage()
        mem = program.getMemory()
        return {
            "name": program.getName(),
            "source_path": self.source_path,
            "project_dir": self._project_location,
            "format": str(program.getExecutableFormat()),
            "language_id": str(lang.getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": _hex(program.getImageBase().getOffset()),
            "size": int(mem.getNumAddresses()),
            "function_count": len(self._funcs()),
        }

    # ---------------------------------------------------------------- queries

    def program_info(self) -> dict[str, Any] | None:
        if self.program is None:
            # fast path: during a long auto-analysis the queue is busy; queueing
            # here would block until its 30s timeout and surface as HTTP 500 (B2)
            return None
        return self.submit(lambda: self._program_info(), timeout=30)

    def _funcs(self) -> list[dict[str, Any]]:
        if self._funcs_cache is not None:
            return self._funcs_cache
        program = self._require_program()
        fm = program.getFunctionManager()
        out: list[dict[str, Any]] = []
        for f in fm.getFunctions(True):
            try:
                sig = str(f.getSignature(False))
            except Exception:  # noqa: BLE001
                sig = ""
            out.append({
                "addr": int(f.getEntryPoint().getOffset()),
                "name": f.getName(),
                "size": int(f.getBody().getNumAddresses()),
                "signature": sig,
            })
        self._funcs_cache = out
        return out

    def list_functions(self, query: str = "", offset: int = 0, limit: int = 200) -> dict[str, Any]:
        def job():
            items = self._funcs()
            if query:
                q = query.lower()
                items = [f for f in items if q in f["name"].lower() or q in f["signature"].lower()]
            return {
                "total": len(items),
                "items": items[offset : offset + limit],
            }

        return self.submit(job, timeout=120)

    def function_at(self, addr: int) -> dict[str, Any] | None:
        def job():
            program = self._require_program()
            fm = program.getFunctionManager()
            a = self._to_addr(addr)
            f = fm.getFunctionAt(a)
            if f is None:
                f = fm.getFunctionContaining(a)
            if f is None:
                return None
            return {
                "addr": int(f.getEntryPoint().getOffset()),
                "name": f.getName(),
                "size": int(f.getBody().getNumAddresses()),
            }

        return self.submit(job, timeout=30)

    # ------------------------------------------------------------- annotations

    def _find_function(self, fm: Any, a: Any) -> Any:
        f = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if f is None:
            raise EngineError(f"no function at {_hex(int(a.getOffset()))}")
        return f

    def rename_function(self, addr: int, name: str) -> dict[str, Any]:
        """Rename the function containing addr; persists to the project."""

        def job():
            program = self._require_program()
            fm = program.getFunctionManager()
            f = self._find_function(fm, self._to_addr(addr))
            from ghidra.program.model.symbol import SourceType

            old = str(f.getName())
            f.setName(name, SourceType.USER_DEFINED)
            self._funcs_cache = None
            try:
                self.project.save(program)
            except Exception:  # noqa: BLE001 - in-memory change still applied
                pass
            return {"addr": int(f.getEntryPoint().getOffset()), "old": old, "name": name}

        return self.submit(job, timeout=60)

    def set_function_comment(self, addr: int, text: str) -> dict[str, Any]:
        """Set the plate comment (shown atop decompiled output) of the function at addr."""

        def job():
            program = self._require_program()
            fm = program.getFunctionManager()
            f = self._find_function(fm, self._to_addr(addr))
            from ghidra.program.model.listing import CodeUnit

            entry = f.getEntryPoint()
            cu = program.getListing().getCodeUnitAt(entry) or program.getListing().getCodeUnitContaining(entry)
            if cu is None:
                raise EngineError("no code unit at function entry")
            cu.setComment(CodeUnit.PLATE_COMMENT, text)
            try:
                self.project.save(program)
            except Exception:  # noqa: BLE001
                pass
            return {"addr": int(entry.getOffset()), "comment": text}

        return self.submit(job, timeout=60)

    def function_comment(self, addr: int) -> str | None:
        def job():
            program = self._require_program()
            cu = program.getListing().getCodeUnitAt(self._to_addr(addr))
            if cu is None:
                return None
            from ghidra.program.model.listing import CodeUnit

            return cu.getComment(CodeUnit.PLATE_COMMENT)

        return self.submit(job, timeout=30)

    def _get_decompiler(self) -> Any:
        """Lazy, cached DecompInterface bound to the current program."""
        if self._decompiler is None:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions

            di = DecompInterface()
            di.setOptions(DecompileOptions())
            di.openProgram(self.program)
            self._decompiler = di
        return self._decompiler

    def decompile(self, addr: int) -> dict[str, Any]:
        def job():
            program = self._require_program()
            fm = program.getFunctionManager()
            a = self._to_addr(addr)
            f = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            if f is None:
                raise EngineError(f"no function at {_hex(addr)}")
            di = self._get_decompiler()
            res = di.decompileFunction(f, 120, _monitor())
            if not res.decompileCompleted():
                raise EngineError(f"decompile failed: {res.getErrorMessage()}")
            code = res.getDecompiledFunction().getC()

            # Line-number -> memory address maps. Lets the frontend jump from
            # a data xref (e.g. a string reference) to the exact decompiled
            # line that performs the reference.
            #
            # Implementation notes (probed on Ghidra 12.2): tokens carry no
            # usable line number/parent in this API path (getLineParent() is
            # always None), so we derive display line numbers by counting
            # ClangBreak tokens (they delimit lines). The markup is a
            # ClangFunction whose top-level children include nested groups,
            # so we recurse in Python — ClangTokenGroup.tokenIterator(boolean)
            # exists but JPype fails to dispatch a Python bool to it.
            #
            # Per line we keep the [min, max] range of *code* addresses
            # (inside the function body) plus the first *data* address seen
            # (string/constant literals often carry their own data address).
            # The frontend highlights by: exact data match on the xref
            # target, then code-range containment of the ref instruction,
            # then nearest following code line (argument-setup instructions
            # precede the call they feed, so refs in a gap belong to the
            # NEXT line, not the previous one).
            addr_lines: dict[int, int] = {}
            addr_lines_hi: dict[int, int] = {}
            addr_data: dict[int, int] = {}
            markup = res.getCCodeMarkup()
            if markup is not None:
                from ghidra.app.decompiler import ClangBreak, ClangTokenGroup

                body = f.getBody()
                bmin = int(body.getMinAddress().getOffset())
                bmax = int(body.getMaxAddress().getOffset())

                def _iter_tokens(group):
                    for item in group:
                        if isinstance(item, ClangTokenGroup):
                            yield from _iter_tokens(item)
                        else:
                            yield item

                line_no = 1
                for tk in _iter_tokens(markup):
                    if isinstance(tk, ClangBreak):
                        line_no += 1
                        continue
                    try:
                        a2 = tk.getMinAddress()
                    except Exception:  # noqa: BLE001 - token without address
                        continue
                    if a2 is None:
                        continue
                    off = int(a2.getOffset())
                    if off <= 0:
                        continue
                    if bmin <= off <= bmax:
                        cur = addr_lines.get(line_no)
                        if cur is None or off < cur:
                            addr_lines[line_no] = off
                        curh = addr_lines_hi.get(line_no)
                        if curh is None or off > curh:
                            addr_lines_hi[line_no] = off
                    else:
                        addr_data.setdefault(line_no, off)

            return {
                "addr": addr,
                "name": f.getName(),
                "code": str(code),
                "addr_lines": addr_lines,
                "addr_lines_hi": addr_lines_hi,
                "addr_data": addr_data,
            }

        return self.submit(job, timeout=180)

    def callgraph(self, addr: int, depth: int = 2, max_nodes: int = 250) -> dict[str, Any]:
        """Call-graph neighborhood around the function at addr (BFS both directions)."""

        def job():
            program = self._require_program()
            fm = program.getFunctionManager()
            a = self._to_addr(addr)
            start = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            if start is None:
                raise EngineError(f"no function at {_hex(addr)}")
            monitor = _monitor()

            center = int(start.getEntryPoint().getOffset())
            nodes = {center: start.getName()}
            edges: set[tuple[int, int]] = set()
            frontier: list[tuple[Any, int]] = [(start, 0)]

            while frontier and len(nodes) < max_nodes:
                f, d = frontier.pop(0)
                if d >= depth:
                    continue
                fa = int(f.getEntryPoint().getOffset())
                try:
                    callees = f.getCalledFunctions(monitor)
                except Exception:  # noqa: BLE001
                    callees = []
                for callee in callees:
                    try:
                        ca = int(callee.getEntryPoint().getOffset())
                    except Exception:  # noqa: BLE001
                        continue
                    edges.add((fa, ca))
                    if ca not in nodes:
                        nodes[ca] = callee.getName()
                        if len(nodes) < max_nodes:
                            frontier.append((callee, d + 1))
                try:
                    callers = f.getCallingFunctions(monitor)
                except Exception:  # noqa: BLE001
                    callers = []
                for caller in callers:
                    try:
                        pa = int(caller.getEntryPoint().getOffset())
                    except Exception:  # noqa: BLE001
                        continue
                    edges.add((pa, fa))
                    if pa not in nodes:
                        nodes[pa] = caller.getName()
                        if len(nodes) < max_nodes:
                            frontier.append((caller, d + 1))

            return {
                "center": center,
                "nodes": [{"addr": a2, "name": n} for a2, n in nodes.items()],
                "edges": [list(e) for e in sorted(edges)],
            }

        return self.submit(job, timeout=120)

    def decompile_many(
        self, addrs: list[int], progress: Callable[[int, int], None] | None = None
    ) -> list[tuple[int, str, str]]:
        def job():
            program = self._require_program()
            fm = program.getFunctionManager()
            di = self._get_decompiler()
            out: list[tuple[int, str, str]] = []
            for i, addr in enumerate(addrs):
                try:
                    f = fm.getFunctionAt(self._to_addr(addr))
                    if f is None:
                        continue
                    res = di.decompileFunction(f, 30, _monitor())
                    if res.decompileCompleted():
                        out.append((addr, f.getName(), str(res.getDecompiledFunction().getC())))
                except Exception:  # noqa: BLE001 - skip failures, keep going
                    pass
                if progress and (i % 10 == 0 or i == len(addrs) - 1):
                    progress(i + 1, len(addrs))
            return out

        return self.submit(job, timeout=None)

    def disasm(self, addr: int, max_instructions: int = 400) -> dict[str, Any]:
        def job():
            program = self._require_program()
            listing = program.getListing()
            fm = program.getFunctionManager()
            a = self._to_addr(addr)
            f = fm.getFunctionContaining(a)
            body = f.getBody() if f else None
            rows: list[dict[str, Any]] = []
            it = listing.getInstructions(a, True)
            count = 0
            while it.hasNext() and count < max_instructions:
                instr = it.next()
                ia = int(instr.getAddress().getOffset())
                if body is not None and not body.contains(instr.getAddress()):
                    break
                try:
                    raw = bytes(b & 0xFF for b in instr.getBytes())
                except Exception:  # noqa: BLE001
                    raw = b""
                refs = [
                    int(r.getToAddress().getOffset())
                    for r in instr.getReferencesFrom()
                    if r.getToAddress() is not None
                ]
                rows.append({
                    "addr": ia,
                    "bytes": raw.hex(" "),
                    "text": str(instr.toString()),
                })
                if refs:
                    rows[-1]["refs"] = refs
                count += 1
            return {
                "addr": addr,
                "function": f.getName() if f else None,
                "function_addr": int(f.getEntryPoint().getOffset()) if f else None,
                "instructions": rows,
            }

        return self.submit(job, timeout=60)

    def disasm_raw(self, addr: int, max_bytes: int = 2048) -> dict[str, Any]:
        """Decode the raw byte stream at ``addr`` along the executed order.

        Deliberately independent of Ghidra's instruction definitions: obfuscated
        samples (overlapped instructions, CALL-chains that are really JMPs)
        pollute the listing/decompiler because Ghidra must pick one alignment
        per byte. The raw decode follows unconditional-JMP targets instead —
        the same thing a human does when hand-reading the HEX view.
        """
        def job():
            program = self._require_program()
            mem = program.getMemory()
            a = self._to_addr(addr)
            block = mem.getBlock(a)
            if block is None or not block.isInitialized():
                raise EngineError(f"no initialized memory at 0x{addr:x}")
            avail = int(block.getEnd().getOffset()) - addr + 1
            n = max(0, min(int(max_bytes), avail, 1 << 16))
            if n == 0:
                raise EngineError(f"nothing readable at 0x{addr:x}")
            raw = _read_bytes(mem, a, n)
            bits = int(program.getMinAddress().getAddressSpace().getSize())
            from lovelyreverse.disasm import decode_trace

            out = decode_trace(raw, addr, mode_bits=bits)
            out["block"] = str(block.getName())
            return out

        return self.submit(job, timeout=60)

    def _strings(self) -> list[dict[str, Any]]:
        if self._strings_cache is not None:
            return self._strings_cache
        program = self._require_program()
        out: list[dict[str, Any]] = []
        for data in program.getListing().getDefinedData(True):
            try:
                value = data.getValue()
                if not isinstance(value, str):
                    continue
            except Exception:  # noqa: BLE001
                continue
            if len(value) < 2:
                continue
            if len(value) > 4096:
                value = value[:4096] + "…"
            out.append({
                "addr": int(data.getAddress().getOffset()),
                "length": int(data.getLength()),
                "value": value,
            })
        self._strings_cache = out
        return out

    def list_strings(self, query: str = "", offset: int = 0, limit: int = 200) -> dict[str, Any]:
        def job():
            items = self._strings()
            if query:
                q = query.lower()
                items = [s for s in items if q in s["value"].lower()]
            return {"total": len(items), "items": items[offset : offset + limit]}

        return self.submit(job, timeout=120)

    def _imports_exports(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        program = self._require_program()
        imports: list[dict[str, Any]] = []
        # Thunk functions (import stubs) live in the binary and are named
        # after the import they forward to. Their real entry addresses are
        # what callers CALL, so xrefs against them reveal "who calls this
        # import". External-space symbol addresses (offset 0x29 etc.) are
        # NOT usable for that — do not use the symbol table for lookups.
        thunks: dict[str, int] = {}
        st = program.getSymbolTable()
        for f in program.getFunctionManager().getFunctions(True):
            try:
                if f.isThunk():
                    thunks.setdefault(str(f.getName()), int(f.getEntryPoint().getOffset()))
            except Exception:  # noqa: BLE001
                continue

        for sym in st.getAllSymbols(True):
            try:
                if not sym.isExternal():
                    continue
                lib = ""
                try:
                    parent = sym.getParentNamespace()
                    if parent is not None and parent.getName() != "EXTERNAL":
                        lib = str(parent.getName())
                except Exception:  # noqa: BLE001
                    pass
                imports.append({"name": str(sym.getName()), "library": lib})
            except Exception:  # noqa: BLE001
                continue
        for imp in imports:
            imp["addr"] = thunks.get(imp["name"])
        exports: list[dict[str, Any]] = []
        for addr_off in st.getExternalEntryPointIterator():
            try:
                offset = int(addr_off.getOffset())
                sym = st.getPrimarySymbol(addr_off)
                if sym is not None:
                    exports.append({"addr": offset, "name": str(sym.getName())})
            except Exception:  # noqa: BLE001
                continue
        imports.sort(key=lambda i: i["name"].lower())
        exports.sort(key=lambda e: e["name"].lower())
        self._imports_cache = imports
        self._exports_cache = exports
        return imports, exports

    def imports(self) -> list[dict[str, Any]]:
        def job():
            self._imports_exports()
            return self._imports_cache

        return self.submit(job, timeout=120)

    def exports(self) -> list[dict[str, Any]]:
        def job():
            self._imports_exports()
            return self._exports_cache

        return self.submit(job, timeout=120)

    def xrefs(self, addr: int) -> dict[str, Any]:
        def job():
            program = self._require_program()
            rm = program.getReferenceManager()
            fm = program.getFunctionManager()
            a = self._to_addr(addr)

            def with_names(refs) -> list[dict[str, Any]]:
                out = []
                for r in refs:
                    ra = int(r.getFromAddress().getOffset())
                    fn = fm.getFunctionContaining(r.getFromAddress())
                    out.append({
                        "addr": ra,
                        "type": str(r.getReferenceType()),
                        "function": fn.getName() if fn else None,
                        "function_addr": int(fn.getEntryPoint().getOffset()) if fn else None,
                    })
                return out

            to_refs = with_names(rm.getReferencesTo(a))
            from_refs = [
                {
                    "addr": int(r.getFromAddress().getOffset()),
                    "to": int(r.getToAddress().getOffset()),
                    "type": str(r.getReferenceType()),
                }
                for r in rm.getReferencesFrom(a)
            ]
            return {"to": to_refs, "from": from_refs}

        return self.submit(job, timeout=120)

    # ----------------------------------------------------------------- memory

    def _blocks(self) -> list[dict[str, Any]]:
        if self._blocks_cache is not None:
            return self._blocks_cache
        program = self._require_program()
        from lovelyreverse.util.binfile import shannon_entropy

        out = []
        for b in program.getMemory().getBlocks():
            size = int(b.getSize())
            start = int(b.getStart().getOffset())
            ent = None
            if b.isInitialized() and size:
                sample_len = min(size, 1 << 20)
                try:
                    raw = _read_bytes(program.getMemory(), b.getStart(), sample_len)
                    ent = shannon_entropy(raw)
                except Exception:  # noqa: BLE001
                    ent = None
            out.append({
                "name": str(b.getName()),
                "start": start,
                "size": size,
                "initialized": bool(b.isInitialized()),
                "read": bool(b.isRead()),
                "write": bool(b.isWrite()),
                "execute": bool(b.isExecute()),
                "entropy": ent,
            })
        self._blocks_cache = out
        return out

    def memory_blocks(self) -> list[dict[str, Any]]:
        return self.submit(self._blocks, timeout=120)

    def read_memory(self, block_name: str, offset: int, length: int) -> bytes:
        def job():
            program = self._require_program()
            mem = program.getMemory()
            block = mem.getBlock(block_name)
            if block is None:
                raise EngineError(f"no memory block named {block_name!r}")
            n = min(length, 1 << 18)
            start = block.getStart().add(offset)
            try:
                raw = _read_bytes(mem, start, n)
            except Exception as e:  # noqa: BLE001
                raise EngineError(f"read failed: {e}") from e
            return raw

        return self.submit(job, timeout=60)

    def search_hex(self, hex_pattern: str, limit: int = 500) -> list[dict[str, Any]]:
        def job():
            program = self._require_program()
            mem = program.getMemory()
            fm = program.getFunctionManager()
            try:
                needle = bytes.fromhex(hex_pattern.replace(" ", ""))
            except ValueError as e:
                raise EngineError(f"bad hex pattern: {e}") from e
            if not needle:
                raise EngineError("empty pattern")
            matches: list[dict[str, Any]] = []
            monitor = _monitor()
            from ghidra.program.model.address import AddressSet

            for block in mem.getBlocks():
                if not block.isInitialized() or len(matches) >= limit:
                    continue
                start, end = block.getStart(), block.getEnd()
                pos = start
                while len(matches) < limit:
                    found = mem.findBytes(pos, end, needle, None, True, monitor)
                    if found is None:
                        break
                    fn = fm.getFunctionContaining(found)
                    matches.append({
                        "addr": int(found.getOffset()),
                        "block": str(block.getName()),
                        "function": fn.getName() if fn else None,
                    })
                    if found.equals(end):
                        break
                    pos = found.add(1)
            return matches

        return self.submit(job, timeout=300)

    # -------------------------------------------------------------- constants

    def constants_scan(self) -> list[dict[str, Any]]:
        """Run the FindCrypt-style scanner over all initialized memory."""

        def job():
            from lovelyreverse.engine.constants import scan_bytes

            program = self._require_program()
            fm = program.getFunctionManager()
            mem = program.getMemory()
            hits: list[dict[str, Any]] = []
            for block in mem.getBlocks():
                if not block.isInitialized():
                    continue
                size = int(block.getSize())
                if size == 0:
                    continue
                try:
                    raw = _read_bytes(mem, block.getStart(), min(size, 1 << 26))
                except Exception:  # noqa: BLE001
                    continue
                data = raw
                for hit in scan_bytes(data):
                    addr = block.getStart().add(hit.pop("offset"))
                    off = int(addr.getOffset())
                    fn = fm.getFunctionContaining(addr)
                    hit["addr"] = off
                    hit["block"] = str(block.getName())
                    hit["function"] = fn.getName() if fn else None
                    hits.append(hit)
            hits.sort(key=lambda h: h["addr"])
            return hits

        return self.submit(job, timeout=600)


# ------------------------------------------------------------------ utilities

def _hex(offset: int) -> str:
    return f"0x{offset:x}"


def _read_bytes(mem: Any, addr: Any, n: int) -> bytes:
    """Read n bytes at addr via Ghidra's (Address, byte[]) overload."""
    import jpype

    buf = jpype.JArray(jpype.JByte)(n)
    read = mem.getBytes(addr, buf)
    return bytes(b & 0xFF for b in buf[: max(read, 0)])


def _monitor() -> Any:
    from ghidra.util.task import ConsoleTaskMonitor

    return ConsoleTaskMonitor()


def _safe_program_name(name: str) -> str:
    keep = "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)
    return keep[:96] or "program"


def _safe_project_name(stem: str) -> str:
    """ASCII-safe Ghidra project name for a sample stem.

    Non-ASCII or stripped-out names become a short deterministic hash so
    e.g. `PangBai 过家家` and two mangled-to-identical stems never collide
    on disk (project dir names are invisible plumbing).
    """
    keep = "".join(c if (c.isalnum() or c in "._-") else "_" for c in stem)
    keep = keep[:60]
    if not keep or keep != stem or not keep.isascii():
        return "p_" + hashlib.sha1(stem.encode("utf-8", "ignore")).hexdigest()[:10]
    return keep
