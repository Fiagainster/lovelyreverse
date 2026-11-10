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
    def __init__(self, ghidra_install_dir: Path | None = None):
        self._ghidra_dir = ghidra_install_dir
        self._queue: queue.Queue[tuple[Callable[[], Any], _Box] | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._boot_error: BaseException | None = None

        self.project: Any = None  # ghidra.base.project.GhidraProject
        self.program: Any = None
        self.program_name: str | None = None
        self.source_path: str | None = None

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
            deadline = time.time() + 600
            while time.time() < deadline:
                if self._queue.empty() and (self._booted or self._boot_error):
                    break
                time.sleep(0.1)
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

        def job() -> dict[str, Any]:
            from ghidra.base.project import GhidraProject

            src = Path(path)
            if not src.is_file():
                raise EngineError(f"file not found: {src}")
            name = _safe_program_name(src.name)
            if progress:
                progress("closing previous program")

            if self.project is not None:
                try:
                    self.project.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass
                self.project = None
                self.program = None
            self._invalidate_caches()

            if progress:
                progress(f"importing {src.name}")

            pdir = project_dir() / "main"
            pdir.mkdir(parents=True, exist_ok=True)
            if (pdir / "main.rep").exists() or (pdir / "main.gpr").exists():
                project = GhidraProject.openProject(pdir, "main", True)
            else:
                project = GhidraProject.createProject(pdir, "main", False)

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

            self.project = project
            self.program = program
            self.program_name = name
            self.source_path = str(src)

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

        return self.submit(job, timeout=None)

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
            "format": str(program.getExecutableFormat()),
            "language_id": str(lang.getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": _hex(program.getImageBase().getOffset()),
            "size": int(mem.getNumAddresses()),
            "function_count": program.getFunctionManager().getFunctionCount(),
        }

    # ---------------------------------------------------------------- queries

    def program_info(self) -> dict[str, Any] | None:
        return self.submit(lambda: self._program_info() if self.program else None, timeout=30)

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
            return {"addr": addr, "name": f.getName(), "code": str(code)}

        return self.submit(job, timeout=180)

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
        st = program.getSymbolTable()
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
                    raw = program.getMemory().getBytes(b.getStart(), sample_len)
                    ent = shannon_entropy(bytes(x & 0xFF for x in raw))
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
            if length > (1 << 18):
                length = 1 << 18
            start = block.getStart().add(offset)
            try:
                raw = mem.getBytes(start, length)
            except Exception as e:  # noqa: BLE001
                raise EngineError(f"read failed: {e}") from e
            return bytes(b & 0xFF for b in raw)

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
                    raw = mem.getBytes(block.getStart(), min(size, 1 << 26))
                except Exception:  # noqa: BLE001
                    continue
                data = bytes(b & 0xFF for b in raw)
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


def _monitor() -> Any:
    from ghidra.util.task import ConsoleTaskMonitor

    return ConsoleTaskMonitor()


def _safe_program_name(name: str) -> str:
    keep = "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)
    return keep[:96] or "program"
