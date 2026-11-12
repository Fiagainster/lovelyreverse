"""Raw instruction-stream decoding, independent of Ghidra's listings.

Why this exists: obfuscated samples use *overlapped instructions* — one byte
stream decoded from several entry points — and CALL-chains that are really
JMPs (CALL; entry: `eb rel8` → `ADD ESP,4` discards the pushed return →
JMP back past the call). Ghidra must commit to one alignment per byte, so
its listing/decompiler gets polluted (offcut instructions, halt_baddata,
wrong function boundaries). The ground truth is the *executed* order, which
a human reading the HEX view reconstructs by decoding bytes linearly and
hopping to unconditional-JMP targets. This module automates exactly that.

Pure logic — no Ghidra imports — so it unit-tests without the engine.
capstone does the byte→instruction lifting; the interesting part (flow
policy) lives here.
"""

from __future__ import annotations

from typing import Any

# Stop reasons, mirrored by frontend i18n keys (raw.stop.<reason>):
#   end      — ran out of the read window (or jumped past it)
#   ret      — hit RET (trace leaves the function)
#   trap     — hit int3/ud2
#   invalid  — bytes that don't decode as an instruction at all
#   loop     — jumped back to an already-decoded address
#   indirect — unconditional jump/call through a register/memory
#   limit    — max_insn instructions decoded

_MAX_INSN_DEFAULT = 2000
_MAX_RECOVER = 16


def _decoder(mode_bits: int) -> Any:
    try:
        import capstone
    except ImportError as e:  # pragma: no cover - guarded by packaging
        raise RuntimeError(
            "capstone is required for raw disassembly: pip install capstone"
        ) from e
    mode = capstone.CS_MODE_64 if mode_bits >= 64 else capstone.CS_MODE_32
    return capstone.Cs(capstone.CS_ARCH_X86, mode)


def _insn_from(capstone_insn: Any, data: bytes, off: int, flow: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "addr": int(capstone_insn.address),
        "size": capstone_insn.size,
        "bytes": data[off : off + capstone_insn.size].hex(" "),
        "text": f"{capstone_insn.mnemonic} {capstone_insn.op_str}".strip(),
    }
    if flow:
        entry["flow"] = flow
    m = capstone_insn.mnemonic
    if m.startswith("j") and m != "jmp" and capstone_insn.op_str.startswith("0x"):
        entry["_jcc"] = int(capstone_insn.op_str, 16)
    return entry


def decode_trace(
    data: bytes,
    base: int,
    mode_bits: int = 32,
    max_insn: int = _MAX_INSN_DEFAULT,
) -> dict[str, Any]:
    """Decode ``data`` (loaded at virtual address ``base``) along execution order.

    Policy (matches hand-reading a HEX view):
      - linear sweep from ``base``;
      - an unconditional direct JMP continues at its *target*, never the
        fall-through — this is what carries the trace through obfuscated
        CALL-is-really-JMP chains;
      - a CALL whose callee *starts with a backward direct JMP* is the
        obfuscation signature (callee: `eb rel8` → `ADD ESP,N` discarding
        the pushed return → JMP onward): follow the callee and skip the
        fall-through, whose bytes are deliberate junk (marked "dead");
        any other CALL falls through (control returns);
      - a conditional jump falls through; if the fall-through turns out to
        be junk (anti-debug: undecodable bytes or int3/ud2 padding), resume
        at the conditional jump's target instead (capped attempts);
      - RET / loop back-edge / indirect jump / window end stop the trace.
    """
    md = _decoder(mode_bits)
    items: list[dict[str, Any]] = []
    visited: set[int] = set()
    addr = base
    end = base + len(data)
    stop = "end"
    recovered = 0
    last_jcc: int | None = None
    junk_addr = addr  # where the junk lives, for the resume marker

    while addr < end and len(items) < max_insn:
        if addr in visited:
            stop = "loop"
            break
        visited.add(addr)
        off = addr - base
        junk_addr = addr
        insn = next(md.disasm(data[off : off + 15], addr), None)

        stopped: str | None = None
        if insn is not None:
            entry = _insn_from(insn, data, off)
            items.append(entry)
            if "_jcc" in entry:
                last_jcc = entry["_jcc"]
            m = insn.mnemonic
            if m == "jmp":
                if not insn.op_str.startswith("0x"):
                    stop = "indirect"
                    break
                t = int(insn.op_str, 16)
                if not (base <= t < end):
                    stop = "end"  # direct jump out of the read window
                    break
                if t in visited:
                    stop = "loop"
                    break
                nxt_off = t - base
                nxt = next(md.disasm(data[nxt_off : nxt_off + 15], t), None)
                if nxt is None:
                    items.append({
                        "addr": t,
                        "invalid": True,
                        "size": 1,
                        "bytes": data[nxt_off : nxt_off + 1].hex(" "),
                        "text": "(bad)",
                    })
                    junk_addr = t
                    stop = "invalid"
                else:
                    nxt_entry = _insn_from(nxt, data, nxt_off, flow="jmp")
                    items.append(nxt_entry)
                    if "_jcc" in nxt_entry:
                        last_jcc = nxt_entry["_jcc"]
                    visited.add(t)
                    if nxt.mnemonic == "jmp" and nxt.op_str.startswith("0x"):
                        addr = int(nxt.op_str, 16)  # chained jmp: keep following
                    else:
                        addr = t + nxt.size
                    continue
            elif m == "call":
                # CALL-actually-JMP detection: callee entry is a *backward*
                # direct jmp — lands on the ADD ESP,N cluster that discards
                # the pushed return, so the fall-through bytes are dead junk.
                handled = False
                if insn.op_str.startswith("0x"):
                    t = int(insn.op_str, 16)
                    if base <= t < end and t not in visited:
                        peek = next(md.disasm(data[t - base : t - base + 15], t), None)
                        if peek is not None and peek.mnemonic == "jmp" \
                                and peek.op_str.startswith("0x") and int(peek.op_str, 16) < t:
                            items.append({"addr": addr + insn.size, "dead": True})
                            addr = t
                            handled = True
                if not handled:
                    addr += insn.size  # real call: control returns to fall-through
                continue
            elif m.startswith("ret"):
                stop = "ret"
            elif m in ("int3", "ud2"):
                stop = "trap"
            else:
                addr += insn.size
                continue
        else:
            items.append({
                "addr": addr,
                "invalid": True,
                "size": 1,
                "bytes": data[off : off + 1].hex(" "),
                "text": "(bad)",
            })
            stop = "invalid"

        # junk underfoot (undecodable bytes / int3 / ud2) right after a
        # conditional jump → the anti-debug pattern; resume at its target
        if stop in ("trap", "invalid") and recovered < _MAX_RECOVER \
                and last_jcc is not None and base <= last_jcc < end \
                and last_jcc not in visited:
            items.append({"addr": junk_addr, "resume": True})
            addr = last_jcc  # the loop head re-adds it to visited
            last_jcc = None
            recovered += 1
            continue

        break  # ret, or unrecoverable trap/invalid

    if len(items) >= max_insn:
        stop = "limit"

    for it in items:
        it.pop("_jcc", None)

    return {
        "base": base,
        "mode_bits": mode_bits,
        "items": items,
        "stop": stop,
        "recovered": recovered,
    }
