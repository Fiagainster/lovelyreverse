"""decode_trace — raw instruction-stream decode along the executed order.

The flow policy is the product here: linear sweep + follow unconditional
JMPs + CALL-actually-JMP detection + anti-debug junk recovery. Synthetic
scenarios mirror the obfuscation family found in Root-Me's KeygenMe
(overlapped instructions, disguised calls, RDTSC gauntlets).
"""

from lovelyreverse.disasm import decode_trace


def texts(r):
    return [i.get("text") for i in r["items"]]


def test_plain_prologue_decodes_to_window_end():
    r = decode_trace(b"\x55\x89\xe5\xc3\xcc\xcc", 0x1000)
    assert r["stop"] == "ret"
    assert texts(r) == ["push ebp", "mov ebp, esp", "ret"]
    assert r["recovered"] == 0


def test_jmp_follows_target_skipping_junk():
    # `eb 05` jumps over five int3 bytes a linear sweep would decode
    r = decode_trace(b"\xeb\x05\xcc\xcc\xcc\xcc\xcc\x90\xc3", 0x2000)
    assert r["stop"] == "ret"
    assert texts(r) == ["jmp 0x2007", "nop", "ret"]
    assert all(i["addr"] != 0x2002 for i in r["items"])


def test_self_jmp_is_a_loop():
    r = decode_trace(b"\xeb\xfe", 0x3000)
    assert r["stop"] == "loop"
    assert len(r["items"]) == 1


def test_disguised_call_chain_call_then_jmp():
    # call $+5; entry: `eb 02` (forward — not the backward stack-discard
    # signature, so the call falls through onto the jmp itself); junk
    # int3s between are never executed
    r = decode_trace(b"\xe8\x00\x00\x00\x00\xeb\x02\xcc\xcc\x90\x90\xc3", 0x4000)
    assert r["stop"] == "ret"
    assert texts(r) == ["call 0x4005", "jmp 0x4009", "nop", "nop", "ret"]


def test_backward_jmp_callee_marks_return_dead():
    # The obfuscation signature (as in Root-Me KeygenMe):
    #   call CALLEE          ; pushes a return address into dead bytes
    #   CALLEE: eb rel8      ; jumps BACKWARD onto the discard cluster
    #   ...: add esp, 4      ; discards the pushed return
    #   ...: eb rel8         ; jumps FORWARD to the real continuation
    # The call's fall-through bytes are deliberate junk and must be skipped.
    base = 0x5000
    data = bytearray(b"\x00" * 0x20)
    data[0x00:0x05] = b"\xe8\x07\x00\x00\x00"  # 0x5000: call 0x500c, return 0x5005
    data[0x05:0x07] = b"\x90\x90"              # 0x5005: dead junk (return addr)
    data[0x07:0x0A] = b"\x83\xc4\x04"          # 0x5007: add esp, 4 (executed)
    data[0x0A:0x0C] = b"\xeb\x04"              # 0x500a: jmp 0x5010 (executed)
    data[0x0C:0x0E] = b"\xeb\xf9"              # 0x500c: callee, jmp back to 0x5007
    data[0x0E:0x10] = b"\xcc\xcc"              # 0x500e: dead junk (never executed)
    data[0x10:0x12] = b"\x90\xc3"              # 0x5010: nop; ret
    r = decode_trace(bytes(data), base)
    assert r["stop"] == "ret"
    got = [(i["addr"], i.get("text"), "dead" if i.get("dead") else "") for i in r["items"]]
    assert (0x5000, "call 0x500c", "") in got
    assert (0x500C, "jmp 0x5007", "") in got
    assert (0x5007, "add esp, 4", "") in got
    assert (0x500A, "jmp 0x5010", "") in got
    assert (0x5010, "nop", "") in got
    assert got[-1] == (0x5011, "ret", "")
    dead = [i for i in r["items"] if i.get("dead")]
    assert len(dead) == 1 and dead[0]["addr"] == 0x5005
    # neither junk region was decoded as instructions
    assert all(i["addr"] not in (0x5005, 0x500E) or i.get("dead") for i in r["items"])


def test_real_call_falls_through():
    # callee is `ret` (not a backward jmp) → ordinary call semantics
    r = decode_trace(b"\xe8\x05\x00\x00\x00\x90\xc3\x90\xc3", 0x6000)
    assert r["stop"] == "ret"
    assert texts(r) == ["call 0x600a", "nop", "ret"]


def test_trap_after_jcc_recovers_to_target():
    # anti-debug: int3 padding on the fall-through, real code at the target
    r = decode_trace(b"\x74\x04\xcc\xcc\xcc\xcc\x90\xc3", 0x7000)
    assert r["stop"] == "ret"
    assert r["recovered"] == 1
    kinds = [("resume" if i.get("resume") else i.get("text")) for i in r["items"]]
    assert kinds == ["je 0x7006", "int3", "resume", "nop", "ret"]


def test_undecodable_junk_after_jcc_recovers():
    r = decode_trace(b"\x75\x04\xff\xff\xff\xff\x90\xc3", 0x8000)
    assert r["stop"] == "ret"
    assert r["recovered"] == 1
    assert texts(r)[-2:] == ["nop", "ret"]


def test_64bit_mode():
    r = decode_trace(b"\x48\x89\xe5\xc3", 0x9000, mode_bits=64)
    assert r["stop"] == "ret"
    assert texts(r) == ["mov rbp, rsp", "ret"]


def test_indirect_jmp_stops():
    r = decode_trace(b"\xff\xe0", 0xA000)  # jmp eax
    assert r["stop"] == "indirect"


def test_limit_cap():
    r = decode_trace(b"\x90" * 64, 0xB000, max_insn=10)
    assert r["stop"] == "limit"
    assert len(r["items"]) == 10
