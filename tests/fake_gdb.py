"""A minimal fake gdb: speaks just enough MI over stdio for session tests."""
import sys
import time

w = sys.stdout

def out(s):
    w.write(s + "\n")
    w.flush()

def out2(s):
    w.write(s)
    w.flush()

out2("=thread-group-added,id=\"i1\"\n")
out2("(gdb)\n")

state = {"bp": 0}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    token = ""
    while line and line[0].isdigit():
        token += line[0]
        line = line[1:]
    if line in ("-gdb-set confirm off", "-gdb-set pagination off"):
        out(f"{token}^done")
    elif line.startswith("-file-exec-and-symbols"):
        out(f'{token}^done')
        out('~"Reading symbols from fake.\\n"')
    elif line.startswith("-gdb-set args"):
        out(f"{token}^done")
    elif line.startswith("-gdb-set env"):
        out(f"{token}^done")
    elif line.startswith("-break-insert"):
        state["bp"] += 1
        n = state["bp"]
        out(f'{token}=breakpoint-created,bkpt={{number="{n}",addr="0x00401370"}}')
        out(f'{token}^done,bkpt={{number="{n}",type="breakpoint",addr="0x00401370"}}')
    elif line == "-break-list":
        entries = ",".join(f'{{number="{i}",addr="0x00401370"}}' for i in range(1, state["bp"] + 1))
        out(f'{token}^done,BreakpointTable={{body={{bkpt=[{entries}]}}}}')
    elif line.startswith("-break-delete"):
        out(f"{token}^done")
    elif line in ("-exec-run", "-exec-continue"):
        out(f"{token}^running")
        time.sleep(0.3)
        out('*stopped,reason="breakpoint-hit",disp="keep",bkptno="1",frame={addr="0x00401370",func="main",args=[]},thread-id="1"')
    elif line in ("-exec-next", "-exec-step", "-exec-nexti", "-exec-stepi"):
        out(f"{token}^running")
        time.sleep(0.2)
        out('*stopped,reason="end-stepping-range",frame={addr="0x00401375",func="main",args=[]},thread-id="1"')
    elif line == "-data-list-register-names":
        out(f'{token}^done,register-names=["rax","rbx","rcx"]')
    elif line == "-data-list-register-values x":
        out(f'{token}^done,register-values=[{{number="0",value="0x11"}},{{number="1",value="0x22"}},{{number="2",value="0x33"}}]')
    elif line.startswith("-data-read-memory-bytes"):
        out(f'{token}^done,memory=[{{begin="0x0",contents="41424344",size="4"}}]')
    elif line == "-stack-list-frames":
        out(f'{token}^done,stack=[frame={{level="0",func="main",addr="0x00401370"}},frame={{level="1",func="__start",addr="0x00401000"}}]')
    elif line.startswith("-data-evaluate-expression"):
        out(f'{token}^done,value="42"')
    elif line.startswith("-interpreter-exec console"):
        # console escape: echo the command back through the ~console stream
        out(f'~"console: {line[len("-interpreter-exec console "):].strip(chr(34))}\\n"')
        out(f"{token}^done")
    elif line == "-gdb-exit":
        out(f"{token}^exit")
        break
    else:
        out(f'{token}^error,msg="unhandled: {line[:40]}"')
    out2("(gdb)\n")
