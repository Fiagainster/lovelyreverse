"""Unit tests for the GDB/MI line parser."""

from lovelyreverse.gdb.mi import parse_mi_line, parse_stopped, parse_breakpoint_table, format_register_values


class TestClassify:
    def test_result_done_empty(self):
        r = parse_mi_line("^done")
        assert r["kind"] == "result" and r["class"] == "done" and r["payload"] == {}

    def test_result_with_payload(self):
        r = parse_mi_line('^done,bkpt={number="1",type="breakpoint",addr="0x00401370"}')
        assert r["kind"] == "result"
        assert r["payload"]["bkpt"]["number"] == "1"
        assert r["payload"]["bkpt"]["addr"] == "0x00401370"

    def test_token_prefix(self):
        r = parse_mi_line('12^error,msg="No symbol table is loaded."')
        assert r["kind"] == "result" and r["class"] == "error"
        assert r["token"] == "12" and r["payload"]["msg"] == "No symbol table is loaded."

    def test_exec_stopped(self):
        r = parse_mi_line('*stopped,reason="breakpoint-hit",disp="keep",bkptno="1",frame={addr="0x0040138f",func="main",args=[]},thread-id="1"')
        assert r["kind"] == "exec" and r["class"] == "stopped"
        assert r["payload"]["reason"] == "breakpoint-hit"
        assert r["payload"]["frame"]["addr"] == "0x0040138f"
        assert r["payload"]["frame"]["args"] == []

    def test_exec_running(self):
        assert parse_mi_line("*running,thread-id=\"all\"")["class"] == "running"

    def test_notify_breakpoint_created(self):
        r = parse_mi_line('=breakpoint-created,bkpt={number="2",addr="0x0040138f"}')
        assert r["kind"] == "notify" and r["payload"]["bkpt"]["number"] == "2"

    def test_console_stream(self):
        r = parse_mi_line('~"Please input flag: "')
        assert r["kind"] == "console" and r["payload"] == "Please input flag: "

    def test_console_with_escapes(self):
        r = parse_mi_line('~"line1\\nline2\\tdone\\\\"')
        assert r["kind"] == "console"
        assert r["payload"] == "line1\nline2\tdone\\"

    def test_log_stream(self):
        assert parse_mi_line('&"set confirm off\\n"')["kind"] == "log"

    def test_prompt(self):
        assert parse_mi_line("(gdb)")["kind"] == "prompt"

    def test_noise_rejected(self):
        # the wsl.exe proxy warning must not explode the parser
        r = parse_mi_line("wsl: 检测到 localhost 代理配置，但未镜像到 WSL。")
        assert r["kind"] == "noise"

    def test_blank(self):
        assert parse_mi_line("") is None
        assert parse_mi_line("   ") is None

    def test_escapes_in_value_string(self):
        r = parse_mi_line('^done,value="\\x41\\x42"')
        assert r["payload"]["value"] == "AB"


class TestValueGrammar:
    def test_nested_tuple_list(self):
        r = parse_mi_line('^done,stack=[frame={level="0",addr="0x1"},frame={level="1",addr="0x2"}]')
        assert r["payload"]["stack"][0]["frame"]["level"] == "0"
        assert r["payload"]["stack"][1]["frame"]["addr"] == "0x2"

    def test_list_of_results(self):
        r = parse_mi_line('^done,register-values=[{number="0",value="0x1a"},{number="1",value="0x2b"}]')
        vals = r["payload"]["register-values"]
        assert vals[0]["number"] == "0" and vals[1]["value"] == "0x2b"

    def test_empty_containers(self):
        assert parse_mi_line("^done,x={}")["payload"]["x"] == {}
        assert parse_mi_line("^done,x=[]")["payload"]["x"] == []

    def test_string_with_braces(self):
        r = parse_mi_line('^done,value="struct {int a;} t"')
        assert r["payload"]["value"] == "struct {int a;} t"


class TestHelpers:
    def test_parse_stopped(self):
        payload = {"reason": "breakpoint-hit", "stopped-threads": ["1"],
                   "frame": {"addr": "0x0040138f", "func": "main"}}
        out = parse_stopped(payload)
        assert out["reason"] == "breakpoint-hit"
        assert out["func"] == "main" and out["addr"] == "0x0040138f"

    def test_parse_stopped_no_frame(self):
        out = parse_stopped({"reason": "exited-normally"})
        assert out["reason"] == "exited-normally" and "addr" not in out

    def test_breakpoint_table_nested(self):
        payload = {"BreakpointTable": {"body": {"bkpt": [
            {"number": "1", "addr": "0x1"},
            {"number": "2", "addr": "0x2"},
        ]}}}
        bps = parse_breakpoint_table(payload)
        assert len(bps) == 2 and bps[1]["number"] == "2"

    def test_breakpoint_table_list(self):
        payload = {"BreakpointTable": {"body": [{"bkpt": {"number": "1"}}]}}
        assert len(parse_breakpoint_table(payload)) == 1

    def test_register_zip(self):
        names = ["rax", "rbx", "rcx"]
        values = {"register-values": [
            {"number": "0", "value": "0x11"},
            {"number": "2", "value": "0x33"},
        ]}
        zipped = format_register_values(names, values)
        assert zipped == {"rax": "0x11", "rcx": "0x33"}
