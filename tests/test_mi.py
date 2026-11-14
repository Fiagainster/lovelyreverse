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


class TestUnescapeBytes:
    """Escapes must be decoded at BYTE level: gdb emits non-ASCII as octal or
    \\xHH byte escapes, and utf-8 sequences must reassemble (中文 paths)."""

    BS = chr(92)  # backslash, kept out of source escapes

    def _oct(self, text: str) -> str:
        return "".join(f"{self.BS}{b:03o}" for b in text.encode("utf-8"))

    def _hex(self, text: str) -> str:
        return "".join(f"{self.BS}x{b:02x}" for b in text.encode("utf-8"))

    def test_octal_utf8_path(self):
        payload = parse_mi_line(f'~"Reading symbols from /mnt/d/{self._oct("临时取证")}/x.bin..."')["payload"]
        assert "临时取证" in payload

    def test_hex_utf8_path(self):
        payload = parse_mi_line(f'~"path /mnt/d/{self._hex("临时")} end"')["payload"]
        assert "临时" in payload

    def test_octal_newline_not_eaten_by_nul_rule(self):
        # the old parser mapped "\0" to NUL and left the "12" dangling
        assert parse_mi_line(f'~"a{self.BS}012b"')["payload"] == "a\nb"

    def test_octal_letter(self):
        assert parse_mi_line(f'~"x{self.BS}101y"')["payload"] == "xAy"

    def test_nul_octal(self):
        assert parse_mi_line(f'~"a{self.BS}000b"')["payload"] == "a\x00b"

    def test_ascii_untouched(self):
        assert parse_mi_line('~"hello \\n world \\t \\\\"')["payload"] == "hello \n world \t \\"

    def test_payload_strings_use_encoding(self):
        line = '*stopped,frame={addr="0x1",file="' + self._oct("证") + '.c"}'
        r = parse_mi_line(line)
        assert "证" in r["payload"]["frame"]["file"]

    def test_mixed_raw_and_escapes_latin1_view(self):
        # REAL observed gdb output: 临 as raw utf-8 bytes, 时/取/证 as a MIX
        # of raw bytes and \NNN octal escapes — the caller hands us a
        # latin-1 (byte-transparent) view of the line and the parser must
        # reassemble every char.
        raw = (b'~"Reading symbols from /mnt/d/\xe4\xb8\xb4\xe6\\227\xb6'
               b'\xe5\\217\\226\xe8\xaf\\201/\xe6\xb5\\213\xe8\xaf\\225/ch18.bin"')
        payload = parse_mi_line(raw.decode("latin-1"), "utf-8")["payload"]
        assert "临时取证" in payload and "测试" in payload

    def test_noise_payload_decoded_with_transport_encoding(self):
        # program stdout (noise) is a latin-1 byte view too — utf-8 text
        # must survive, mbcs mojibake must not crash
        raw = "欢迎来到挑战".encode("utf-8").decode("latin-1")
        r = parse_mi_line(raw, "utf-8")
        assert r["kind"] == "noise" and "欢迎来到挑战" in r["payload"]
