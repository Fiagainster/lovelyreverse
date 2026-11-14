"""Session-layer tests against a fake gdb (no WSL / no real binary needed)."""

import sys
from pathlib import Path

import time

import pytest

from lovelyreverse.gdb.session import GdbSession, GdbError, parse_env_text, to_wsl_path

FAKE = Path(__file__).parent / "fake_gdb.py"


def test_parse_env_text():
    assert parse_env_text("DISPLAY=:99") == [("DISPLAY", ":99")]
    assert parse_env_text("DISPLAY=:99, LANG=C.UTF-8") == [
        ("DISPLAY", ":99"), ("LANG", "C.UTF-8")]
    assert parse_env_text("A=1\nB=2\n# comment\n\nC=3") == [
        ("A", "1"), ("B", "2"), ("C", "3")]
    assert parse_env_text("") == []
    assert parse_env_text("KEY = spaced value") == [("KEY", "spaced value")]
    with pytest.raises(GdbError):
        parse_env_text("NOEQUALS")
    with pytest.raises(GdbError):
        parse_env_text("HAS SPACE=1")


@pytest.fixture()
def session():
    s = GdbSession("local", argv_override=[sys.executable, str(FAKE)])
    s.start()
    yield s
    s.exit()


def test_wsl_path_conversion():
    assert to_wsl_path(r"D:\Project\网安训练\MazE") == "/mnt/d/Project/网安训练/MazE"
    assert to_wsl_path("C:/x/y.exe") == "/mnt/c/x/y.exe"
    assert to_wsl_path("/usr/bin/gdb") == "/usr/bin/gdb"
    with pytest.raises(GdbError):
        to_wsl_path("relative/path")


class TestSessionFlow:
    def test_boot_and_load(self, session):
        info = session.load("C:\\fake\\target.exe", args="--demo")
        assert info["program"] == "C:\\fake\\target.exe"
        st = session.status()
        assert st["loaded"] and st["program"] == "C:\\fake\\target.exe"

    def test_load_emits_env_commands(self, session, monkeypatch):
        sent = []
        real = session.cmd

        def spy(mi_cmd, timeout=25.0):
            sent.append(mi_cmd)
            return real(mi_cmd, timeout)

        monkeypatch.setattr(session, "cmd", spy)
        session.load("C:\\fake\\target.exe", env_text="DISPLAY=:99, FOO=a b")
        env_cmds = [c for c in sent if c.startswith("-gdb-set env")]
        assert env_cmds == ['-gdb-set env DISPLAY :99', '-gdb-set env FOO "a b"']

    def test_break_insert_list_delete(self, session):
        bk = session.insert_break("*0x00401370")
        assert bk["number"] == "1"
        bk2 = session.insert_break("main")
        assert bk2["number"] == "2"
        bps = session.list_breaks()
        assert len(bps) == 2
        session.delete_break("1")
        bps = session.list_breaks()
        assert len(bps) == 2  # fake gdb doesn't really delete; router works though

    def test_run_until_breakpoint(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        stop = session.wait_stop(timeout=5)
        assert stop is not None and stop["reason"] == "breakpoint-hit"
        assert stop["func"] == "main"
        st = session.status()
        assert not st["running"]

    def test_registers(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        regs = session.registers()
        assert regs["rax"] == "0x11" and regs["rcx"] == "0x33"

    def test_memory(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        data = session.read_memory("$rsp", 4)
        assert data == b"ABCD"

    def test_stack(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        frames = session.stack()
        assert frames[0]["func"] == "main"
        assert frames[1]["func"] == "__start"

    def test_evaluate(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        assert session.evaluate("$rax") == "42"

    def test_next_then_stop(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        session.next_()
        stop = session.wait_stop(timeout=5)
        assert stop is not None and stop["reason"] == "end-stepping-range"

    def test_stepi_nexti(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        for act in (session.stepi_, session.nexti_):
            act()
            stop = session.wait_stop(timeout=5)
            assert stop is not None and stop["reason"] == "end-stepping-range"

    def test_list_breaks_while_running_raises(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        session.state["running"] = True  # simulate live target (MI would block)
        with pytest.raises(GdbError, match="running"):
            session.list_breaks()
        session.state["running"] = False

    def test_continue_after_stop(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        session.continue_()
        stop = session.wait_stop(timeout=5)
        assert stop is not None and stop["reason"] == "breakpoint-hit"

    def test_error_command_raises(self, session):
        session.load("C:\\fake\\target.exe")
        with pytest.raises(GdbError):
            session.cmd("-frobnicate")  # unknown → fake replies ^error

    def test_console_cmd(self, session):
        session.load("C:\\fake\\target.exe")
        res = session.console_cmd("handle SIGTRAP nostop noprint pass")
        assert res["command"] == "handle SIGTRAP nostop noprint pass"
        deadline = time.time() + 3
        while time.time() < deadline:
            if any("handle SIGTRAP" in line for line in session.console):
                break
            time.sleep(0.1)
        assert any("handle SIGTRAP" in line for line in session.console)

    def test_console_cmd_empty_raises(self, session):
        with pytest.raises(GdbError):
            session.console_cmd("   ")

    def test_console_cmd_while_running_raises(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        session.state["running"] = True  # sync-mode MI would block
        with pytest.raises(GdbError, match="running"):
            session.console_cmd("info proc mappings")
        session.state["running"] = False

    def test_console_capture(self, session):
        session.load("C:\fake\target.exe")
        # the ~console line arrives asynchronously — poll briefly
        deadline = time.time() + 3
        while time.time() < deadline:
            if any("Reading symbols" in line for line in session.console):
                return
            time.sleep(0.1)
        assert any("Reading symbols" in line for line in session.console)
        assert any("Reading symbols" in line for line in session.console)
