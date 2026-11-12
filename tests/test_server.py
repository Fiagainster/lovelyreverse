"""HTTP layer tests with a stub engine — no JVM involved."""

import base64
import json
import threading
import time
import urllib.request

import pytest

from lovelyreverse.server.app import AppState, serve


class StubEngine:
    """Mimics EngineManager's surface with canned data."""

    def __init__(self):
        self._functions = [
            {"addr": 0x401000 + i * 0x10, "name": f"fun_{i}", "size": 0x20, "signature": f"undefined fun_{i}()"}
            for i in range(5)
        ]
        self.opened_paths: list[str] = []
        self._comments: dict[int, str] = {}

    # lifecycle
    def open(self, path, progress=None):
        if progress:
            progress("importing")
        self.opened_paths.append(path)
        return {"name": "stub.exe", "function_count": len(self._functions)}

    def program_info(self):
        if not self.opened_paths:
            return None
        return {"name": "stub.exe", "format": "PE", "language_id": "x86:LE:32:default",
                "compiler": "visualstudio", "image_base": "0x400000", "size": 0x1000,
                "function_count": 5, "source_path": self.opened_paths[-1]}

    # listings
    def list_functions(self, query="", offset=0, limit=300):
        items = [f for f in self._functions if query.lower() in f["name"].lower()]
        return {"total": len(items), "items": items[offset:offset + limit]}

    def list_strings(self, query="", offset=0, limit=300):
        items = [{"addr": 0x408000, "length": 5, "value": "hello"}]
        if query and query not in items[0]["value"]:
            items = []
        return {"total": len(items), "items": items}

    def imports(self):
        return [{"name": "MessageBoxA", "library": "user32.dll"}]

    def exports(self):
        return [{"addr": 0x401000, "name": "DllMain"}]

    # per-function
    def decompile(self, addr):
        return {"addr": addr, "name": "main", "code": "int main() { return 0; }"}

    def decompile_many(self, addrs, progress=None):
        return [(a, f"fun_{i}", f"// {a:x}") for i, a in enumerate(addrs)]

    def disasm(self, addr, limit=500):
        return {"addr": addr, "function": "main", "function_addr": addr,
                "instructions": [{"addr": addr, "bytes": "55", "text": "PUSH EBP"}]}

    def xrefs(self, addr):
        return {"to": [{"addr": 0x401100, "type": "CALL", "function": "caller"}],
                "from": [{"addr": addr, "to": 0x402000, "type": "CALL"}]}

    def callgraph(self, addr, depth=2, max_nodes=250):
        return {"center": addr,
                "nodes": [{"addr": addr, "name": "main"}, {"addr": 0x402000, "name": "callee"}],
                "edges": [[addr, 0x402000]]}

    # memory
    def memory_blocks(self):
        return [{"name": ".text", "start": 0x401000, "size": 0x1000, "initialized": True,
                 "read": True, "write": False, "execute": True, "entropy": 6.1}]

    def read_memory(self, block, offset, length):
        assert block == ".text"
        return bytes(range(offset, offset + length))

    def search_hex(self, pattern, limit=500):
        return [{"addr": 0x401234, "block": ".text", "function": "fun_1"}]

    def disasm_raw(self, addr, max_bytes=2048):
        return {"base": addr, "mode_bits": 32,
                "items": [{"addr": addr, "size": 1, "bytes": "55", "text": "push ebp"}],
                "stop": "ret", "recovered": 0, "block": ".text"}

    def constants_scan(self):
        return [{"name": "AES S-box", "category": "block-cipher", "note": "", "length": 16,
                 "addr": 0x409000, "block": ".rdata", "function": None}]

    # annotations
    def rename_function(self, addr, name):
        for f in self._functions:
            if f["addr"] == addr:
                old = f["name"]
                f["name"] = name
                return {"addr": addr, "old": old, "name": name}
        return {"addr": addr, "old": None, "name": name}

    def set_function_comment(self, addr, text):
        self._comments[addr] = text
        return {"addr": addr, "comment": text}

    def function_comment(self, addr):
        return self._comments.get(addr)


@pytest.fixture()
def server(tmp_path_factory, monkeypatch):
    # isolate app-data writes (recent.json etc.) from the real user dir
    monkeypatch.setenv("LVR_DATA_DIR", str(tmp_path_factory.mktemp("lvrdata")))
    httpd = serve(AppState(StubEngine()), "127.0.0.1", 0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def get(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return r.status, json.loads(r.read().decode())


def post(base: str, path: str, obj: dict):
    req = urllib.request.Request(
        base + path, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read().decode())


def get_raw(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return r.status, r.read()


class TestBasics:
    def test_index_served(self, server):
        status, body = get_raw(server, "/")
        assert status == 200 and b"lovelyreverse" in body

    def test_status(self, server):
        status, data = get(server, "/api/status")
        assert status == 200
        assert data["version"] and "engine_ready" in data

    def test_unknown_route_404(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            get(server, "/api/nope")
        assert e.value.code == 404

    def test_static_traversal_blocked(self, server):
        with pytest.raises(urllib.error.HTTPError):
            get_raw(server, "/static/../engine/manager.py")


class TestStubbedApi:
    def test_functions(self, server):
        _, data = get(server, "/api/functions?q=fun_3")
        assert data["total"] == 1 and data["items"][0]["name"] == "fun_3"

    def test_strings(self, server):
        _, data = get(server, "/api/strings?q=hello")
        assert data["items"][0]["value"] == "hello"

    def test_decompile(self, server):
        _, data = get(server, "/api/function/4198400/decompile")
        assert data["code"].startswith("int main")

    def test_disasm(self, server):
        _, data = get(server, "/api/function/4198400/disasm")
        assert data["instructions"][0]["text"] == "PUSH EBP"

    def test_xrefs(self, server):
        _, data = get(server, "/api/function/4198400/xrefs")
        assert data["to"][0]["function"] == "caller"

    def test_callgraph(self, server):
        _, data = get(server, "/api/function/4198400/callgraph?depth=2")
        assert data["center"] == 4198400
        assert len(data["nodes"]) == 2
        assert data["edges"][0] == [4198400, 0x402000]

    def test_memory_read(self, server):
        _, data = get(server, "/api/memory/read?block=.text&offset=3&len=4")
        assert base64.b64decode(data["data_b64"]) == bytes([3, 4, 5, 6])

    def test_constants(self, server):
        _, data = get(server, "/api/constants")
        assert data["items"][0]["name"] == "AES S-box"

    def test_no_program_409(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            get(server, "/api/program")
        assert e.value.code == 409

    def test_disasm_raw(self, server):
        _, data = get(server, "/api/disasm-raw?addr=0x401000")
        assert data["base"] == 0x401000
        assert data["items"][0]["text"] == "push ebp"
        _, data = get(server, "/api/disasm-raw?addr=4198404")  # decimal form works too
        assert data["base"] == 4198404

    def test_disasm_raw_bad_addr(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            get(server, "/api/disasm-raw?addr=zzz")
        assert e.value.code == 400


class TestPureRoutes:
    def test_decode_route(self, server):
        payload = base64.b64encode(b"hi").decode()
        _, data = post(server, "/api/decode", {"input_b64": payload, "recipe": [{"op": "to_hex"}]})
        assert base64.b64decode(data["result_b64"]) == b"6869"
        assert data["log"]

    def test_decode_bad_recipe(self, server):
        payload = base64.b64encode(b"hi").decode()
        with pytest.raises(urllib.error.HTTPError) as e:
            post(server, "/api/decode", {"input_b64": payload, "recipe": [{"op": "bogus"}]})
        assert e.value.code == 400
        assert "unknown operation" in e.value.read().decode()

    def test_xor_brute_route(self, server):
        plain = b"the flag is flag{x} and more english text follows here!!"
        data = base64.b64encode(bytes(b ^ 0x20 for b in plain)).decode()
        _, out = post(server, "/api/xor/brute", {"input_b64": data})
        assert out["items"][0]["key"] == 0x20

    def test_xor_derive_route(self, server):
        plain = b"flag{known_prefix}"
        key = b"KEYS"
        data = bytes(b ^ key[i % 4] for i, b in enumerate(plain))
        _, out = post(server, "/api/xor/derive", {"input_b64": base64.b64encode(data).decode(),
                                                  "prefix": "flag{"})
        assert out["items"][0]["key_ascii"] == "KEYS"


class TestOpenFlow:
    def test_open_creates_triage(self, server, tmp_path):
        sample = tmp_path / "tiny.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 200)
        _, data = post(server, "/api/open", {"path": str(sample)})
        job_id = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{job_id}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "done", job
        assert job["result"]["name"] == "stub.exe"

        _, tri = get(server, "/api/triage")
        assert tri["sniff"]["format"] == "PE"

    def test_open_missing_file_errors(self, server):
        _, data = post(server, "/api/open", {"path": "Z:/no/such/file.bin"})
        job_id = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{job_id}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "error"
        assert "not found" in job["error"]

    def test_decompile_all_zip(self, server):
        sample = None
        # ensure a program is "loaded"
        _, data = post(server, "/api/open", {"path": __file__})
        job_id = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{job_id}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "done"

        _, data = post(server, "/api/export/decompile-all", {})
        jid = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{jid}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "done"
        status, zbytes = get_raw(server, f"/api/download/decompile-all.zip?job={jid}")
        assert status == 200 and zbytes[:2] == b"PK"


def _wait_job(server, jid):
    for _ in range(100):
        _, job = get(server, f"/api/job/{jid}")
        if job["status"] != "running":
            return job
        time.sleep(0.05)
    return job


class TestAnnotationsAndRecent:
    def _open(self, server, tmp_path, name="tiny.exe"):
        sample = tmp_path / name
        sample.write_bytes(b"MZ" + b"\x00" * 200)
        _, data = post(server, "/api/open", {"path": str(sample)})
        job = _wait_job(server, data["job"])
        assert job["status"] == "done", job
        return sample

    def test_rename_and_comment(self, server, tmp_path):
        self._open(server, tmp_path)
        addr = 0x401000
        _, out = post(server, f"/api/function/{addr}/rename", {"name": "check_flag"})
        assert out["name"] == "check_flag" and out["old"] == "fun_0"
        _, out = post(server, f"/api/function/{addr}/comment", {"text": "CRC check here"})
        assert out["comment"] == "CRC check here"
        _, out = get(server, f"/api/function/{addr}/comment")
        assert out["comment"] == "CRC check here"

    def test_rename_requires_program(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            post(server, "/api/function/4198400/rename", {"name": "x"})
        assert e.value.code == 409

    def test_rename_validates_name(self, server, tmp_path):
        self._open(server, tmp_path)
        with pytest.raises(urllib.error.HTTPError) as e:
            post(server, "/api/function/4198400/rename", {"name": "   "})
        assert e.value.code == 400

    def test_recent_lists_opened(self, server, tmp_path):
        sample = self._open(server, tmp_path, "recent_sample.bin")
        _, out = get(server, "/api/recent")
        assert out["items"][0]["path"] == str(sample)
        assert out["items"][0]["name"] == "recent_sample.bin"
        assert out["items"][0]["size"] == 202
