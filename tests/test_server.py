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

    # memory
    def memory_blocks(self):
        return [{"name": ".text", "start": 0x401000, "size": 0x1000, "initialized": True,
                 "read": True, "write": False, "execute": True, "entropy": 6.1}]

    def read_memory(self, block, offset, length):
        assert block == ".text"
        return bytes(range(offset, offset + length))

    def search_hex(self, pattern, limit=500):
        return [{"addr": 0x401234, "block": ".text", "function": "fun_1"}]

    def constants_scan(self):
        return [{"name": "AES S-box", "category": "block-cipher", "note": "", "length": 16,
                 "addr": 0x409000, "block": ".rdata", "function": None}]


@pytest.fixture()
def server():
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
