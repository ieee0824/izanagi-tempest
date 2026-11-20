"""Fixed HTTP JSON-RPC fixture on guest loopback for the two-VM trial."""
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


METHODS = ("initialize", "tools/list")
PORT = 19236
BOOT = Path("/proc/sys/kernel/random/boot_id").read_text().strip()


class Receiver(HTTPServer):
    def __init__(self, record, nonce):
        super().__init__(("127.0.0.1", PORT), Handler)
        self.record = record
        self.state = {"nonce": nonce, "boot_id": BOOT, "accepted": 0, "methods": []}
        self.timeout = 0.25
        self.save()

    def save(self):
        pending = self.record.with_suffix(".pending")
        pending.write_text(json.dumps(self.state))
        pending.replace(self.record)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(2)
        self.state["accepted"] += 1
        self.save()
        return request, address


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if self.path != "/mcp" or not 0 < length <= 4096:
            self.send_error(400)
            return
        request = json.loads(self.rfile.read(length))
        method = request.get("method")
        if method not in METHODS or request != {
            "jsonrpc": "2.0", "id": METHODS.index(method) + 1,
            "method": method, "params": {"nonce": self.server.state["nonce"]},
        }:
            self.send_error(400)
            return
        result = ({"serverInfo": {"name": "tempest-fixed", "version": "1"},
                   "protocolVersion": "2025-03-26", "capabilities": {"tools": {}}}
                  if method == "initialize" else {"tools": []})
        result.update(nonce=self.server.state["nonce"], boot_id=BOOT)
        raw = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
        self.server.state["methods"].append(method)
        self.server.save()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def query(nonce):
    replies = []
    for index, method in enumerate(METHODS, 1):
        connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=3)
        try:
            request = {"jsonrpc": "2.0", "id": index, "method": method,
                       "params": {"nonce": nonce}}
            connection.request("POST", "/mcp", json.dumps(request),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError("fixed HTTP response rejected")
            replies.append(json.loads(response.read(4097)))
        finally:
            connection.close()
    return replies


def main(mode, nonce):
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("invalid fixture nonce")
    area = Path("/tmp") / f"tempest-http-mcp-{nonce}"
    record = area / "record.json"
    if mode == "start":
        area.mkdir(mode=0o700)
        child = subprocess.Popen(
            (sys.executable, "-I", "-B", __file__, "serve", nonce),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
        deadline = time.monotonic() + 5
        while not record.exists():
            if time.monotonic() >= deadline or child.poll() is not None:
                (area / "stop").touch()
                raise RuntimeError("fixed HTTP receiver did not start")
            time.sleep(.02)
    elif mode == "serve":
        with Receiver(record, nonce) as server:
            deadline = time.monotonic() + 120
            while not (area / "stop").exists() and time.monotonic() < deadline:
                server.handle_request()
        (area / "closed").touch()
        return
    elif mode == "request":
        print(json.dumps(query(nonce)))
        return
    elif mode == "stop":
        (area / "stop").touch()
        deadline = time.monotonic() + 5
        while not (area / "closed").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("fixed HTTP receiver did not close")
            time.sleep(.02)
        for name in ("record.json", "stop", "closed"):
            (area / name).unlink()
        area.rmdir()
        print(json.dumps({"closed": not area.exists(), "boot_id": BOOT}))
        return
    elif mode != "snapshot":
        raise ValueError("unsupported mode")
    print(record.read_text())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(2)
    os.umask(0o077)
    main(*sys.argv[1:])
