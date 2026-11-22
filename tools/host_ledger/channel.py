"""Bounded framing and request validation for the dedicated management channel."""

import json
import re
import socket
import time

from read_snapshot import IDENTIFIER

REQUEST_LIMIT = 1024
RESPONSE_LIMIT = 4096
REQUEST_SECONDS = 2.0
CHALLENGE = re.compile(r"[0-9a-f]{64}")
PERMIT = re.compile(r"[0-9a-f]{32}")
FIELDS = {"version", "operation", "target_id", "boot_id", "permit_id", "generation", "challenge"}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def read_frame(connection, limit, deadline):
    """Read one frame without extending the absolute request deadline."""
    result = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("management channel deadline expired")
        connection.settimeout(remaining)
        chunk = connection.recv(1)
        if not chunk:
            raise ConnectionError("management channel disconnected")
        if chunk == b"\n":
            return bytes(result)
        result.extend(chunk)
        if len(result) > limit:
            raise ValueError("management frame too large")


def write_frame(connection, payload, limit, deadline):
    if len(payload) > limit or b"\n" in payload:
        raise ValueError("invalid management frame")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("management channel deadline expired")
    connection.settimeout(remaining)
    connection.sendall(payload + b"\n")


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate management field")
        result[key] = value
    return result


def validate_request(payload, registration, peer_cid):
    """Bind requests to a host-selected VM registration and actual peer CID."""
    if len(payload) > REQUEST_LIMIT:
        raise ValueError("management request too large")
    request = json.loads(payload, object_pairs_hook=unique_fields)
    if not isinstance(request, dict) or set(request) != FIELDS:
        raise ValueError("invalid management request fields")
    if type(request["version"]) is not int or request["version"] != 1:
        raise ValueError("unsupported management request version")
    if request["operation"] not in ("query", "consume"):
        raise ValueError("invalid management operation")
    for field in ("target_id", "boot_id"):
        value = request[field]
        if not isinstance(value, str) or len(value) > 128 or not IDENTIFIER.fullmatch(value):
            raise ValueError("invalid management identity")
        if value != registration[field]:
            raise ValueError("management identity mismatch")
    if type(peer_cid) is not int or peer_cid != registration["cid"]:
        raise ValueError("management peer mismatch")
    if (not isinstance(request["permit_id"], str)
            or not PERMIT.fullmatch(request["permit_id"])
            or request["permit_id"] != registration["permit_id"]):
        raise ValueError("management permit mismatch")
    if (type(request["generation"]) is not int
            or not 0 < request["generation"] < 2**63
            or request["generation"] != registration["generation"]):
        raise ValueError("management generation mismatch")
    if not isinstance(request["challenge"], str) or not CHALLENGE.fullmatch(request["challenge"]):
        raise ValueError("invalid management challenge")
    return request


def require_live_instance(registration, deadline):
    """Check the registered process lifetime and its actual QMP peer."""
    import os
    import struct
    from pathlib import Path

    pid = registration["qemu_pid"]
    if type(pid) is not int or pid <= 0:
        raise ValueError("invalid QEMU process")
    import select
    descriptor = os.pidfd_open(pid)
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        start_ticks = int(stat[stat.rindex(")") + 2:].split()[19])
        if start_ticks != registration["qemu_start_ticks"]:
            raise ValueError("QEMU process lifetime mismatch")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as qmp:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("instance check deadline expired")
            qmp.settimeout(remaining)
            qmp.connect(registration["qmp_socket"])
            peer_pid, _, _ = struct.unpack("3i", qmp.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_pid != pid:
                raise ValueError("QMP peer process mismatch")
            greeting = json.loads(read_frame(qmp, RESPONSE_LIMIT, deadline))
            if "QMP" not in greeting:
                raise ValueError("invalid QMP greeting")
            for operation in ("qmp_capabilities", "query-status"):
                write_frame(qmp, canonical_json({"execute": operation}), REQUEST_LIMIT, deadline)
                while True:
                    reply = json.loads(read_frame(qmp, RESPONSE_LIMIT, deadline))
                    if "event" in reply:
                        continue
                    if "error" in reply or "return" not in reply:
                        raise ValueError("QMP check refused")
                    break
            if reply["return"].get("status") != "running":
                raise ValueError("QEMU is not running")
            device = registration["qemu_device_id"]
            if not isinstance(device, str) or not IDENTIFIER.fullmatch(device):
                raise ValueError("invalid registered channel device")
            command = {"execute": "qom-get", "arguments": {
                "path": "/machine/peripheral/" + device, "property": "guest-cid"}}
            write_frame(qmp, canonical_json(command), REQUEST_LIMIT, deadline)
            while True:
                reply = json.loads(read_frame(qmp, RESPONSE_LIMIT, deadline))
                if "event" not in reply:
                    break
            if type(reply.get("return")) is not int or reply["return"] != registration["cid"]:
                raise ValueError("QEMU channel CID assignment mismatch")
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        if poller.poll(0):
            raise ValueError("registered QEMU exited")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


RECEIPT_DOMAIN = b"izanagi-tempest:host-ledger-channel:v1\0"


def serve_query(connection, peer_cid, registration, management, signer, deadline):
    """Handle a query using the host's independently checked committed ledger."""
    import os
    import select
    from read_snapshot import read_management_snapshot

    request = validate_request(read_frame(connection, REQUEST_LIMIT, deadline),
                               registration, peer_cid)
    process = require_live_instance(registration, deadline)
    try:
        expected = {key: request[key] for key in ("target_id", "permit_id", "generation")}
        if request["operation"] == "consume":
            from write_transition import advance
            if time.monotonic() >= deadline:
                raise TimeoutError("consumption deadline expired")
            if registration["expires_unix_ms"] <= time.time_ns() // 1_000_000:
                raise ValueError("host registration expired")
            advance(management, "consume", expected_scope=expected, deadline=deadline)
        commit = read_management_snapshot(management)
        if commit["scope"] != expected:
            raise ValueError("host ledger scope mismatch")
        # A consumed record is necessary, while a separately approved expiry
        # prevents a stale management registration from authorizing new work.
        now = time.time_ns() // 1_000_000
        expires = min(now + 2000, registration["expires_unix_ms"])
        if expires <= now:
            raise ValueError("host registration expired")
        poller = select.poll()
        poller.register(process, select.POLLIN)
        if poller.poll(0):
            raise ValueError("registered QEMU exited")
        response = {"request": request, "commit": commit,
                    "issued_unix_ms": now, "expires_unix_ms": expires}
        if time.monotonic() >= deadline:
            raise TimeoutError("signing deadline expired")
        payload = canonical_json(response)
        signed = {"payload": response,
                  "signature": signer.sign(RECEIPT_DOMAIN + payload).hex()}
        write_frame(connection, canonical_json(signed), RESPONSE_LIMIT, deadline)
    finally:
        os.close(process)


def verify_response(payload, request, public_key, now_unix_ms):
    """Verify a response bound to this request before the guest accepts it."""
    if len(payload) > RESPONSE_LIMIT:
        raise ValueError("management response too large")
    response = json.loads(payload, object_pairs_hook=unique_fields)
    if not isinstance(response, dict) or set(response) != {"payload", "signature"}:
        raise ValueError("invalid management response")
    body = response["payload"]
    if not isinstance(body, dict) or set(body) != {
            "request", "commit", "issued_unix_ms", "expires_unix_ms"}:
        raise ValueError("invalid signed response fields")
    signature = response["signature"]
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{128}", signature):
        raise ValueError("invalid management signature encoding")
    public_key.verify(bytes.fromhex(signature), RECEIPT_DOMAIN + canonical_json(body))
    if body["request"] != request:
        raise ValueError("management response request mismatch")
    issued, expires = body["issued_unix_ms"], body["expires_unix_ms"]
    if (type(issued) is not int or type(expires) is not int
            or not issued <= now_unix_ms < expires or not 0 < expires - issued <= 2000):
        raise ValueError("management response expired or invalid")
    commit = body["commit"]
    if not isinstance(commit, dict) or set(commit) != {"ledger_id", "scope", "sequence", "state"}:
        raise ValueError("invalid management commit")
    expected = {key: request[key] for key in ("target_id", "permit_id", "generation")}
    if (commit["scope"] != expected or commit["state"] != "consumed"
            or type(commit["sequence"]) is not int or commit["sequence"] <= 0
            or not isinstance(commit["ledger_id"], str)
            or not IDENTIFIER.fullmatch(commit["ledger_id"])):
        raise ValueError("management commit mismatch")
    return body


def exchange(connection, request, public_key, deadline):
    """Exchange a single request without resetting the caller's deadline."""
    write_frame(connection, canonical_json(request), REQUEST_LIMIT, deadline)
    payload = read_frame(connection, RESPONSE_LIMIT, deadline)
    body = verify_response(payload, request, public_key, time.time_ns() // 1_000_000)
    if time.monotonic() >= deadline:
        raise TimeoutError("verified response arrived after deadline")
    return body


def query_host(scope, boot_id, public_key, operation, deadline):
    """Connect to the fixed host CID and port with a fresh request challenge."""
    import secrets

    request = dict(scope, version=1, boot_id=boot_id, operation=operation,
                   challenge=secrets.token_hex(32))
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("host connection deadline expired")
        connection.settimeout(remaining)
        connection.connect((socket.VMADDR_CID_HOST, 23100))
        return exchange(connection, request, public_key, deadline)
