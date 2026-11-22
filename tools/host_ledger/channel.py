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
        # Retain a process handle so callers can detect exit before signing.
        descriptor = os.pidfd_open(pid)
    return descriptor
