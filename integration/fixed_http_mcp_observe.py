"""Compare authenticated guest executions with independent HTTP receive counts."""
from pathlib import Path
import secrets
import stat

FIXTURE = Path(__file__).resolve().parents[1] / "image/fixed_http_mcp_fixture.py"
GUEST_PATH = "/workspace/readonly-check/fixed-http-mcp.py"
METHODS = ["initialize", "tools/list"]


def stage(workspace, mapped_metadata):
    path = workspace / GUEST_PATH.removeprefix("/workspace/")
    with path.open("xb") as output:
        output.write(FIXTURE.read_bytes())
    mapped_metadata(path, stat.S_IFREG | 0o444)
    path.chmod(0o444)


def guest_argv(mode, nonce):
    return ("/usr/bin/python3", "-I", "-B", GUEST_PATH, mode, nonce)


def collect(invoke, boot_ids):
    """Invoke fixed commands through two independently bound Izanagi sessions."""
    if len(boot_ids) != 2 or boot_ids[0] == boot_ids[1]:
        raise ValueError("two distinct guest boots required")
    nonces = [secrets.token_hex(16) for _ in boot_ids]
    started = []
    record = {"runs": [{"nonce": nonce, "boot_id": boot}
                       for nonce, boot in zip(nonces, boot_ids, strict=True)]}

    def operation(index, mode):
        return invoke(index, mode, nonces[index])

    def snapshot(index, mode, exchanges):
        observed = operation(index, mode)
        expected = {**record["runs"][index], "accepted": 2 * exchanges,
                    "methods": METHODS * exchanges}
        if observed != expected:
            raise ValueError("unexpected HTTP receiver record")
        return observed["accepted"]

    def request(index):
        replies = operation(index, "request")
        if not isinstance(replies, list) or len(replies) != len(METHODS):
            raise ValueError("missing fixed HTTP replies")
        for position, message in enumerate(replies, 1):
            fixed = ({"serverInfo": {"name": "tempest-fixed", "version": "1"},
                      "protocolVersion": "2025-03-26", "capabilities": {"tools": {}}}
                     if position == 1 else {"tools": []})
            if message != {"jsonrpc": "2.0", "id": position,
                           "result": {**fixed, **record["runs"][index]}}:
                raise ValueError("HTTP response does not match run and boot")

    try:
        for index in range(2):
            started.append(index)
            snapshot(index, "start", 0)
        request(1)
        before = [snapshot(0, "snapshot", 0), snapshot(1, "snapshot", 1)]
        request(0)
        during = [snapshot(0, "snapshot", 1), snapshot(1, "snapshot", 1)]
        request(1)
        after = [snapshot(0, "snapshot", 1), snapshot(1, "snapshot", 2)]
        record["accept_deltas"] = [
            before, [current - baseline for current, baseline in zip(during, before, strict=True)],
            [current - baseline for current, baseline in zip(after, during, strict=True)],
        ]
    finally:
        recovery = []
        for index in started:
            try:
                stopped = operation(index, "stop")
                recovery.append(stopped == {"closed": True, "boot_id": boot_ids[index]})
            except (ValueError, RuntimeError, OSError):
                recovery.append(False)
        record["receivers_closed"] = recovery
    if record["receivers_closed"] != [True, True]:
        raise RuntimeError("fixed HTTP receiver recovery failed")
    return record


def require_control_directory(path):
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or stat.S_IMODE(details.st_mode) != 0o700:
        raise ValueError("control directory must be root-private")


def publish(path, value):
    import json

    temporary = path.with_suffix(".pending")
    with temporary.open("x") as output:
        json.dump(value, output)
    temporary.rename(path)


def serve_commands(control, execute, binding, process, guest):
    import json
    import re
    import time

    forward, fingerprint = binding()
    publish(control / "ready.json", {"guest": guest, "qemu": forward,
                                     "session_fingerprint": fingerprint.hex()})
    for position in range(30):
        command = control / f"command-{position}.json"
        deadline = time.monotonic() + 90
        while not command.exists():
            if (control / "release").exists():
                return
            if time.monotonic() >= deadline or process.poll() is not None:
                raise RuntimeError("HTTP fixture coordination interrupted")
            time.sleep(0.025)
        mode, nonce = json.loads(command.read_text())
        if mode not in ("start", "snapshot", "request", "stop") or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
            raise ValueError("unexpected HTTP fixture command")
        if binding() != (forward, fingerprint):
            raise RuntimeError("HTTP fixture session changed")
        result = execute(*guest_argv(mode, nonce), timeout=12)
        if result.returncode != 0 or len(result.stdout) > 4096:
            raise RuntimeError(f"fixed HTTP guest operation failed: {mode}")
        if binding() != (forward, fingerprint):
            raise RuntimeError("HTTP fixture session changed")
        publish(control / f"reply-{position}.json", json.loads(result.stdout))
    raise RuntimeError("HTTP fixture operation limit exhausted")
