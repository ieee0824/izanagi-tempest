"""Apply the fixed synthetic config and waiting-role checks before the VM trial."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import socket
import tempfile

import fixed_mcp_config_preflight as config
import linux_waiting_egress_smoke as roles
from linux_synthetic_egress_smoke import POLICY, PORTS, TABLE, PreflightDenied, accept_count, run


def check(run_id, case):
    expected = {"match": None, "config-mismatch": "digest mismatch",
                "policy-mismatch": "policy mismatch"}[case]
    evidence = {"trial_id": run_id, "released": 0, "admitted": False,
                "participants": [], "gate_accepted": [0, 0]}
    with tempfile.TemporaryDirectory(prefix="tempest-joined-config-") as temporary:
        root = Path(temporary)
        path = root / config.NAME
        config.write_config(path, config.FIXED_BYTES + (b"\n" if case == "config-mismatch" else b""))
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            verified = config.prepare_args(directory, config.EXPECTED_DIGEST)[-1]
        except config.Rejected as error:
            evidence["denial"] = str(error)
        else:
            # Handoff uses the in-memory bytes even after replacing the source path.
            replacement = root / "replacement"
            config.write_config(replacement, b'{"mcpServers":{}}')
            replacement.replace(path)
            try:
                check_policy(run_id, case, verified, evidence)
            except PreflightDenied as error:
                evidence["denial"] = str(error)
        finally:
            os.close(directory)
    if root.exists() or evidence.get("denial") != expected:
        raise RuntimeError("unexpected preflight outcome")
    evidence["recovered"] = True
    return evidence


def check_policy(run_id, case, verified, evidence):
    with socket.socket() as allowed, socket.socket() as denied:
        listeners = (allowed, denied)
        for listener, port in zip(listeners, PORTS, strict=True):
            listener.bind(("127.0.0.1", port))
            listener.listen()
            listener.setblocking(False)
        policy = POLICY.replace("dport 39181", "dport 39182") if case == "policy-mismatch" else POLICY
        run("nft", "-f", "-", input=policy)
        try:
            with ExitStack() as stack:
                participants = [
                    roles.start_participant(stack, run_id, role, uid,
                                            config=verified if role == "parent" else None)
                    for role, uid in roles.ROLES.items()
                ]
                evidence["participants"] = [
                    {"run_id": item.run_id, "role": item.role, "pid": item.pid,
                     "start_ticks": item.start_ticks}
                    for item, _, _ in participants
                ]
                with open("/proc/self/ns/net", "rb") as namespace:
                    try:
                        roles.check_release("match", participants, namespace)
                    except PreflightDenied:
                        evidence["gate_accepted"] = list(map(accept_count, listeners))
                        if evidence["gate_accepted"] != [0, 0]:
                            raise RuntimeError("blocked participants sent traffic")
                        raise
                    for _, process, _ in participants:
                        process.stdin.write(run_id + "\n")
                        process.stdin.flush()
                        evidence["released"] += 1
                    parent, child = [process for _, process, _ in participants]
                    parent_reply, _ = parent.communicate(timeout=5)
                    child_reply, _ = child.communicate(timeout=5)
                    expected = "config:" + verified.decode("ascii") + "\nconnected\ndenied:EHOSTUNREACH\n"
                    if parent.returncode or child.returncode or parent_reply != expected or child_reply != "pong\n":
                        raise RuntimeError("fixed participant response mismatch")
                connection, _ = allowed.accept()
                with connection:
                    connection.settimeout(2)
                    with connection.makefile("rb") as stream:
                        if stream.read(33) != run_id.encode("ascii"):
                            raise RuntimeError("fixed local request run mismatch")
                evidence["gate_accepted"] = [1 + accept_count(allowed), accept_count(denied)]
                if evidence["gate_accepted"] != [1, 0]:
                    raise RuntimeError("unexpected fixed local accepts")
                evidence["config_sha256"] = hashlib.sha256(verified).hexdigest()
                evidence["admitted"] = True
        finally:
            run("nft", "delete", "table", "inet", TABLE)
            if run("nft", "list", "tables", capture_output=True).stdout.strip():
                raise RuntimeError("unexpected policy remains")
