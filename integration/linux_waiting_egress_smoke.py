"""Inspect two waiting synthetic roles before releasing their fixed test traffic."""
from contextlib import ExitStack
from dataclasses import dataclass, replace
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import sys

from linux_synthetic_egress_smoke import (
    POLICY, PORTS, TABLE, PreflightDenied, accept_count, check_namespace_released,
    check_preflight, namespace_id, preflight_namespace, require, run,
)


ROLES = {"parent": 61001, "mcp": 61002}
CASES = {
    "match": None,
    "other_run": "run mismatch",
    "wrong_role": "role mismatch",
    "wrong_process": "process mismatch",
    "wrong_uid": "process UID mismatch",
    "wrong_namespace": "namespace mismatch",
    "missing_policy": "policy missing",
    "wrong_policy": "policy mismatch",
}

CLIENT = """
import errno
import socket
import sys

role, nonce = sys.argv[1:]
print("waiting", flush=True)
if input() != nonce:
    raise SystemExit(2)
def check_denial(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            raise RuntimeError("unexpected connection to denied port")
    except OSError as error:
        if error.errno != errno.EHOSTUNREACH:
            raise

if role == "mcp":
    for port in (39181, 39182):
        check_denial(port)
    print("pong")
else:
    with socket.create_connection(("127.0.0.1", 39181), timeout=2):
        print("connected")
    check_denial(39182)
    print("denied:EHOSTUNREACH")
"""


@dataclass(frozen=True)
class Participant:
    run_id: str
    role: str
    pid: int
    start_ticks: str


def file_identity(metadata):
    return metadata.st_dev, metadata.st_ino


def process_start(proc):
    return (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]


def close_process(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)
    process.stdin.close()
    process.stdout.close()


def start_participant(stack, run_id, role, uid):
    process = subprocess.Popen(
        (sys.executable, "-I", "-c", CLIENT, role, run_id),
        user=uid, group=uid, extra_groups=[], env={}, text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    stack.callback(close_process, process)
    pidfd = os.pidfd_open(process.pid)
    stack.callback(os.close, pidfd)
    ready, _, _ = select.select([process.stdout], [], [], 5)
    require(ready and process.stdout.readline() == "waiting\n", "missing fixture readiness")
    proc = Path("/proc") / str(process.pid)
    participant = Participant(run_id, role, process.pid, process_start(proc))
    return participant, process, pidfd


def check_participant(expected, claimed, process, pidfd, expected_network):
    if claimed.run_id != expected.run_id:
        raise PreflightDenied("run mismatch")
    if claimed.role != expected.role:
        raise PreflightDenied("role mismatch")
    proc = Path("/proc") / str(process.pid)
    if (claimed.pid != process.pid or claimed.start_ticks != expected.start_ticks
            or select.select([pidfd], [], [], 0)[0] or process_start(proc) != expected.start_ticks
            or file_identity((proc / "exe").stat()) != file_identity(os.stat(sys.executable))
            or file_identity((proc / "fd/0").stat()) != file_identity(os.fstat(process.stdin.fileno()))):
        raise PreflightDenied("process mismatch")
    status = (proc / "status").read_text().splitlines()
    uid_row = next(line for line in status if line.startswith("Uid:"))
    if [int(uid) for uid in uid_row.split()[1:]] != [ROLES[expected.role]] * 4:
        raise PreflightDenied("process UID mismatch")
    if file_identity((proc / "ns/net").stat()) != file_identity(os.fstat(expected_network.fileno())):
        raise PreflightDenied("namespace mismatch")


def check_release(case, participants, namespace):
    parent, child = participants
    expected, process, pidfd = child
    changed = {
        "other_run": replace(expected, run_id=secrets.token_hex(16)),
        "wrong_role": replace(expected, role="parent"),
        "wrong_process": replace(expected, pid=parent[0].pid, start_ticks=parent[0].start_ticks),
    }
    check_participant(parent[0], parent[0], parent[1], parent[2], namespace)
    check_participant(expected, changed.get(case, expected), process, pidfd, namespace)
    check_preflight(namespace)


def worker(case, caller_namespace):
    current = namespace_id()
    caller = os.stat(f"/proc/{os.getppid()}/ns/net").st_ino
    require(current != caller == caller_namespace, "expected private network namespace")
    interfaces = run("ip", "-o", "link", "show", capture_output=True).stdout.splitlines()
    require(len(interfaces) == 1 and interfaces[0].split(":")[1].strip() == "lo",
            "expected only loopback")
    print(f"netns={current}", flush=True)
    run("ip", "link", "set", "lo", "up")
    grants = 0
    installed = case != "missing_policy"
    with socket.socket() as allowed, socket.socket() as denied:
        listeners = (allowed, denied)
        for listener, port in zip(listeners, PORTS, strict=True):
            listener.bind(("127.0.0.1", port))
            listener.listen()
            listener.setblocking(False)
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                require(accept_count(listener) == 1, "listener control did not arrive")
        if installed:
            policy = POLICY.replace("dport 39181", "dport 39182") if case == "wrong_policy" else POLICY
            run("nft", "-f", "-", input=policy)
        try:
            with ExitStack() as stack:
                run_id = secrets.token_hex(16)
                participants = [
                    start_participant(stack, run_id, "parent", ROLES["parent"]),
                    start_participant(stack, run_id, "mcp",
                                      ROLES["parent"] if case == "wrong_uid" else ROLES["mcp"]),
                ]
                mode = "--wrong-namespace" if case == "wrong_namespace" else "--traffic-worker"
                with preflight_namespace(mode) as namespace:
                    try:
                        check_release(case, participants, namespace)
                    except PreflightDenied as error:
                        require(str(error) == CASES[case], f"unexpected denial: {error}")
                    else:
                        require(CASES[case] is None, "negative case received release permission")
                        for _, process, _ in participants:
                            process.stdin.write(run_id + "\n")
                            process.stdin.flush()
                            grants += 1
                        for participant, process, _ in participants:
                            output, _ = process.communicate(timeout=5)
                            expected = ("connected\ndenied:EHOSTUNREACH\n"
                                        if participant.role == "parent" else "pong\n")
                            require(process.returncode == 0 and output == expected,
                                    "fixed participant did not respond")
            require(all(process.returncode is not None for _, process, _ in participants),
                    "participant was not reaped")
            counts = tuple(map(accept_count, listeners))
            require(grants == (2 if case == "match" else 0), "unexpected grant count")
            require(counts == ((1, 0) if case == "match" else (0, 0)), "unexpected accept counts")
        finally:
            if installed:
                run("nft", "delete", "table", "inet", TABLE)
        require(not run("nft", "list", "tables", capture_output=True).stdout.strip(),
                "unexpected policy remains")
    require(all(listener.fileno() == -1 for listener in listeners), "listener was not closed")
    if case == "match":
        print("released parent: allowed connection succeeded; denied port returned EHOSTUNREACH")
    print(f"{case}: grants={grants} accepted={counts} denial={CASES[case]} recovered=true")


def main():
    require(os.geteuid() == 0, "run on the dedicated Linux host as root")
    if len(sys.argv) == 3 and sys.argv[1] in CASES:
        worker(sys.argv[1], int(sys.argv[2]))
        return
    require(len(sys.argv) == 1, "this test takes no arguments")
    for case in CASES:
        result = run("unshare", "--net", sys.executable, str(Path(__file__).resolve()),
                     case, str(namespace_id()), capture_output=True)
        print(result.stdout, end="")
        check_namespace_released(result.stdout.splitlines()[0].removeprefix("netns="))


if __name__ == "__main__":
    main()
