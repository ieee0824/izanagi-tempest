"""Exercise fixed loopback egress rules in a disposable Linux network namespace."""

import errno
import hashlib
import json
import os
import secrets
import select
import socket
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path


PORTS = (39181, 39182)
TABLE = "tempest_synthetic"
POLICY = """
table inet tempest_synthetic {
    chain output {
        type filter hook output priority filter; policy accept;
        meta skuid 61001 ip daddr 127.0.0.1 tcp dport 39181 counter accept
        meta skuid 61001 counter reject with icmpx type admin-prohibited
        meta skuid 61002 counter reject with icmpx type admin-prohibited
    }
}
"""
MODES = (
    "--traffic-worker",
    "--cleanup-worker",
    "--missing-namespace",
    "--wrong-namespace",
    "--missing-policy",
    "--wrong-policy",
)
PREFLIGHT_ERRORS = {
    "--missing-namespace": "namespace missing",
    "--wrong-namespace": "namespace mismatch",
    "--missing-policy": "policy missing",
    "--wrong-policy": "policy mismatch",
}
CLIENT = """
import socket
import sys

role, port = sys.argv[1:]
if role == "child":
    if input() != "ping":
        raise RuntimeError("unexpected stdio request")
    print("pong")
with socket.socket() as connection:
    connection.settimeout(2)
    try:
        connection.connect(("127.0.0.1", int(port)))
    except OSError as error:
        print(error.errno)
    else:
        print(0)
"""


class PreflightDenied(Exception):
    pass


class InjectedFailure(Exception):
    pass


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, timeout=10, **kwargs)


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def accept_count(listener):
    count = 0
    while True:
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            return count
        connection.close()
        count += 1


def check_traffic(listeners):
    for uid, role, port, permitted in (
        (61001, "parent", PORTS[0], True),
        (61001, "parent", PORTS[1], False),
        (61002, "child", PORTS[0], False),
        (61002, "child", PORTS[1], False),
    ):
        lines = run(
            sys.executable, "-I", "-c", CLIENT, role, str(port),
            user=uid, group=uid, extra_groups=[], env={}, input="ping\n",
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        counts = tuple(map(accept_count, listeners))
        expected_counts = (1, 0) if permitted else (0, 0)
        expected_errno = 0 if permitted else errno.EHOSTUNREACH
        expected_stdio = ["pong"] if role == "child" else []
        print(f"{role} {port}: output={lines}, accepts={counts}")
        require(lines == [*expected_stdio, str(expected_errno)], "unexpected client result")
        require(counts == expected_counts, "unexpected listener accept counts")

    rules = json.loads(run(
        "nft", "-j", "list", "table", "inet", TABLE, capture_output=True,
    ).stdout)["nftables"]
    denied_packets = [
        next(expr["counter"]["packets"] for expr in entry["rule"]["expr"] if "counter" in expr)
        for entry in rules
        if "rule" in entry and any("reject" in expr for expr in entry["rule"]["expr"])
    ]
    require(denied_packets == [1, 2], f"unexpected reject counters: {denied_packets}")
    print(f"reject counters: parent={denied_packets[0]}, child={denied_packets[1]}")


def namespace_id():
    return os.stat("/proc/self/ns/net").st_ino


def check_preflight(expected_namespace, expected_policy=POLICY):
    if expected_namespace is None:
        raise PreflightDenied("namespace missing")
    expected = os.fstat(expected_namespace.fileno())
    current = os.stat("/proc/self/ns/net")
    if (expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino):
        raise PreflightDenied("namespace mismatch")
    interfaces = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
    if [link["ifname"] for link in interfaces] != ["lo"]:
        raise PreflightDenied("expected only loopback")

    policy = run("nft", "-s", "list", "ruleset", capture_output=True).stdout.split()
    if not policy:
        raise PreflightDenied("policy missing")
    if policy != expected_policy.replace("icmpx type ", "icmpx ").split():
        raise PreflightDenied("policy mismatch")


@contextmanager
def preflight_namespace(mode):
    if mode == "--missing-namespace":
        yield None
        return
    if mode == "--wrong-namespace":
        with subprocess.Popen(
            ("unshare", "--net", sys.executable, "-I", "-c",
             "print('ready', flush=True); input()"),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        ) as other:
            try:
                require(other.stdout.readline() == "ready\n", "missing second test namespace")
                with open(f"/proc/{other.pid}/ns/net", "rb") as namespace:
                    other_namespace = os.fstat(namespace.fileno()).st_ino
                    yield namespace
            finally:
                other.communicate(input="done\n", timeout=2)
            require(other.returncode == 0, "second namespace worker failed")
        check_namespace_released(str(other_namespace))
        return
    with open("/proc/self/ns/net", "rb") as namespace:
        yield namespace


def check_launch(mode, listeners):
    launches = 0
    expected_error = PREFLIGHT_ERRORS.get(mode)
    with preflight_namespace(mode) as pinned_namespace:
        try:
            check_preflight(pinned_namespace)
        except PreflightDenied as error:
            require(str(error) == expected_error, f"unexpected preflight denial: {error}")
        else:
            result = run(
                sys.executable, "-I", "-c", 'print("started")',
                user=61002, group=61002, extra_groups=[], env={}, capture_output=True,
            )
            require(result.stdout == "started\n", "missing synthetic launch marker")
            launches += 1

    require(launches == int(expected_error is None), "unexpected launch count")
    require(tuple(map(accept_count, listeners)) == (0, 0), "unexpected preflight traffic")
    print(f"{mode}: launches={launches}, denial={expected_error}")
    if launches:
        check_traffic(listeners)


def worker(mode, parent_namespace):
    current_namespace = namespace_id()
    parent_path = f"/proc/{os.getppid()}/ns/net"
    actual_parent = os.stat(parent_path).st_ino
    require(actual_parent == parent_namespace, "unexpected launcher network namespace")
    require(current_namespace != actual_parent, "worker is in the caller network namespace")
    interfaces = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
    require([link["ifname"] for link in interfaces] == ["lo"], "expected only loopback")
    print(f"netns={current_namespace}", flush=True)
    if mode == "--traffic-worker":
        require(input() == "record", "missing parent recording acknowledgement")
    run("ip", "link", "set", "lo", "up")

    with socket.socket() as allowed, socket.socket() as denied:
        listeners = (allowed, denied)
        for listener, port in zip(listeners, PORTS, strict=True):
            listener.bind(("127.0.0.1", port))
            listener.listen()
            listener.setblocking(False)
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                require(accept_count(listener) == 1, f"control did not reach port {port}")

        policy_installed = mode != "--missing-policy"
        if policy_installed:
            policy = POLICY.replace("dport 39181", "dport 39182") if mode == "--wrong-policy" else POLICY
            run("nft", "-f", "-", input=policy)
        try:
            try:
                if mode == "--cleanup-worker":
                    raise InjectedFailure("intentional failure after applying policy")
                check_launch(mode, listeners)
            finally:
                if policy_installed:
                    run("nft", "delete", "table", "inet", TABLE)
        except InjectedFailure:
            require(mode == "--cleanup-worker", "unexpected injected failure")
        tables = run("nft", "list", "tables", capture_output=True).stdout
        require(not tables.strip(), "test policy remains")
    require(all(listener.fileno() == -1 for listener in listeners), "listener socket remains open")
    print("policy removed and listeners closed")


def check_namespace_released(namespace):
    namespaces = run("lsns", "-n", "-t", "net", "-o", "NS", capture_output=True).stdout
    require(namespace not in namespaces.split(), f"namespace {namespace} remains")
    print(f"netns={namespace} released")


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    target: tuple[int, int]
    sha256: bytes


def verify_evidence(expected, observed, payload):
    if expected is None or observed is None or not payload:
        raise PreflightDenied("evidence missing")
    if observed.run_id != expected.run_id:
        raise PreflightDenied("run mismatch")
    if observed.target != expected.target:
        raise PreflightDenied("target mismatch")
    if hashlib.sha256(payload).digest() != expected.sha256 or observed.sha256 != expected.sha256:
        raise PreflightDenied("digest mismatch")


def worker_command(mode):
    return ("unshare", "--net", sys.executable, str(Path(__file__).resolve()),
            mode, str(namespace_id()))


def record_traffic(stack):
    run_id = secrets.token_hex(16)
    with subprocess.Popen(
        worker_command("--traffic-worker"), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    ) as worker_process:
        try:
            readable, _, _ = select.select([worker_process.stdout], [], [], 10)
            require(readable, "missing traffic worker readiness")
            header = worker_process.stdout.readline()
            namespace = stack.enter_context(open(f"/proc/{worker_process.pid}/ns/net", "rb"))
            identity = os.fstat(namespace.fileno())
            require(header == f"netns={identity.st_ino}\n".encode(), "unexpected worker namespace")
            payload, _ = worker_process.communicate(input=b"record\n", timeout=10)
        except BaseException:
            worker_process.kill()
            worker_process.wait()
            raise
        require(worker_process.returncode == 0 and payload, "traffic observation failed")

    print(header.decode() + payload.decode(), end="")
    return RunRecord(
        run_id, (identity.st_dev, identity.st_ino), hashlib.sha256(payload).digest(),
    ), payload


def check_run_evidence():
    # Keep both namespaces pinned so the kernel cannot reuse the first identity.
    with ExitStack() as stack:
        first, payload = record_traffic(stack)
        second, other_payload = record_traffic(stack)
        require(first.run_id != second.run_id and first.target != second.target,
                "expected two independent fixture runs")
        verify_evidence(first, first, payload)
        verify_evidence(second, second, other_payload)
        for expected, observed, contents, reason in (
            (first, second, other_payload, "run mismatch"),
            (first, replace(first, target=second.target), payload, "target mismatch"),
            (first, first, payload + b"extra", "digest mismatch"),
            (first, replace(first, sha256=bytes(32)), payload, "digest mismatch"),
            (first, None, payload, "evidence missing"),
            (None, first, payload, "evidence missing"),
            (first, first, None, "evidence missing"),
        ):
            try:
                verify_evidence(expected, observed, contents)
            except PreflightDenied as error:
                require(str(error) == reason, f"unexpected evidence rejection: {error}")
            else:
                raise RuntimeError(f"accepted negative control: {reason}")
    for record in (first, second):
        check_namespace_released(str(record.target[1]))
    print("run evidence: two accepted, seven rejected")


def main():
    require(os.geteuid() == 0, "run as root on the dedicated Linux host")
    if len(sys.argv) == 3 and sys.argv[1] in MODES:
        worker(sys.argv[1], int(sys.argv[2]))
        return
    require(len(sys.argv) == 1, "this test takes no arguments")
    check_run_evidence()
    for mode in MODES[1:]:
        result = run(*worker_command(mode), stdout=subprocess.PIPE)
        print(result.stdout, end="")
        first_line = result.stdout.splitlines()[0]
        used_namespace = first_line.removeprefix("netns=")
        require(used_namespace.isdecimal(), "missing worker namespace ID")
        check_namespace_released(used_namespace)


if __name__ == "__main__":
    main()
