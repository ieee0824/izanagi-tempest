"""Exercise fixed loopback egress rules in a disposable Linux network namespace."""

import errno
import json
import os
import socket
import subprocess
import sys
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


def worker(mode, parent_namespace):
    current_namespace = namespace_id()
    actual_parent = os.stat(f"/proc/{os.getppid()}/ns/net").st_ino
    require(actual_parent == parent_namespace, "unexpected launcher network namespace")
    require(current_namespace != actual_parent, "worker is in the caller network namespace")
    interfaces = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
    require([link["ifname"] for link in interfaces] == ["lo"], "expected only loopback")
    print(f"netns={current_namespace}", flush=True)
    run("ip", "link", "set", "lo", "up")

    with socket.socket() as allowed, socket.socket() as denied:
        listeners = (allowed, denied)
        for listener, port in zip(listeners, PORTS, strict=True):
            listener.bind(("127.0.0.1", port))
            listener.listen()
            listener.setblocking(False)
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                require(accept_count(listener) == 1, f"control did not reach port {port}")

        run("nft", "-f", "-", input=POLICY)
        try:
            try:
                if mode == "--cleanup-worker":
                    raise InjectedFailure("intentional failure after applying policy")
                check_traffic(listeners)
            finally:
                run("nft", "delete", "table", "inet", TABLE)
        except InjectedFailure:
            require(mode == "--cleanup-worker", "unexpected injected failure")
        tables = run("nft", "list", "tables", capture_output=True).stdout
        require(not tables.strip(), "test policy remains")
    require(all(listener.fileno() == -1 for listener in listeners), "listener socket remains open")
    print("policy removed and listeners closed")


def main():
    require(os.geteuid() == 0, "run as root on the dedicated Linux host")
    if len(sys.argv) == 3 and sys.argv[1] in ("--traffic-worker", "--cleanup-worker"):
        worker(sys.argv[1], int(sys.argv[2]))
        return
    require(len(sys.argv) == 1, "this test takes no arguments")
    for mode in ("--traffic-worker", "--cleanup-worker"):
        result = run(
            "unshare", "--net", sys.executable, str(Path(__file__).resolve()),
            mode, str(namespace_id()), stdout=subprocess.PIPE,
        )
        print(result.stdout, end="")
        first_line = result.stdout.splitlines()[0]
        used_namespace = first_line.removeprefix("netns=")
        require(used_namespace.isdecimal(), "missing worker namespace ID")
        namespaces = run("lsns", "-n", "-t", "net", "-o", "NS", capture_output=True).stdout
        require(used_namespace not in namespaces.split(), f"namespace {used_namespace} remains")
        print(f"{mode}: namespace released")


if __name__ == "__main__":
    main()
