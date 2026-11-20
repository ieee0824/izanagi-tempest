"""Verify login-only egress with fixed synthetic listeners and a local PTY."""

from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import sys
import tempfile

from claude_offline_pty_smoke import read_until
from linux_synthetic_egress_smoke import (
    PreflightDenied, accept_count, check_namespace_released, check_preflight,
    namespace_id, require, run,
)

ROLES = ("auth", "model-api", "mcp", "unlisted")
PORTS = (39271, 39272, 39273, 39274)
UID = 61001
TABLE = "tempest_login_fixture"
POLICY = f"""
table inet {TABLE} {{
    chain output {{
        type filter hook output priority filter; policy accept;
        meta skuid {UID} ip daddr 127.0.0.1 tcp dport {PORTS[0]} counter accept
        meta skuid {UID} counter reject with icmpx type admin-prohibited
    }}
}}
"""
CASES = {
    "match": None,
    "missing-policy": "policy missing",
    "wrong-policy": "policy mismatch",
}
CLIENT = """
import signal
import socket
import sys
for port in sys.argv[1:]:
    with socket.socket() as sock:
        sock.settimeout(2)
        try:
            sock.connect(("127.0.0.1", int(port)))
        except OSError as error:
            print(error.errno, flush=True)
        else:
            print(0, flush=True)
print("fixture-ready", flush=True)
signal.pause()
"""


def assert_offline():
    links = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
    require([link["ifname"] for link in links] == ["lo"], "expected only loopback")
    for family in ("-4", "-6"):
        require(not json.loads(run("ip", family, "-j", "route", "show", capture_output=True).stdout),
                "unexpected external route")


def exercise_client(work):
    master, slave = pty.openpty()
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", CLIENT, *map(str, PORTS)],
            stdin=slave, stdout=slave, stderr=subprocess.DEVNULL, cwd=work,
            user=UID, group=UID, extra_groups=[], env={},
        )
        try:
            expected = [0, *([errno.EHOSTUNREACH] * 3)]
            marker = ("".join(f"{value}\r\n" for value in expected) + "fixture-ready").encode()
            read_until(master, marker)
            monitor = select.poll()
            monitor.register(slave, select.POLLHUP)
            require(not monitor.poll(0) and process.poll() is None,
                    "client was not waiting on a connected PTY")
            os.close(master)
            master = -1
            events = monitor.poll(2000)
            require(any(mask & select.POLLHUP for _, mask in events),
                    "supervisor did not observe terminal disconnect")
            process.kill()
            require(process.wait(timeout=5) == -signal.SIGKILL, "synthetic client was not reaped")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    finally:
        for fd in (master, slave):
            if fd >= 0:
                os.close(fd)


def worker(case, caller_namespace):
    current = namespace_id()
    parent = os.stat(f"/proc/{os.getppid()}/ns/net").st_ino
    require(current != parent == caller_namespace, "expected isolated namespace")
    print(f"netns={current}", flush=True)
    assert_offline()
    run("ip", "link", "set", "lo", "up")
    assert_offline()

    with tempfile.TemporaryDirectory(prefix="tempest-login-egress-") as directory:
        work = Path(directory)
        work.chmod(0o755)
        with ExitStack() as stack:
            listeners = []
            for port in PORTS:
                listener = stack.enter_context(socket.socket())
                listener.bind(("127.0.0.1", port))
                listener.listen()
                listener.setblocking(False)
                listeners.append(listener)
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    require(accept_count(listener) == 1, f"control failed for port {port}")

            if case != "missing-policy":
                policy = POLICY
                if case == "wrong-policy":
                    policy = policy.replace(f"dport {PORTS[0]}", f"dport {PORTS[1]}")
                run("nft", "-f", "-", input=policy)
                stack.callback(run, "nft", "delete", "table", "inet", TABLE)

            launches = 0
            with open("/proc/self/ns/net", "rb") as namespace:
                try:
                    check_preflight(namespace, POLICY)
                except PreflightDenied as error:
                    require(str(error) == CASES[case], f"unexpected preflight denial: {error}")
                else:
                    require(CASES[case] is None, "negative case passed preflight")
                    launches += 1
                    exercise_client(work)

            expected_accepts = (1, 0, 0, 0) if case == "match" else (0, 0, 0, 0)
            accepts = tuple(map(accept_count, listeners))
            require(accepts == expected_accepts, f"unexpected accepts: {accepts}")
            require(launches == int(case == "match"), "unexpected launch count")
            if case == "match":
                rules = json.loads(run("nft", "-j", "list", "table", "inet", TABLE,
                                       capture_output=True).stdout)["nftables"]
                counts = [expression["counter"]["packets"] for entry in rules if "rule" in entry
                          for expression in entry["rule"]["expr"] if "counter" in expression]
                require(len(counts) == 2 and counts[0] >= 1 and counts[1] == 3,
                        f"unexpected nftables counters: {counts}")
                print(f"nftables packets: accepted={counts[0]} rejected={counts[1]}")
            print(f"{case}: launches={launches} accepts={dict(zip(ROLES, accepts))}")
        require(all(listener.fileno() == -1 for listener in listeners), "listeners remain")
        require(not run("nft", "list", "tables", capture_output=True).stdout.strip(),
                "policy remains")
    require(not work.exists(), "work directory remains")
    print("cleanup: client, policy, listeners and work verified")


def main():
    if os.geteuid() != 0:
        return 2
    if len(sys.argv) == 4 and sys.argv[1] == "--worker" and sys.argv[2] in CASES:
        worker(sys.argv[2], int(sys.argv[3]))
    elif len(sys.argv) == 1:
        for case in CASES:
            result = run("unshare", "--net", sys.executable, __file__, "--worker",
                         case, str(namespace_id()), stdout=subprocess.PIPE)
            print(result.stdout, end="")
            check_namespace_released(result.stdout.splitlines()[0].removeprefix("netns="))
    else:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
