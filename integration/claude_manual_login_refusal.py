"""Check the public manual-login entry without running the fixed CLI."""

import errno
import os
from pathlib import Path
import pty
import subprocess
import sys
import tempfile


def exercise(binary, root):
    etc = root / "etc"
    config = etc / "tempest"
    ledger = config / "claude-login-diagnostic-ledger"
    ledger.mkdir(parents=True, mode=0o700)
    policy = config / "claude-manual-login.json"
    with open(policy, "xb", opener=lambda path, flags: os.open(path, flags, 0o600)) as out:
        out.write(b'{"version":1,"authority":"platform.claude.com:443"}')
    baseline = [(entry, entry.stat().st_ctime_ns) for entry in config.rglob("*")]
    trace = root / "trace"

    def check(label, endpoints, expected, args=(), env=None):
        master, slave = pty.openpty()
        other_master, other_slave = pty.openpty()
        with open(os.devnull, "rb+") as null:
            fds = (slave, other_slave, null.fileno(), master)
            try:
                result = subprocess.run(
                    ["/usr/bin/strace", "-f", "-qq", "-o", trace, "-e",
                     "trace=%process,%network,%file", binary, *args],
                    stdin=fds[endpoints[0]], stdout=fds[endpoints[1]], stderr=fds[endpoints[2]],
                    env={} if env is None else env, timeout=5,
                )
                os.set_blocking(master, False)
                os.set_blocking(other_master, False)
                output = b""
                for descriptor in (master, other_master):
                    try:
                        output += os.read(descriptor, 4096)
                    except OSError as error:
                        if error.errno not in (errno.EAGAIN, errno.EIO):
                            raise
            finally:
                for descriptor in (master, slave, other_master, other_slave):
                    os.close(descriptor)
        if result.returncode != 1 or expected not in output:
            raise RuntimeError(f"{label}: exit={result.returncode}, output={output!r}")
        allowed = {"execve", "openat", "access", "newfstatat", "statx", "readlink", "exit_group"}
        lines = [line.split(maxsplit=1)[1] for line in trace.read_text().splitlines()]
        unexpected = [
            line for line in lines
            if line.split("(", 1)[0] not in allowed
            or any(token in line for token in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"))
        ]
        if sum(line.startswith("execve(") for line in lines) != 1 or unexpected:
            raise RuntimeError(f"{label}: unexpected traced operations: {unexpected!r}")
        if sorted(baseline) != sorted(
            (entry, entry.stat().st_ctime_ns) for entry in config.rglob("*")
        ) or any(ledger.iterdir()):
            raise RuntimeError(f"{label}: policy or ledger changed")
        print(f"{label}: exit 1, no child, network, or ledger mutation")

    same = (0, 0, 0)
    terminal = b"dedicated administrator PTY required"
    check("extra argument", same, b"arguments are unsupported", ("auth", "login"))
    check("redirected stdin", (2, 0, 0), terminal)
    check("split stdout", (0, 1, 0), terminal)
    check("split stderr", (0, 0, 1), terminal)
    check("PTY master", (3, 3, 3), terminal)
    check("same PTY", same, b"administrator policy acceptance disabled")
    check(
        "environment overrides", same, b"administrator policy acceptance disabled",
        env={
            "HOME": "/missing-test-home", "CLAUDE_CONFIG_DIR": "/missing-test-config",
            "HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": "*",
            "PATH": "/missing-test-path",
        },
    )


def main():
    if len(sys.argv) == 2 and os.geteuid() == 0:
        binary = str(Path(sys.argv[1]).resolve(strict=True))
        return subprocess.call([
            "/usr/bin/unshare", "-mn", "--propagation", "private",
            sys.executable, str(Path(__file__).resolve()), "--isolated",
            os.readlink("/proc/self/ns/mnt"), os.readlink("/proc/self/ns/net"), binary,
        ])
    if len(sys.argv) != 5 or sys.argv[1] != "--isolated" or os.geteuid() != 0:
        return 2
    if any(os.readlink(f"/proc/self/ns/{kind}") == original
           for kind, original in zip(("mnt", "net"), sys.argv[2:4])):
        raise RuntimeError("test requires new mount and network namespaces")
    if any(subprocess.check_output(["ip", family, "route", "show"]).strip()
           for family in ("-4", "-6")):
        raise RuntimeError("external route in the test namespace")
    with tempfile.TemporaryDirectory(prefix="tempest-cli-refusal-") as directory:
        root = Path(directory)
        (root / "etc").mkdir()
        subprocess.run(["mount", "--bind", root / "etc", "/etc"], check=True)
        try:
            exercise(sys.argv[4], root)
        finally:
            subprocess.run(["umount", "/etc"], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
