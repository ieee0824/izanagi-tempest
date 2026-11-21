"""Check the public manual-login entry without running the fixed CLI."""

import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import subprocess
import sys
import time
import tempfile


FIXED_CLI = "/var/lib/tempest-claude-offline/claude"
SIGNED = "--signed-publication"


def check_signed_publication(config, ledger, check, *, combined_check=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    publication = config / "claude-login-publication"
    authority = config / "claude-login-authority"
    generation = publication / "1"
    publication.mkdir(mode=0o700)
    authority.mkdir(mode=0o700)
    generation.mkdir(mode=0o700)

    def write(path, data):
        with open(path, "wb", opener=lambda name, flags: os.open(name, flags, 0o600)) as out:
            out.write(data)

    def encode(data):
        return json.dumps(data).encode()

    def digest(data):
        return hashlib.sha256(data).hexdigest()

    handoff_key, revocation_key = (Ed25519PrivateKey.generate() for _ in range(2))

    def public_key(key):
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    hostname = os.uname().nodename
    target = "synthetic-diagnostic-target"
    permit_id = f"{1:032x}"
    endpoint = "platform.claude.com:443"
    write(publication / "lock", b"")
    write(publication / "current", b"1")
    write(authority / "minimum", b"1")
    write(authority / "trust-key", public_key(handoff_key))
    write(authority / "revocation-key", public_key(revocation_key))
    write(authority / "revocation-minimum", b"1")

    def publish(case, permit_id=permit_id, target=target, revocation_seconds=25):
        now = int(time.time())
        handoff = b"izanagi-tempest:manual-login-handoff:fixture-v1\0" + encode({
            "permit_id": permit_id, "approval_pair_sha256": "a" * 64,
            "executable_sha256": "0dc4f4a9a165fc60746d7ae8489712e5fc352f1e7ad4eb22e7141bd0812eb0cf",
            "arguments": ["auth", "login"], "authority": endpoint,
            "target_id": "different-target" if case == "target" else target,
            "approved_ips_revision": 1, "expires_unix_seconds": now + 40,
        })
        inputs = {
            "claude-manual-login.json": encode({
                "version": 2, "authority": endpoint,
                "approved_ips": {"revision": 1, "addresses": ["192.0.2.1"]},
                "permit": {
                    "target_hostname": hostname, "authority": endpoint,
                    "approved_ips_revision": 1, "expires_unix_seconds": now + 45,
                },
            }),
            "claude-login-diagnostic-handoff": handoff,
            "claude-login-diagnostic-trust-key": public_key(handoff_key),
            "claude-login-diagnostic-signature": (
                revocation_key if case == "signature" else handoff_key
            ).sign(handoff),
            "claude-login-diagnostic-target-registration": encode({
                "target_hostname": hostname, "target_id": target,
            }),
        }
        for name, data in inputs.items():
            write(generation / name, data)
        manifest = encode({name: digest(data) for name, data in inputs.items()})
        write(generation / "manifest", manifest)
        write(authority / "approved-generation", encode({
            "revision": 2 if case == "generation" else 1, "manifest_sha256": digest(manifest),
        }))
        revocation = b"izanagi-tempest:manual-login-revocation:fixture-v1\0" + encode({
            "revision": 1, "revocation_revision": 1, "manifest_sha256": digest(manifest),
            "permit_id": permit_id, "target_id": target, "issued_unix_seconds": now,
            "expires_unix_seconds": now + revocation_seconds, "revoked": case == "revoked",
        })
        write(authority / "revocation-state", revocation)
        write(authority / "revocation-signature", revocation_key.sign(revocation))
        write(authority / "revocation-committed", encode({
            "revision": 2 if case == "revocation" else 1, "state_sha256": digest(revocation),
        }))

    if combined_check is not None:
        combined_check(lambda permit=permit_id, registered_target=target, revocation_seconds=25:
                       publish("normal", permit, registered_target, revocation_seconds))
        return

    stages = (
        b"manual login handoff diagnostic verified",
        b"manual login revocation diagnostic verified",
        b"manual login fixed CLI verified",
        b"manual login ledger diagnostic verified",
        b"manual login final diagnostic verified",
        b"manual login publication diagnostic verified",
        b"manual login verified inputs handed off",
    )
    cases = (
        ("normal", b"administrator policy acceptance disabled", len(stages)),
        ("generation", b"publication does not match approved generation", 0),
        ("signature", b"invalid handoff signature", 0),
        ("target", b"handoff scope mismatch", 0),
        ("revocation", b"revocation state does not match independent commit", 1),
        ("revoked", b"permit revoked", 1),
        ("ledger", b"already consumed or revoked", 3),
    )
    for case, expected, completed in cases:
        publish(case)
        if case == "ledger":
            write(ledger / permit_id, b"")
        check(f"signed publication {case}", (0, 0, 0), expected, stages=stages,
              completed=completed, unopened={
                  "generation": ("claude-login-diagnostic-handoff", "revocation-state", FIXED_CLI,
                                 ledger.name),
                  "signature": ("revocation-state", FIXED_CLI, ledger.name),
                  "target": ("revocation-state", FIXED_CLI, ledger.name),
                  "revocation": (FIXED_CLI, ledger.name),
                  "revoked": (FIXED_CLI, ledger.name),
              }.get(case, ()))


def check_full_publication_terminal(binary, config, trace):
    lock = config / "claude-login-publication/lock"
    master, slave = pty.openpty()
    filler = os.open(os.ttyname(slave), os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY)
    try:
        for _ in range(8):
            try:
                while True:
                    os.write(filler, b"x" * 4096)
            except BlockingIOError:
                time.sleep(0.025)
        try:
            os.write(filler, b"x" * 65)
        except BlockingIOError:
            pass
        else:
            raise RuntimeError("publication PTY queue is not full")
        result = subprocess.run(
            ["strace", "-f", "-qq", "-s", "120", "-o", trace, "-e", "trace=write,%process,%network", binary],
            stdin=slave, stdout=slave, stderr=slave, timeout=15,
        )
        if result.returncode != 1:
            raise RuntimeError("full PTY changed the public refusal result")
        subprocess.run(["flock", "-n", "-x", lock, "true"], check=True, timeout=3)
        calls = trace.read_text().splitlines()
        if (not any("manual login verified inputs handed off" in line and "EAGAIN" in line
                    for line in calls)
                or sum("execve(" in line for line in calls) != 1
                or any("socket(" in line or "connect(" in line for line in calls)):
            raise RuntimeError(f"did not verify the full-queue refusal: {calls!r}")
        print("signed publication with a full PTY: exit 1, exclusive lock recovered")
    finally:
        for descriptor in (filler, slave, master):
            os.close(descriptor)


def exercise(binary, root, signed=False):
    etc = root / "etc"
    config = etc / "tempest"
    ledger = config / "claude-login-diagnostic-ledger"
    ledger.mkdir(parents=True, mode=0o700)
    policy = config / "claude-manual-login.json"
    def snapshot():
        entries = {}
        for entry in [config, *config.rglob("*")]:
            stat = entry.stat()
            entries[entry] = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_ctime_ns)
        return entries
    trace = root / "trace"

    def check(label, endpoints, expected, args=(), env=None, stages=(), completed=0, unopened=()):
        baseline = snapshot()
        master, slave = pty.openpty()
        other_master, other_slave = pty.openpty()
        with open(os.devnull, "rb+") as null:
            fds = (slave, other_slave, null.fileno(), master)
            try:
                result = subprocess.run(
                    ["/usr/bin/strace", "-f", "-qq", "-o", trace, "-e",
                     "trace=%process,%network,%file", binary, *args],
                    stdin=fds[endpoints[0]], stdout=fds[endpoints[1]], stderr=fds[endpoints[2]],
                    env={} if env is None else env, timeout=15 if stages else 5,
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
        observed = tuple(line for line in output.splitlines() if line in stages)
        if observed != stages[:completed]:
            raise RuntimeError(f"{label}: unexpected diagnostic progress: {output!r}")
        allowed = {"execve", "openat", "access", "newfstatat", "statx", "readlink", "exit_group"}
        lines = [line.split(maxsplit=1)[1] for line in trace.read_text().splitlines()]
        unexpected = [
            line for line in lines
            if line.split("(", 1)[0] not in allowed
            or any(token in line for token in ("O_RDWR", "O_CREAT", "O_TRUNC"))
            or ("O_WRONLY" in line and not (
                '"/proc/self/fd/2"' in line and "O_NONBLOCK" in line
            ))
        ]
        if sum(line.startswith("execve(") for line in lines) != 1 or unexpected:
            raise RuntimeError(f"{label}: unexpected traced operations: {unexpected!r}")
        for path in unopened:
            if any(line.startswith("openat(") and f'"{path}"' in line for line in lines):
                raise RuntimeError(f"{label}: opened later diagnostic input {path}")
        if snapshot() != baseline:
            raise RuntimeError(f"{label}: policy or ledger changed")
        print(f"{label}: exit 1, no child, network, or ledger mutation")
        if label == "signed publication normal":
            check_full_publication_terminal(binary, config, trace)


    same = (0, 0, 0)
    if not signed:
        check("policy missing", same, b"administrator policy missing")
    with open(policy, "xb", opener=lambda path, flags: os.open(path, flags, 0o600)) as out:
        out.write(b'{"version":1,"authority":"platform.claude.com:443"}')
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
    if signed:
        check_signed_publication(config, ledger, check)


def main():
    if len(sys.argv) == 2 or sys.argv[2:] == [SIGNED]:
        if os.geteuid() != 0:
            return 2
        binary = str(Path(sys.argv[1]).resolve(strict=True))
        return subprocess.call([
            "/usr/bin/unshare", "-mn", "--propagation", "private",
            sys.executable, str(Path(__file__).resolve()), "--isolated",
            os.readlink("/proc/self/ns/mnt"), os.readlink("/proc/self/ns/net"), binary, *sys.argv[2:],
        ])
    if (len(sys.argv) < 5 or sys.argv[1] != "--isolated" or os.geteuid() != 0
            or sys.argv[5:] not in ([], [SIGNED])):
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
        signed = sys.argv[5:] == [SIGNED]
        if signed:
            subprocess.run(["mount", "--bind", FIXED_CLI, FIXED_CLI], check=True)
            subprocess.run(["mount", "-o", "remount,bind,ro,noexec", FIXED_CLI], check=True)
        try:
            exercise(sys.argv[4], root, signed)
        finally:
            subprocess.run(["umount", "/etc"], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
