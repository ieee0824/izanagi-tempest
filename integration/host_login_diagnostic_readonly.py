"""Check the dedicated host management reader in isolated mount and network namespaces."""

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from host_permit_receipt import Commit, Scope, receipt_bytes


VERIFIED_INPUTS = "receipt verified; launch disabled"
INVALID_RECEIPT = "receipt unavailable or invalid"
INVALID_INPUTS = "management inputs unavailable or invalid"


def exercise(binary, root):
    parent = root / "izanagi-tempest"
    authority = parent / "host-login-authority"
    recovery = parent / "host-login-recovery"
    for directory in (parent, authority, recovery):
        directory.mkdir(mode=0o700)
    key = authority / "verification-key"
    key.write_bytes(bytes.fromhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"))
    key.chmod(0o600)
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    scope = Scope("qemu-fixture-target", "permit-fixture", 1)
    commit = Commit("host-fixture-ledger", 2, scope, "consumed")
    scope_path = authority / "scope.json"
    scope_path.write_text(json.dumps(asdict(scope)), encoding="ascii")
    scope_path.chmod(0o600)
    checkpoint = recovery / "checkpoint.json"

    def write_checkpoint(value):
        checkpoint.write_text(json.dumps({
            "sequence": value.sequence, "digest": value.digest().hex(),
        }), encoding="ascii")
        checkpoint.chmod(0o600)

    def sign(challenge, value, signing_key=signer):
        signature = signing_key.sign(receipt_bytes(bytes.fromhex(challenge), value))
        return {"challenge": challenge, "commit": asdict(value), "signature": signature.hex()}

    write_checkpoint(commit)
    subprocess.run(["mount", "--bind", str(root), "/var/lib"], check=True)
    subprocess.run(["mount", "-o", "remount,bind,ro", "/var/lib"], check=True)
    try:
        def check(expected, *arguments, reply=None):
            trace = root / "syscalls"
            with subprocess.Popen(
                ["strace", "-f", "-qq", "-o", str(trace), "-e", "trace=%network,%process",
                 binary, *arguments],
                env={"HOME": str(root), "TEMPEST_HOST_LOGIN_DIRECTORY": str(root)},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ) as process:
                response = None
                try:
                    if reply is not None:
                        if not select.select([process.stdout], [], [], 10)[0]:
                            raise RuntimeError("missing host challenge")
                        challenge = process.stdout.readline().strip()
                        if len(challenge) != 64 or len(bytes.fromhex(challenge)) != 32:
                            raise RuntimeError(f"invalid host challenge: {challenge!r}")
                        response = reply(challenge)
                    _, stderr = process.communicate(
                        "" if response is None else json.dumps(response) + "\n", timeout=10,
                    )
                finally:
                    if process.poll() is None:
                        process.kill()
            calls = trace.read_text(encoding="utf-8").splitlines()
            if process.returncode != 1 or expected not in stderr:
                raise RuntimeError(f"unexpected diagnostic result: {stderr}")
            # The initial exec and the diagnostic's own exit are the only traced calls.
            if len(calls) != 2 or "execve(" not in calls[0] or "exit_group(1)" not in calls[1]:
                raise RuntimeError(f"unexpected child or network activity: {calls}")
            return response

        initial = checkpoint.read_bytes()
        accepted = check(VERIFIED_INPUTS, reply=lambda challenge: sign(challenge, commit))
        check(INVALID_RECEIPT, reply=lambda _: accepted)
        check(INVALID_RECEIPT)
        other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        check(INVALID_RECEIPT, reply=lambda challenge: sign(challenge, commit, other_key))
        check(INVALID_RECEIPT, reply=lambda challenge: sign(challenge, replace(commit, sequence=3)))
        check(INVALID_RECEIPT, reply=lambda challenge: sign(challenge, replace(commit, ledger_id="other")))
        for wrong in (replace(scope, target_id="other"), replace(scope, permit_id="other"),
                      replace(scope, generation=2)):
            wrong_commit = replace(commit, scope=wrong)
            write_checkpoint(wrong_commit)
            check(INVALID_RECEIPT, reply=lambda challenge: sign(challenge, wrong_commit))
        write_checkpoint(commit)
        check("dedicated administrator entry required", str(root))
        if checkpoint.read_bytes() != initial:
            raise RuntimeError("diagnostic changed the checkpoint")
        checkpoint.unlink()
        check(INVALID_INPUTS)
        checkpoint.write_bytes(b"broken")
        checkpoint.chmod(0o600)
        check(INVALID_INPUTS)
        checkpoint.write_bytes(initial)
        key.rename(authority / "test-key")
        check(INVALID_INPUTS)
        key.symlink_to("test-key")
        check(INVALID_INPUTS)
        print("PASS: isolated signature verification, scope/checkpoint/replay refusal, no child/network activity")
    finally:
        subprocess.run(["umount", "/var/lib"], check=True)


def main():
    if len(sys.argv) != 3:
        binary = str(Path(sys.argv[1]).resolve(strict=True))
        return subprocess.call([
            "unshare", "--mount", "--net", "--propagation", "private",
            sys.executable, str(Path(__file__).resolve()), binary, "isolated",
        ])
    if sys.argv[2] != "isolated" or os.geteuid() != 0:
        return 2
    with tempfile.TemporaryDirectory(prefix="tempest-host-diagnostic-") as directory:
        exercise(sys.argv[1], Path(directory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
