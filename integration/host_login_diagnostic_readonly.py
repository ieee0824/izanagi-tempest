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


def exercise(binary, root, responder=None):
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
        if responder is not None:
            key.unlink()
            (authority / "test-key").rename(key)
            ledger = parent / "host-login-ledger"
            signer_directory = parent / "host-login-signer"
            ledger.mkdir(mode=0o700)
            signer_directory.mkdir(mode=0o700)
            seed = signer_directory / "signing-seed"
            seed.write_bytes(bytes(range(32)))
            seed.chmod(0o600)
            record = ledger / "record.json"

            def write_record(value):
                record.write_text(json.dumps(asdict(value)), encoding="ascii")
                record.chmod(0o600)

            def request(challenge, status):
                trace = root / "responder-syscalls"
                before = record.read_bytes(), checkpoint.read_bytes()
                result = subprocess.run(
                    ["strace", "-f", "-qq", "-o", str(trace), "-e", "trace=%network,%process",
                     responder], input=challenge + "\n", capture_output=True, text=True, timeout=10,
                )
                calls = trace.read_text(encoding="utf-8").splitlines()
                if (result.returncode != status or len(calls) != 2 or "execve(" not in calls[0]
                        or f"exit_group({status})" not in calls[1]):
                    raise RuntimeError(f"unexpected responder result: {result}, {calls}")
                if before != (record.read_bytes(), checkpoint.read_bytes()):
                    raise RuntimeError("responder changed the management records")
                if status:
                    if result.stdout:
                        raise RuntimeError("refusal emitted a response")
                    return None
                return json.loads(result.stdout)

            def lose_response(challenge):
                request(challenge, 0)
                return None

            write_record(commit)
            check(VERIFIED_INPUTS, reply=lambda challenge: request(challenge, 0))
            check(INVALID_RECEIPT, reply=lose_response)
            pending = replace(commit, state="pending")
            write_record(pending)
            write_checkpoint(pending)
            check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
            write_checkpoint(commit)
            write_record(replace(commit, sequence=1))
            check(INVALID_RECEIPT, reply=lambda challenge: request(challenge, 1))
            print("PASS: real responder connected, pending/rollback/dropped response refused")
        print("PASS: isolated signature verification, scope/checkpoint/replay refusal, no child/network activity")
    finally:
        subprocess.run(["umount", "/var/lib"], check=True)


def main():
    if sys.argv[1:2] != ["--isolated"]:
        if len(sys.argv) not in (2, 3):
            return 2
        binaries = [str(Path(path).resolve(strict=True)) for path in sys.argv[1:]]
        return subprocess.call([
            "unshare", "--mount", "--net", "--propagation", "private",
            sys.executable, str(Path(__file__).resolve()), "--isolated", *binaries,
        ])
    if len(sys.argv) not in (3, 4) or os.geteuid() != 0:
        return 2
    with tempfile.TemporaryDirectory(prefix="tempest-host-diagnostic-") as directory:
        exercise(sys.argv[2], Path(directory), *sys.argv[3:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
