"""Check the dedicated host management reader in isolated mount and network namespaces."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile


READ_INPUTS = "management inputs read; receipt verification unavailable"
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
    checkpoint = recovery / "checkpoint.json"
    checkpoint.write_text('{"sequence":2,"digest":"' + "ab" * 32 + '"}', encoding="ascii")
    checkpoint.chmod(0o600)
    subprocess.run(["mount", "--bind", str(root), "/var/lib"], check=True)
    subprocess.run(["mount", "-o", "remount,bind,ro", "/var/lib"], check=True)
    try:
        def check(expected, *arguments):
            trace = root / "syscalls"
            result = subprocess.run(
                ["strace", "-f", "-qq", "-o", str(trace), "-e", "trace=%network,%process",
                 binary, *arguments],
                env={"HOME": str(root), "TEMPEST_HOST_LOGIN_DIRECTORY": str(root)},
                capture_output=True, text=True, timeout=10,
            )
            calls = trace.read_text(encoding="utf-8").splitlines()
            if result.returncode != 1 or expected not in result.stderr:
                raise RuntimeError(f"unexpected diagnostic result: {result}")
            # The initial exec and the diagnostic's own exit are the only traced calls.
            if len(calls) != 2 or "execve(" not in calls[0] or "exit_group(1)" not in calls[1]:
                raise RuntimeError(f"unexpected child or network activity: {calls}")

        initial = checkpoint.read_bytes()
        check(READ_INPUTS)
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
        print("PASS: fixed management reader, missing/corrupt inputs, no child/network activity")
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
