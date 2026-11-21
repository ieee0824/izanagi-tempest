"""Run the fixed dummy permit over serial with no guest access to the host ledger."""

import argparse
from contextlib import closing
import gzip
import os
from pathlib import Path
import select
import shutil
import sqlite3
import subprocess
import tempfile
import time


PERMIT = "permit-dummy-qemu"
INIT = """#!/bin/busybox sh
set -eu
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
for device in /sys/class/block/*; do
    case "$device" in
        */loop*|*/ram*|'/sys/class/block/*') ;;
        *) exit 1 ;;
    esac
done
[ "$(/bin/busybox ls /sys/class/net)" = lo ]
[ ! -e /ledger.sqlite3 ]
echo 'FIXTURE_REQUEST permit-dummy-qemu'
IFS= read -r command
case "$command" in
    FIXTURE_POWER_OFF) echo 'GUEST_EXIT_WITHOUT_ACK' ;;
    FIXTURE_REFUSED) echo 'GUEST_OBSERVED_REFUSAL' ;;
    *) echo 'GUEST_UNEXPECTED_COMMAND'; exit 1 ;;
esac
/bin/busybox poweroff -f
"""


def create_initramfs(root, busybox):
    guest = root / "guest"
    for name in ("bin", "dev", "proc", "sys"):
        (guest / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(busybox, guest / "bin/busybox")
    (guest / "bin/busybox").chmod(0o755)
    (guest / "init").write_text(INIT, encoding="utf-8")
    (guest / "init").chmod(0o755)
    archive = subprocess.run(
        ["cpio", "-o", "-H", "newc", "--quiet"],
        cwd=guest, input=b".\nbin\nbin/busybox\ndev\nproc\nsys\ninit\n",
        stdout=subprocess.PIPE, check=True,
    ).stdout
    image = root / "initrd.gz"
    image.write_bytes(gzip.compress(archive))
    return image


def consume_dummy(ledger):
    with closing(sqlite3.connect(ledger.as_uri() + "?mode=rw", uri=True)) as db, db:
        db.execute("PRAGMA synchronous=FULL")
        result = db.execute(
            "UPDATE permits SET state='consumed' WHERE id=? AND state='issued'", (PERMIT,),
        )
    return result.rowcount == 1


def await_request(output):
    deadline = time.monotonic() + 40
    pending = b""
    while time.monotonic() < deadline:
        readable, _, _ = select.select([output], [], [], max(0, deadline - time.monotonic()))
        if not readable:
            break
        data = os.read(output.fileno(), 4096)
        if not data:
            break
        lines = (pending + data).split(b"\n")
        pending = lines.pop()
        if f"FIXTURE_REQUEST {PERMIT}".encode() in [line.rstrip(b"\r") for line in lines]:
            return
    raise RuntimeError("guest did not request the fixed dummy permit")


def run_guest(kernel, image, ledger, *, drop_ack):
    command = [
        "qemu-system-x86_64", "-machine", "q35,accel=tcg", "-m", "256",
        "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
        "-nic", "none", "-serial", "stdio", "-no-reboot",
        "-kernel", str(kernel), "-initrd", str(image),
        "-append", "console=ttyS0 rdinit=/init quiet",
    ]
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as vm:
        try:
            await_request(vm.stdout)
            consumed = consume_dummy(ledger)
            if consumed != drop_ack:
                raise RuntimeError(f"unexpected consumption result: {consumed}")
            if drop_ack:
                # Fault-control signal only. No consumption result is sent.
                signal, expected = b"FIXTURE_POWER_OFF", b"GUEST_EXIT_WITHOUT_ACK"
            else:
                signal, expected = b"FIXTURE_REFUSED", b"GUEST_OBSERVED_REFUSAL"
            output, _ = vm.communicate(signal + b"\n", timeout=20)
            if vm.returncode != 0 or expected not in output.splitlines():
                raise RuntimeError(f"guest did not complete as expected: {output!r}")
        finally:
            if vm.poll() is None:
                vm.kill()
    print(f"QEMU {vm.pid}: {expected.decode()}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path, help="Readable local x86-64 Linux kernel")
    parser.add_argument("--busybox", type=Path, default=Path("/usr/bin/busybox"),
                        help="Local statically linked x86-64 BusyBox")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="tempest-qemu-permit-") as directory:
        root = Path(directory).resolve()
        image = create_initramfs(root, args.busybox)
        ledger = root / "ledger.sqlite3"
        with closing(sqlite3.connect(ledger)) as db, db:
            db.execute("CREATE TABLE permits (id TEXT PRIMARY KEY, state TEXT NOT NULL)")
            db.execute("INSERT INTO permits VALUES (?, 'issued')", (PERMIT,))
        run_guest(args.kernel, image, ledger, drop_ack=True)
        run_guest(args.kernel, image, ledger, drop_ack=False)
        with closing(sqlite3.connect(ledger)) as db:
            if db.execute("SELECT id, state FROM permits").fetchall() != [(PERMIT, "consumed")]:
                raise RuntimeError("host ledger lost the committed consumption")
        print("PASS: host consumption survived VM shutdown without acknowledgement")


if __name__ == "__main__":
    main()
