#!/usr/bin/env python3
"""Read-only observer for fixed transient bootstrap and full image units."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time

UNIT = "tempest-izanagi-bootstrap-build-001.service"
PROPERTIES = ("LoadState", "ActiveState", "SubState", "Result", "ExecMainCode",
              "ExecMainStatus", "ControlGroup", "InvocationID", "MainPID")


def command(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=5).stdout


def loopback(endpoint):
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def process_starttime(stat):
    # comm may contain spaces and closing parentheses; fields follow its last ')'.
    fields = stat.rsplit(')', 1)[1].split()
    value = int(fields[19])  # /proc/PID/stat field 22, in clock ticks since boot.
    if value <= 0:
        raise ValueError('invalid process start time')
    return value


def sample(unit=UNIT):
    data = command(["/usr/bin/systemctl", "show", unit,
                    *["--property=" + key for key in PROPERTIES]])
    state = dict(line.split("=", 1) for line in data.splitlines() if "=" in line)
    group = state.get("ControlGroup", "")
    pids = set()
    if group:
        if group != "/system.slice/" + unit:
            raise RuntimeError("unexpected control group")
        root = Path("/sys/fs/cgroup") / group.lstrip("/")
        if root.exists():
            for path in root.rglob("cgroup.procs"):
                try:
                    pids.update(int(pid) for pid in path.read_text().split())
                except FileNotFoundError:
                    pass
    listeners = []
    for line in command(["/usr/bin/ss", "-H", "-ltnp"]).splitlines():
        owners = {int(pid) for pid in re.findall(r"pid=(\d+)", line)}
        if owners & pids:
            endpoint = line.split()[3]
            listeners.append({"local": endpoint, "loopback": loopback(endpoint),
                              "pids": sorted(owners & pids)})
    network_args = []
    for pid in sorted(pids):
        try:
            stat = Path(f'/proc/{pid}/stat')
            starttime = process_starttime(stat.read_text())
            executable = os.readlink(f"/proc/{pid}/exe")
            if executable != "/usr/bin/qemu-system-x86_64":
                continue
            args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            cwd = os.readlink(f'/proc/{pid}/cwd')
            selected = []
            storage = []
            for index, value in enumerate(args[:-1]):
                if value in (b"-netdev", b"-vnc"):
                    selected.append([value.decode(), args[index + 1].decode("utf-8", "replace")])
                if value in (b"-drive", b"-fsdev"):
                    storage.append([value.decode(), args[index + 1].decode("utf-8", "replace")])
            if process_starttime(stat.read_text()) != starttime:
                raise RuntimeError('QEMU process identity changed during observation')
            network_args.append({"pid": pid, "starttime_ticks": starttime,
                                 "cwd": cwd, "network_args": selected, "storage_args": storage})
        except (FileNotFoundError, ProcessLookupError):
            pass
    return {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "unit": state, "cgroup_pids": sorted(pids), "listeners": listeners,
            "qemu_network": network_args,
            "external_listener_observed": any(not row["loopback"] for row in listeners)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--attempt", choices=("001", "002", "003", "004"), required=True)
    parser.add_argument("--phase", choices=("build", "boot", "image"), default="build")
    args = parser.parse_args()
    if args.phase == "boot" and args.attempt not in ("001", "002"):
        parser.error("only boot attempt001/002 are defined")
    if args.phase == "image" and args.attempt not in ("001", "002", "003"):
        parser.error("only image attempt001/002/003 are defined")
    unit = f"tempest-izanagi-bootstrap-{args.phase}-{args.attempt}.service"
    if os.geteuid() != 0:
        raise SystemExit("root required to observe all unit socket owners")
    invocation = None
    start = time.monotonic()
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        while time.monotonic() - start < 3670:
            row = sample(unit)
            current = row["unit"].get("InvocationID")
            if current:
                if invocation and current != invocation:
                    raise RuntimeError("unit invocation changed")
                invocation = current
            stream.write(json.dumps(row) + "\n")
            stream.flush()
            if row["external_listener_observed"]:
                raise SystemExit("external listener observed; stop the fixed build unit")
            if invocation and row["unit"].get("ActiveState") in ("inactive", "failed"):
                if row["unit"].get("LoadState") != "loaded" or current != invocation:
                    raise SystemExit("same-invocation terminal attributes not captured")
                if row["cgroup_pids"]:
                    raise SystemExit("terminal unit retains processes")
                return
            if not invocation and time.monotonic() - start > 60:
                raise SystemExit("unit invocation not observed within startup window")
            time.sleep(1)
    raise SystemExit("observation deadline exceeded; inspect the fixed build unit")


if __name__ == "__main__":
    main()
