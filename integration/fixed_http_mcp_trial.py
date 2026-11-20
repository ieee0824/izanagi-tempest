"""Run two pinned Linux VMs and compare their fixed local HTTP MCP responses."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

import fixed_http_mcp_observe as observe
import fixed_vm_receive_observe as vm


IZANAGI_SHA256 = "088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8"
MIB = 1024**2
ROOT = Path(__file__).resolve().parent


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def available_ram():
    return int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                    if line.startswith("MemAvailable:")))


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, timeout=15, **kwargs)


def same_process(ready):
    qemu = ready["qemu"]
    try:
        return Path(f"/proc/{qemu['pid']}/stat").read_text().rsplit(")", 1)[1].split()[19] == qemu["starttime"]
    except FileNotFoundError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("izanagi", "image", "build-inputs", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--joined-preflight", choices=("match", "config-mismatch", "policy-mismatch"),
                        help="run the fixed configuration and waiting-role checks before the VM trial")
    args = parser.parse_args()
    if os.geteuid() != 0 or os.stat("/proc/self/ns/net") == os.stat("/proc/1/ns/net"):
        parser.error("requires root in a fresh network namespace")
    interfaces = json.loads(command("ip", "-j", "link", "show", capture_output=True).stdout)
    if [row["ifname"] for row in interfaces] != ["lo"]:
        parser.error("requires a loopback-only network namespace")
    command("ip", "link", "set", "lo", "up")
    os.umask(0o077)
    image_sha = sha(args.image)
    if image_sha != vm.FIXED_IMAGE_SHA256 or sha(args.izanagi) != IZANAGI_SHA256:
        parser.error("fixed input digest mismatch")
    initial = available_ram()
    if initial < int(6.5 * 1024**2):
        parser.error(f"insufficient available RAM: {initial} KiB")
    if subprocess.run(["pgrep", "-u", "62002,62004,999"], stdout=subprocess.DEVNULL).returncode != 1:
        parser.error("dedicated fixture users must be idle")
    output = args.output.resolve()
    if any(path.resolve().is_relative_to("/tmp")
           for path in (ROOT, output, args.izanagi, args.image, args.build_inputs)):
        parser.error("checkout, inputs and output must be outside the service-private /tmp")
    output.mkdir(mode=0o700, exist_ok=False)
    trial_id = secrets.token_hex(16)
    preflight = None
    network_namespace = os.stat("/proc/self/ns/net").st_ino
    if args.joined_preflight:
        import fixed_http_mcp_gate
        preflight = fixed_http_mcp_gate.check(trial_id, args.joined_preflight)
        if not preflight["admitted"]:
            observe.publish(output / "result.json", {
                "trial_id": trial_id, "network_namespace": network_namespace,
                "preflight": preflight, "vm_starts": 0,
                "management_prepared": 0, "http_requests": 0, "http_accepts": [0, 0],
            })
            return
    mount_ids = []
    minimum = initial
    peaks = [0, 0]
    prefix = f"tempest-http-mcp-{secrets.token_hex(5)}"
    units = []
    jobs = []
    logs = []
    controls = []
    sequences = [0, 0]
    request_counts = [0, 0]

    def start(index):
        unit = f"{prefix}-{index}.service"
        control = output / str(index)
        control.mkdir(mode=0o700)
        log = (output / f"{index}.log").open("xb")
        logs.append(log)
        controls.append(control)
        process = subprocess.Popen([
            "systemd-run", f"--unit={unit}", "--wait", "--pipe", "--property=UMask=0077",
            f"--property=NetworkNamespacePath=/proc/{os.getpid()}/ns/net",
            "--property=TemporaryFileSystem=/tmp:rw,nosuid,nodev,size=512M,mode=1777",
            "--property=RuntimeMaxSec=180", "--property=TimeoutStopSec=20",
            "/usr/bin/python3", str(ROOT / "image_smoke.py"),
            "--izanagi", str(args.izanagi.resolve()), "--image", str(args.image.resolve()),
            "--build-inputs", str(args.build_inputs.resolve()),
            "--output", f"/tmp/tempest-http-mcp-{index}", "--exec-evidence",
            "--fixed-vm-receiver-preflight", "--fixed-http-mcp-control", str(control),
        ], stdout=log, stderr=log)
        units.append(unit)
        jobs.append(process)

    ready = []

    def sample():
        nonlocal minimum
        minimum = min(minimum, available_ram())
        if minimum < 1536 * 1024:
            raise RuntimeError("host RAM fell below the trial floor")
        for index, entry in enumerate(ready):
            pid = entry["qemu"]["pid"]
            mount = os.statvfs(f"/proc/{pid}/root/tmp")
            peaks[index] = max(peaks[index], (mount.f_blocks - mount.f_bfree) * mount.f_frsize)
            if peaks[index] >= 448 * MIB:
                raise RuntimeError("write area reached the trial watermark")

    def read_when_ready(path):
        deadline = time.monotonic() + 65
        while not path.exists():
            if time.monotonic() >= deadline or any(job.poll() is not None for job in jobs):
                raise RuntimeError(f"fixture did not publish {path.name}")
            sample()
            time.sleep(.1)
        sample()
        return json.loads(path.read_text())

    def invoke(index, mode, nonce):
        position = sequences[index]
        sequences[index] += 1
        control = controls[index]
        observe.publish(control / f"command-{position}.json", [mode, nonce])
        response = read_when_ready(control / f"reply-{position}.json")
        if not all(map(same_process, ready)):
            raise RuntimeError("fixture QEMU identity changed")
        if mode == "request":
            request_counts[index] += len(response)
        return response

    try:
        for index in range(2):
            start(index)
            ready.append(read_when_ready(controls[index] / "ready.json"))
        for key in ("pid", "port"):
            if ready[0]["qemu"][key] == ready[1]["qemu"][key]:
                raise RuntimeError(f"fixture QEMU {key} collision")
        if ready[0]["session_fingerprint"] == ready[1]["session_fingerprint"]:
            raise RuntimeError("fixture session collision")
        mount_ids = [Path(f"/proc/{row['qemu']['pid']}/ns/mnt").stat().st_ino for row in ready]
        if mount_ids[0] == mount_ids[1]:
            raise RuntimeError("fixture mount namespace collision")

        http = observe.collect(invoke, [row["guest"]["boot_id"] for row in ready])
        sample()
        for control in controls:
            (control / "release").touch()
        if any(job.wait(timeout=45) != 0 for job in jobs):
            raise RuntimeError("fixed VM trial did not exit normally")
        terminal = [json.loads((path / "stopped.json").read_text()) for path in controls]
        sockets = command("ss", "-Hltpn", capture_output=True).stdout
        active_mounts = command("lsns", "-n", "-t", "mnt", "-o", "NS", capture_output=True).stdout.split()
        for row, record, unit, mount in zip(ready, terminal, units, mount_ids, strict=True):
            if (record["up_exit"] != 0 or record["down_exit"] != 0 or not record["hmac_gone"]
                    or same_process(row) or f"127.0.0.1:{row['qemu']['port']} " in sockets
                    or str(mount) in active_mounts
                    or (Path("/sys/fs/cgroup/system.slice") / unit).exists()):
                raise RuntimeError("fixed VM recovery failed")
            fingerprint = row.pop("session_fingerprint")
            if preflight is not None:
                row["trial_session_binding"] = hashlib.sha256(
                    bytes.fromhex(trial_id) + bytes.fromhex(fingerprint)
                ).hexdigest()
        if sha(args.image) != image_sha:
            raise RuntimeError("base image changed")
        result = {
            "initial_available_kib": initial, "minimum_available_kib": minimum,
            "observed_write_peaks": peaks, "http": http, "vms": ready,
            "terminal": terminal, "base_sha256": image_sha, "recovered": True,
        }
        if preflight is not None:
            result.update(trial_id=trial_id, network_namespace=network_namespace,
                          preflight=preflight, vm_starts=len(jobs),
                          management_prepared=len(ready), http_requests=sum(request_counts),
                          http_accepts=[sum(row[index] for row in http["accept_deltas"])
                                        for index in range(2)])
        observe.publish(output / "result.json", result)
    finally:
        for unit, job in zip(units, jobs, strict=True):
            if job.poll() is None:
                subprocess.run(["systemctl", "kill", "--kill-whom=main", "--signal=SIGINT", unit],
                               check=False, timeout=10)
                try:
                    job.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    command("systemctl", "stop", unit)
                    job.wait(timeout=15)
        for log in logs:
            log.close()
        for path in controls:
            (path / "ready.json").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
