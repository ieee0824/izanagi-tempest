#!/usr/bin/env python3
"""Explicit dedicated-VM root integration; never called by cargo test.

Only a fixed repository build is temporarily installed under /var/lib. No model,
credential, network destination, persistent account or OS policy is configured.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def privileged(*args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sudo", "-n", *args], capture_output=True, timeout=timeout, check=False
    )


def main() -> int:
    if len(sys.argv) != 1 or sys.platform != "linux" or os.geteuid() == 0:
        print('{"status":"rejected","reason":"nonroot_dedicated_vm_entry_required"}')
        return 2
    binary = Path(__file__).resolve().parent.parent / "target/debug/tempest"
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    # /run is noexec on the dedicated VM. Do not relax that mount policy;
    # use a private, temporary directory on the executable root filesystem.
    root = Path("/var/lib") / ("tempest-probe-install-" + uuid.uuid4().hex)
    installed = root / "tempest"
    created = False
    try:
        if privileged("/usr/bin/mkdir", "-m", "0700", "--", str(root)).returncode:
            raise RuntimeError("private_install_directory_failed")
        created = True
        if privileged("/usr/bin/install", "-o", "root", "-g", "root", "-m", "0700", "--", str(binary), str(installed)).returncode:
            raise RuntimeError("fixed_binary_install_failed")
        # A root timeout bounds a wedged supervisor. The watchdog has its own
        # session and no inherited stdio, so it can recover after this timeout.
        result = privileged(
            "/usr/bin/timeout", "--signal=TERM", "--kill-after=5", "120",
            "/usr/bin/env", "-i", str(installed), "linux-isolation-probe",
            timeout=140,
        )
        if result.returncode == 124:
            print(json.dumps({"status": "failed", "reason": "driver_timeout", "exit_code": 124}))
            return 1
        for marker in [b"dummy-argv-marker", b"dummy-stderr-marker", b"synthetic-canary-only", b"dummy-output-marker"]:
            if marker in result.stdout or marker in result.stderr:
                raise RuntimeError("untrusted_marker_reached_audit")
        try:
            report = json.loads(result.stdout)
        except (ValueError, UnicodeDecodeError) as error:
            print(json.dumps({"status": "failed", "reason": "invalid_public_audit",
                              "exit_code": result.returncode,
                              "stdout_bytes": len(result.stdout),
                              "stderr_bytes": len(result.stderr)}))
            return 1
        allowed = {"schema_version", "status", "reason", "formal_eligible", "model_launched", "code_sha256", "checks", "errno", "resources_removed", "phase", "child_exit", "child_signal", "child_core_dumped", "output_role", "output_stream", "watchdog_exit", "watchdog_signal", "watchdog_core_dumped", "active_scenario", "elapsed_ms", "watchdog_status", "handoff_status", "parent_recovery_status", "guardian_alive", "first_fault"}
        if not isinstance(report, dict) or report.keys() - allowed:
            raise RuntimeError("unexpected_public_audit_fields")
        if report.get("code_sha256", digest) != digest:
            raise RuntimeError("executed_binary_identity_changed")
        if Path("/run/tempest-linux-isolation-probe").exists() or Path("/sys/fs/cgroup/tempest-linux-isolation-probe").exists():
            print(json.dumps({"status": "failed", "reason": "probe_resources_remain_new_probe_must_refuse",
                              "probe_exit_code": result.returncode, "probe_report": report}, sort_keys=True))
            return 1
        print(json.dumps(report, sort_keys=True))
        return 0 if result.returncode == 0 and report.get("status") == "passed" else 1
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
        # Never echo raw stderr, argv, arbitrary paths or an OS exception body.
        reason = str(error) if type(error) is RuntimeError else "integration_process_failed"
        print(json.dumps({"status": "failed", "reason": reason}))
        return 1
    finally:
        if created:
            privileged("/usr/bin/rm", "-f", "--", str(installed))
            privileged("/usr/bin/rmdir", "--", str(root))


if __name__ == "__main__":
    raise SystemExit(main())
