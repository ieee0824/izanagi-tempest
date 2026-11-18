#!/usr/bin/env python3
"""Fixed boot unit ExecStopPost recorder; no secret or arbitrary environment dump."""
import json
import os
import subprocess

UNIT = "tempest-izanagi-bootstrap-boot-001.service"
OUTPUT = "/run/tempest-izanagi-bootstrap/evidence/exit-status.json"
PROPERTIES = ("InvocationID", "ExecMainCode", "ExecMainStatus", "Result",
              "ActiveState", "SubState", "ControlGroup")


def collect():
    invocation = os.environ.get("INVOCATION_ID", "")
    if len(invocation) != 32 or any(c not in "0123456789abcdef" for c in invocation):
        raise RuntimeError("missing valid unit invocation")
    response = subprocess.run(
        ["/usr/bin/systemctl", "show", UNIT,
         *["--property=" + p for p in PROPERTIES]],
        capture_output=True, text=True, check=True, timeout=5,
    )
    state = dict(line.split("=", 1) for line in response.stdout.splitlines() if "=" in line)
    if state.get("InvocationID") != invocation:
        raise RuntimeError("exit recorder invocation mismatch")
    return {
        "unit_name": UNIT, "invocation_id": invocation, "unit": state,
        "service_result": os.environ.get("SERVICE_RESULT"),
        "exit_code": os.environ.get("EXIT_CODE"),
        "exit_status": os.environ.get("EXIT_STATUS"),
        "scope": "ExecStopPost snapshot; final cgroup and journal checks are separate",
    }


def main():
    row = collect()
    fd = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(row, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == "__main__":
    main()
