"""Handle one fixed dummy request delivered by the existing guest session."""
import json
from pathlib import Path
import re
import sys
import uuid


PHASES = ("before", "allowed", "denied", "after")


def receive(nonce, phase, request):
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None or phase not in PHASES:
        raise ValueError("invalid fixed receiver binding")
    expected = f"tempest-dummy-v1:{nonce}:{phase}"
    matched = request == expected
    return {
        "schema_version": 1,
        "run_nonce": nonce,
        "boot_id": str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip())),
        "phase": phase,
        "received": 1,
        "matched": int(matched),
    }


def main():
    if len(sys.argv) != 4:
        return 2
    try:
        report = receive(*sys.argv[1:])
    except (ValueError, OSError):
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["matched"] else 1


if __name__ == "__main__":
    sys.exit(main())
