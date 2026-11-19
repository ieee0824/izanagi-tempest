"""Handle one fixed dummy request delivered by the existing guest session."""
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import uuid


PHASES = ("control_before", "allow_same_run", "deny_other", "control_after")
RECORD_DIR = Path("/run/tempest-fixed-vm-receiver")
MAX_RECORD_BYTES = 4096


def start_phase(report, phase):
    phases = report["phases"]
    if len(phases) >= len(PHASES) or phase != PHASES[len(phases)]:
        raise ValueError("unexpected receiver phase")
    if phases and phases[-1]["end"] is None:
        raise ValueError("previous receiver phase is open")
    phases.append({"phase": phase, "start": report["counts"].copy(), "end": None})


def record_request(report, phase, request):
    open_phase(report, phase)
    matched = request == f"tempest-dummy-v1:{report['run_nonce']}:{phase}"
    report["counts"]["received"] += 1
    report["counts"]["matched"] += int(matched)
    return matched


def end_phase(report, phase):
    current = open_phase(report, phase)
    current["end"] = report["counts"].copy()
    current["delta"] = {
        key: value - current["start"][key] for key, value in current["end"].items()
    }
    return current


def open_phase(report, phase):
    phases = report["phases"]
    if not phases or phases[-1]["phase"] != phase or phases[-1]["end"] is not None:
        raise ValueError("receiver phase is not open")
    return phases[-1]


def process(operation, nonce, phase, request):
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None or phase not in PHASES:
        raise ValueError("invalid fixed receiver binding")
    boot_id = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
    binding = {"schema_version": 1, "run_nonce": nonce, "boot_id": boot_id}
    if RECORD_DIR.is_symlink() or not RECORD_DIR.is_dir():
        raise ValueError("missing receiver record directory")
    info = RECORD_DIR.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o700:
        raise ValueError("receiver record directory must be owner-private")
    with (RECORD_DIR / "lock").open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return update(binding, operation, phase, request)


def update(binding, operation, phase, request):
    state = RECORD_DIR / "report.json"
    if state.exists():
        with state.open("rb") as stream:
            raw = stream.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError("oversize receiver record")
        report = json.loads(raw)
        if any(report.get(key) != value for key, value in binding.items()):
            raise ValueError("receiver binding changed")
    else:
        report = binding | {
            "counts": {"received": 0, "matched": 0},
            "phases": [],
            "complete": False,
        }
    matched = True
    if operation == "start":
        start_phase(report, phase)
    elif operation == "request":
        matched = record_request(report, phase, request)
    else:
        end_phase(report, phase)
        report["complete"] = phase == PHASES[-1]
    result = {
        **binding,
        "operation": operation,
        "phase": phase,
        "counts": report["counts"],
        "matched": matched,
    }
    raw = json.dumps(report, sort_keys=True).encode()
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("oversize receiver record")
    pending = RECORD_DIR / "report.pending"
    with pending.open("xb") as stream:
        stream.write(raw)
    pending.replace(state)
    return result


def main():
    if len(sys.argv) not in (4, 5):
        return 2
    operation, nonce, phase, *payload = sys.argv[1:]
    if operation not in ("start", "request", "end") or len(payload) != int(operation == "request"):
        return 2
    try:
        result = process(operation, nonce, phase, payload[0] if payload else None)
    except (ValueError, OSError):
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["matched"] else 1


if __name__ == "__main__":
    sys.exit(main())
