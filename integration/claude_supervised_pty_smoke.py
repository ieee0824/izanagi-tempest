"""Verify the fixed supervised PTY fixture on a dedicated Linux host."""

import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time

from claude_offline_pty_smoke import read_until

WORK = Path("/var/lib/tempest-claude-version-work")
SUCCESS = b"offline PTY: supervisor stopped and reaped namespace; cleanup complete\n"


def process_children(proc):
    for task in (proc / "task").iterdir():
        try:
            yield from map(int, (task / "children").read_text().split())
        except (FileNotFoundError, ProcessLookupError):
            continue


def live_descendant(supervisor: int) -> int:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        pending = [supervisor]
        while pending:
            pid = pending.pop()
            proc = Path(f"/proc/{pid}")
            try:
                pending.extend(process_children(proc))
                if (proc / "cmdline").read_bytes() == b"/bin/busybox\0sleep\0" + b"60\0":
                    pidfd = os.pidfd_open(pid)
                    watcher = select.poll()
                    watcher.register(pidfd, select.POLLIN)
                    if not watcher.poll(0):
                        return pidfd
                    os.close(pidfd)
            except ProcessLookupError:
                pass
            except FileNotFoundError:
                pass
        time.sleep(0.02)
    raise RuntimeError("fixed descendant was not alive before disconnect")


def fixture(
    command: list[str], env: dict[str, str], complete_probe: bool, success: bytes = SUCCESS,
    *, startup_timeout: float = 3, before_probe=None, observe_child=None,
    quarantine=None, check_evidence=None, after_probe=None, before_ready=None,
    shared_entry=False,
) -> None:
    master, slave = pty.openpty()
    descendant = evidence_read = evidence_write = -1
    try:
        stderr = subprocess.PIPE
        pass_fds = ()
        if shared_entry:
            evidence_read, evidence_write = os.pipe()
            env = {**env, "TEMPEST_FIXTURE_EVIDENCE_FD": str(evidence_write)}
            stderr = slave
            pass_fds = (evidence_write,)
        with subprocess.Popen(
            command, stdin=slave, stdout=slave, stderr=stderr, env=env, pass_fds=pass_fds,
        ) as child:
            if shared_entry:
                os.close(evidence_write)
                evidence_write = -1
            os.close(slave)
            slave = -1
            readiness_error = None
            try:
                try:
                    if before_ready is not None:
                        before_ready(master)
                    read_until(master, b"fixture-ready", timeout=startup_timeout)
                except (OSError, RuntimeError) as error:
                    readiness_error = error
                if readiness_error is None and complete_probe:
                    if observe_child is not None:
                        observe_child(child.pid)
                    if before_probe is not None:
                        before_probe()
                    os.write(master, b"probe\n")
                    read_until(master, b"fixture-response")
                    descendant = live_descendant(child.pid)
                    if after_probe is not None:
                        after_probe(child.pid)
            finally:
                os.close(master)
                master = -1
                try:
                    _, result = child.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    _, result = child.communicate()
                    if readiness_error is None:
                        raise RuntimeError(f"supervised PTY did not exit: stderr={result!r}")
        if shared_entry:
            with os.fdopen(evidence_read, "rb") as evidence:
                evidence_read = -1
                result = evidence.read()
        if readiness_error is not None:
            raise RuntimeError(
                f"supervised PTY failed before readiness: exit={child.returncode}, "
                f"stderr={result!r}, read_error={readiness_error!r}"
            ) from readiness_error
        if complete_probe:
            watcher = select.poll()
            watcher.register(descendant, select.POLLIN)
            if not watcher.poll(0):
                raise RuntimeError("fixed descendant survived the PTY disconnect")
            if check_evidence is not None:
                result = check_evidence(result)
            expected_exit = 0 if quarantine is None else 1
            if child.returncode != expected_exit or result != success:
                raise RuntimeError(f"disconnect and recovery failed: {result!r}")
        elif child.returncode != 1 or success in result:
            raise RuntimeError(f"early disconnect was not rejected: {result!r}")
        if quarantine is not None:
            quarantine()
        elif any(WORK.iterdir()):
            raise RuntimeError("supervised work area remains after disconnect")
    finally:
        for fd in (master, slave, descendant, evidence_read, evidence_write):
            if fd != -1:
                os.close(fd)


def main() -> int:
    if sys.platform != "linux" or os.geteuid() != 0 or len(sys.argv) != 2:
        print("usage: sudo python3 integration/claude_supervised_pty_smoke.py /path/to/fixture", file=sys.stderr)
        return 2
    if any(WORK.iterdir()):
        raise RuntimeError("the dedicated work area must start empty")
    command = [str(Path(sys.argv[1]).resolve(strict=True))]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
    if result.returncode != 1 or any(WORK.iterdir()):
        raise RuntimeError("non-PTY launch was not rejected before staging")
    with tempfile.TemporaryDirectory(prefix="tempest-pty-parent-") as directory:
        home = Path(directory) / "synthetic-home"
        config = home / "synthetic-config"
        config.mkdir(parents=True)
        settings = config / "settings.json"
        settings.write_text('{"fixture":"parent"}\n')
        env = dict(os.environ, HOME=str(home), CLAUDE_CONFIG_DIR=str(config))
        fixture(command, env, complete_probe=False)
        fixture(command, env, complete_probe=True)
        if settings.read_text() != '{"fixture":"parent"}\n':
            raise RuntimeError("synthetic parent settings changed")
    print("non-pty=rejected early-disconnect=rejected parent-env=replaced probe=ok descendant=reaped cleanup=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
