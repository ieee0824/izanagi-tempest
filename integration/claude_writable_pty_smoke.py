"""Verify removal, explicit retention and generation independence on Linux."""

import os
from pathlib import Path
import stat
import sys
import tempfile

from claude_supervised_pty_smoke import WORK, fixture

CONFIG = Path("/var/lib/tempest-claude-config-fixture")
REMOVED = b"offline writable PTY: recovered; synthetic configuration removed\n"
RETAINED = b"offline writable PTY: recovered; synthetic configuration retained\n"


def snapshot():
    return sorted(CONFIG.iterdir())


def verify_retained(path: Path) -> tuple[int, int]:
    directory = path.lstat()
    assert stat.S_ISDIR(directory.st_mode)
    assert (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode)) == (999, 988, 0o700)
    assert {entry.name for entry in path.iterdir()} == {"settings.json", "write-probe"}
    for entry in path.iterdir():
        info = entry.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink) == (999, 988, 0o600, 1)
        expected = b"{}\n" if entry.name == "settings.json" else b""
        assert entry.read_bytes() == expected
    return directory.st_dev, directory.st_ino


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or len(sys.argv) != 2:
        return 2
    if snapshot() or any(WORK.iterdir()):
        raise RuntimeError("dedicated fixture parents must start empty")
    command = [str(Path(sys.argv[1]).resolve(strict=True))]
    with tempfile.TemporaryDirectory(prefix="tempest-writable-parent-") as directory:
        home = Path(directory) / "home"
        config = home / ".claude"
        config.mkdir(parents=True)
        settings = config / "settings.json"
        settings.touch()
        env = dict(os.environ, HOME=str(home), CLAUDE_CONFIG_DIR=str(config))
        fixture(command, env, complete_probe=False, success=REMOVED)
        assert not snapshot()
        fixture(command, env, complete_probe=True, success=REMOVED)
        assert not snapshot()
        fixture([*command, "--retain-fixture"], env, complete_probe=True, success=RETAINED)
        (retained,) = snapshot()
        identity = verify_retained(retained)
        fixture(command, env, complete_probe=True, success=REMOVED)
        assert snapshot() == [retained] and verify_retained(retained) == identity
        assert settings.stat().st_size == 0 and list(config.iterdir()) == [settings]
        for entry in retained.iterdir():
            entry.unlink()
        retained.rmdir()
        assert not snapshot() and not any(WORK.iterdir())
    print("owner-write=ok other-uid-denied=ok early-disconnect=ok remove=ok retain=ok independent-generation=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
