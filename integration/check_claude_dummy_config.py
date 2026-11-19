"""Validate the settings file for the pre-login Claude Code dummy fixture."""

import argparse
import json
import os
import stat
from pathlib import Path

MAX_SETTINGS_BYTES = 4096


def check_settings(directory: Path, owner_uid: int) -> None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    root_fd = os.open(directory, flags | os.O_DIRECTORY)
    try:
        root = os.fstat(root_fd)
        if root.st_uid != owner_uid or stat.S_IMODE(root.st_mode) != 0o700:
            raise ValueError("settings directory must belong to the fixture owner and have mode 0700")
        settings_fd = os.open("settings.json", flags | os.O_NONBLOCK, dir_fd=root_fd)
        with os.fdopen(settings_fd, "rb") as settings:
            metadata = os.fstat(settings.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != owner_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ValueError("settings.json must be a regular, fixture-owned file with mode 0600")
            data = settings.read(MAX_SETTINGS_BYTES + 1)
            if len(data) > MAX_SETTINGS_BYTES:
                raise ValueError("settings.json exceeds fixture size limit")
    finally:
        os.close(root_fd)
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):
        raise ValueError("settings.json is invalid JSON") from None
    if value != {}:
        raise ValueError("settings.json must be an empty object for the pre-login dummy fixture")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--owner-uid", type=int, required=True)
    args = parser.parse_args()
    try:
        check_settings(args.directory, args.owner_uid)
    except (OSError, ValueError) as error:
        parser.exit(1, f"fixture settings rejected: {error}\n")


if __name__ == "__main__":
    main()
