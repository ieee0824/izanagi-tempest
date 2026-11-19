"""Validate the settings file for the pre-login Claude Code dummy fixture."""

import argparse
import json
import os
import stat
from pathlib import Path

MAX_SETTINGS_BYTES = 4096


def initialize_settings(directory: Path, owner_uid: int) -> None:
    if owner_uid != os.geteuid():
        raise ValueError("initialize as the fixture owner")
    directory.mkdir(mode=0o700)
    root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(
            "settings.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=root_fd,
        )
        with os.fdopen(fd, "wb") as settings:
            settings.write(b"{}\n")
    finally:
        os.close(root_fd)


def check_settings(directory: Path, owner_uid: int) -> dict:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    root_fd = os.open(directory, flags | os.O_DIRECTORY)
    try:
        root = os.fstat(root_fd)
        if root.st_uid != owner_uid or stat.S_IMODE(root.st_mode) != 0o700:
            raise ValueError("settings directory must belong to the fixture owner and have mode 0700")
        if os.listdir(root_fd) != ["settings.json"]:
            raise ValueError("unexpected entries in the pre-login dummy fixture")
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


    return {
        "root": {"kind": "directory", "uid": root.st_uid, "mode": "0700"},
        "settings.json": {"kind": "regular", "uid": metadata.st_uid, "mode": "0600"},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--owner-uid", type=int, required=True)
    parser.add_argument("--initialize", action="store_true", help="create a new dummy directory")
    parser.add_argument("--audit", action="store_true", help="print validated metadata as JSON")
    args = parser.parse_args()
    try:
        if args.initialize:
            initialize_settings(args.directory, args.owner_uid)
        report = check_settings(args.directory, args.owner_uid)
        if args.audit:
            print(json.dumps(report, sort_keys=True))
    except (OSError, ValueError) as error:
        parser.exit(1, f"fixture settings rejected: {error}\n")


if __name__ == "__main__":
    main()
