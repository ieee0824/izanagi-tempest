"""Check and pass the exact bytes of a single fixed synthetic MCP config."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


NAME = "mcp.json"
FIXED_BYTES = (
    b'{"mcpServers":{"izanagi":{"type":"stdio",'
    b'"command":"/usr/local/libexec/tempest/izanagi-mcp-fixture","args":[]}}}'
)
EXPECTED = json.loads(FIXED_BYTES)
EXPECTED_DIGEST = hashlib.sha256(FIXED_BYTES).digest()
LIMIT = 4096
CHILD = "import os, sys; sys.stdout.buffer.write(os.fsencode(sys.argv[1]))"


class Rejected(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate key")
        result[key] = value
    return result


def prepare_args(directory):
    details = os.fstat(directory)
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
        raise Rejected("directory metadata")
    try:
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError as error:
        raise Rejected("missing config") from error
    except OSError as error:
        raise Rejected("unreadable config") from error
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
            raise Rejected("file metadata")
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > LIMIT:
        raise Rejected("config too large")
    if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or len(raw) != before.st_size):
        raise Rejected("config changed during read")
    try:
        settings = json.loads(raw, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise Rejected("invalid JSON") from error
    if settings != EXPECTED:
        raise Rejected("unexpected MCP configuration")
    if hashlib.sha256(raw).digest() != EXPECTED_DIGEST:
        raise Rejected("digest mismatch")
    return (os.fsencode(sys.executable), b"-I", b"-B", b"-c", CHILD.encode(), raw)


def write_config(path, contents):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(contents)


def case(root, name, contents, reason, alter=None):
    folder = root / name
    folder.mkdir(mode=0o700)
    path = folder / NAME
    if contents is not None:
        write_config(path, contents)
    if alter is not None:
        alter(path)
    directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    launches = 0
    try:
        args = prepare_args(directory)
    except Rejected as error:
        if str(error) != reason:
            raise RuntimeError(f"{name}: wrong rejection: {error}") from error
    else:
        if reason is not None:
            raise RuntimeError(f"{name}: unexpected admission")
        # Replace the source after validation. The child must still see the saved bytes.
        replacement = folder / "replacement"
        write_config(replacement, b'{"mcpServers":{}}')
        replacement.replace(path)
        child = subprocess.run(args, check=True, capture_output=True, timeout=5, env={})
        launches += 1
        if child.stdout != FIXED_BYTES:
            raise RuntimeError("child received different config bytes")
    finally:
        os.close(directory)
    return {"case": name, "rejected": reason, "launches": launches}


def main():
    if len(sys.argv) != 1 or not sys.platform.startswith("linux"):
        raise SystemExit("fixed Linux fixture takes no arguments")
    if os.geteuid() != 0:
        raise SystemExit("run as root to exercise the synthetic owner mismatch")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="tempest-fixed-mcp-config-") as directory:
        root = Path(directory)
        result = [
            case(root, "fixed", FIXED_BYTES, None),
            case(root, "missing", None, "missing config"),
            case(root, "extra", FIXED_BYTES.replace(b'"izanagi":', b'"extra":{},"izanagi":'),
                 "unexpected MCP configuration"),
            case(root, "duplicate", FIXED_BYTES.replace(b'"izanagi":', b'"izanagi":{},"izanagi":'),
                 "duplicate key"),
            case(root, "transport", FIXED_BYTES.replace(b'"stdio"', b'"http"'),
                 "unexpected MCP configuration"),
            case(root, "arguments", FIXED_BYTES.replace(b'"args":[]', b'"args":["extra"]'),
                 "unexpected MCP configuration"),
            case(root, "environment", FIXED_BYTES.replace(b'"args":[]', b'"args":[],"env":{"X":"1"}'),
                 "unexpected MCP configuration"),
            case(root, "digest", FIXED_BYTES + b"\n", "digest mismatch"),
            case(root, "oversized", b" " * (LIMIT + 1), "config too large"),
            case(root, "permission", FIXED_BYTES, "file metadata", lambda path: path.chmod(0o644)),
            case(root, "owner", FIXED_BYTES, "file metadata", lambda path: os.chown(path, 65534, -1)),
            case(root, "symlink", None, "unreadable config",
                 lambda path: path.symlink_to(root / "digest" / NAME)),
        ]
    if root.exists():
        raise RuntimeError("fixture directory was not removed")
    print(json.dumps({"cases": result, "recovered": True}))


if __name__ == "__main__":
    main()
