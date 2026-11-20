import os
import re
from pathlib import Path
import stat


def check_placement(supervisor, image):
    matches = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            executable = (proc / 'exe').readlink().name
            if not executable.startswith('qemu-system-'):
                continue
            raw = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            args = (proc / 'cmdline').read_bytes().split(b'\0')
            if int(raw[2]) != supervisor:
                continue
            matches.append((proc, raw[19], args))
        except (FileNotFoundError, ProcessLookupError):
            continue
    if len(matches) != 1:
        raise RuntimeError(f'expected one QEMU in trial process group, got {len(matches)}')
    proc, started, args = matches[0]
    if b'restrict=on' not in b' '.join(args) or not any(
        arg in (b'2048', b'2G', b'2048M') for arg in args
    ):
        raise RuntimeError('QEMU restrictions or RAM mismatch')
    vfs = os.statvfs('/tmp')
    if (vfs.f_blocks * vfs.f_frsize) != 512 * 1024**2:
        raise RuntimeError('unexpected tmpfs cap')
    mount_device = os.stat('/tmp').st_dev
    base = image.stat()
    overlays = set()
    has_base = False
    for fd in (proc / 'fd').iterdir():
        try:
            metadata = fd.stat()
            if not stat.S_ISREG(metadata.st_mode):
                continue
            info = (proc / 'fdinfo' / fd.name).read_text().splitlines()
            flags = int(next(line.split()[1] for line in info if line.startswith('flags:')), 8)
            mode = flags & os.O_ACCMODE
            if (metadata.st_dev, metadata.st_ino) == (base.st_dev, base.st_ino):
                if mode != os.O_RDONLY:
                    raise RuntimeError('base image writable')
                has_base = True
                continue
            if mode == os.O_RDONLY:
                continue
            if metadata.st_dev != mount_device:
                raise RuntimeError('writable regular QEMU FD outside capped mount')
            with fd.open('rb', buffering=0) as stream:
                if stream.read(4) == b'QFI\xfb':
                    overlays.add((metadata.st_ino, str(fd.readlink())))
        except FileNotFoundError:
            continue
    if not has_base or len(overlays) != 1:
        raise RuntimeError(f'expected readonly base and one capped qcow2 overlay, got {has_base=} overlay_count={len(overlays)}')
    overlay = next(iter(overlays))[1]
    if not overlay.startswith('/tmp/'):
        raise RuntimeError('overlay path outside dedicated /tmp')
    forwards = re.findall(rb'hostfwd=tcp:127\.0\.0\.1:(\d+)-:9001(?:[, ]|$)', b' '.join(args))
    if len(forwards) != 1:
        raise RuntimeError("expected one fixed management port")
    return {'port': int(forwards[0]), 'pid': int(proc.name), 'starttime': started, 'overlay': overlay,
            'base_readonly': has_base, 'cap_bytes': 512 * 1024**2}
