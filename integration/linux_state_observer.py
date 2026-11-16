"""Fixed dirfd observer for the independent root state-isolation fixture."""
import hashlib
import os
import stat

CATEGORIES = ('settings', 'hooks', 'plugins', 'mcp', 'session', 'project',
              'cache', 'lock', 'backup')
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def identity(metadata):
    return metadata.st_dev, metadata.st_ino


def observe_home(run_fd, previous=None):
    run = os.fstat(run_fd)
    if not stat.S_ISDIR(run.st_mode) or run.st_uid != 0 or stat.S_IMODE(run.st_mode) != 0o700:
        raise ValueError('run_owner_mode')
    home_fd = os.open('host-home', DIRECTORY_FLAGS, dir_fd=run_fd)
    try:
        home = os.fstat(home_fd)
        if home.st_uid != 0 or stat.S_IMODE(home.st_mode) != 0o700:
            raise ValueError('home_owner_mode')
        entries = []
        for category in CATEGORIES:
            fd = os.open(category, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=home_fd)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                        or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
                    raise ValueError('canary_owner_mode_type')
                content = os.read(fd, 16)
                after = os.fstat(fd)
                if (content != b'dummy-host-home' or os.read(fd, 1)
                        or identity(before) != identity(after)
                        or before.st_size != 15 or after.st_size != 15):
                    raise ValueError('canary_content_identity')
                entries.append((category, identity(after), hashlib.sha256(content).hexdigest()))
            finally:
                os.close(fd)
        result = {'run_identity': identity(run), 'home_identity': identity(home),
                  'entries': entries}
        if previous is not None and result != previous:
            raise ValueError('host_generation_changed')
        return result
    finally:
        os.close(home_fd)
