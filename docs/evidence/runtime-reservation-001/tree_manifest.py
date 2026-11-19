"""Private full-tree inventory. Atime is excluded because inspection reads files."""
import hashlib
import json
import os
from pathlib import Path
import stat


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    root = Path(root)
    rows = []
    for path in [root, *sorted(root.rglob('*'))]:
        before = path.lstat()
        mode = before.st_mode
        row = {'path': str(path.relative_to(root)), 'uid': before.st_uid, 'gid': before.st_gid,
               'mode': stat.S_IMODE(mode), 'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns,
               'inode': before.st_ino, 'device': before.st_dev, 'links': before.st_nlink}
        row['xattrs'] = {name: hashlib.sha256(os.getxattr(path, name, follow_symlinks=False)).hexdigest()
                         for name in sorted(os.listxattr(path, follow_symlinks=False))}
        if stat.S_ISLNK(mode):
            row.update(type='symlink', target=os.readlink(path))
        elif stat.S_ISDIR(mode):
            row['type'] = 'directory'
        elif stat.S_ISREG(mode):
            row.update(type='file', bytes=before.st_size, sha256=digest(path))
        else:
            raise ValueError('unexpected special file in preserved tree')
        after = path.lstat()
        assert (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        rows.append(row)
    encoded = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
    return {'rows': rows, 'sha256': hashlib.sha256(encoded).hexdigest(), 'entries': len(rows),
            'scope': 'content, ownership, mode, identity, timestamps except atime, symlink targets and xattr hashes'}
