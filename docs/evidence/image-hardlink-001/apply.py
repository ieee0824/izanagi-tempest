"""Draft for review. Run only after explicit authorization of this exact allowlist."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
NAMES = ('image-smoke-002', 'image-smoke-001', 'image-smoke-001-v2', 'exec-exposure-001',
         'proc-exposure-001', 'proc-exposure-002', 'proc-exposure-003', 'sidecar-001')
PATHS = tuple(Path('/var/lib/tempest-izanagi-' + name + '/inputs/image.qcow2') for name in NAMES)
DIGEST = '5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7e'
JOURNAL = Path('/tmp/tempest-image-hardlink-001.private.jsonl')


def metadata(s):
    return {'device': s.st_dev, 'inode': s.st_ino, 'nlink': s.st_nlink,
            'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
            'bytes': s.st_size, 'blocks_512': s.st_blocks,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns}


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def open_directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
            s = os.fstat(fd)
            assert s.st_uid == 0 and s.st_mode & 0o022 == 0
        return fd
    except BaseException:
        os.close(fd)
        raise


def verify_preserved():
    spec = importlib.util.spec_from_file_location('tree', REPO / 'docs/evidence/runtime-reservation-001/tree_manifest.py')
    tree = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tree)
    baseline = json.loads(Path('/var/lib/tempest-izanagi-runtime-reservation-001/baseline.private.json').read_text())
    assert tree.inventory('/var/lib/tempest-izanagi-runtime-seed-loss-001') == baseline
    spec = importlib.util.spec_from_file_location('base', REPO / 'docs/evidence/runtime-normal-001/collect_result.py')
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    # Content/owner/mode verification only; this does not assert old physical identities.
    for snapshot in Path('/var/lib').glob('tempest-*/snapshot.json'):
        rows = json.loads(snapshot.read_text())['files']
        if all('type' in row for row in rows):
            base.verify_snapshot(snapshot.parent)
        else:
            for row in rows:
                path = Path(row['path'])
                metadata_now = path.lstat()
                assert stat.S_ISREG(metadata_now.st_mode)
                assert base.sha(path) == row['sha256']
                assert (metadata_now.st_uid, metadata_now.st_gid, stat.S_IMODE(metadata_now.st_mode)) == (row['uid'], row['gid'], int(row['mode'], 8))
    for document in REPO.glob('docs/*_RESULT.json'):
        value = json.loads(document.read_text())
        for path, receipt in value.get('files', {}).items():
            if isinstance(receipt, dict) and 'sha256' in receipt:
                assert base.sha(path) == receipt['sha256']
    return {'seed_loss_full_tree_unchanged': True, 'snapshot_content_owner_mode_verified': True,
            'public_result_file_hashes_verified': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true', help='Authorized mutation; never implicit')
    parser.add_argument('--authorization-message', required=True, help='Previously verified room authorization reference; not proof by itself')
    args = parser.parse_args()
    assert args.apply and os.getuid() == 0
    os.umask(0o077)
    assert subprocess.run(['pgrep', '-u', '999'], capture_output=True).returncode == 1
    # Exclusive journal means a partial run cannot be retried automatically.
    with JOURNAL.open('x') as journal:
        def record(value):
            journal.write(json.dumps(value, sort_keys=True) + '\n')
            journal.flush()
            os.fsync(journal.fileno())
        record({'phase': 'preservation_check_started', 'paths': [str(p) for p in PATHS],
                'authorization_message': args.authorization_message,
                'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'physical_identity_exception': ['canonical nlink/ctime', 'seven target inode/nlink/mtime/ctime',
                                                'seven parent directory mtime/ctime'],
                'authorization_scope': 'Reference must be verified before invocation; recording a reference alone grants no authority.'})
        preserved = verify_preserved()
        dirs, files, rows = [], [], []
        try:
            for path in PATHS:
                directory = open_directory(path.parent)
                dirs.append(directory)
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                files.append(fd)
                s = os.fstat(fd)
                assert stat.S_ISREG(s.st_mode)
                assert (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) == (0, 988, 0o440, 1)
                assert not os.listxattr(fd) and digest(fd) == DIGEST
                assert metadata(os.fstat(fd)) == metadata(s)
                rows.append({'path': str(path), 'file': metadata(s), 'parent': metadata(os.fstat(directory)), 'sha256': DIGEST})
            assert len({row['file']['device'] for row in rows}) == 1
            assert len({row['file']['inode'] for row in rows}) == 8
            free_before = shutil.disk_usage(PATHS[0]).free
            record({'phase': 'validated', 'before': rows, 'free_bytes': free_before, 'preserved': preserved})
            for index in range(1, len(PATHS)):
                name = '.image.qcow2.hardlink-001'
                assert metadata(os.stat(PATHS[index].name, dir_fd=dirs[index], follow_symlinks=False)) == rows[index]['file']
                canonical = os.stat(PATHS[0].name, dir_fd=dirs[0], follow_symlinks=False)
                assert (canonical.st_dev, canonical.st_ino, canonical.st_nlink) == (rows[0]['file']['device'], rows[0]['file']['inode'], index)
                record({'phase': 'link_pending', 'target': str(PATHS[index])})
                os.link(PATHS[0].name, name, src_dir_fd=dirs[0], dst_dir_fd=dirs[index], follow_symlinks=False)
                linked = os.stat(name, dir_fd=dirs[index], follow_symlinks=False)
                assert (linked.st_dev, linked.st_ino) == (canonical.st_dev, canonical.st_ino)
                assert metadata(os.stat(PATHS[index].name, dir_fd=dirs[index], follow_symlinks=False)) == rows[index]['file']
                os.replace(name, PATHS[index].name, src_dir_fd=dirs[index], dst_dir_fd=dirs[index])
                os.fsync(dirs[index])
                record({'phase': 'replaced', 'target': str(PATHS[index]), 'after': metadata(os.stat(PATHS[index].name, dir_fd=dirs[index], follow_symlinks=False)), 'parent_after': metadata(os.fstat(dirs[index]))})
            for fd in files:
                os.close(fd)
            files.clear()
            after = []
            for path in PATHS:
                s = path.lstat()
                assert (s.st_ino, s.st_nlink, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (rows[0]['file']['inode'], 8, 0, 988, 0o440)
                with path.open('rb') as stream:
                    assert hashlib.file_digest(stream, 'sha256').hexdigest() == DIGEST
                after.append({'path': str(path), 'file': metadata(s)})
            record({'phase': 'completed', 'after': after, 'preserved': verify_preserved(),
                    'free_before': free_before, 'free_after': shutil.disk_usage(PATHS[0]).free})
        finally:
            for fd in files + dirs:
                os.close(fd)
    print('Completed exact allowlist; physical identity exception recorded; old result documents unchanged.')


if __name__ == '__main__':
    main()
