"""Fixed smoke002 caller. Execute only after snapshot/preflight review."""
import os
import subprocess
from pathlib import Path

ROOT = '/var/lib/tempest-izanagi-image-smoke-002'
COMMAND = [
    'sudo', '-n', '/usr/bin/systemd-run', '--unit=tempest-izanagi-image-smoke-002', '--wait', '--pipe',
    '--property=Type=exec', '--property=User=tempest-kvm', '--property=Group=tempest-kvm',
    '--property=SupplementaryGroups=kvm', '--property=KillMode=control-group',
    '--property=RuntimeMaxSec=1800s', '--property=TimeoutStopSec=10s',
    '--property=SendSIGKILL=yes', '--property=Restart=no', '--property=UMask=0077',
    '--property=NoNewPrivileges=yes', '--property=Delegate=no',
    '--property=ExecStopPost=/usr/bin/python3 -I -B ' + ROOT + '/inputs/record_exit.py',
    '--working-directory=' + ROOT + '/work',
    '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'TZ=UTC', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8',
    'HOME=' + ROOT + '/work/home', 'TMPDIR=' + ROOT + '/work/tmp',
    ROOT + '/inputs/python/bin/python', '-I', '-B', ROOT + '/inputs/repo/integration/image_smoke.py',
    '--izanagi', ROOT + '/inputs/izanagi', '--image', ROOT + '/inputs/image.qcow2',
    '--build-inputs', ROOT + '/inputs/build-inputs.json',
    '--offline-artifacts', ROOT + '/inputs/offline-artifacts.json', '--output', ROOT + '/work/output',
]

if __name__ == '__main__':
    os.umask(0o077)
    fd = os.open('/tmp/tempest-image-smoke-002.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as log:
        result = subprocess.run(COMMAND, stdout=log, stderr=subprocess.STDOUT, check=False)
    raise SystemExit(result.returncode)
