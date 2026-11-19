"""Fixed fixture image build caller; do not execute before snapshot/command audit."""
import os
from pathlib import Path
import subprocess

ROOT='/var/lib/tempest-izanagi-delivery-race-build-001'
EXEC=[
    '/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME='+ROOT+'/work/home','TMPDIR='+ROOT+'/work/tmp',
    'PACKER_CACHE_DIR='+ROOT+'/work/cache','PACKER_PLUGIN_PATH='+ROOT+'/inputs/plugins',
    'CHECKPOINT_DISABLE=1','PACKER_LOG=1','PACKER_LOG_PATH='+ROOT+'/work/packer-debug.log',
    ROOT+'/inputs/packer','build','-color=false','-on-error=abort',
    '-var-file='+ROOT+'/inputs/definition/packer/tempest.pkrvars.json',
    ROOT+'/inputs/definition/packer/debian.pkr.hcl',
]
COMMAND=[
    'sudo','-n','/usr/bin/systemd-run','--unit=tempest-izanagi-delivery-race-build-001','--wait','--pipe',
    '--property=Type=exec','--property=User=tempest-kvm','--property=Group=tempest-kvm',
    '--property=SupplementaryGroups=kvm','--property=KillMode=control-group',
    '--property=RuntimeMaxSec=3600s','--property=TimeoutStopSec=10s','--property=SendSIGKILL=yes',
    '--property=Restart=no','--property=UMask=0077','--property=NoNewPrivileges=yes','--property=Delegate=no',
    '--property=ExecStopPost=/usr/bin/python3 -I -B '+ROOT+'/inputs/record_exit.py',
    '--working-directory='+ROOT+'/work',*EXEC,
]

if __name__ == '__main__':
    os.umask(0o077)
    descriptor=os.open('/tmp/tempest-delivery-race-build-001.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as log:
        result=subprocess.run(COMMAND,stdout=log,stderr=subprocess.STDOUT)
    raise SystemExit(result.returncode)
