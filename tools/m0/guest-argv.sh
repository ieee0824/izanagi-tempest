#!/bin/sh
set -eu
python3 - <<'INNER'
import subprocess,json,os
from pathlib import Path
marker='TEMPEST-M2-DUMMY-ARGV-20261111'
p=subprocess.Popen(['/bin/sh','-c','sleep 2',marker])
try:
 cmdline=Path(f'/proc/{p.pid}/cmdline').read_bytes()
 print(json.dumps({'kind':'m2_argv_probe','uid':os.getuid(),'child_cmdline_marker_visible':marker.encode() in cmdline,'parent_shell':True}))
finally:
 p.wait(timeout=5)
INNER
