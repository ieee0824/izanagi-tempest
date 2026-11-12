#!/usr/bin/env python3
"""Private pipe companion: reuse the verified mailbox mapping and reply codec.

No VM lifecycle, CLI execution, retries, or policy decisions live here.
"""
import json
import base64
import os
import stat
from pathlib import Path
import sys
import cryptography

sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport import Mailbox, mapped_metadata

LIMIT = 8 * 1024 * 1024


def serve(workspace):
    box = Mailbox(workspace)
    probe = box.workspace / '.tempest-readonly-probe'
    probe.write_bytes(b'TEMPEST-PUBLIC-READONLY-CANARY')
    probe.chmod(0o600)
    mapped_metadata(probe, stat.S_IFREG | 0o666)
    pending = None
    print(json.dumps({'ok': True, 'result': {'ready': True, 'python_version': sys.version.split()[0],
                                           'cryptography_version': cryptography.__version__}}), flush=True)
    try:
        while line := sys.stdin.buffer.readline(LIMIT + 1):
            if len(line) > LIMIT or not line.endswith(b'\n'):
                raise ValueError('invalid_frame')
            message = json.loads(line)
            operation = message.get('command')
            if operation == 'prepare':
                if pending is not None or set(message) != {'command', 'operation', 'fields'}:
                    raise ValueError('invalid_phase')
                if message['operation'] not in {'ping', 'claim', 'attest', 'seed', 'probe', 'seal', 'export', 'fetch'}:
                    raise ValueError('invalid_operation')
                pending = box.prepare(message['operation'], **message['fields'])
                result = {'guest_path': pending.guest_path}
            elif operation == 'decode':
                if pending is None or set(message) != {'command', 'frame'}:
                    raise ValueError('invalid_phase')
                result = pending.decode(message['frame'])
                if pending.operation == 'fetch' and result.get('ok'):
                    fields = result['result']
                    fields['data_hex'] = base64.b64decode(fields.pop('data_base64'), validate=True).hex()
                pending.remove()
                pending = None
            else:
                raise ValueError('invalid_command')
            print(json.dumps({'ok': True, 'result': result}, separators=(',', ':')), flush=True)
    finally:
        probe.unlink(missing_ok=True)
        if pending is not None:
            pending.remove()


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) != 2:
            raise ValueError('invalid_arguments')
        serve(Path(sys.argv[1]))
    except Exception:
        # Input, keys, paths, and exception details never enter diagnostics.
        print('{"ok":false,"error":"mailbox_companion_failed"}', flush=True)
        sys.exit(1)
