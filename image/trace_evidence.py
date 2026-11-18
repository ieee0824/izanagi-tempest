"""Check a fixed dummy file-open probe in pinned Izanagi event logs."""
import hashlib
import json
import re


EVENT = re.compile(r'^\[[^\]\r\n]+\] INFO pid=(\d+) [^:\r\n]+: (open|openat)\((.*)\) → ')


def trace_probe_evidence(paths, pid, path):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError('invalid trace probe PID')
    if not path.startswith('/tmp/tempest-trace-'):
        raise ValueError('invalid trace probe path')
    quoted = json.dumps(path)
    matches = 0
    files = []
    for source in paths:
        data = source.read_bytes()
        files.append({'name': source.name, 'sha256': hashlib.sha256(data).hexdigest(),
                      'bytes': len(data)})
        for line in data.decode('utf-8', errors='replace').splitlines():
            event = EVENT.match(line)
            if event and int(event[1]) == pid and quoted in event[3]:
                matches += 1
    if not matches:
        raise RuntimeError('no file-open trace event for the dummy probe PID/path')
    return {'passed': True, 'pid': pid, 'path': path, 'matched_open_events': matches,
            'files': files, 'scope': 'one dummy PID/path; not full route coverage'}
