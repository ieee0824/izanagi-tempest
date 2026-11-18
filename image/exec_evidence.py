"""Private evidence for host-observed exec streams; never publish marker values."""
from collections import Counter
import json
import os
from pathlib import Path
import subprocess


class MarkerLeak(RuntimeError):
    pass


def contains_marker(path, markers, chunk_bytes=65536):
    needles = [marker.encode() if isinstance(marker, str) else marker for marker in markers]
    if any(not needle for needle in needles):
        raise ValueError('empty marker is not evidence')
    if not needles:
        return False
    overlap = max(map(len, needles)) - 1
    tail = b''
    with Path(path).open('rb') as stream:
        while block := stream.read(chunk_bytes):
            window = tail + block
            if any(needle in window for needle in needles):
                return True
            tail = window[-overlap:] if overlap else b''
    return False


class ExecEvidence:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.directory.chmod(0o700)
        self.rows = []

    def write_private(self, name, content):
        fd = os.open(self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

    def record(self, stdout, stderr, returncode, timed_out, context):
        context = context or {}
        operation = context.get('operation', 'exec')
        if operation not in {'exec', 'ping', 'claim', 'seed', 'probe', 'seal', 'attest', 'export', 'fetch'}:
            raise ValueError('unexpected evidence context')
        row = {'id': len(self.rows) + 1, 'operation': operation,
               'expected_error': context.get('expected_error', False),
               'returncode': returncode, 'timed_out': timed_out, 'streams': []}
        for kind, value in [('stdout', stdout), ('stderr', stderr)]:
            data = value.encode('utf-8', 'surrogateescape') if isinstance(value, str) else value or b''
            name = f'exec-{row["id"]:06d}.{kind}'
            self.write_private(name, data)
            row['streams'].append({'file': name, 'bytes': len(data)})
        self.write_private(f'exec-{row["id"]:06d}.json', (json.dumps(row) + '\n').encode())
        self.rows.append(row)
        return row

    def leaks(self, rows, markers):
        return [item['file'] for row in rows for item in row['streams']
                if contains_marker(self.directory / item['file'], markers)]

    def capture(self, invoke, markers, context=None):
        try:
            result = invoke()
        except subprocess.TimeoutExpired as error:
            row = self.record(error.stdout, error.stderr, None, True, context)
            if self.leaks([row], markers):
                raise MarkerLeak('private marker found in captured exec streams') from None
            raise
        row = self.record(result.stdout, result.stderr, result.returncode, False, context)
        if self.leaks([row], markers):
            raise MarkerLeak('private marker found in captured exec streams')
        return result

    def summary(self, markers):
        leaked = self.leaks(self.rows, markers)
        return {'passed': bool(self.rows) and not leaked, 'executions': len(self.rows),
                'streams': sum(len(row['streams']) for row in self.rows),
                'timed_out': sum(row['timed_out'] for row in self.rows),
                'operations': dict(Counter(row['operation'] for row in self.rows)),
                'expected_error_reads': sum(bool(row['expected_error']) for row in self.rows),
                'leaked_streams': leaked,
                'scope': 'captured host CLI exec stdout/stderr only; not native PIPEs or complete proc lifetime'}
