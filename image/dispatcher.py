#!/usr/bin/python3 -I
"""Root-only, fixed mailbox dispatcher. Delegated by doas, never a shell runner."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

INBOX = Path('/workspace/.tempest-control')
STATE = Path('/run/tempest-control')
NATIVE = '/usr/local/libexec/tempest-guest-native'
CONFIG = '/etc/tempest/guest.json'
MAX_INPUT = 8 * 1024 * 1024
MAX_CHUNK = 32768
ID = re.compile(r'[a-f0-9]{32}\Z')
FILES = {'api.jsonl', 'capture.pcap', 'manifest.json'}


class Rejected(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def private_directory(path, owner=0, create=False):
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == owner and
            stat.S_IMODE(metadata.st_mode) == 0o700, 'unsafe_directory')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_field')
        result[key] = value
    return result


def read_request(path, inbox=INBOX, owner=0):
    require(path.is_absolute() and path.parent == inbox and ID.fullmatch(path.stem) and path.suffix == '.json', 'invalid_request_path')
    private_directory(inbox, owner)
    directory = os.open(inbox, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(directory)
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == owner and
                stat.S_IMODE(metadata.st_mode) == 0o700, 'unsafe_directory')
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == owner and
                    stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= MAX_INPUT, 'unsafe_request_file')
            raw = stream.read(MAX_INPUT + 1)
            require(len(raw) <= MAX_INPUT, 'request_too_large')
    finally:
        os.close(directory)
    payload = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(payload, dict) and payload.get('version') == 1 and payload.get('id') == path.stem, 'invalid_envelope')
    return path.stem, payload


def consume(directory, request_id, owner=0):
    require(ID.fullmatch(request_id), 'invalid_request_id')
    private_directory(directory, owner, create=True)
    try:
        descriptor = os.open(directory / request_id, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise Rejected('request_already_consumed') from None
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(b'consumed\n')
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def authenticate(value, state=STATE):
    require(isinstance(value, str) and len(value) == 64, 'invalid_authorization')
    document = json.loads((state / 'state.json').read_bytes())
    expected = document.get('token_digest')
    require(isinstance(expected, str) and hmac.compare_digest(hashlib.sha256(value.encode()).hexdigest(), expected), 'invalid_authorization')


def file_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fetch(payload, exports):
    export_id = payload.get('export_id')
    name = payload.get('file')
    offset = payload.get('offset', 0)
    size = payload.get('max_bytes', MAX_CHUNK)
    require(isinstance(export_id, str) and ID.fullmatch(export_id) and name in FILES, 'invalid_export_reference')
    require(type(offset) is int and offset >= 0 and type(size) is int and 1 <= size <= MAX_CHUNK, 'invalid_chunk')
    directory = exports / export_id
    private_directory(directory)
    index = json.loads((directory / 'files.json').read_bytes())
    require(name in index, 'export_file_missing')
    descriptor = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        require(os.fstat(stream.fileno()).st_size == index[name]['bytes'] and offset <= index[name]['bytes'], 'export_size_mismatch')
        stream.seek(offset)
        data = stream.read(size)
    return {'export_id': export_id, 'file': name, 'offset': offset,
            'next_offset': offset + len(data), 'total_bytes': index[name]['bytes'],
            'sha256': index[name]['sha256'], 'chunk_sha256': hashlib.sha256(data).hexdigest(),
            'data_base64': base64.b64encode(data).decode()}


def dispatch(request_id, payload):
    operation = payload.get('operation')
    fields = {'claim': set(), 'ping': set(), 'seed': {'setup'}, 'probe': {'probe'},
              'seal': set(), 'export': set(), 'fetch': {'export_id', 'file', 'offset', 'max_bytes'}}
    require(operation in fields, 'unknown_operation')
    require(set(payload) <= {'version', 'id', 'operation', 'authorization', 'reply_key'} | fields[operation], 'unknown_field')
    if operation not in {'claim', 'ping'}:
        authenticate(payload.get('authorization'))
    delivery = STATE / 'delivery'
    private_directory(delivery, create=True)
    consume(delivery / 'consumed', request_id)
    exports = delivery / 'exports'
    private_directory(exports, create=True)
    if operation == 'ping':
        require((STATE / 'control.sock').is_socket(), 'not_ready')
        return {'ready': True}
    if operation == 'fetch':
        return fetch(payload, exports)
    command = [NATIVE, '--config', CONFIG, operation]
    stdin = None
    if operation != 'claim':
        command.append('--token-stdin')
        stdin = (payload['authorization'] + '\n').encode()
    work = delivery / request_id
    private_directory(work, create=True)
    source = None
    if operation in {'seed', 'probe'}:
        field = 'setup' if operation == 'seed' else 'probe'
        require(field in payload, 'input_required')
        source = work / 'input.json'
        write_json(source, payload[field])
        command.append(str(source))
    if operation == 'export':
        command.append(str(exports / request_id))
    try:
        response = subprocess.run(command, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env={'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'}, timeout=240)
    finally:
        if source is not None:
            source.unlink(missing_ok=True)
    require(response.stdout and len(response.stdout) <= 1024 * 1024, 'native_operation_failed')
    result = json.loads(response.stdout)
    require(response.returncode == 0 or (operation == 'export' and result.get('complete') is False), 'native_operation_failed')
    if operation == 'export':
        index = {name: {'bytes': (exports / request_id / name).stat().st_size,
                        'sha256': file_digest(exports / request_id / name)}
                 for name in FILES if (exports / request_id / name).is_file()}
        write_json(exports / request_id / 'files.json', index)
        return {'export_id': request_id, 'files': index, 'complete': result['complete'], 'manifest': result['manifest']}
    return result


REPLY_SIZE = 65536


def reply_key(payload):
    try:
        key = base64.b64decode(payload['reply_key'], validate=True)
    except (KeyError, ValueError, TypeError):
        raise Rejected('invalid_reply_key') from None
    require(len(key) == 32, 'invalid_reply_key')
    return key


def encrypt_reply(request_id, payload, value):
    data = json.dumps(value, separators=(',', ':')).encode()
    if len(data) > REPLY_SIZE:
        data = b'{"ok":false,"error":"reply_too_large_operation_uncertain"}'
    nonce = os.urandom(12)
    aad = ('tempest-mailbox-v1:' + request_id + ':' + payload['operation']).encode()
    encrypted = AESGCM(reply_key(payload)).encrypt(nonce, data.ljust(REPLY_SIZE, b' '), aad)
    return {'version': 1, 'id': request_id, 'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(encrypted).decode()}


def process(path, replies):
    request_id, payload = read_request(path)
    reply_key(payload)
    destination = replies / (request_id + '.json')
    if destination.exists():
        return
    try:
        result = dispatch(request_id, payload)
        value = {'ok': True, 'id': request_id, 'result': result}
    except Rejected as error:
        value = {'ok': False, 'id': request_id, 'error': str(error)}
    except Exception:
        value = {'ok': False, 'id': request_id, 'error': 'delivery_failed_operation_uncertain'}
    # Publish once, only after complete authenticated encryption. Root-only spool.
    temporary = replies / (request_id + '.tmp')
    write_json(temporary, encrypt_reply(request_id, payload, value))
    os.replace(temporary, destination)


def watch():
    deadline = time.monotonic() + 30
    while True:
        try:
            private_directory(STATE)
            require((STATE / 'control.sock').is_socket(), 'not_ready')
            break
        except (OSError, Rejected):
            if time.monotonic() >= deadline:
                raise Rejected('control_not_ready')
            time.sleep(0.1)
    replies = STATE / 'replies'
    private_directory(replies, create=True)
    while True:
        try:
            private_directory(INBOX)
            for path in sorted(INBOX.glob('*.json')):
                try:
                    process(path, replies)
                except Exception:
                    # Malformed/untrusted files never produce diagnostic contents.
                    pass
        except (OSError, Rejected):
            pass  # The read-only workspace mount may arrive after service startup.
        time.sleep(0.1)


def main():
    os.umask(0o077)
    try:
        require(os.geteuid() == 0, 'root_required')
        if sys.argv[1:] == ['--watch']:
            require(Path(__file__).resolve() == Path('/usr/local/libexec/tempest-mailbox'), 'watch_not_delegated')
            watch()
        require(len(sys.argv) == 3 and sys.argv[1] == 'deliver', 'use_deliver_mailbox')
        path = Path(sys.argv[2])
        require(path.parent == INBOX and path.suffix == '.json' and ID.fullmatch(path.stem), 'invalid_request_path')
        # This delegated entry never reads requests or triggers an operation.
        # Known IDs grant access only to padded authenticated ciphertext.
        private_directory(STATE / 'replies')
        response = STATE / 'replies' / (path.stem + '.json')
        with response.open('rb') as stream:
            data = stream.read(100000)
        sys.stdout.buffer.write(data + b'\n')
        return 0
    except Exception:
        print('{"ok":false,"error":"reply_unavailable"}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
