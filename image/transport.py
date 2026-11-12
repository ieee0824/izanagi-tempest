"""Host-only private 9p mailbox preparation and authenticated reply decoding."""
import base64
import json
import os
from pathlib import Path
import secrets
import stat
import struct
import subprocess
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPLY_SIZE = 65536


def mapped_metadata(path, mode):
    """QEMU mapped-xattr metadata; never fall back to an agent-readable mapping."""
    for field, value in [('uid', 0), ('gid', 0), ('mode', mode)]:
        # QEMU uses host sizeof(mode_t): Darwin is 16-bit, Linux 32-bit.
        data = struct.pack('<H' if sys.platform == 'darwin' and field == 'mode' else '<I', value)
        if sys.platform == 'darwin':
            subprocess.run(['/usr/bin/xattr', '-wx', 'user.virtfs.' + field, data.hex(), str(path)], check=True)
        else:
            os.setxattr(path, 'user.virtfs.' + field, data)


class Mailbox:
    def __init__(self, workspace):
        self.workspace = Path(workspace)
        self.workspace.mkdir(mode=0o700, exist_ok=False)
        mapped_metadata(self.workspace, stat.S_IFDIR | 0o755)
        self.inbox = self.workspace / '.tempest-control'
        self.inbox.mkdir(mode=0o700)
        mapped_metadata(self.inbox, stat.S_IFDIR | 0o700)

    def prepare(self, operation, **fields):
        request_id = secrets.token_hex(16)
        key = AESGCM.generate_key(bit_length=256)
        payload = {**fields, 'version': 1, 'id': request_id, 'operation': operation,
                   'reply_key': base64.b64encode(key).decode()}
        encoded = json.dumps(payload, separators=(',', ':')).encode()
        if len(encoded) > 8 * 1024 * 1024:
            raise ValueError('mailbox request exceeds 8 MiB')
        # Keep plaintext private even before owner xattrs are applied (host UID may
        # equal the guest actor UID). The consumer watches only *.json.
        temporary = self.inbox / (request_id + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        mapped_metadata(temporary, stat.S_IFREG | 0o600)
        path = self.inbox / (request_id + '.json')
        os.rename(temporary, path)
        return Request(path, request_id, operation, key)


class Request:
    def __init__(self, path, request_id, operation, key):
        self.path, self.id, self.operation, self.key = path, request_id, operation, key

    @property
    def guest_path(self):
        return '/workspace/.tempest-control/' + self.id + '.json'

    def decode(self, frame):
        value = json.loads(frame)
        if value.get('version') != 1 or value.get('id') != self.id:
            raise ValueError('reply unavailable or mismatched')
        nonce = base64.b64decode(value['nonce'], validate=True)
        data = base64.b64decode(value['ciphertext'], validate=True)
        if len(nonce) != 12 or len(data) != REPLY_SIZE + 16:
            raise ValueError('invalid reply size')
        aad = ('tempest-mailbox-v1:' + self.id + ':' + self.operation).encode()
        plaintext = AESGCM(self.key).decrypt(nonce, data, aad)
        return json.loads(plaintext)

    def remove(self):
        self.path.unlink(missing_ok=True)
