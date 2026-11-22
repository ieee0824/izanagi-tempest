"""Refresh only signed revocation freshness, without extending operation authority.

Both host and guest invoke publish() on their independent root-only sources.
Private signing material stays on the host; the guest receives only signed bytes.
"""
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import shutil
import tempfile
import time

from channel import canonical_json
from egress_authority import positive
from egress_generation import (REVOCATION_DOMAIN, no_pending, read_generation, read_private,
                               revision, signed_payload)
from read_snapshot import check_file
from freshness import FreshnessLatch

class RefreshBusy(BlockingIOError):
    """No source mutation occurred; the existing lease may cover a bounded retry."""


FIELDS = {'revision', 'revocation_revision', 'manifest_sha256', 'permit_id', 'target_id',
          'issued_unix_seconds', 'expires_unix_seconds', 'revoked'}


@dataclass(frozen=True)
class Refresh:
    payload: bytes
    signature: bytes


def sign_refresh(root, registration, signer, *, now_unix_ms=None):
    now = time.time_ns() // 1_000_000 if now_unix_ms is None else now_unix_ms
    old = read_generation(root, registration, now)
    issued = now // 1000
    expires = min(issued + 30, old.operation_expires_unix_ms // 1000)
    if expires <= issued:
        raise ValueError('operation deadline reached')
    payload = REVOCATION_DOMAIN + canonical_json(dict(
        revision=registration['generation'], revocation_revision=old.revocation_revision+1,
        manifest_sha256=old.manifest_sha256, permit_id=registration['permit_id'],
        target_id=registration['target_id'], issued_unix_seconds=issued,
        expires_unix_seconds=expires, revoked=False))
    return Refresh(payload, signer.sign(payload))


def validate_refresh(refresh, key, registration, old, now_unix_ms):
    if len(refresh.payload) > 4096:
        raise ValueError('oversized revocation refresh')
    state = signed_payload(refresh.payload, refresh.signature, key, REVOCATION_DOMAIN, FIELDS)
    if (type(state['revision']) is not int or state['revision'] != registration['generation']
            or state['manifest_sha256'] != old.manifest_sha256
            or state['permit_id'] != registration['permit_id'] or state['target_id'] != registration['target_id']
            or state['revoked'] is not False or not positive(state['revocation_revision'])
            or state['revocation_revision'] != old.revocation_revision + 1
            or not positive(state['issued_unix_seconds']) or not positive(state['expires_unix_seconds'])
            or state['issued_unix_seconds'] * 1000 > now_unix_ms
            or not 0 < state['expires_unix_seconds'] - state['issued_unix_seconds'] <= 30
            or not now_unix_ms < state['expires_unix_seconds'] * 1000 <= old.operation_expires_unix_ms):
        raise ValueError('refresh exceeds the existing scope or deadlines')
    return state


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def mark_uncertain(authority):
    path = authority / 'revocation-pending'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    sync_directory(authority)


def publish(root, registration, refresh, *, now_unix_ms=None):
    """Stage first, then switch all freshness files under one publication lock.

    No normal-refresh pending marker is exposed. Readers unable to take SH use
    only their already valid lease, without renewal. A failed partial switch
    creates the irreversible uncertainty marker before releasing EX.
    """
    now = time.time_ns() // 1_000_000 if now_unix_ms is None else now_unix_ms
    old = read_generation(root, registration, now)
    authority, publication = root / 'claude-login-authority', root / 'claude-login-publication'
    if (sha256(refresh.payload).hexdigest() == old.revocation_state_sha256
            and read_private(authority / 'revocation-signature', 64) == refresh.signature):
        return old.revocation_revision
    state = validate_refresh(refresh, read_private(authority / 'revocation-key', 32), registration, old, now)
    files = {'revocation-state': refresh.payload, 'revocation-signature': refresh.signature,
             'revocation-committed': canonical_json(dict(revision=state['revocation_revision'],
                                                        state_sha256=sha256(refresh.payload).hexdigest())),
             'revocation-minimum': str(state['revocation_revision']).encode('ascii')}
    staged = Path(tempfile.mkdtemp(prefix='.refresh-', dir=authority))
    try:
        for name, data in files.items():
            descriptor = os.open(staged / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        sync_directory(staged)
        lock = publication / 'lock'
        check_file(lock)
        with lock.open('rb') as held:
            try:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RefreshBusy('publication readers still active') from error
            no_pending(publication / 'pending')
            no_pending(authority / 'revocation-pending')
            if (sha256(read_private(authority / 'revocation-state', 4096)).hexdigest() != old.revocation_state_sha256
                    or revision(authority / 'revocation-minimum') > old.revocation_revision):
                raise ValueError('revocation changed during refresh preparation')
            current_now = time.time_ns() // 1_000_000 if now_unix_ms is None else now_unix_ms
            if current_now >= min(old.revocation_expires_unix_ms, old.operation_expires_unix_ms,
                                  state['expires_unix_seconds'] * 1000):
                raise ValueError('refresh was not committed before the old deadline')
            changed = False
            try:
                for name in files:
                    os.replace(staged / name, authority / name)
                    changed = True
                sync_directory(authority)
            except BaseException:
                if changed:
                    mark_uncertain(authority)
                raise
        return state['revocation_revision']
    finally:
        shutil.rmtree(staged)


def run_updater(root, registration, signer, deliver, stop_event, operation_deadline,
                *, interval=10.0, clock=time.monotonic):
    """Host-only driver. deliver(refresh, deadline) must use bounded root transport.

    The operation cap is sampled once before all source I/O. Neither successful
    publications nor a changed wall clock can extend it. Any failed delivery
    quarantines the host source so the broker/relay stop rather than running on.
    """
    started = clock()
    wall = time.time_ns() // 1_000_000
    original = read_generation(root, registration, wall)
    hard = min(operation_deadline, started + (original.operation_expires_unix_ms-wall)/1000)
    if not 0 < interval <= 10:
        raise ValueError('invalid revocation refresh interval')
    freshness = FreshnessLatch(original.revocation_revision, original.revocation_state_sha256,
        started + (original.revocation_expires_unix_ms-wall)/1000, hard, clock)
    try:
        while not stop_event.is_set() and clock() < hard:
            old_deadline = freshness.deadline()
            if old_deadline is None:
                raise TimeoutError('publisher missed the previous signed freshness')
            delivery_deadline = min(hard, old_deadline, clock()+10)
            source = read_generation(root, registration, time.time_ns() // 1_000_000)
            if (source.manifest_sha256 != original.manifest_sha256
                    or source.operation_expires_unix_ms != original.operation_expires_unix_ms
                    or source.approved_ips_revision != original.approved_ips_revision
                    or source.addresses != original.addresses):
                raise ValueError('operation source changed during refresh')
            signed = sign_refresh(root, registration, signer)
            while True:
                if clock() >= delivery_deadline:
                    raise TimeoutError('refresh transaction exceeded its deadline')
                try:
                    publish(root, registration, signed)
                    break
                except RefreshBusy:
                    if stop_event.wait(min(0.01, max(0, delivery_deadline-clock()))):
                        return
            # Even a delayed successful file switch must not revive this updater.
            source_started = clock()
            source_wall = time.time_ns() // 1_000_000
            current = read_generation(root, registration, source_wall)
            if not freshness.observe(current.revocation_revision, current.revocation_state_sha256,
                    current.revocation_expires_unix_ms, source_wall, source_started):
                raise TimeoutError('publisher freshness cannot resume after expiry')
            if clock() >= delivery_deadline:
                raise TimeoutError('refresh transaction completed too late')
            deliver(signed, delivery_deadline)
            if clock() >= delivery_deadline:
                raise TimeoutError('revocation delivery exceeded its deadline')
            stop_event.wait(min(interval, max(0, hard-clock())))
    except BaseException:
        mark_uncertain(root / 'claude-login-authority')
        raise


def encode_refresh(refresh):
    import base64
    return canonical_json(dict(payload=base64.b64encode(refresh.payload).decode('ascii'),
                               signature=refresh.signature.hex()))


def publish_stdin(encoded):
    """Fixed guest root entry; no filesystem path or scope comes from stdin."""
    import base64
    import json
    from channel import unique_fields
    from read_snapshot import read_json
    root = Path('/etc/tempest')
    if len(encoded) > 8192:
        raise ValueError('oversized signed refresh input')
    envelope = json.loads(encoded, object_pairs_hook=unique_fields)
    if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'}:
        raise ValueError('invalid refresh envelope')
    if (not isinstance(envelope['payload'], str) or not isinstance(envelope['signature'], str)
            or len(envelope['signature']) != 128
            or any(c not in '0123456789abcdef' for c in envelope['signature'])):
        raise ValueError('invalid refresh encoding')
    signed = Refresh(base64.b64decode(envelope['payload'], validate=True), bytes.fromhex(envelope['signature']))
    registration = read_json(root / 'host-channel.json')
    if registration['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise ValueError('refresh belongs to another guest boot')
    number = publish(root, registration, signed)
    return dict(revision=number, state_sha256=sha256(signed.payload).hexdigest())


def deliver_to_login_vm(refresh, deadline):
    """Pinned SSH transport to the owner VM; only already signed public bytes travel."""
    import json
    import subprocess
    from read_snapshot import check_directory
    transfer = Path('/var/lib/izanagi-tempest/transfer')
    for directory in reversed(transfer.parents):
        check_directory(directory)
    check_directory(transfer, 0o700)
    key, known = transfer / 'prelogin-key', transfer / 'login-vm-known-hosts'
    check_file(key)
    check_file(known)
    command = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
               '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(known),
               '-i', str(key), '-p', '22333', 'tempest@127.0.0.1',
               'sudo -n /usr/bin/python3 -B /usr/local/lib/tempest-login-host-ledger/refresh_revocation.py --publish-stdin']
    encoded = encode_refresh(refresh)
    expected = dict(revision=json.loads(refresh.payload.split(b'\0',1)[1])['revocation_revision'],
                    state_sha256=sha256(refresh.payload).hexdigest())
    while True:
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('guest refresh transport deadline expired')
        try:
            result = subprocess.run(command, input=encoded, capture_output=True, timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError('guest refresh transport timed out') from error
        if result.returncode == 75:
            time.sleep(min(0.01, max(0, deadline-time.monotonic())))
            continue
        if result.returncode != 0:
            raise OSError('guest signed refresh delivery failed')
        if len(result.stdout) > 1024 or json.loads(result.stdout) != expected:
            raise ValueError('guest refresh acknowledgement mismatch')
        return


def main():
    import signal
    import sys
    import threading
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from channel import validate_registration_deadline
    from read_snapshot import MANAGEMENT, read_json
    if os.geteuid() != 0:
        return 1
    try:
        if sys.argv[1:] == ['--publish-stdin']:
            result = publish_stdin(sys.stdin.buffer.read(8193))
            print(canonical_json(result).decode('ascii'))
            return 0
        if sys.argv[1:] != ['--run-login-vm-updater']:
            return 1
        registration = read_json(MANAGEMENT / 'host-login-authority/channel-registration.json')
        validate_registration_deadline(registration, read_json(MANAGEMENT / 'host-login-authority/channel-approval.json'))
        signer = Ed25519PrivateKey.from_private_bytes(read_private(MANAGEMENT / 'host-login-signer/revocation-seed', 32))
        if signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != read_private(MANAGEMENT / 'claude-login-authority/revocation-key', 32):
            raise ValueError('independent revocation key mismatch')
        stopped = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stopped.set())
        signal.signal(signal.SIGINT, lambda *_: stopped.set())
        started = time.monotonic()
        wall = time.time_ns() // 1_000_000
        deadline = started + (registration['expires_unix_ms']-wall)/1000
        run_updater(MANAGEMENT, registration, signer, deliver_to_login_vm, stopped, deadline)
        return 0
    except BlockingIOError:
        return 75
    except (OSError, ValueError, KeyError, TypeError):
        print('signed revocation refresh refused', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
