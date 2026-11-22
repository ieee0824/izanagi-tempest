"""Root-only host daemon connecting existing originals to both vsock listeners."""
import os
import signal
import socket
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker import PORT as CONTROL_PORT, CONNECTION_LIMIT as CONTROL_LIMIT
from channel import require_live_instance
from egress_authority import PORT, CONNECTION_LIMIT, RunAuthorization, Scope, parse_signed_policy
from egress_generation import read_generation, read_private
from egress_service import REJECTIONS, serve_both
from freshness import FreshnessLatch
from read_snapshot import MANAGEMENT, check_directory, read_json, read_management_snapshot


class HostOriginals:
    """Bind a run to immutable originals; re-read mutable commits without renewal."""
    def __init__(self, management, registration, policy, generation, ledger_id, sequence,
                 public_key, authorization):
        self.management = management
        self.registration = registration
        self.policy = policy
        self.generation = generation
        self.ledger_id = ledger_id
        self.sequence = sequence
        self.revocation_revision = generation.revocation_revision
        self.public_key = public_key
        self.authorization = authorization
        self.freshness = authorization.freshness
        self.lock = threading.Lock()

    def check(self, deadline):
        acquired = self.lock.acquire(timeout=max(0, deadline - time.monotonic()))
        try:
            if not acquired or time.monotonic() >= deadline:
                raise TimeoutError('host original check deadline expired')
            if self.freshness.deadline() is None:
                raise TimeoutError('signed revocation freshness ended')
            authority = self.management / 'host-login-authority'
            if read_json(authority / 'channel-registration.json') != self.registration:
                raise ValueError('host registration changed')
            if read_private(authority / 'egress-trust-key', 32) != self.public_key:
                raise ValueError('egress trust key changed')
            source_started_at = time.monotonic()
            source_wall = time.time_ns() // 1_000_000
            generation = read_generation(self.management, self.registration, source_wall, defer_busy=True)
            if generation is not None and (generation.manifest_sha256 != self.generation.manifest_sha256
                    or generation.approved_ips_revision != self.generation.approved_ips_revision
                    or generation.addresses != self.generation.addresses
                    or generation.revocation_revision < self.revocation_revision):
                raise ValueError('approved generation changed or rolled back')
            policy = parse_signed_policy(read_private(authority / 'egress-policy.json', 4096),
                self.public_key, self.registration, read_json(authority / 'channel-approval.json'),
                (generation or self.generation).route(), time.time_ns() // 1_000_000)
            if policy != self.policy:
                raise ValueError('signed egress policy changed')
            commit = read_management_snapshot(self.management, allowed_states=('issued', 'consumed'))
            if (commit['ledger_id'] != self.ledger_id or Scope.parse(commit['scope']) != policy.scope
                    or commit['sequence'] < self.sequence
                    or self.authorization.current() is not None and commit['state'] != 'consumed'):
                raise ValueError('host ledger changed or rolled back')
            process = require_live_instance(self.registration, deadline)
            os.close(process)
            if time.monotonic() >= deadline:
                raise TimeoutError('host original check completed too late')
            if generation is not None and not self.freshness.observe(generation.revocation_revision, generation.revocation_state_sha256,
                    generation.revocation_expires_unix_ms, source_wall, source_started_at):
                raise TimeoutError('signed revocation freshness could not advance')
            self.sequence = commit['sequence']
            if generation is not None:
                self.revocation_revision = generation.revocation_revision
        except REJECTIONS:
            self.freshness.stop()
            self.authorization.stop()
            raise
        finally:
            if acquired:
                self.lock.release()


def load_run(management):
    for parent in reversed(management.parents):
        check_directory(parent)
    check_directory(management, 0o700)
    authority, signers = management / 'host-login-authority', management / 'host-login-signer'
    check_directory(authority, 0o700)
    check_directory(signers, 0o700)
    registration = read_json(authority / 'channel-registration.json')
    # Capture the monotonic origin before wall time and all input processing.
    started_at = time.monotonic()
    now = time.time_ns() // 1_000_000
    generation = read_generation(management, registration, now)
    key = read_private(authority / 'egress-trust-key', 32)
    policy = parse_signed_policy(read_private(authority / 'egress-policy.json', 4096), key,
        registration, read_json(authority / 'channel-approval.json'), generation.route(), now)
    absolute_deadline = started_at + (policy.expires_unix_ms - now) / 1000
    commit = read_management_snapshot(management, allowed_states=('issued', 'consumed'))
    if Scope.parse(commit['scope']) != policy.scope:
        raise ValueError('initial host ledger scope mismatch')
    # No freshness exists until this process successfully sends a control response.
    freshness = FreshnessLatch(generation.revocation_revision, generation.revocation_state_sha256,
        started_at + (generation.revocation_expires_unix_ms - now) / 1000, absolute_deadline)
    state = RunAuthorization(policy.scope, policy.boot_id, commit['ledger_id'], absolute_deadline,
                             freshness=freshness)
    signer = Ed25519PrivateKey.from_private_bytes(read_private(signers / 'signing-seed', 32))
    originals = HostOriginals(management, registration, policy, generation, commit['ledger_id'],
                             commit['sequence'], key, state)
    originals.check(min(absolute_deadline, time.monotonic() + 2))
    return registration, policy, state, signer, absolute_deadline, originals


def main():
    if os.geteuid() != 0:
        raise PermissionError('host egress daemon requires root')
    registration, policy, state, signer, deadline, originals = load_run(MANAGEMENT)
    stop = threading.Event()

    def terminate(_signum, _frame):
        state.stop()
        stop.set()

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as control, \
            socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as data:
        # Binding both before serving also refuses an occupied dedicated port.
        control.bind((socket.VMADDR_CID_HOST, CONTROL_PORT))
        data.bind((socket.VMADDR_CID_HOST, PORT))
        control.listen(CONTROL_LIMIT)
        data.listen(CONNECTION_LIMIT)
        serve_both(control, data, registration, MANAGEMENT, policy, state, signer,
                   deadline, originals.check, stop)


if __name__ == '__main__':
    main()
