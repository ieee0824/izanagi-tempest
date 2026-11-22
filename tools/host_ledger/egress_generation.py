"""Read the existing manual-login publication without introducing a new schema."""
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import ipaddress
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from channel import unique_fields
from egress_authority import AUTHORITY, DIGEST, positive
from read_snapshot import check_directory, check_file

HANDOFF_DOMAIN = b'izanagi-tempest:manual-login-handoff:fixture-v1\0'
REVOCATION_DOMAIN = b'izanagi-tempest:manual-login-revocation:fixture-v1\0'
CLI_SHA256 = '0dc4f4a9a165fc60746d7ae8489712e5fc352f1e7ad4eb22e7141bd0812eb0cf'
INPUTS = {'claude-manual-login.json': 4096, 'claude-login-diagnostic-handoff': 4096,
          'claude-login-diagnostic-signature': 64, 'claude-login-diagnostic-trust-key': 32,
          'claude-login-diagnostic-target-registration': 4096}


def decode(data, fields):
    value = json.loads(data, object_pairs_hook=unique_fields)
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('invalid published generation fields')
    return value


def read_private(path, limit):
    check_file(path)
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('published generation input too large')
    return data


def revision(path):
    data = read_private(path, 20)
    try:
        number = int(data)
    except ValueError as error:
        raise ValueError('invalid publication revision') from error
    if not positive(number) or data != str(number).encode('ascii'):
        raise ValueError('invalid publication revision')
    return number


def no_pending(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise ValueError('publication update is pending')


def signed_payload(payload, signature, key, domain, fields):
    if len(key) != 32 or len(signature) != 64 or not payload.startswith(domain):
        raise ValueError('invalid publication signature inputs')
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, payload)
    except InvalidSignature as error:
        raise ValueError('publication signature refused') from error
    return decode(payload[len(domain):], fields)


@dataclass(frozen=True)
class ApprovedGeneration:
    manifest_sha256: str
    approved_ips_revision: int
    addresses: tuple
    operation_expires_unix_ms: int
    revocation_revision: int
    revocation_expires_unix_ms: int
    revocation_state_sha256: str

    def route(self):
        return dict(manifest_sha256=self.manifest_sha256,
                    approved_ips_revision=self.approved_ips_revision,
                    addresses=list(self.addresses), expires_unix_ms=self.operation_expires_unix_ms)


def verify_inputs(manifest, approved, inputs, trust_key, registration,
                  revocation_payload, revocation_signature, revocation_key,
                  revocation_minimum, committed, now_unix_ms):
    """Mirror the existing version-2 policy and fixture-v1 handoff/revocation."""
    digest = sha256(manifest).hexdigest()
    approved = decode(approved, {'revision', 'manifest_sha256'})
    if (type(approved['revision']) is not int or approved['revision'] != registration['generation']
            or approved['manifest_sha256'] != digest):
        raise ValueError('generation is not independently approved')
    hashes = decode(manifest, INPUTS)
    if set(inputs) != set(INPUTS):
        raise ValueError('incomplete generation')
    for name, limit in INPUTS.items():
        if len(inputs[name]) > limit or hashes[name] != sha256(inputs[name]).hexdigest():
            raise ValueError('generation input digest mismatch')
    if inputs['claude-login-diagnostic-trust-key'] != trust_key:
        raise ValueError('generation trust key mismatch')
    policy = decode(inputs['claude-manual-login.json'], {'version', 'authority', 'approved_ips', 'permit'})
    ips, permit = policy['approved_ips'], policy['permit']
    if (not isinstance(ips, dict) or set(ips) != {'revision', 'addresses'}
            or not isinstance(permit, dict) or set(permit) != {'target_hostname', 'authority', 'approved_ips_revision', 'expires_unix_seconds'}
            or type(policy['version']) is not int or policy['version'] != 2
            or policy['authority'] != AUTHORITY or permit['authority'] != AUTHORITY
            or not positive(ips['revision']) or type(permit['approved_ips_revision']) is not int
            or permit['approved_ips_revision'] != ips['revision']
            or not isinstance(ips['addresses'], list) or not ips['addresses']
            or not positive(permit['expires_unix_seconds'])
            or not now_unix_ms < permit['expires_unix_seconds'] * 1000 <= now_unix_ms + 300000):
        raise ValueError('invalid scoped login policy')
    addresses = []
    for value in ips['addresses']:
        if not isinstance(value, str) or '%' in value:
            raise ValueError('invalid published address')
        addresses.append(str(ipaddress.ip_address(value)))
    target = decode(inputs['claude-login-diagnostic-target-registration'], {'target_id', 'target_hostname'})
    if (target['target_id'] != registration['target_id'] or not isinstance(target['target_hostname'], str)
            or not target['target_hostname'] or permit['target_hostname'] != target['target_hostname']):
        raise ValueError('published target mismatch')
    handoff = signed_payload(inputs['claude-login-diagnostic-handoff'], inputs['claude-login-diagnostic-signature'],
                             trust_key, HANDOFF_DOMAIN, {'permit_id', 'approval_pair_sha256', 'expires_unix_seconds',
                             'target_id', 'executable_sha256', 'arguments', 'authority', 'approved_ips_revision'})
    if (handoff['permit_id'] != registration['permit_id'] or handoff['target_id'] != registration['target_id']
            or handoff['executable_sha256'] != CLI_SHA256 or handoff['arguments'] != ['auth', 'login']
            or handoff['authority'] != AUTHORITY or type(handoff['approved_ips_revision']) is not int
            or handoff['approved_ips_revision'] != ips['revision']
            or not isinstance(handoff['approval_pair_sha256'], str) or not DIGEST.fullmatch(handoff['approval_pair_sha256'])
            or not positive(handoff['expires_unix_seconds']) or handoff['expires_unix_seconds'] * 1000 <= now_unix_ms):
        raise ValueError('published handoff mismatch or expiry')
    state = signed_payload(revocation_payload, revocation_signature, revocation_key, REVOCATION_DOMAIN,
                           {'revision', 'revocation_revision', 'manifest_sha256', 'permit_id', 'target_id',
                            'issued_unix_seconds', 'expires_unix_seconds', 'revoked'})
    commit = decode(committed, {'revision', 'state_sha256'})
    if (type(state['revision']) is not int or state['revision'] != registration['generation']
            or state['manifest_sha256'] != digest or state['permit_id'] != registration['permit_id']
            or state['target_id'] != registration['target_id'] or state['revoked'] is not False
            or not positive(state['revocation_revision']) or not positive(revocation_minimum)
            or state['revocation_revision'] < revocation_minimum
            or type(commit['revision']) is not int or commit['revision'] != state['revocation_revision']
            or commit['state_sha256'] != sha256(revocation_payload).hexdigest()
            or not positive(state['issued_unix_seconds']) or not positive(state['expires_unix_seconds'])
            or state['issued_unix_seconds'] * 1000 > now_unix_ms
            or not 0 < state['expires_unix_seconds'] - state['issued_unix_seconds'] <= 30
            or state['expires_unix_seconds'] * 1000 <= now_unix_ms):
        raise ValueError('published revocation state refused')
    expires = 1000 * min(permit['expires_unix_seconds'], handoff['expires_unix_seconds'])
    return ApprovedGeneration(digest, ips['revision'], tuple(addresses), expires, state['revocation_revision'],
                              state['expires_unix_seconds'] * 1000, sha256(revocation_payload).hexdigest())


def read_generation(root, registration, now_unix_ms):
    """All source files are host root originals; hold no lock during relay I/O."""
    for ancestor in reversed(root.parents):
        check_directory(ancestor)
    check_directory(root, 0o700)
    authority = root / 'claude-login-authority'
    publication = root / 'claude-login-publication'
    check_directory(authority, 0o700)
    check_directory(publication, 0o700)
    lock = publication / 'lock'
    check_file(lock)
    with lock.open('rb') as held:
        fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
        no_pending(publication / 'pending')
        no_pending(authority / 'revocation-pending')
        current = revision(publication / 'current')
        if current < revision(authority / 'minimum') or current != registration['generation']:
            raise ValueError('publication generation changed or rolled back')
        generation = publication / str(current)
        check_directory(generation, 0o700)
        return verify_inputs(read_private(generation / 'manifest', 4096),
            read_private(authority / 'approved-generation', 4096),
            {name: read_private(generation / name, limit) for name, limit in INPUTS.items()},
            read_private(authority / 'trust-key', 32), registration,
            read_private(authority / 'revocation-state', 4096),
            read_private(authority / 'revocation-signature', 64),
            read_private(authority / 'revocation-key', 32), revision(authority / 'revocation-minimum'),
            read_private(authority / 'revocation-committed', 4096), now_unix_ms)
