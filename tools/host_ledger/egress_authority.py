"""Immutable signed egress scope and control-derived freshness, without network I/O."""
from dataclasses import dataclass
import ipaddress
import json
import re
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from channel import canonical_json, unique_fields, validate_registration_deadline
from read_snapshot import IDENTIFIER

POLICY_DOMAIN = b'izanagi-tempest:login-egress-policy:v1\0'
RECEIPT_DOMAIN = b'izanagi-tempest:login-egress:v1\0'
AUTHORITY = 'platform.claude.com:443'
PORT = 23105
CONNECTION_LIMIT = 4
DIGEST = re.compile(r'[0-9a-f]{64}')
SIGNATURE = re.compile(r'[0-9a-f]{128}')


def positive(value):
    return type(value) is int and 0 < value < 2**63


@dataclass(frozen=True)
class Scope:
    target_id: str
    permit_id: str
    generation: int

    @classmethod
    def parse(cls, value):
        if (not isinstance(value, dict) or set(value) != {'target_id', 'permit_id', 'generation'}
                or not isinstance(value['target_id'], str) or len(value['target_id']) > 128
                or not IDENTIFIER.fullmatch(value['target_id'])
                or not isinstance(value['permit_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', value['permit_id'])
                or not positive(value['generation'])):
            raise ValueError('invalid egress scope')
        return cls(**value)


@dataclass(frozen=True)
class EgressPolicy:
    scope: Scope
    boot_id: str
    manifest_sha256: str
    approved_ips_revision: int
    authority: str
    address: str
    port: int
    expires_unix_ms: int


def parse_signed_policy(encoded, public_key, registration, approval, approved_route, now_unix_ms):
    """Verify a host signature and bind its peer to an independent approved route."""
    if len(encoded) > 4096 or len(public_key) != 32:
        raise ValueError('invalid egress policy size or trust key')
    envelope = json.loads(encoded, object_pairs_hook=unique_fields)
    if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'}:
        raise ValueError('invalid egress policy envelope')
    body, signature = envelope['payload'], envelope['signature']
    if not isinstance(signature, str) or not SIGNATURE.fullmatch(signature):
        raise ValueError('invalid egress policy signature')
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(signature), POLICY_DOMAIN + canonical_json(body))
    except InvalidSignature as error:
        raise ValueError('egress policy signature refused') from error
    fields = {'version', 'scope', 'boot_id', 'manifest_sha256', 'approved_ips_revision', 'authority', 'peer', 'expires_unix_ms'}
    if (not isinstance(body, dict) or set(body) != fields
            or type(body['version']) is not int or body['version'] != 1):
        raise ValueError('invalid signed egress fields')
    scope = Scope.parse(body['scope'])
    if scope != Scope.parse({name: registration[name] for name in ('target_id', 'permit_id', 'generation')}):
        raise ValueError('egress registration scope mismatch')
    validate_registration_deadline(registration, approval)
    if (not isinstance(body['boot_id'], str) or len(body['boot_id']) > 128
            or not IDENTIFIER.fullmatch(body['boot_id']) or body['boot_id'] != registration['boot_id']
            or not isinstance(body['manifest_sha256'], str) or not DIGEST.fullmatch(body['manifest_sha256'])
            or not positive(body['approved_ips_revision']) or body['authority'] != AUTHORITY):
        raise ValueError('invalid signed egress identity')
    peer = body['peer']
    if (not isinstance(peer, dict) or set(peer) != {'address', 'port'}
            or type(peer['port']) is not int or peer['port'] != 443
            or not isinstance(peer['address'], str) or '%' in peer['address']):
        raise ValueError('invalid fixed egress peer')
    address = str(ipaddress.ip_address(peer['address']))
    if (not isinstance(approved_route, dict)
            or set(approved_route) != {'manifest_sha256', 'approved_ips_revision', 'addresses', 'expires_unix_ms'}
            or body['manifest_sha256'] != approved_route['manifest_sha256']
            or type(approved_route['approved_ips_revision']) is not int
            or body['approved_ips_revision'] != approved_route['approved_ips_revision']
            or not isinstance(approved_route['addresses'], list) or not approved_route['addresses']):
        raise ValueError('egress route is not independently approved')
    addresses = []
    for value in approved_route['addresses']:
        if not isinstance(value, str) or '%' in value:
            raise ValueError('invalid approved egress address')
        addresses.append(str(ipaddress.ip_address(value)))
    expires = body['expires_unix_ms']
    if (address not in addresses or not positive(expires) or not positive(approved_route['expires_unix_ms'])
            or type(now_unix_ms) is not int or not now_unix_ms < expires
            or expires > min(registration['expires_unix_ms'], approved_route['expires_unix_ms'])):
        raise ValueError('egress peer or lifetime exceeds approval')
    return EgressPolicy(scope, body['boot_id'], body['manifest_sha256'], body['approved_ips_revision'],
                        AUTHORITY, address, 443, expires)


@dataclass(frozen=True)
class FreshAuthorization:
    deadline: float
    sequence: int


class RunAuthorization:
    """One run's irreversible stop latch; only successful control replies renew it."""
    def __init__(self, scope, boot_id, ledger_id, absolute_deadline, clock=time.monotonic):
        self.scope = scope
        self.boot_id = boot_id
        self.ledger_id = ledger_id
        self.absolute_deadline = absolute_deadline
        self.clock = clock
        self.lock = threading.Lock()
        self.last = None
        self.stopped = False

    def stop(self):
        with self.lock:
            self.stopped = True

    def _active(self, now):
        if now >= self.absolute_deadline or (self.last is not None and now >= self.last.deadline):
            self.stopped = True
        return not self.stopped

    def observe(self, signed_response, accepted_at):
        """Called by the trusted control worker only after write_frame succeeds."""
        with self.lock:
            now = self.clock()
            if not self._active(now):
                return False
            try:
                body = signed_response['payload']
                request, commit = body['request'], body['commit']
                if request['operation'] == 'preflight':
                    return False
                if (request['operation'] not in ('consume', 'query') or commit['state'] != 'consumed'
                        or commit['ledger_id'] != self.ledger_id
                        or Scope.parse(commit['scope']) != self.scope
                        or Scope.parse({key: request[key] for key in ('target_id', 'permit_id', 'generation')}) != self.scope
                        or request['boot_id'] != self.boot_id or not positive(commit['sequence'])
                        or self.last is not None and commit['sequence'] < self.last.sequence
                        or type(body['issued_unix_ms']) is not int or type(body['expires_unix_ms']) is not int):
                    raise ValueError('control response does not authorize this egress run')
                lifetime_ms = body['expires_unix_ms'] - body['issued_unix_ms']
                if not 0 < lifetime_ms <= 2000 or accepted_at > now:
                    raise ValueError('invalid control lifetime')
                deadline = min(accepted_at + lifetime_ms / 1000, self.absolute_deadline)
                if deadline <= now:
                    raise ValueError('control reply arrived after its conservative deadline')
                self.last = FreshAuthorization(deadline, commit['sequence'])
                return True
            except (KeyError, TypeError, ValueError):
                self.stopped = True
                return False

    def current(self):
        with self.lock:
            return self.last if self._active(self.clock()) else None
