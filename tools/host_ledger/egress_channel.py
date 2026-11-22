"""Bounded egress handshake with a domain-separated, challenge-bound ready receipt."""
import ipaddress
import json
import math
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from channel import (CHALLENGE, REQUEST_LIMIT, RESPONSE_LIMIT, canonical_json,
                     read_frame, unique_fields, write_frame)
from egress_authority import RECEIPT_DOMAIN, SIGNATURE, Scope, positive
from egress_relay import dial_peer, relay_opaque, require_authorization

FIELDS = {'version', 'scope', 'boot_id', 'manifest_sha256',
          'approved_ips_revision', 'authority', 'challenge'}


def validate_request(encoded, peer_cid, registration, policy):
    if len(encoded) > REQUEST_LIMIT:
        raise ValueError('egress request too large')
    request = json.loads(encoded, object_pairs_hook=unique_fields)
    if (not isinstance(request, dict) or set(request) != FIELDS
            or type(request['version']) is not int or request['version'] != 1
            or type(peer_cid) is not int or peer_cid != registration['cid']
            or Scope.parse(request['scope']) != policy.scope
            or request['boot_id'] != policy.boot_id
            or request['manifest_sha256'] != policy.manifest_sha256
            or type(request['approved_ips_revision']) is not int
            or request['approved_ips_revision'] != policy.approved_ips_revision
            or request['authority'] != policy.authority
            or not isinstance(request['challenge'], str) or not CHALLENGE.fullmatch(request['challenge'])):
        raise ValueError('egress request does not match approved run')
    return request


def ready_receipt(request, policy, upstream, authorization, signer, deadline):
    require_authorization(authorization, deadline)
    actual = upstream.getpeername()
    if ipaddress.ip_address(actual[0]) != ipaddress.ip_address(policy.address) or actual[1] != policy.port:
        raise ValueError('egress ready peer mismatch')
    fresh = authorization.current()
    if fresh is None:
        raise ValueError('egress authorization stopped')
    # Use a lower bound in integer milliseconds, never round the lease up.
    now_mono = time.monotonic()
    lifetime = int(1000 * (min(fresh.deadline, deadline) - now_mono))
    now = time.time_ns() // 1_000_000
    expires = min(now + lifetime, policy.expires_unix_ms)
    if not 0 < expires - now <= 2000:
        raise ValueError('egress ready lifetime expired')
    body = dict(request=request, peer=dict(address=str(ipaddress.ip_address(actual[0])), port=actual[1]),
                sequence=fresh.sequence, issued_unix_ms=now, expires_unix_ms=expires)
    return dict(payload=body, signature=signer.sign(RECEIPT_DOMAIN + canonical_json(body)).hex())


def verify_ready(encoded, request, policy, public_key, sequence_floor, started_at, now_monotonic):
    """Verify request-start-relative freshness; guest wall clock is not trusted."""
    if len(encoded) > RESPONSE_LIMIT:
        raise ValueError('egress ready too large')
    envelope = json.loads(encoded, object_pairs_hook=unique_fields)
    if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'}:
        raise ValueError('invalid egress ready envelope')
    body, signature = envelope['payload'], envelope['signature']
    if not isinstance(signature, str) or not SIGNATURE.fullmatch(signature):
        raise ValueError('invalid egress ready signature')
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(signature), RECEIPT_DOMAIN + canonical_json(body))
    except InvalidSignature as error:
        raise ValueError('egress ready signature refused') from error
    if (not isinstance(body, dict) or set(body) != {'request', 'peer', 'sequence', 'issued_unix_ms', 'expires_unix_ms'}
            or body['request'] != request or not positive(body['sequence']) or body['sequence'] < sequence_floor
            or body['peer'] != dict(address=policy.address, port=policy.port)
            or type(body['issued_unix_ms']) is not int or type(body['expires_unix_ms']) is not int):
        raise ValueError('egress ready scope or peer mismatch')
    lifetime = body['expires_unix_ms'] - body['issued_unix_ms']
    if (not math.isfinite(started_at) or not math.isfinite(now_monotonic)
            or not 0 < lifetime <= 2000 or body['expires_unix_ms'] > policy.expires_unix_ms
            or now_monotonic < started_at or now_monotonic >= started_at + lifetime / 1000):
        raise ValueError('egress ready arrived after conservative deadline')
    return body


def serve_connection(connection, peer_cid, registration, policy, authorization, signer,
                     handshake_deadline, absolute_deadline, validate_current):
    """Validate host originals before dialing; only then enter opaque data mode.

    validate_current is a trusted host callback, independent of the guest request.
    The surrounding service also monitors originals throughout long-lived relays.
    """
    upstream = None
    try:
        request = validate_request(read_frame(connection, REQUEST_LIMIT, handshake_deadline),
                                   peer_cid, registration, policy)
        validate_current(handshake_deadline)
        require_authorization(authorization, handshake_deadline)
        upstream = dial_peer(policy, authorization, handshake_deadline)
        validate_current(handshake_deadline)
        signed = ready_receipt(request, policy, upstream, authorization, signer, handshake_deadline)
        write_frame(connection, canonical_json(signed), RESPONSE_LIMIT, handshake_deadline)
        require_authorization(authorization, handshake_deadline)
        relay_opaque(connection, upstream, authorization, absolute_deadline)
    finally:
        connection.close()
        if upstream is not None:
            upstream.close()
