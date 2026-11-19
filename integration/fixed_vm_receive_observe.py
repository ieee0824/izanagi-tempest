"""Validate the fixed guest receipt against independently obtained run identity."""
import json
import re
import uuid

MAX_RECEIPT_BYTES = 512
RECEIPT_PHASES = ('before', 'allowed', 'after')
RECEIPT_FIELDS = {
    'schema_version', 'run_nonce', 'boot_id', 'phase', 'received', 'matched',
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate guest receipt field')
        result[key] = value
    return result


def validate_guest_receipt(stdout, *, run_nonce, boot_id, phase):
    """Check a single data-plane receipt; zero counts require separate evidence."""
    if (
        re.fullmatch(r'[0-9a-f]{32}', run_nonce) is None
        or str(uuid.UUID(boot_id)) != boot_id
        or phase not in RECEIPT_PHASES
    ):
        raise ValueError('invalid expected guest receipt binding')
    if not 0 < len(stdout) <= MAX_RECEIPT_BYTES or stdout.count(b'\n') != 1 or not stdout.endswith(b'\n'):
        raise ValueError('invalid guest receipt framing')
    receipt = json.loads(stdout.decode('utf-8'), object_pairs_hook=unique_object)
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise ValueError('invalid guest receipt schema')
    for field in ('schema_version', 'received', 'matched'):
        if type(receipt[field]) is not int or receipt[field] != 1:
            raise ValueError(f'invalid guest receipt {field}')
    if (receipt['run_nonce'], receipt['boot_id'], receipt['phase']) != (run_nonce, boot_id, phase):
        raise ValueError('guest receipt binding mismatch')
    return receipt
