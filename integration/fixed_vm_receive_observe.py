"""Validate fixed guest acknowledgements and private export on the host."""
import json
import re
import uuid

PHASES = ('control_before', 'allow_same_run', 'deny_other', 'control_after')
FIELDS = {'schema_version', 'run_nonce', 'boot_id'}
COUNT_FIELDS = ('received', 'matched')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate guest record field')
        result[key] = value
    return result


def parse_record(raw, limit, extra_fields, run_nonce, boot_id):
    if (
        re.fullmatch(r'[0-9a-f]{32}', run_nonce) is None
        or str(uuid.UUID(boot_id)) != boot_id
        or not 0 < len(raw) <= limit
    ):
        raise ValueError('invalid guest record binding or size')
    record = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
    if not isinstance(record, dict) or set(record) != FIELDS | extra_fields:
        raise ValueError('invalid guest record schema')
    if type(record['schema_version']) is not int or record['schema_version'] != 1:
        raise ValueError('invalid guest record version')
    if (record['run_nonce'], record['boot_id']) != (run_nonce, boot_id):
        raise ValueError('guest record binding mismatch')
    return record


def require_counts(counts, expected):
    if not isinstance(counts, dict) or set(counts) != set(COUNT_FIELDS):
        raise ValueError('invalid guest count schema')
    if any(type(counts[key]) is not int or counts[key] != expected for key in COUNT_FIELDS):
        raise ValueError('unexpected guest count')


def validate_guest_ack(stdout, *, run_nonce, boot_id, phase, operation):
    """Require the exact cumulative count at a fixed phase operation."""
    index = PHASES.index(phase)
    if operation not in ('start', 'request', 'end') or (phase == 'deny_other' and operation == 'request'):
        raise ValueError('invalid expected guest operation')
    if stdout.count(b'\n') != 1 or not stdout.endswith(b'\n'):
        raise ValueError('invalid guest acknowledgement framing')
    ack = parse_record(stdout, 512, {'phase', 'operation', 'counts', 'matched'}, run_nonce, boot_id)
    if (ack['phase'], ack['operation']) != (phase, operation) or ack['matched'] is not True:
        raise ValueError('unexpected guest acknowledgement')
    total = index - int(index > 2)
    require_counts(ack['counts'], total + int(phase != 'deny_other' and operation != 'start'))
    return ack


def validate_guest_export(raw, *, run_nonce, boot_id):
    """Require all closed phases, including independently measured denial."""
    report = parse_record(raw, 4096, {'counts', 'phases', 'complete'}, run_nonce, boot_id)
    if report['complete'] is not True or not isinstance(report['phases'], list) or len(report['phases']) != len(PHASES):
        raise ValueError('incomplete guest report')
    total = 0
    for phase, row in zip(PHASES, report['phases'], strict=True):
        if not isinstance(row, dict) or set(row) != {'phase', 'start', 'end', 'delta'} or row['phase'] != phase:
            raise ValueError('invalid guest phase record')
        delta = int(phase != 'deny_other')
        require_counts(row['start'], total)
        require_counts(row['delta'], delta)
        total += delta
        require_counts(row['end'], total)
    require_counts(report['counts'], total)
    return report
