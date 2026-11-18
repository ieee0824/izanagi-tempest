"""Pure validation of bounded loopback fixture and fixed sidecar audit records."""
import re
import json
from pathlib import Path
import stat
import tomllib

CASES = {'allowed': ('allowed', 'completed', 200),
         'private_port': ('allowed', 'failed', None),
         'denied_host': ('denied', 'rejected', None)}


def configure(template):
    config = tomllib.loads(template)
    if config['sandbox']['qemu']['restrict_network'] is not True or config['share']['read_only'] is not True:
        raise ValueError('sidecar fixture requires restricted network and readonly share')
    if config['detect']['allowed_hosts'] != [] or 'behavior' in config:
        raise ValueError('sidecar fixture requires the unchanged baseline template')
    if template.count('allowed_hosts = []') != 1:
        raise ValueError('ambiguous sidecar policy replacement')
    return template.replace('allowed_hosts = []', 'allowed_hosts = ["127.0.0.1"]') + '''
[behavior]
enabled = true
proxy_listen = "127.0.0.1:18080"
fixture_endpoint = "127.0.0.1:19090"
baseline_hosts = ["127.0.0.1"]
[behavior.classifier]
provider = "mock"
allow_export = false
'''


def validate_probe(value, nonce):
    if value['schema_version'] != 1 or value['actor_uid'] != 1000 or value['nonce'] != nonce \
            or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise ValueError('sidecar fixture identity mismatch')
    if value['receiver_counts'] != [1, 1] or value['receiver_threads_joined'] is not True:
        raise ValueError('sidecar receiver control or cleanup failed')
    identity = value['sidecar']
    if identity['uid'] != 0 or any(type(identity[k]) is not int or identity[k] <= 0
                                   for k in ('pid', 'ppid', 'starttime_ticks')):
        raise ValueError('sidecar root process identity missing')
    if not isinstance(value['guest_boot_id'], str) or not value['guest_boot_id']:
        raise ValueError('sidecar guest boot missing')
    start, end = value['started_monotonic_ns'], value['ended_monotonic_ns']
    if type(start) is not int or type(end) is not int or not 0 < start <= end or end - start > 30_000_000_000:
        raise ValueError('sidecar fixture time bound exceeded')
    if set(value['cases']) != {'control', *CASES}:
        raise ValueError('sidecar fixture cases missing or unexpected')
    for name, case in value['cases'].items():
        status = 200 if name in ('allowed', 'control') else 502
        if case['status'] != status or not 0 < case['body_bytes'] <= 1024 \
                or re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}', case['client']) is None:
            raise ValueError('sidecar fixture case invalid')
    if len({value['cases'][name]['client'] for name in CASES}) != 3:
        raise ValueError('sidecar fixture client sockets ambiguous')
    return value


def validate_records(records, probe, nonce, session):
    validate_probe(probe, nonce)
    if not isinstance(records, list) or not records or len(records) > 50000:
        raise ValueError('sidecar audit record budget exceeded')
    requests, outcomes, sources, sequences = {}, {}, set(), set()
    for record in records:
        if record.get('storage_gap') is not False:
            raise ValueError('sidecar audit storage gap')
        event = record['payload'].get('Event')
        if event is None or not event['source_instance_id'].startswith('http-'):
            continue
        # Normal sidecar teardown may report EOF health after the bounded fixture.
        # It is not evidence about request-time health or whole-run availability.
        if set(event['payload']) == {'CollectorHealth'} and event['observed_monotonic_ns'] > probe['ended_monotonic_ns']:
            continue
        source = event['source_instance_id']
        sequence = event['source_seq']
        if event['schema_version'] != 1 or event['session_id'] != session \
                or event['guest_boot_id'] != probe['guest_boot_id'] \
                or event['clock_domain'] != 'linux-monotonic:' + probe['guest_boot_id'] \
                or event['event_id'] != f'{session}:{source}:{sequence}' \
                or re.fullmatch('http-[0-9a-f]{32}', source) is None \
                or type(sequence) is not int or sequence <= 0 or (source, sequence) in sequences \
                or event['quality']['issues']:
            raise ValueError('sidecar event identity or quality mismatch')
        sequences.add((source, sequence))
        sources.add(source)
        payload = event['payload']
        if set(payload) == {'HttpRequest'}:
            item = payload['HttpRequest']
            client = item['tuple']['client']
            if client in requests:
                raise ValueError('duplicate sidecar client request')
            if item['tuple']['local'] != '127.0.0.1:18080' or item['tuple']['net_namespace'] <= 0 \
                    or item['raw_host'] is not None or item['method'] != 'post':
                raise ValueError('sidecar request metadata mismatch')
            requests[client] = (item, event)
        elif set(payload) == {'HttpOutcome'}:
            item = payload['HttpOutcome']
            if item['request_id'] in outcomes:
                raise ValueError('duplicate sidecar request outcome')
            outcomes[item['request_id']] = (item, event)
        elif set(payload) != {'HttpStreamRange'}:
            raise ValueError('unexpected sidecar telemetry or collector gap')
    if len(sources) != 1 or len(requests) != 3 or len(outcomes) != 3:
        raise ValueError('missing or extra sidecar audit observations')
    ids = set()
    for name, (policy, outcome, status) in CASES.items():
        case = probe['cases'][name]
        item, request_event = requests[case['client']]
        result, outcome_event = outcomes[item['request_id']]
        ids.add(item['request_id'])
        if item['policy'] != policy or item['declared_content_length'] != case['body_bytes'] \
                or result['outcome'] != outcome or result['status'] != status \
                or not probe['started_monotonic_ns'] <= request_event['observed_monotonic_ns'] \
                    <= outcome_event['observed_monotonic_ns'] <= probe['ended_monotonic_ns']:
            raise ValueError('sidecar request/outcome binding mismatch')
        if result['client_bytes_received'] <= case['body_bytes']:
            raise ValueError('sidecar byte control missing')
        if name == 'allowed':
            if result['upstream_bytes_written'] <= case['body_bytes'] or result['response_bytes_received'] <= 0:
                raise ValueError('sidecar successful transfer bytes missing')
        elif result['upstream_bytes_written'] != 0 or result['response_bytes_received'] != 0:
            raise ValueError('rejected request reached upstream')
    if len(ids) != 3:
        raise ValueError('sidecar request IDs reused')
    return {'passed': True, 'requests': 3, 'completed': 1, 'private_port_failed': 1,
            'host_rejected': 1, 'receiver_counts': probe['receiver_counts'],
            'session_id': session, 'guest_boot_id': probe['guest_boot_id'],
            'sidecar_process': probe['sidecar'],
            'scope': 'fixed loopback fixture and sidecar metadata; not external egress, classifier accuracy or writer attribution'}


def collect(source, destination, probe):
    """Copy only bounded regular audit segments from one fresh instance session."""
    source, destination = Path(source), Path(destination)
    sessions = list(source.iterdir())
    if len(sessions) != 1 or sessions[0].is_symlink() or not sessions[0].is_dir():
        raise ValueError('expected one fresh behavior audit session')
    session = sessions[0]
    destination.mkdir(mode=0o700, exist_ok=False)
    records, total = [], 0
    files = sorted(session.glob('*.jsonl'))
    if not files or len(files) > 32:
        raise ValueError('behavior segment count budget')
    for path in files:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError('behavior audit segment must be regular single-link')
        total += metadata.st_size
        if total > 10 * 1024 * 1024:
            raise ValueError('behavior audit byte budget')
        data = path.read_bytes()
        if b'TEMPEST-SIDECAR-PUBLIC-' in data:
            raise ValueError('dummy HTTP body persisted in metadata audit')
        if len(data) != metadata.st_size:
            raise ValueError('behavior audit segment changed')
        for line in data.splitlines():
            if len(line) > 65536:
                raise ValueError('behavior audit record byte budget')
            records.append(json.loads(line))
            if len(records) > 50000:
                raise ValueError('behavior audit record count budget')
        target = destination / path.name
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o600)
    result = validate_records(records, probe, probe['nonce'], session.name)
    result.update(audit_files=len(files), audit_bytes=total)
    return result
