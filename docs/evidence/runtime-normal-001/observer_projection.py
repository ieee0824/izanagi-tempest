"""Select observer metadata without publishing raw command lines or room keys."""
import json
from pathlib import Path


def project(path):
    samples = []
    sessions = []
    for line in Path(path).read_text().splitlines():
        record = json.loads(line)
        if set(record) == {'sample'}:
            samples.append(record['sample'])
        elif set(record) == {'observed_sessions'}:
            sessions = record['observed_sessions']
        else:
            raise ValueError('unexpected runtime observer envelope')
    return {'sample_count': len(samples),
            'external_listener_observed': any(row['external_listener_observed'] for row in samples),
            'last_observed_unit': samples[-1]['unit'] if samples else None,
            'observed_sessions': sessions,
            'scope': 'sampled sessions; observer caller exit and trusted terminal evidence recorded separately'}
