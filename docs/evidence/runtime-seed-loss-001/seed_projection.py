"""Validate nonsecret seed-success witness against host control failure evidence."""
from collections import Counter

EXPECTED_WITNESS = {'seed_reply_verified': True, 'admin_key_rotated': True,
                    'new_key_verified': True, 'old_key_rejected': True, 'users': ['worker']}


def project(witness, controls):
    assert witness == EXPECTED_WITNESS, 'seed success witness mismatch'
    seeds = [row for row in controls if row['operation'] == 'seed']
    terminal = [row for row in seeds if row['state'] in ('started', 'completed', 'failed')]
    assert Counter(row['state'] for row in terminal) == {'started': 1, 'failed': 1}
    assert terminal[0]['state'] == 'started' and terminal[-1]['state'] == 'failed'
    assert len({row['id'] for row in seeds}) == 1, 'seed control ID changed or request repeated'
    reads = [row for row in seeds if row['state'] == 'delivery_read_started']
    observed = [row for row in seeds if row['state'] == 'delivery_read_observed']
    assert reads and [row['attempt'] for row in reads] == list(range(1, len(reads) + 1))
    assert len(observed) == len(reads)
    assert [row['attempt'] for row in observed] == [row['attempt'] for row in reads]
    categories = Counter(row['category'] for row in observed)
    assert categories['ciphertext_received'] == 1 and observed[-1]['category'] == 'ciphertext_received'
    assert set(categories) <= {'reply_unavailable', 'ciphertext_received'}
    assert not any(row['operation'] in ('probe', 'seal', 'export', 'fetch') for row in controls)
    return {'witness': witness, 'seed_started': 1, 'seed_failed': 1, 'seed_completed': 0,
            'distinct_seed_control_ids': 1, 'delivery_reads': len(reads),
            'delivery_categories': dict(categories), 'agent_stage_operations_absent': True,
            'scope': 'one successful decoded seed reply deliberately withheld; delivery reads may poll the same reply'}
