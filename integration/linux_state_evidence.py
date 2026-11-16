"""Exact dummy-only evidence projection; never authorizes production launch."""
from collections import Counter


def validate_probe(report):
    if (report.get('status') != 'incomplete'
            or report.get('formal_eligible') is not False
            or report.get('model_launched') is not False
            or report.get('resources_removed') is not True
            or report.get('guardian_alive') is not False):
        raise ValueError('dummy_report_boundary')
    digest = report.get('code_sha256', '')
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('binary_digest')
    expected = Counter()
    for role in ['a', 'b', 'guard']:
        for name, attempts, denials in [
            ('host_home_denied', 10, 10),
            ('private_home_readable', 1, 0),
            ('previous_state_absent', 1, 1),
            ('state_marker_created', 1, 0),
            ('state_marker_created', 1, 0),
            ('state_marker_observed', 1, 0),
        ]:
            expected[(name, role, attempts, denials)] += 1
    for name, attempts in [('state_generation_bound', 3),
                           ('state_cleanup_complete', 3), ('host_home_readable', 18)]:
        expected[(name, None, attempts, 0)] += 1
    for run in ['state_run1', 'state_run2']:
        actual = Counter()
        for check in report.get('checks', []):
            if check.get('scenario') != run:
                continue
            if (check.keys() != {'scenario', 'check', 'role', 'passed', 'attempts', 'denials'}
                    or check['passed'] is not True
                    or type(check['attempts']) is not int
                    or type(check['denials']) is not int):
                raise ValueError('state_check_schema')
            actual[(check['check'], check['role'], check['attempts'], check['denials'])] += 1
        if actual != expected:
            raise ValueError('state_check_set')
    terminal = report.get('parent_recovery_status', [])
    if not terminal:
        raise ValueError('terminal_missing')
    terminal = terminal[-1]
    if (terminal.get('transition') != 'verified'
            or terminal.get('reason') != 'normal_completion'
            or terminal.get('guardian_dead') is not True
            or terminal.get('guardian_reaped') is not True
            or terminal.get('guardian_exit') != 0
            or terminal.get('guardian_signal') is not None
            or terminal.get('status_drain') != 'empty'):
        raise ValueError('terminal_invalid')
    counts = terminal.get('counts', {})
    if (counts.get('cgroup_populated') is not False
            or any(counts.get(name) != 0 for name in
                   ['registry_total', 'unattached', 'reap_unconfirmed'])
            or counts.get('unconfirmed_reason') is not None):
        raise ValueError('cleanup_unconfirmed')
    return {'dummy_checks_per_run': 21, 'production_authorized': False,
            'binary_sha256': digest}
