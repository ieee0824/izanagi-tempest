import copy
import unittest

from integration.linux_state_evidence import validate_probe


def report():
    checks = []
    for run in ['state_run1', 'state_run2']:
        for role in ['a', 'b', 'guard']:
            for check, attempts, denials in [
                ('host_home_denied', 10, 10), ('private_home_readable', 1, 0),
                ('previous_state_absent', 1, 1), ('state_marker_created', 1, 0),
                ('state_marker_created', 1, 0), ('state_marker_observed', 1, 0),
            ]:
                checks.append(dict(scenario=run, role=role, check=check,
                                   attempts=attempts, denials=denials, passed=True))
        for check, attempts in [('state_generation_bound', 3),
                                ('state_cleanup_complete', 3), ('host_home_readable', 18)]:
            checks.append(dict(scenario=run, role=None, check=check,
                               attempts=attempts, denials=0, passed=True))
    return dict(status='incomplete', formal_eligible=False, model_launched=False,
                resources_removed=True, guardian_alive=False, code_sha256='a' * 64,
                checks=checks, parent_recovery_status=[dict(transition='verified',
                    reason='normal_completion', guardian_dead=True, guardian_reaped=True,
                    guardian_exit=0, guardian_signal=None, status_drain='empty',
                    counts=dict(cgroup_populated=False, registry_total=0, unattached=0,
                                reap_unconfirmed=0, unconfirmed_reason=None))])


class StateEvidenceTests(unittest.TestCase):
    def test_exact_dummy_report_does_not_authorize_production(self):
        self.assertIs(validate_probe(report())['production_authorized'], False)

    def test_missing_extra_failed_or_inexact_checks_are_rejected(self):
        for mutation in ['missing', 'extra', 'failed', 'count', 'bool_count']:
            value = report()
            if mutation == 'missing':
                value['checks'].pop()
            elif mutation == 'extra':
                value['checks'].append(copy.deepcopy(value['checks'][0]))
            elif mutation == 'failed':
                value['checks'][0]['passed'] = False
            else:
                value['checks'][1]['attempts'] = True if mutation == 'bool_count' else 2
            with self.assertRaises(ValueError):
                validate_probe(value)

    def test_production_claim_or_unconfirmed_cleanup_is_rejected(self):
        for key, replacement in [('status', 'passed'), ('formal_eligible', True),
                                 ('resources_removed', False), ('guardian_alive', True)]:
            value = report()
            value[key] = replacement
            with self.assertRaises(ValueError):
                validate_probe(value)
        value = report()
        value['parent_recovery_status'][-1]['counts']['reap_unconfirmed'] = 1
        with self.assertRaises(ValueError):
            validate_probe(value)
