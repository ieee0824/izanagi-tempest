import importlib.util
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / 'integration' / 'linux_existing_cgroup_smoke.py'
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location('linux_existing_cgroup_smoke', MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AuditBasenameTests(unittest.TestCase):
    def test_snapshot_accepts_only_snapshot_prefix(self):
        self.assertTrue(MODULE.valid_audit_basename({
            'scenario': 'snapshot_exit_race',
            'audit_basename': 'tempest-snapshot-race-audit-a1_b2c3d.json'}))
        self.assertFalse(MODULE.valid_audit_basename({
            'scenario': 'snapshot_exit_race',
            'audit_basename': 'tempest-primary-fault-audit-a1_b2c3d.json'}))

    def test_primary_accepts_only_primary_prefix(self):
        for scenario in ['primary_eof_guardian_death', 'primary_output_cleanup_eio']:
            with self.subTest(scenario=scenario):
                self.assertTrue(MODULE.valid_audit_basename({
                    'scenario': scenario,
                    'audit_basename': 'tempest-primary-fault-audit-a1_b2c3d.json'}))
                self.assertFalse(MODULE.valid_audit_basename({
                    'scenario': scenario,
                    'audit_basename': 'tempest-snapshot-race-audit-a1_b2c3d.json'}))

    def test_other_scenarios_require_no_audit(self):
        self.assertTrue(MODULE.valid_audit_basename({
            'scenario': 'initial_admission', 'audit_basename': None}))
        self.assertFalse(MODULE.valid_audit_basename({
            'scenario': 'initial_admission',
            'audit_basename': 'tempest-primary-fault-audit-a1_b2c3d.json'}))

    def test_none_is_allowed_before_audit_close(self):
        for scenario in ['snapshot_exit_race', 'primary_eof_guardian_death']:
            with self.subTest(scenario=scenario):
                self.assertTrue(MODULE.valid_audit_basename({
                    'scenario': scenario, 'audit_basename': None}))


if __name__ == '__main__':
    unittest.main()
