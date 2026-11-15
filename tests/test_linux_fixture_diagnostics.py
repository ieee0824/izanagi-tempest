import importlib.util
import ast
import os
import pathlib
import select
import sys
import time
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / 'integration' / 'linux_existing_cgroup_smoke.py'
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location('linux_existing_cgroup_smoke', MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SNAPSHOT_PATH = MODULE_PATH.parent / 'linux_snapshot_race_smoke.py'
SNAPSHOT_MODULE = ast.parse(SNAPSHOT_PATH.read_text())
SNAPSHOT_FIXTURE = ast.literal_eval(SNAPSHOT_MODULE.body[2].value)
FIXTURE_TREE = ast.parse(SNAPSHOT_FIXTURE)
PATH_FUNCTION = next(node for node in FIXTURE_TREE.body
                     if isinstance(node, ast.FunctionDef) and node.name == 'path_presence_disposition')
PATH_NAMESPACE = {}
exec(compile(ast.Module(body=[PATH_FUNCTION], type_ignores=[]), '<fixture-helper>', 'exec'), PATH_NAMESPACE)
PIPE_FUNCTION = next(node for node in FIXTURE_TREE.body
                     if isinstance(node, ast.FunctionDef) and node.name == 'bounded_pipe_reads')
PIPE_NAMESPACE = {'os': os, 'select': select, 'time': time}
exec(compile(ast.Module(body=[PIPE_FUNCTION], type_ignores=[]), '<fixture-helper>', 'exec'), PIPE_NAMESPACE)


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


class SnapshotPathPresenceTests(unittest.TestCase):
    def test_all_presence_boundaries(self):
        classify = PATH_NAMESPACE['path_presence_disposition']
        self.assertEqual(classify(False, False), 'already_absent')
        self.assertEqual(classify(True, False), 'preserved')
        self.assertEqual(classify(False, True), 'preserved')
        self.assertEqual(classify(True, True), 'both_present')


class BoundedPipeReadTests(unittest.TestCase):
    def run_read(self, content, close_writer, limit=9, timeout=0.02):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, 'rb', buffering=0)
        try:
            if content: os.write(write_fd, content)
            if close_writer:
                os.close(write_fd)
                write_fd = None
            return PIPE_NAMESPACE['bounded_pipe_reads']({'stdout': stream}, limit, timeout)
        finally:
            stream.close()
            if write_fd is not None: os.close(write_fd)

    def test_complete_oversize_and_timeout(self):
        values, status = self.run_read(b'{}', True)
        self.assertEqual((values['stdout'], status), (b'{}', 'complete'))
        values, status = self.run_read(b'123456789', True)
        self.assertEqual((values['stdout'], status), (b'123456789', 'oversize'))
        values, status = self.run_read(b'', False)
        self.assertEqual((values['stdout'], status), (b'', 'timeout'))


if __name__ == '__main__':
    unittest.main()
