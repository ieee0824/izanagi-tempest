import json
import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / 'tools/m0/probe-agent.py'
SPEC = importlib.util.spec_from_file_location('probe_agent', PROBE)
PROBE_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE_MODULE)


class ProbeAgentGateTests(unittest.TestCase):
    def run_fake(self, body):
        with tempfile.TemporaryDirectory(prefix='tempest-probe-test-') as temporary:
            root = Path(temporary)
            executable = root / 'fake-agent.py'
            executable.write_text('#!/usr/bin/env python3\n' + body)
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            output = root / 'output'
            result = subprocess.run(
                [sys.executable, str(PROBE), '--agent', 'codex', '--executable',
                 str(executable), '--output', str(output)],
                capture_output=True, text=True, timeout=20)
            summary = json.loads((output / 'summary.json').read_text())
            return result, summary

    def test_zero_request_cli_is_rejected(self):
        result, summary = self.run_fake(
            "import sys\n"
            "print('fake 1.0' if '--version' in sys.argv else '')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(summary['status'], 'failed')
        self.assertIn('api_requests_incomplete', summary['failures'])
        self.assertIn('tool_results_missing', summary['failures'])

    def test_host_write_is_rejected_even_when_cli_exits_zero(self):
        result, summary = self.run_fake(
            "import pathlib, sys\n"
            "if '--version' in sys.argv:\n"
            "    print('fake 1.0')\n"
            "else:\n"
            "    (pathlib.Path.cwd().parent / 'write-canary.txt').write_text('changed')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(summary['write_canary_exists'])
        self.assertIn('write_canary_created', summary['failures'])

    def test_result_ids_and_structured_rejections_are_required(self):
        attempts = [('exec_command', {}), ('apply_patch', {}), ('view_image', {})]
        valid = [[
            {'type': 'function_call_output', 'call_id': f'call_{index}',
             'output': f'unsupported call: {name}'}
            for index, (name, _) in enumerate(attempts)
        ]]
        self.assertEqual(PROBE_MODULE.verify_tool_results('codex', attempts, valid), [])

        false_success = [[
            {'type': 'function_call_output', 'call_id': f'wrong_{index}',
             'output': 'success: read file denied.txt'}
            for index in range(3)
        ]]
        failures = PROBE_MODULE.verify_tool_results('codex', attempts, false_success)
        self.assertIn('tool_result_unknown_id', failures)
        self.assertIn('tool_results_missing', failures)
        self.assertIn('host_tool_rejection_unverified_0', failures)

    def test_claude_rejection_requires_error_flag_and_matching_id(self):
        attempts = [('Bash', {}), ('Read', {}), ('Write', {})]
        valid = [[
            {'type': 'tool_result', 'tool_use_id': f'call_{index}', 'is_error': True,
             'content': f'<tool_use_error>Error: No such tool available: {name}. disabled</tool_use_error>'}
            for index, (name, _) in enumerate(attempts)
        ]]
        self.assertEqual(PROBE_MODULE.verify_tool_results('claude', attempts, valid), [])
        valid[0][0]['is_error'] = False
        self.assertIn('host_tool_rejection_unverified_0',
                      PROBE_MODULE.verify_tool_results('claude', attempts, valid))


if __name__ == '__main__':
    unittest.main()
