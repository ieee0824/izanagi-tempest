import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / 'tools/m0/probe-agent.py'


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


if __name__ == '__main__':
    unittest.main()
