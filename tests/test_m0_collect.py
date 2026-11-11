import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

MODULE = Path(__file__).resolve().parents[1] / 'tools/m0/collect.py'
spec = importlib.util.spec_from_file_location('m0_collect', MODULE)
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)
BASELINE = (MODULE.parent / 'izanagi.example.toml').read_text()


class IsolationConfigTests(unittest.TestCase):
    def validate(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'izanagi.toml'
            path.write_text(text)
            return collect.validate_config(path)

    def test_rejects_weakened_isolation(self):
        for original, replacement in [
            ('restrict_network = true', 'restrict_network = false'),
            ('require_auth = true', 'require_auth = false'),
            ('read_only = true', 'read_only = false'),
            ('backend = "qemu"', 'backend = "native"'),
            ('tracer = "vm-agent"', 'tracer = "none"'),
            ('paths = ["."]', 'paths = ["/Users"]'),
        ]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.validate(BASELINE.replace(original, replacement))

    def test_rejects_export_and_proxies(self):
        for section in ['[behavior]\nenabled = true', '[dns_proxy]\nenabled = true',
                        '[http_capture]\nenabled = true']:
            with self.subTest(section=section), self.assertRaises(ValueError):
                self.validate(BASELINE + '\n' + section)

    def test_accepts_baseline(self):
        self.assertEqual(self.validate(BASELINE)['sandbox']['backend'], 'qemu')

    def test_missing_executable_is_evidence_not_crash(self):
        result = collect.capture(['/nonexistent/tempest-m0-executable'], Path.cwd())
        self.assertEqual(result['error'], 'spawn_failed')
        self.assertIsNone(result['returncode'])


class ReadinessTests(unittest.TestCase):
    def test_foreground_process_can_be_ready_without_exiting(self):
        process = Mock()
        process.poll.return_value = None
        probe = Mock(return_value={'returncode': 0, 'stdout': 'tempest-m0-ready\n'})
        self.assertTrue(collect.wait_ready(process, probe))

    def test_failed_supervisor_never_probes_auto_starting_exec(self):
        process = Mock()
        process.poll.return_value = 1
        probe = Mock()
        self.assertFalse(collect.wait_ready(process, probe))
        probe.assert_not_called()

    def test_retries_until_authenticated_marker(self):
        process = Mock()
        process.poll.return_value = None
        probe = Mock(side_effect=[{'returncode': 1, 'stdout': ''},
                                  {'returncode': 0, 'stdout': 'tempest-m0-ready\n'}])
        with patch.object(collect.time, 'sleep'):
            self.assertTrue(collect.wait_ready(process, probe))
        self.assertEqual(probe.call_count, 2)

    def test_deadline_does_not_pass_on_living_process_alone(self):
        process = Mock()
        process.poll.return_value = None
        self.assertFalse(collect.wait_ready(process, Mock(), timeout=0))


class CollectorLifecycleTests(unittest.TestCase):
    def test_foreground_boot_is_probed_then_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'izanagi'
            executable.write_text('#!' + sys.executable + '\n' + r"""
import json, os, signal, sys, time
from pathlib import Path
args = sys.argv[1:]
if args == ['--version']:
    print('fake-izanagi 1'); sys.exit(0)
command = args[2]
state = Path('fake-supervisor.pid')
if command == 'up':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    state.write_text(str(os.getpid()))
    print('サンドボックスを起動しました', flush=True)
    while True: time.sleep(0.01)
elif command == 'exec':
    if not state.exists(): sys.exit(9)
    if args[-1] == 'tempest-m0-ready': print('tempest-m0-ready')
elif command == 'down':
    os.kill(int(state.read_text()), signal.SIGTERM)
    state.unlink()
elif command == 'mcp':
    for line in sys.stdin:
        request = json.loads(line)
        if 'id' in request:
            print(json.dumps({'id':request['id'], 'result':{}}))
""")
            executable.chmod(0o700)
            config = root / 'izanagi.toml'
            config.write_text(BASELINE)
            output = root / 'evidence'
            result = subprocess.run([sys.executable, str(MODULE), '--output', str(output),
                                     '--config', str(config), '--boot'],
                                    env=dict(os.environ, PATH=str(root)),
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary['status'], 'unverified')
            self.assertEqual(summary['checks']['boot']['status'], 'passed')
            self.assertEqual(summary['checks']['cleanup']['status'], 'passed')
            self.assertFalse((output / 'sandbox/fake-supervisor.pid').exists())
            supervisor = summary['commands'][-1]
            self.assertIn('up', supervisor['argv'])
            self.assertEqual(supervisor['returncode'], 0)
            # The fake PATH has no Codex. A failed optional probe must not skip cleanup
            # or silently look like a successfully collected run.
            failed_output = root / 'failed-agent'
            failed = subprocess.run([sys.executable, str(MODULE), '--output', str(failed_output),
                                     '--config', str(config), '--boot', '--agent-probe', 'codex'],
                                    env=dict(os.environ, PATH=str(root)),
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(failed.returncode, 1, failed.stderr)
            failed_summary = json.loads((failed_output / 'summary.json').read_text())
            self.assertEqual(failed_summary['status'], 'blocked')
            self.assertEqual(failed_summary['checks']['agent_codex']['status'], 'failed')
            self.assertEqual(failed_summary['checks']['cleanup']['status'], 'passed')
            self.assertFalse((failed_output / 'sandbox/fake-supervisor.pid').exists())

    def test_guest_transfer_preserves_binary_across_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'lws'
            source.write_bytes(bytes(range(256)) * 300)
            original_capture = collect.capture

            def local_exec(argv, cwd):
                command = [sys.executable, *argv[4:]]
                command = [argument.replace('/tmp/tempest-m0-assets/', str(root / 'guest') + '/')
                           for argument in command]
                return original_capture(command, cwd)

            with patch.object(collect, 'capture', side_effect=local_exec):
                asset, entries = collect.upload_guest_file(['fake'], root, source)
            self.assertEqual(asset['status'], 'verified')
            self.assertEqual((root / 'guest/lws').read_bytes(), source.read_bytes())
            chunks = [entry for entry in entries if 'payload' in entry]
            self.assertEqual(len(chunks), 3)
            self.assertTrue(all(entry['argv'][-1] == '<base64 payload omitted>' for entry in chunks))


if __name__ == '__main__':
    unittest.main()
