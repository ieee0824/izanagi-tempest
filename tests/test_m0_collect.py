import importlib.util
from pathlib import Path
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
