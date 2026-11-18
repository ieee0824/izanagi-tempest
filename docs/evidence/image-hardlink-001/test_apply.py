"""Root-only dummy filesystem tests; production image paths are never opened."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('apply.py')


class HardlinkTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.getuid(), 0)
        self.temp = tempfile.TemporaryDirectory(prefix='tempest-hardlink-dummy-', dir='/run')
        self.root = Path(self.temp.name)
        spec = importlib.util.spec_from_file_location('dummy_apply', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        paths = []
        self.body = b'local dummy qcow2 substitute\n' * 100
        for i in range(8):
            parent = self.root / str(i)
            parent.mkdir(mode=0o750)
            path = parent / 'image.qcow2'
            path.write_bytes(self.body)
            os.chown(path, 0, 988)
            path.chmod(0o440)
            paths.append(path)
        self.module.PATHS = tuple(paths)
        self.module.DIGEST = hashlib.sha256(self.body).hexdigest()
        self.module.JOURNAL = self.root / 'journal.private.jsonl'
        self.module.verify_preserved = lambda: {'dummy_only': True}

    def tearDown(self):
        self.temp.cleanup()

    def run_apply(self):
        with patch.object(sys, 'argv', ['apply.py', '--apply', '--authorization-message', 'DUMMY-TEST-ONLY']), \
             patch.object(self.module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), \
             contextlib.redirect_stdout(io.StringIO()):
            self.module.main()

    def identities(self):
        return [(p.stat().st_ino, p.stat().st_nlink) for p in self.module.PATHS]

    def test_seven_replacements_keep_bytes_modes_and_record_authority(self):
        canonical = self.module.PATHS[0].stat().st_ino
        self.run_apply()
        self.assertEqual(self.identities(), [(canonical, 8)] * 8)
        for path in self.module.PATHS:
            self.assertEqual(path.read_bytes(), self.body)
            self.assertEqual(path.stat().st_mode & 0o777, 0o440)
        rows = [json.loads(l) for l in self.module.JOURNAL.read_text().splitlines()]
        self.assertEqual(sum(r['phase'] == 'replaced' for r in rows), 7)
        self.assertEqual(rows[-1]['phase'], 'completed')
        self.assertEqual(rows[0]['authorization_message'], 'DUMMY-TEST-ONLY')
        self.assertEqual(rows[0]['script_sha256'], hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
        self.assertEqual(len(rows[0]['physical_identity_exception']), 3)

    def test_wrong_hash_owner_mode_and_link_count_refused_before_replacement(self):
        for fault in ('hash', 'owner', 'mode', 'links'):
            with self.subTest(fault=fault):
                target = self.module.PATHS[-1]
                if fault == 'hash': target.write_bytes(b'wrong dummy data')
                if fault == 'owner': os.chown(target, 999, 988)
                if fault == 'mode': target.chmod(0o640)
                extra = self.root / 'extra'
                if fault == 'links': os.link(target, extra)
                before = self.identities()
                with self.assertRaises(AssertionError): self.run_apply()
                self.assertEqual(self.identities(), before)
                self.module.JOURNAL.unlink()
                if extra.exists(): extra.unlink()
                target.write_bytes(self.body)
                os.chown(target, 0, 988)
                target.chmod(0o440)

    def test_existing_journal_refuses_all_changes(self):
        self.module.JOURNAL.write_text('prior attempt\n')
        before = self.identities()
        with self.assertRaises(FileExistsError): self.run_apply()
        self.assertEqual(self.identities(), before)

    def test_partial_failure_cannot_be_retried(self):
        original = os.replace
        calls = 0
        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('injected dummy replace failure')
            return original(*args, **kwargs)
        with patch.object(self.module.os, 'replace', side_effect=fail_second):
            with self.assertRaises(OSError): self.run_apply()
        before = self.identities()
        self.assertEqual(sum(i == before[0][0] for i, n in before), 2)
        with self.assertRaises(FileExistsError): self.run_apply()
        self.assertEqual(self.identities(), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
