import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('reservation_observe',
    Path(__file__).resolve().parents[1] / 'docs/evidence/runtime-reservation-001/observe.py')
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)


class ReadinessTests(unittest.TestCase):
    def test_marker_is_complete_and_group_readable_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = os.link
            def publish(source, target, **kwargs):
                self.assertFalse(target.exists())
                self.assertEqual(source.read_text(), 'ready\n')
                self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o440)
                link(source, target, **kwargs)
            previous = os.umask(0o077)
            try:
                with patch.object(OBS.os, 'fchown') as owner, patch.object(OBS.os, 'link', side_effect=publish):
                    OBS.publish_ready(root)
                self.assertEqual(owner.call_args.args[1:], (0, 988))
            finally:
                os.umask(previous)
            self.assertEqual((root / 'observer-ready').read_text(), 'ready\n')
            self.assertFalse((root / 'observer-ready.pending').exists())

    def test_existing_marker_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'observer-ready').write_text('previous')
            with patch.object(OBS.os, 'fchown'), self.assertRaises(FileExistsError):
                OBS.publish_ready(root)
            self.assertEqual((root / 'observer-ready').read_text(), 'previous')

    def test_failed_write_does_not_publish_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(OBS.os, 'fchown', side_effect=OSError('injected')):
                with self.assertRaises(OSError):
                    OBS.publish_ready(root)
            self.assertFalse((root / 'observer-ready').exists())
