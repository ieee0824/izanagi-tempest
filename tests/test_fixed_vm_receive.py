import json
from pathlib import Path
import runpy
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integration'))
from fixed_vm_receive_observe import PHASES, validate_guest_export


class FixedVmReceiveTests(unittest.TestCase):
    def test_denied_guest_receipt_cannot_be_hidden_by_closing_phase(self):
        process = runpy.run_path(str(ROOT / 'image/fixed_vm_receive.py'))['process']
        nonce = 'a' * 32
        boot_id = '3d6aa964-65a7-4c14-9444-70ecc42b55f8'
        with TemporaryDirectory() as directory, patch('pathlib.Path.read_text', return_value=boot_id):
            process.__globals__['RECORD_DIR'] = Path(directory)
            for phase in PHASES:
                process('start', nonce, phase, None)
                payload = f'tempest-dummy-v1:{nonce}:{phase}'
                if phase == 'deny_other':
                    payload = 'unexpected request'
                ack = process('request', nonce, phase, payload)
                self.assertEqual(ack['matched'], phase != 'deny_other')
                process('end', nonce, phase, None)
            report = process('report', nonce, PHASES[-1], None)
        self.assertEqual(report['phases'][2]['delta'], {'received': 1, 'matched': 0})
        with self.assertRaisesRegex(ValueError, 'unexpected guest count'):
            validate_guest_export(json.dumps(report).encode(), run_nonce=nonce, boot_id=boot_id)
