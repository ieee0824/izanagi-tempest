import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integration'))
from fixed_vm_receive_observe import (
    PHASES,
    TrialBoundaries,
    session_binding,
    validate_guest_export,
    validate_trial_counts,
)


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

    def test_trial_accepts_only_matching_host_intervals(self):
        process = runpy.run_path(str(ROOT / 'image/fixed_vm_receive.py'))['process']
        nonce = 'b' * 32
        boot_id = '3d6aa964-65a7-4c14-9444-70ecc42b55f8'
        host_phases = []
        total = 0
        with TemporaryDirectory() as directory, patch('pathlib.Path.read_text', return_value=boot_id):
            process.__globals__['RECORD_DIR'] = Path(directory)
            for phase in PHASES:
                process('start', nonce, phase, None)
                if phase != 'deny_other':
                    process('request', nonce, phase, f'tempest-dummy-v1:{nonce}:{phase}')
                process('end', nonce, phase, None)
                delta = int(phase in ('control_before', 'control_after'))
                host_phases.append({
                    'run_nonce': nonce,
                    'boot_id': boot_id,
                    'phase': phase,
                    'start': {'accepted': total, 'matched': total},
                    'end': {'accepted': total + delta, 'matched': total + delta},
                    'delta': {'accepted': delta, 'matched': delta},
                })
                total += delta
            report = process('report', nonce, PHASES[-1], None)
        raw = json.dumps(report).encode()
        self.assertEqual(validate_trial_counts(raw, host_phases, run_nonce=nonce, boot_id=boot_id), report)

        host_phases[2]['delta']['accepted'] = 1
        with self.assertRaisesRegex(ValueError, 'unexpected alternate host listener count'):
            validate_trial_counts(raw, host_phases, run_nonce=nonce, boot_id=boot_id)
        host_phases[2]['delta']['accepted'] = 0

        host_phases[2]['run_nonce'] = 'c' * 32
        with self.assertRaisesRegex(ValueError, 'host phase binding mismatch'):
            validate_trial_counts(raw, host_phases, run_nonce=nonce, boot_id=boot_id)

    def test_session_binding_rejects_wrong_parent_port_and_symlink(self):
        with TemporaryDirectory() as directory:
            home = Path(directory)
            workspace = home / 'workspace'
            instance = hashlib.sha256(os.fsencode(workspace)).hexdigest()
            path = home / '.izanagi' / 'instances' / instance / 'session.json'
            path.parent.mkdir(parents=True)
            data = json.dumps({'backend': {'type': 'qemu', 'host_port': 23456},
                               'pid': 123, 'started_at': 1}).encode()
            path.write_bytes(data)
            path.chmod(0o600)
            expected = {'owner_uid': os.getuid(), 'supervisor_pid': 123,
                        'forward': {'port': 23456}}
            self.assertEqual(session_binding(workspace, home, **expected),
                             hashlib.sha256(data).digest())
            for difference in ({'supervisor_pid': 124}, {'forward': {'port': 23457}}):
                with self.subTest(difference=difference), self.assertRaises(ValueError):
                    session_binding(workspace, home, **(expected | difference))
            moved = path.rename(path.with_suffix('.original'))
            path.symlink_to(moved)
            with self.assertRaises(OSError):
                session_binding(workspace, home, **expected)

    def test_trial_boundaries_require_one_identity_through_all_phases(self):
        nonce = 'b' * 32
        boot_id = '3d6aa964-65a7-4c14-9444-70ecc42b55f8'
        forward = {'pid': 42, 'starttime': 100, 'port': 34765}
        fingerprint = b'a' * 32
        identity = dict(run_nonce=nonce, boot_id=boot_id, forward=forward,
                        session_fingerprint=fingerprint)
        trial = TrialBoundaries(**identity)
        for phase in PHASES:
            for edge in ('start', 'end'):
                ack = {'run_nonce': nonce, 'boot_id': boot_id, 'phase': phase, 'operation': edge}
                with self.assertRaisesRegex(ValueError, 'incomplete trial boundary'):
                    trial.require_complete()
                if (phase, edge) == ('deny_other', 'end'):
                    changes = (
                        {'guest_ack': ack | {'boot_id': 'c6ce3b14-fb73-46dc-8e4b-b10c673a19a4'}},
                        {'forward': forward | {'pid': 43}},
                        {'session_fingerprint': b'b' * 32},
                    )
                    observed = dict(guest_ack=ack, forward=forward, session_fingerprint=fingerprint)
                    for change in changes:
                        with self.subTest(change=change):
                            with self.assertRaisesRegex(ValueError, 'identity changed'):
                                trial.observe(phase, edge, **(observed | change))
                trial.observe(phase, edge, guest_ack=ack, forward=forward,
                              session_fingerprint=fingerprint)
        trial.require_complete()
