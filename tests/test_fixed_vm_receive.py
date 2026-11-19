import errno
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import sys
import time
from types import SimpleNamespace
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integration'))
from fixed_vm_receive_observe import (
    AlternateListener,
    PHASES,
    TrialBoundaries,
    collect_trial,
    observe_guest,
    receiver_argv,
    session_binding,
    validate_guest_export,
    validate_trial_counts,
)


def phase_transport(phase, refused=errno.EPERM):
    if phase == 'deny_other':
        return {'alternate': {'connect_errno': refused, 'relay_exit': 'not_started'}}
    result = {'agent': {'connect_errno': 0, 'relay_exit': 'complete'}}
    if phase != 'allow_same_run':
        result['alternate'] = {'connect_errno': 0, 'relay_exit': 'complete'}
    return result


class FixedVmReceiveTests(unittest.TestCase):
    def test_alternate_listener_counts_unserviced_accept_separately(self):
        with AlternateListener() as listener:
            self.assertEqual(listener.snapshot(), {'accepted': 0, 'matched': 0})
            address = ('127.0.0.1', listener.port)
            with socket.create_connection(address, timeout=2) as peer:
                peer.sendall(b'tempest-alternate-dummy-v1')
                listener.serve_control(deadline=time.monotonic() + 2)
                with peer.makefile('rb') as stream:
                    self.assertEqual(stream.read(), b'tempest-alternate-ack-v1')
            self.assertEqual(listener.snapshot(), {'accepted': 1, 'matched': 1})
            with socket.create_connection(address, timeout=2):
                self.assertEqual(listener.snapshot(), {'accepted': 2, 'matched': 1})
            self.assertEqual(listener.snapshot(), {'accepted': 2, 'matched': 1})

    def test_request_requires_trial_connection(self):
        execute = Mock()
        nonce = 'a' * 32
        boot_id = '3d6aa964-65a7-4c14-9444-70ecc42b55f8'
        with self.assertRaisesRegex(ValueError, 'request requires the trial connection'):
            observe_guest(execute, run_nonce=nonce, boot_id=boot_id,
                          phase='allow_same_run', operation='request')
        execute.assert_not_called()
        argv = receiver_argv(run_nonce=nonce, phase='allow_same_run', operation='request')
        self.assertEqual(argv[-4:], ['request', nonce, 'allow_same_run',
                                    f'tempest-dummy-v1:{nonce}:allow_same_run'])
        with self.assertRaises(ValueError):
            receiver_argv(run_nonce=nonce, phase='deny_other', operation='request')

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

    def test_collects_all_intervals_using_the_guest_receiver(self):
        process = runpy.run_path(str(ROOT / 'image/fixed_vm_receive.py'))['process']
        nonce = 'a' * 32
        boot_id = '3d6aa964-65a7-4c14-9444-70ecc42b55f8'
        forward = {'pid': 42, 'starttime': 100, 'port': 34765}
        host_counts = {'accepted': 0, 'matched': 0}

        def execute(*argv, timeout):
            operation, run_nonce, phase = argv[-3:]
            self.assertIn(operation, ('start', 'end', 'report'))
            record = process(operation, run_nonce, phase, None)
            return SimpleNamespace(returncode=0, stdout=json.dumps(record) + '\n')

        def run_phase(phase):
            if phase != 'deny_other':
                argv = receiver_argv(run_nonce=nonce, phase=phase, operation='request')
                process(*argv[-4:])
            if phase in ('control_before', 'control_after'):
                host_counts['accepted'] += 1
                host_counts['matched'] += 1
            return phase_transport(phase)

        with TemporaryDirectory() as directory, patch('pathlib.Path.read_text', return_value=boot_id):
            process.__globals__['RECORD_DIR'] = Path(directory)
            result = collect_trial(
                execute, lambda: (forward, b'a' * 32), lambda: host_counts,
                run_phase, run_nonce=nonce, boot_id=boot_id,
            )

        self.assertEqual([row['delta']['received'] for row in result['guest']['phases']], [1, 1, 0, 1])
        self.assertEqual([row['delta']['accepted'] for row in result['host_phases']], [1, 0, 0, 1])
        self.assertEqual(result['phase_transport']['deny_other'], phase_transport('deny_other'))

    def test_trial_rejects_forward_change_during_final_report(self):
        nonce = 'b' * 32
        boot_id = '3d6aa964-65a7-4c14-9444-70ecc42b55f8'
        forward = {'pid': 42, 'starttime': 100, 'port': 34765}

        def guest_ack(_execute, *, run_nonce, boot_id, phase, operation):
            if operation == 'report':
                forward['pid'] = 43
            return dict(run_nonce=run_nonce, boot_id=boot_id, phase=phase, operation=operation)

        with patch('fixed_vm_receive_observe.observe_guest', side_effect=guest_ack):
            with self.assertRaisesRegex(ValueError, 'identity changed during final report'):
                collect_trial(
                    None, lambda: (forward, b'a' * 32),
                    lambda: {'accepted': 0, 'matched': 0},
                    phase_transport,
                    run_nonce=nonce, boot_id=boot_id,
                )

    def test_trial_requires_policy_errno_even_when_host_count_is_zero(self):
        def guest_ack(_execute, *, run_nonce, boot_id, phase, operation):
            return dict(run_nonce=run_nonce, boot_id=boot_id, phase=phase, operation=operation)

        with patch('fixed_vm_receive_observe.observe_guest', side_effect=guest_ack):
            for result in (0, errno.ECONNREFUSED, errno.ETIMEDOUT, None):
                with self.subTest(result=result), self.assertRaisesRegex(ValueError, 'connect errno'):
                    collect_trial(
                        None, lambda: ({'pid': 42}, b'a' * 32),
                        lambda: {'accepted': 0, 'matched': 0},
                        lambda phase: phase_transport(phase, result),
                        run_nonce='b' * 32, boot_id='3d6aa964-65a7-4c14-9444-70ecc42b55f8',
                    )

    def test_trial_rejects_failed_relay_after_successful_connect(self):
        def guest_ack(_execute, *, run_nonce, boot_id, phase, operation):
            return dict(run_nonce=run_nonce, boot_id=boot_id, phase=phase, operation=operation)

        with patch('fixed_vm_receive_observe.observe_guest', side_effect=guest_ack):
            for status in ('timeout', 'short_io', 'not_started'):
                result = phase_transport('control_before')
                result['agent']['relay_exit'] = status
                with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'relay exit'):
                    collect_trial(
                        None, lambda: ({'pid': 42}, b'a' * 32),
                        lambda: {'accepted': 0, 'matched': 0}, lambda _phase: result,
                        run_nonce='b' * 32, boot_id='3d6aa964-65a7-4c14-9444-70ecc42b55f8',
                    )


class FixedRelayCleanupTests(unittest.TestCase):
    def test_wait_ready_rejects_readiness_at_absolute_deadline(self):
        from fixed_relay_pipe_smoke import wait_ready

        with (
            patch('fixed_relay_pipe_smoke.time.monotonic', side_effect=(1.0, 2.0)),
            patch('fixed_relay_pipe_smoke.select.poll') as poll,
        ):
            poll.return_value.poll.return_value = [(42, 1)]
            with self.assertRaisesRegex(TimeoutError, 'fixed relay deadline'):
                wait_ready(42, 1, 2.0)
        poll.return_value.poll.assert_called_once_with(1000)


    @unittest.skipUnless(sys.platform == 'linux', 'requires Linux pidfd')
    def test_pidfd_open_failure_reaps_real_child(self):
        from fixed_relay_pipe_smoke import exercise

        failure = OSError(errno.EMFILE, 'injected pidfd_open failure')
        with patch('os.pidfd_open', side_effect=failure) as pidfd_open:
            with self.assertRaises(OSError) as raised:
                exercise('complete')
        self.assertIs(raised.exception, failure)
        pidfd_open.assert_called_once()
        (pid,) = pidfd_open.call_args.args
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)
