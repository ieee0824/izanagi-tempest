import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'runtime_normal_observe', Path(__file__).resolve().parents[1] / 'integration/runtime_normal_observe.py')
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)


def sample(index):
    return {'unit': {'InvocationID': 'one', 'LoadState': 'loaded', 'ActiveState': 'active'},
            'cgroup_pids': [100 + index], 'external_listener_observed': False,
            'qemu_network': [{'pid': 100 + index, 'starttime_ticks': 1000 + index,
                             'cwd': OBS.STAGES[index],
                             'network_args': [['-netdev', 'user,id=n,restrict=on,hostfwd=tcp:127.0.0.1:40001-:9001']],
                             'storage_args': [['-drive', 'file=' + OBS.ROOT + '/inputs/image.qcow2,snapshot=on'],
                                              ['-fsdev', 'local,path=.,security_model=mapped-xattr,readonly=on']]}]}


def launch(index):
    return {'state': 'running', 'boot_nonce': f'{index + 1:032x}',
            'supervisor_pid': 200 + index, 'session_fingerprint': f'{index + 1:064x}'}


class RuntimeObserverTests(unittest.TestCase):
    def test_four_sequential_sessions_are_distinct_and_bound(self):
        sessions = OBS.Sessions()
        for index in range(4):
            self.assertEqual(sessions.observe(sample(index)), index)
            sessions.bind(index, launch(index))
            self.assertEqual(sessions.observe(sample(index)), index)
            sessions.bind(index, launch(index))
            self.assertIsNone(sessions.observe({'qemu_network': [], 'external_listener_observed': False}))
        sessions.require_complete()
        self.assertEqual(len(sessions.snapshot()), 4)
        self.assertTrue(all(row['binding'] for row in sessions.snapshot()))

    def test_stage_skip_reversal_and_same_stage_replacement_fail(self):
        for row in [sample(2), dict(sample(0), qemu_network=[dict(sample(0)['qemu_network'][0], pid=999)]),
                    dict(sample(0), qemu_network=[dict(sample(0)['qemu_network'][0], starttime_ticks=999)])]:
            sessions = OBS.Sessions()
            sessions.observe(sample(0))
            with self.assertRaisesRegex(RuntimeError, 'stage order or VM identity'):
                sessions.observe(row)
        sessions = OBS.Sessions()
        sessions.observe(sample(0))
        sessions.observe(sample(1))
        with self.assertRaises(RuntimeError):
            sessions.observe(sample(0))

    def test_reused_vm_and_parallel_vms_fail(self):
        sessions = OBS.Sessions()
        sessions.observe(sample(0))
        reused = sample(1)
        reused['qemu_network'][0].update(pid=100, starttime_ticks=1000)
        with self.assertRaisesRegex(RuntimeError, 'reused across stages'):
            sessions.observe(reused)
        row = sample(0)
        row['qemu_network'].append(copy.deepcopy(row['qemu_network'][0]))
        with self.assertRaisesRegex(RuntimeError, 'multiple simultaneous'):
            OBS.Sessions().observe(row)

    def test_unexpected_workspace_image_and_network_fail(self):
        for field in ['workspace', 'image', 'network']:
            row = sample(0)
            qemu = row['qemu_network'][0]
            if field == 'workspace':
                qemu['cwd'] = '/unexpected'
            elif field == 'image':
                qemu['storage_args'][0][1] = 'file=/old/image.qcow2,snapshot=on'
            else:
                qemu['network_args'][0][1] = qemu['network_args'][0][1].replace('restrict=on', 'restrict=off')
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                OBS.Sessions().observe(row)

    def test_missing_changed_and_reused_session_metadata_fail(self):
        sessions = OBS.Sessions()
        for index in range(4):
            sessions.observe(sample(index))
        with self.assertRaisesRegex(RuntimeError, 'not all planned'):
            sessions.require_complete()
        sessions.bind(0, launch(0))
        for field, value in [('boot_nonce', 'f' * 32), ('supervisor_pid', 999),
                             ('session_fingerprint', 'f' * 64), ('state', 'spawned')]:
            changed = dict(launch(0), **{field: value})
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                sessions.bind(0, changed)
        for field in ['boot_nonce', 'session_fingerprint']:
            reused = dict(launch(1), **{field: launch(0)[field]})
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                sessions.bind(1, reused)

    def test_invalid_process_identity_is_not_observation_evidence(self):
        for value in [None, True, 0, -1, '100']:
            row = sample(0)
            row['qemu_network'][0]['pid'] = value
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'identity missing or invalid'):
                OBS.Sessions().observe(row)

    def test_launch_reader_rejects_symlink_and_checks_private_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / 'sandbox'
            path = Path(directory) / 'vm-launch.json'
            path.write_text(json.dumps(launch(0)))
            metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=999, st_gid=988)
            with patch.object(OBS.os, 'fstat', return_value=metadata):
                self.assertEqual(OBS.read_launch(workspace), launch(0))
            with patch.object(OBS.os, 'fstat', return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o644, st_uid=999, st_gid=988)):
                with self.assertRaisesRegex(RuntimeError, 'not private'):
                    OBS.read_launch(workspace)
            path.unlink()
            path.symlink_to('/nonexistent')
            with self.assertRaises(OSError):
                OBS.read_launch(workspace)

    def test_gc_keeps_terminal_unknown(self):
        rows = [sample(0), {'unit': {'InvocationID': '', 'LoadState': 'not-found', 'ActiveState': 'inactive'},
                            'cgroup_pids': [], 'qemu_network': [], 'external_listener_observed': False}]
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBS.os, 'geteuid', return_value=0), \
                 patch.object(OBS.BOOTSTRAP, 'sample', side_effect=rows), \
                 patch.object(OBS, 'read_launch', return_value=launch(0)), patch.object(OBS.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'terminal attributes not captured'):
                    OBS.main()

    def test_main_binds_all_four_sessions_before_accepting_terminal(self):
        rows = [sample(index) for index in range(4)]
        rows.append({'unit': {'InvocationID': 'one', 'LoadState': 'loaded', 'ActiveState': 'inactive'},
                     'cgroup_pids': [], 'qemu_network': [], 'external_listener_observed': False})
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence.jsonl'
            with patch('sys.argv', ['observe', '--output', str(output)]), \
                 patch.object(OBS.os, 'geteuid', return_value=0), \
                 patch.object(OBS.BOOTSTRAP, 'sample', side_effect=rows) as read, \
                 patch.object(OBS, 'read_launch', side_effect=[launch(index) for index in range(4)]), \
                 patch.object(OBS.time, 'sleep'):
                OBS.main()
            self.assertTrue(all(call.args == (OBS.UNIT,) for call in read.call_args_list))
            records = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(records[-1]['observed_sessions']), 4)


class SeedLossObserverTests(unittest.TestCase):
    def row(self):
        row = sample(0)
        qemu = row['qemu_network'][0]
        qemu['cwd'] = OBS.PROFILES['seed-loss'][2][0]
        qemu['storage_args'][0][1] = 'file=' + OBS.SEED_ROOT + '/inputs/image.qcow2,snapshot=on'
        return row

    def test_single_seed_session_is_complete_only_after_binding(self):
        sessions = OBS.Sessions('seed-loss')
        self.assertEqual(sessions.observe(self.row()), 0)
        with self.assertRaisesRegex(RuntimeError, 'not all planned'):
            sessions.require_complete()
        sessions.bind(0, launch(0))
        sessions.require_complete()
        self.assertEqual(sessions.snapshot()[0]['workspace'], self.row()['qemu_network'][0]['cwd'])

    def test_normal_workspace_image_and_replacement_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'unexpected runtime workspace'):
            OBS.Sessions('seed-loss').observe(sample(0))
        for change in ('image', 'replacement', 'retest'):
            sessions = OBS.Sessions('seed-loss')
            sessions.observe(self.row())
            row = self.row()
            if change == 'image':
                row['qemu_network'][0]['storage_args'][0][1] = sample(0)['qemu_network'][0]['storage_args'][0][1]
            elif change == 'replacement':
                row['qemu_network'][0]['pid'] += 1
            else:
                row['qemu_network'][0]['cwd'] = OBS.SEED_ROOT + '/work/runs/seed-reply-loss/retest/sandbox'
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                sessions.observe(row)

    def test_main_selects_seed_unit_and_launch_path(self):
        rows = [self.row(), {'unit': {'InvocationID': 'one', 'LoadState': 'loaded', 'ActiveState': 'inactive'},
                            'cgroup_pids': [], 'qemu_network': [], 'external_listener_observed': False}]
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--trial', 'seed-loss', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBS.os, 'geteuid', return_value=0), \
                 patch.object(OBS.BOOTSTRAP, 'sample', side_effect=rows) as read, \
                 patch.object(OBS, 'read_launch', return_value=launch(0)) as binding, patch.object(OBS.time, 'sleep'):
                OBS.main()
            self.assertTrue(all(call.args == (OBS.PROFILES['seed-loss'][1],) for call in read.call_args_list))
            binding.assert_called_once_with(OBS.PROFILES['seed-loss'][2][0])


class PresenceObserverTests(unittest.TestCase):
    def row(self, index):
        row = sample(0)
        qemu = row['qemu_network'][0]
        qemu.update(pid=100 + index, starttime_ticks=1000 + index, cwd=OBS.PRESENCE_STAGES[index])
        qemu['storage_args'][0][1] = 'file=' + OBS.PRESENCE_ROOT + '/inputs/image.qcow2,snapshot=on'
        return row

    def test_six_vm_order_matches_optional_retests(self):
        expected = ['finding-1-retest-1/sandbox', 'finding-1-retest-1/retest/sandbox',
                    'finding-1-retest-0/sandbox', 'finding-0-retest-1/sandbox',
                    'finding-0-retest-1/retest/sandbox', 'finding-0-retest-0/sandbox']
        self.assertEqual([path.removeprefix(OBS.PRESENCE_ROOT + '/work/runs/')
                          for path in OBS.PRESENCE_STAGES], expected)
        sessions = OBS.Sessions('presence')
        for index in range(6):
            self.assertEqual(sessions.observe(self.row(index)), index)
            sessions.bind(index, launch(index))
            if index < 5:
                with self.assertRaisesRegex(RuntimeError, 'not all planned'):
                    sessions.require_complete()
        sessions.require_complete()
        self.assertEqual(len(sessions.snapshot()), 6)

    def test_omitted_retest_and_other_trial_cannot_be_observed(self):
        for path in [OBS.PRESENCE_ROOT + '/work/runs/finding-1-retest-0/retest/sandbox',
                     OBS.PRESENCE_ROOT + '/work/runs/finding-0-retest-0/retest/sandbox', OBS.STAGES[0]]:
            row = self.row(0)
            row['qemu_network'][0]['cwd'] = path
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'unexpected runtime workspace'):
                OBS.Sessions('presence').observe(row)
