import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'image_smoke_observe', Path(__file__).resolve().parents[1] / 'integration/image_smoke_observe.py')
OBSERVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVE)


def sample():
    return {'external_listener_observed': False, 'qemu_network': [{
        'pid': 42, 'starttime_ticks': 1234,
        'network_args': [['-netdev', 'user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:40001-:9001']],
        'storage_args': [['-drive', 'file=' + OBSERVE.ROOT + '/inputs/image.qcow2,format=qcow2,snapshot=on'],
                         ['-fsdev', 'local,id=fs0,path=' + OBSERVE.ROOT + '/work/output/workspace,security_model=mapped-xattr,readonly=on']]}]}


class SmokeObserverTests(unittest.TestCase):
    def test_attempt002_rejects_old_image_or_share(self):
        root = OBSERVE.ATTEMPTS['002'][1]
        row = sample()
        with self.assertRaisesRegex(RuntimeError, 'snapshot protection'):
            OBSERVE.validate_runtime(row, root)
        row['qemu_network'][0]['storage_args'][0][1] = (
            row['qemu_network'][0]['storage_args'][0][1].replace(OBSERVE.ROOT, root))
        with self.assertRaisesRegex(RuntimeError, 'share path'):
            OBSERVE.validate_runtime(row, root)
        row['qemu_network'][0]['storage_args'][1][1] = (
            row['qemu_network'][0]['storage_args'][1][1].replace(OBSERVE.ROOT, root))
        self.assertTrue(OBSERVE.validate_runtime(row, root))

    def test_attempt002_samples_only_its_fixed_unit(self):
        unit, root = OBSERVE.ATTEMPTS['002']
        active = sample()
        for entry in active['qemu_network'][0]['storage_args']:
            entry[1] = entry[1].replace(OBSERVE.ROOT, root)
        active.update(unit={'InvocationID': 'two', 'ActiveState': 'active', 'LoadState': 'loaded'},
                      cgroup_pids=[42])
        terminal = {'unit': {'InvocationID': 'two', 'ActiveState': 'inactive', 'LoadState': 'loaded'},
                    'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--attempt', '002', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=[active, terminal]) as read, \
                 patch.object(OBSERVE.time, 'sleep'):
                OBSERVE.main()
            self.assertEqual([call.args for call in read.call_args_list], [(unit,), (unit,)])

    def test_exec_exposure_rejects_other_image_and_binds_relative_share(self):
        root = OBSERVE.ATTEMPTS['exec-exposure-001'][1]
        row = sample()
        with self.assertRaisesRegex(RuntimeError, 'snapshot protection'):
            OBSERVE.validate_runtime(row, root)
        qemu = row['qemu_network'][0]
        qemu['storage_args'][0][1] = qemu['storage_args'][0][1].replace(OBSERVE.ROOT, root)
        qemu['storage_args'][1][1] = 'local,id=fs0,path=.,security_model=mapped-xattr,readonly=on'
        qemu['cwd'] = OBSERVE.ROOT + '/work/output/workspace'
        with self.assertRaisesRegex(RuntimeError, 'share path'):
            OBSERVE.validate_runtime(row, root)
        qemu['cwd'] = root + '/work/output/workspace'
        self.assertTrue(OBSERVE.validate_runtime(row, root))

    def test_exec_exposure_samples_only_its_fixed_unit(self):
        unit, root = OBSERVE.ATTEMPTS['exec-exposure-001']
        active = sample()
        for entry in active['qemu_network'][0]['storage_args']:
            entry[1] = entry[1].replace(OBSERVE.ROOT, root)
        active.update(unit={'InvocationID': 'exposure', 'ActiveState': 'active', 'LoadState': 'loaded'},
                      cgroup_pids=[42])
        terminal = {'unit': {'InvocationID': 'exposure', 'ActiveState': 'inactive', 'LoadState': 'loaded'},
                    'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--attempt', 'exec-exposure-001', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=[active, terminal]) as read, \
                 patch.object(OBSERVE.time, 'sleep'):
                OBSERVE.main()
            self.assertEqual([call.args for call in read.call_args_list], [(unit,), (unit,)])

    def test_proc_exposure_rejects_other_image_and_binds_relative_share(self):
        root = OBSERVE.ATTEMPTS['proc-exposure-001'][1]
        row = sample()
        with self.assertRaisesRegex(RuntimeError, 'snapshot protection'):
            OBSERVE.validate_runtime(row, root)
        qemu = row['qemu_network'][0]
        qemu['storage_args'][0][1] = qemu['storage_args'][0][1].replace(OBSERVE.ROOT, root)
        qemu['storage_args'][1][1] = 'local,id=fs0,path=.,security_model=mapped-xattr,readonly=on'
        qemu['cwd'] = OBSERVE.ROOT + '/work/output/workspace'
        with self.assertRaisesRegex(RuntimeError, 'share path'):
            OBSERVE.validate_runtime(row, root)
        qemu['cwd'] = root + '/work/output/workspace'
        self.assertTrue(OBSERVE.validate_runtime(row, root))

    def test_proc_exposure_samples_only_its_fixed_unit(self):
        unit, root = OBSERVE.ATTEMPTS['proc-exposure-001']
        active = sample()
        for entry in active['qemu_network'][0]['storage_args']:
            entry[1] = entry[1].replace(OBSERVE.ROOT, root)
        active.update(unit={'InvocationID': 'exposure', 'ActiveState': 'active', 'LoadState': 'loaded'},
                      cgroup_pids=[42])
        terminal = {'unit': {'InvocationID': 'exposure', 'ActiveState': 'inactive', 'LoadState': 'loaded'},
                    'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--attempt', 'proc-exposure-001', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=[active, terminal]) as read, \
                 patch.object(OBSERVE.time, 'sleep'):
                OBSERVE.main()
            self.assertEqual([call.args for call in read.call_args_list], [(unit,), (unit,)])

    def test_proc_exposure002_rejects_other_image_and_binds_relative_share(self):
        root = OBSERVE.ATTEMPTS['proc-exposure-002'][1]
        row = sample()
        with self.assertRaisesRegex(RuntimeError, 'snapshot protection'):
            OBSERVE.validate_runtime(row, root)
        qemu = row['qemu_network'][0]
        qemu['storage_args'][0][1] = qemu['storage_args'][0][1].replace(OBSERVE.ROOT, root)
        qemu['storage_args'][1][1] = 'local,id=fs0,path=.,security_model=mapped-xattr,readonly=on'
        qemu['cwd'] = OBSERVE.ROOT + '/work/output/workspace'
        with self.assertRaisesRegex(RuntimeError, 'share path'):
            OBSERVE.validate_runtime(row, root)
        qemu['cwd'] = root + '/work/output/workspace'
        self.assertTrue(OBSERVE.validate_runtime(row, root))

    def test_proc_exposure002_samples_only_its_fixed_unit(self):
        unit, root = OBSERVE.ATTEMPTS['proc-exposure-002']
        active = sample()
        for entry in active['qemu_network'][0]['storage_args']:
            entry[1] = entry[1].replace(OBSERVE.ROOT, root)
        active.update(unit={'InvocationID': 'exposure', 'ActiveState': 'active', 'LoadState': 'loaded'},
                      cgroup_pids=[42])
        terminal = {'unit': {'InvocationID': 'exposure', 'ActiveState': 'inactive', 'LoadState': 'loaded'},
                    'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--attempt', 'proc-exposure-002', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=[active, terminal]) as read, \
                 patch.object(OBSERVE.time, 'sleep'):
                OBSERVE.main()
            self.assertEqual([call.args for call in read.call_args_list], [(unit,), (unit,)])

    def test_proc_exposure003_rejects_other_image_and_binds_relative_share(self):
        root = OBSERVE.ATTEMPTS['proc-exposure-003'][1]
        row = sample()
        with self.assertRaisesRegex(RuntimeError, 'snapshot protection'):
            OBSERVE.validate_runtime(row, root)
        qemu = row['qemu_network'][0]
        qemu['storage_args'][0][1] = qemu['storage_args'][0][1].replace(OBSERVE.ROOT, root)
        qemu['storage_args'][1][1] = 'local,id=fs0,path=.,security_model=mapped-xattr,readonly=on'
        qemu['cwd'] = OBSERVE.ROOT + '/work/output/workspace'
        with self.assertRaisesRegex(RuntimeError, 'share path'):
            OBSERVE.validate_runtime(row, root)
        qemu['cwd'] = root + '/work/output/workspace'
        self.assertTrue(OBSERVE.validate_runtime(row, root))

    def test_proc_exposure003_samples_only_its_fixed_unit(self):
        unit, root = OBSERVE.ATTEMPTS['proc-exposure-003']
        active = sample()
        for entry in active['qemu_network'][0]['storage_args']:
            entry[1] = entry[1].replace(OBSERVE.ROOT, root)
        active.update(unit={'InvocationID': 'exposure', 'ActiveState': 'active', 'LoadState': 'loaded'},
                      cgroup_pids=[42])
        terminal = {'unit': {'InvocationID': 'exposure', 'ActiveState': 'inactive', 'LoadState': 'loaded'},
                    'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--attempt', 'proc-exposure-003', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=[active, terminal]) as read, \
                 patch.object(OBSERVE.time, 'sleep'):
                OBSERVE.main()
            self.assertEqual([call.args for call in read.call_args_list], [(unit,), (unit,)])

    def test_sidecar001_rejects_other_image_and_binds_relative_share(self):
        root = OBSERVE.ATTEMPTS['sidecar-001'][1]
        row = sample()
        with self.assertRaisesRegex(RuntimeError, 'snapshot protection'):
            OBSERVE.validate_runtime(row, root)
        qemu = row['qemu_network'][0]
        qemu['storage_args'][0][1] = qemu['storage_args'][0][1].replace(OBSERVE.ROOT, root)
        qemu['storage_args'][1][1] = 'local,id=fs0,path=.,security_model=mapped-xattr,readonly=on'
        qemu['cwd'] = OBSERVE.ROOT + '/work/output/workspace'
        with self.assertRaisesRegex(RuntimeError, 'share path'):
            OBSERVE.validate_runtime(row, root)
        qemu['cwd'] = root + '/work/output/workspace'
        self.assertTrue(OBSERVE.validate_runtime(row, root))

    def test_sidecar001_samples_only_its_fixed_unit(self):
        unit, root = OBSERVE.ATTEMPTS['sidecar-001']
        active = sample()
        for entry in active['qemu_network'][0]['storage_args']:
            entry[1] = entry[1].replace(OBSERVE.ROOT, root)
        active.update(unit={'InvocationID': 'exposure', 'ActiveState': 'active', 'LoadState': 'loaded'},
                      cgroup_pids=[42])
        terminal = {'unit': {'InvocationID': 'exposure', 'ActiveState': 'inactive', 'LoadState': 'loaded'},
                    'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--attempt', 'sidecar-001', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=[active, terminal]) as read, \
                 patch.object(OBSERVE.time, 'sleep'):
                OBSERVE.main()
            self.assertEqual([call.args for call in read.call_args_list], [(unit,), (unit,)])

    def test_rejected_runtime_sample_is_flushed_before_observer_stops(self):
        row=sample();row['external_listener_observed']=True
        row.update(unit={'InvocationID':'bad','ActiveState':'active'},cgroup_pids=[42])
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'observation.jsonl'
            with patch('sys.argv',['observe','--output',str(output)]),patch.object(OBSERVE.os,'geteuid',return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP,'sample',return_value=row),self.assertRaises(RuntimeError):
                OBSERVE.main()
            import json
            saved=json.loads(output.read_text())
            self.assertTrue(saved['external_listener_observed'])
            self.assertEqual(saved['observer_error']['type'],'RuntimeError')

    def test_starttime_field_handles_process_name_parentheses(self):
        stat = '42 (qemu ) worker) ' + ' '.join(['S'] + ['0'] * 18 + ['1234', '0'])
        self.assertEqual(OBSERVE.BOOTSTRAP.process_starttime(stat), 1234)

    def test_lifetime_allows_same_vm_and_absence_but_not_replacement(self):
        for field in ['pid', 'starttime_ticks']:
            with self.subTest(field=field):
                lifetime = OBSERVE.VmLifetime()
                lifetime.observe(sample())
                lifetime.observe(sample())
                lifetime.observe({'external_listener_observed': False, 'qemu_network': []})
                lifetime.require_observed()
                replacement = sample()
                replacement['qemu_network'][0][field] += 1
                with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                    lifetime.observe(replacement)

    def test_lifetime_rejects_missing_or_invalid_identity(self):
        for field in ['pid', 'starttime_ticks']:
            for value in [None, True, 0, -1, '1234']:
                with self.subTest(field=field, value=value):
                    row = sample()
                    row['qemu_network'][0][field] = value
                    with self.assertRaisesRegex(RuntimeError, 'identity missing or invalid'):
                        OBSERVE.VmLifetime().observe(row)

    def test_terminal_without_vm_observation_is_not_accepted(self):
        rows = [{'unit': {'InvocationID': 'one', 'ActiveState': 'inactive', 'LoadState': 'loaded'},
                 'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}]
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=rows):
                with self.assertRaisesRegex(RuntimeError, 'without observing'):
                    OBSERVE.main()

    def test_main_rejects_sequential_vm_replacement_in_same_invocation(self):
        for field in ['pid', 'starttime_ticks']:
            with self.subTest(field=field):
                first = sample()
                first.update(unit={'InvocationID': 'one', 'ActiveState': 'active', 'LoadState': 'loaded'},
                             cgroup_pids=[42])
                second = copy.deepcopy(first)
                second['qemu_network'][0][field] += 1
                terminal = {'unit': {'InvocationID': 'one', 'ActiveState': 'inactive', 'LoadState': 'loaded'},
                            'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}
                with tempfile.TemporaryDirectory() as directory:
                    with patch('sys.argv', ['observe', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                         patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                         patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=[first, second, terminal]) as read, \
                         patch.object(OBSERVE.time, 'sleep'):
                        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                            OBSERVE.main()
                    self.assertEqual(read.call_count, 2)

    def test_fixed_single_vm_policy(self):
        self.assertTrue(OBSERVE.validate_runtime(sample()))

    def test_relative_share_requires_the_same_qemu_fixed_workspace_cwd(self):
        for cwd, accepted in [(OBSERVE.ROOT + '/work/output/workspace', True),
                              (None, False), ('/', False), (OBSERVE.ROOT + '/work', False)]:
            with self.subTest(cwd=cwd):
                row = sample()
                row['qemu_network'][0]['cwd'] = cwd
                row['qemu_network'][0]['storage_args'][1][1] = (
                    'local,id=fs0,path=.,security_model=mapped-xattr,readonly=on')
                if accepted:
                    self.assertTrue(OBSERVE.validate_runtime(row))
                else:
                    with self.assertRaisesRegex(RuntimeError, 'share path'):
                        OBSERVE.validate_runtime(row)

    def test_unbound_relative_or_duplicate_share_paths_are_rejected(self):
        for path in ['workspace', '../workspace', '.,path=/unrelated']:
            with self.subTest(path=path):
                row = sample()
                row['qemu_network'][0]['cwd'] = OBSERVE.ROOT + '/work/output/workspace'
                row['qemu_network'][0]['storage_args'][1][1] = (
                    'local,id=fs0,path=' + path + ',security_model=mapped-xattr,readonly=on')
                with self.assertRaisesRegex(RuntimeError, 'share path'):
                    OBSERVE.validate_runtime(row)

    def test_second_vm_and_weakened_isolation_fail(self):
        for change in ['second_vm', 'restrict', 'forward', 'snapshot', 'share', 'listener']:
            with self.subTest(change=change):
                row = sample()
                if change == 'second_vm':
                    row['qemu_network'].append(copy.deepcopy(row['qemu_network'][0]))
                elif change == 'listener':
                    row['external_listener_observed'] = True
                else:
                    entries = row['qemu_network'][0]['network_args' if change in ('restrict', 'forward') else 'storage_args']
                    old, new = {'restrict': ('restrict=on', 'restrict=off'), 'forward': ('127.0.0.1', '0.0.0.0'),
                                'snapshot': ('snapshot=on', 'snapshot=off'), 'share': ('readonly=on', 'readonly=off')}[change]
                    for entry in entries:
                        entry[1] = entry[1].replace(old, new)
                with self.assertRaises(RuntimeError):
                    OBSERVE.validate_runtime(row)

    def test_no_vm_yet_is_not_positive_runtime_evidence(self):
        self.assertFalse(OBSERVE.validate_runtime({'external_listener_observed': False, 'qemu_network': []}))

    def test_gc_is_unknown_and_sample_is_bound_to_smoke_unit(self):
        rows = [{'unit': {'InvocationID': 'one', 'ActiveState': 'active', 'LoadState': 'loaded'},
                 'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []},
                {'unit': {'InvocationID': '', 'ActiveState': 'inactive', 'LoadState': 'not-found'},
                 'cgroup_pids': [], 'external_listener_observed': False, 'qemu_network': []}]
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['observe', '--output', str(Path(directory) / 'evidence.jsonl')]), \
                 patch.object(OBSERVE.os, 'geteuid', return_value=0), \
                 patch.object(OBSERVE.BOOTSTRAP, 'sample', side_effect=rows) as read, \
                 patch.object(OBSERVE.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'terminal attributes not captured'):
                    OBSERVE.main()
            self.assertEqual(read.call_args_list[0].args, (OBSERVE.UNIT,))
