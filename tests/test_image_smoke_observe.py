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
        'network_args': [['-netdev', 'user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:40001-:9001']],
        'storage_args': [['-drive', 'file=' + OBSERVE.ROOT + '/inputs/image.qcow2,format=qcow2,snapshot=on'],
                         ['-fsdev', 'local,id=fs0,path=' + OBSERVE.ROOT + '/work/output/workspace,security_model=mapped-xattr,readonly=on']]}]}


class SmokeObserverTests(unittest.TestCase):
    def test_fixed_single_vm_policy(self):
        self.assertTrue(OBSERVE.validate_runtime(sample()))

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
