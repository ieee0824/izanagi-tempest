import copy
import importlib.util
from pathlib import Path
import unittest

SPEC=importlib.util.spec_from_file_location('build_observer',Path(__file__).resolve().parents[1]/'integration/delivery_race_build_observe.py')
B=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(B)


def sample():
    return {'external_listener_observed':False,'listeners':[{'local':'127.0.0.1:22222','pids':[42]}],
            'qemu_network':[{'pid':42,'starttime_ticks':100,'cwd':B.ROOT+'/work',
             'network_args':[['-netdev','user,id=user.0,hostfwd=tcp:127.0.0.1:22222-:22'],['-vnc','127.0.0.1:2']],
             'storage_args':[['-drive','file=output-debian/debian-x86_64.qcow2,if=virtio,cache=writeback,discard=ignore,format=qcow2'],
                             ['-drive','file='+B.ROOT+'/inputs/base.iso,media=cdrom']]}]}


class BuildObserverTests(unittest.TestCase):
    def test_fixed_installer_policy_and_same_identity_survive_absent_samples(self):
        life=B.BuildLifetime();life.observe(sample());life.observe({'external_listener_observed':False,'listeners':[],'qemu_network':[]});life.observe(sample());life.require_observed()

    def test_sequential_replacement_or_missing_identity_is_rejected(self):
        for field in ('pid','starttime_ticks'):
            life=B.BuildLifetime();life.observe(sample());row=sample();row['qemu_network'][0][field]+=1
            with self.assertRaises(ValueError):life.observe(row)
        with self.assertRaises(ValueError):B.BuildLifetime().require_observed()

    def test_other_cwd_parent_iso_disk_or_runtime_policy_cannot_pass(self):
        for change in ('cwd','iso','disk','network','vnc','duplicate','owner','listener','external'):
            row=copy.deepcopy(sample());vm=row['qemu_network'][0]
            if change=='cwd':vm['cwd']='/old/work'
            elif change=='iso':vm['storage_args'][1][1]='file=/old/base.iso,media=cdrom'
            elif change=='disk':vm['storage_args'][0][1]=vm['storage_args'][0][1].replace('output-debian','old-output')
            elif change=='network':vm['network_args'][0][1]+=',restrict=on'
            elif change=='vnc':vm['network_args'][1][1]='0.0.0.0:2'
            elif change=='duplicate':row['qemu_network']*=2
            elif change=='owner':row['listeners'][0]['pids']=[43]
            elif change=='listener':row['listeners'][0]['local']='127.0.0.1:55555'
            else:row['external_listener_observed']=True
            with self.subTest(change=change),self.assertRaises(ValueError):B.BuildLifetime().observe(row)
