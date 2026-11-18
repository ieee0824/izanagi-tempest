import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('receiver_observe', Path(__file__).resolve().parents[1] / 'integration/network_receiver_observe.py')
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)


def ready():
    return dict(schema_version=1, nonce='a'*32, host_pid=42, address='127.0.0.1', port=32123, socket_inode=123)


def sample():
    return dict(unit={'MainPID':'42', 'InvocationID':'b'*32}, cgroup_pids=[42, 50],
                listeners=[{'local':'127.0.0.1:32123','pids':[42]}],
                qemu_network=[{'pid':50,'network_args':[['-netdev','user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:40001-:9001']]}])


class ReceiverTests(unittest.TestCase):
    def test_schema_rejects_unknown_fields_boolean_ids_and_nonloopback(self):
        for field, value in [('extra',1),('schema_version',True),('host_pid',True),('socket_inode',0),('port',80),('address','0.0.0.0'),('nonce','bad')]:
            changed=ready();changed[field]=value
            with self.subTest(field=field), self.assertRaises(ValueError):N.identity(changed)

    def test_listener_requires_exact_mainpid_owner_and_distinct_forward(self):
        N.listener_matches(ready(),sample())
        for change in ('owner','endpoint','main','group','duplicate','forward'):
            row=sample()
            if change=='owner':row['listeners'][0]['pids']=[42,43]
            elif change=='endpoint':row['listeners'][0]['local']='0.0.0.0:32123'
            elif change=='main':row['unit']['MainPID']='43'
            elif change=='group':row['cgroup_pids']=[50]
            elif change=='duplicate':row['listeners']*=2
            else:row['qemu_network'][0]['network_args'][0][1]='user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:32123-:9001'
            with self.subTest(change=change),self.assertRaises(ValueError):N.listener_matches(ready(),row)

    def test_private_reader_rejects_links_oversize_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'state';p.write_text(json.dumps(ready()));p.chmod(0o600)
            owner=(os.getuid(),os.getgid(),0o600)
            self.assertEqual(N.private_json(p,owner),ready())
            link=p.with_name('link');link.symlink_to(p)
            with self.assertRaises(OSError):N.private_json(link,owner)
            os.link(p,p.with_name('hardlink'))
            with self.assertRaises(ValueError):N.private_json(p,owner)
            p.with_name('hardlink').unlink();p.write_text('x'*4097)
            with self.assertRaises(ValueError):N.private_json(p,owner)
            p.write_text('{}');p.chmod(0o644)
            with self.assertRaises(ValueError):N.private_json(p,owner)

    def test_phase_ack_once_then_closed_and_no_remaining_listener(self):
        closed=dict(schema_version=1,identity=ready(),receiver_closed=True,host_monotonic_ns=99)
        life=N.ReceiverLifetime(Path('/fixed'))
        with patch.object(Path,'exists',return_value=True), patch.object(N,'private_json',side_effect=[ready(),None,ready(),None,ready(),closed]), \
             patch.object(N,'inspect_process',return_value=456),patch.object(N,'publish_ack') as publish:
            self.assertEqual(life.observe(sample())['phase'],'live')
            self.assertEqual(life.observe(sample())['phase'],'live')
            row=sample();row['listeners']=[]
            self.assertEqual(life.observe(row)['phase'],'closed')
            life.require_complete();publish.assert_called_once()
        self.assertEqual(life.ack['host_pid_starttime_ticks'],456)

    def test_no_ack_no_close_or_disappearing_listener_cannot_complete(self):
        life=N.ReceiverLifetime(Path('/fixed'))
        with self.assertRaises(ValueError):life.require_complete()
        row=sample();row['listeners']=[]
        with patch.object(Path,'exists',return_value=True),patch.object(N,'private_json',side_effect=[ready(),None]),self.assertRaises(ValueError):life.observe(row)

    def test_close_binding_and_listener_survival_fail(self):
        base=dict(schema_version=1,identity=ready(),receiver_closed=True,host_monotonic_ns=99)
        for change in ('unacknowledged','false','identity','listener'):
            life=N.ReceiverLifetime(Path('/fixed'));closed=copy.deepcopy(base);row=sample();row['listeners']=[]
            if change!='unacknowledged':life.ack={**ready(),'host_pid_starttime_ticks':1,'invocation_id':'b'*32}
            if change=='false':closed['receiver_closed']=False
            elif change=='identity':closed['identity']['port']+=1
            elif change=='listener':row=sample()
            with self.subTest(change=change),patch.object(Path,'exists',return_value=True),patch.object(N,'private_json',side_effect=[ready(),closed]),self.assertRaises(ValueError):life.observe(row)

    def test_ack_publish_is_exclusive_and_final_mode_is_readonly(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(N.os,'fchown'):
            path=Path(directory)/'ack';N.publish_ack(path,ready())
            self.assertEqual(path.stat().st_mode&0o777,0o440)
            self.assertEqual(json.loads(path.read_text()),ready())
            with self.assertRaises(FileExistsError):N.publish_ack(path,ready())
            self.assertEqual(list(Path(directory).iterdir()),[path])
