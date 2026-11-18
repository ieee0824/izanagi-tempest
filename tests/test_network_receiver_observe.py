import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
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

    def test_listener_requires_full_owners_inode_and_distinct_forward(self):
        fresh=[{'local':'127.0.0.1:32123','all_pids':[42],'socket_inode':123}]
        N.listener_matches(ready(),sample(),fresh)
        for change in ('owner','inode','endpoint','main','group','duplicate','forward'):
            row=sample();sockets=copy.deepcopy(fresh)
            if change=='owner':sockets[0]['all_pids']=[42,99999]
            elif change=='inode':sockets[0]['socket_inode']=456
            elif change=='endpoint':sockets[0]['local']='0.0.0.0:32123'
            elif change=='main':row['unit']['MainPID']='43'
            elif change=='group':row['cgroup_pids']=[50]
            elif change=='duplicate':sockets*=2
            else:row['qemu_network'][0]['network_args'][0][1]='user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:32123-:9001'
            with self.subTest(change=change),self.assertRaises(ValueError):N.listener_matches(ready(),row,sockets)

    def test_fresh_ss_keeps_owner_outside_unit_and_exact_inode(self):
        from types import SimpleNamespace
        output='LISTEN 0 4 127.0.0.1:32123 0.0.0.0:* users:(("python",pid=42,fd=4),("other",pid=99999,fd=8)) uid:999 ino:123 sk:1\n'
        with patch.object(N.subprocess,'run',return_value=SimpleNamespace(stdout=output)) as call:
            sockets=N.fresh_listeners(32123)
        self.assertEqual(sockets,[{'local':'127.0.0.1:32123','all_pids':[42,99999],'socket_inode':123}])
        self.assertEqual(call.call_args.args[0][-1],'( sport = :32123 )')

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

    def test_transient_second_link_waits_but_replaced_inode_is_rejected(self):
        for replace in (False, True):
            with self.subTest(replace=replace),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'ready';pending=Path(directory)/'pending'
                pending.write_text(json.dumps(ready()));pending.chmod(0o600);os.link(pending,path)
                def finish():
                    if replace:
                        path.unlink();path.write_text('{}');path.chmod(0o600)
                    else:
                        pending.unlink()
                timer=threading.Timer(.03,finish);timer.start()
                try:
                    if replace:
                        with self.assertRaises(ValueError):N.private_json(path,(os.getuid(),os.getgid(),0o600))
                    else:
                        self.assertEqual(N.private_json(path,(os.getuid(),os.getgid(),0o600)),ready())
                finally:timer.join()

    def test_phase_ack_once_then_closed_ignores_stale_bootstrap_listener(self):
        closed=dict(schema_version=1,identity=ready(),receiver_closed=True,host_monotonic_ns=99)
        state={'closed':None}
        def read(path):return ready() if path.name.endswith('ready.json') else state['closed']
        fresh=[{'local':'127.0.0.1:32123','all_pids':[42],'socket_inode':123}]
        life=N.ReceiverLifetime(Path('/fixed'))
        with patch.object(Path,'exists',return_value=True),patch.object(N,'private_json',side_effect=read), \
             patch.object(N,'fresh_listeners',return_value=fresh) as sockets, \
             patch.object(N,'inspect_process',return_value=456),patch.object(N,'publish_ack') as publish:
            row=sample();row['listeners']=[]  # Stale snapshot before bind must not reject ready.
            self.assertEqual(life.observe(row)['phase'],'live')
            self.assertEqual(life.observe(row)['phase'],'live')
            state['closed']=closed;sockets.return_value=[]
            self.assertEqual(life.observe(sample())['phase'],'closed') # stale old listener ignored
            life.require_complete();publish.assert_called_once()

    def test_close_to_publication_gap_waits_for_fresh_state(self):
        closed=dict(schema_version=1,identity=ready(),receiver_closed=True,host_monotonic_ns=99)
        life=N.ReceiverLifetime(Path('/fixed'));life.ack={**ready(),'host_pid_starttime_ticks':1,'invocation_id':'b'*32}
        values=[ready(),None,ready(),None,closed,ready(),closed]
        with patch.object(Path,'exists',return_value=True),patch.object(N,'private_json',side_effect=values), \
             patch.object(N,'fresh_listeners',return_value=[]),patch.object(N.time,'sleep'):
            self.assertEqual(life.observe(sample())['phase'],'closed')

    def test_no_close_publication_expires_without_accepting_missing_listener(self):
        life=N.ReceiverLifetime(Path('/fixed'))
        with self.assertRaises(ValueError):life.require_complete()
        def read(path):return ready() if path.name.endswith('ready.json') else None
        with patch.object(Path,'exists',return_value=True),patch.object(N,'private_json',side_effect=read), \
             patch.object(N,'fresh_listeners',return_value=[]),patch.object(N.time,'monotonic',side_effect=[0,2]),self.assertRaises(ValueError):
            life.observe(sample())

    def test_close_binding_and_listener_survival_fail(self):
        base=dict(schema_version=1,identity=ready(),receiver_closed=True,host_monotonic_ns=99)
        for change in ('unacknowledged','false','identity','listener'):
            life=N.ReceiverLifetime(Path('/fixed'));closed=copy.deepcopy(base)
            if change!='unacknowledged':life.ack={**ready(),'host_pid_starttime_ticks':1,'invocation_id':'b'*32}
            if change=='false':closed['receiver_closed']=False
            elif change=='identity':closed['identity']['port']+=1
            sockets=[{'local':'127.0.0.1:32123','all_pids':[42],'socket_inode':123}] if change=='listener' else []
            def read(path):return ready() if path.name.endswith('ready.json') else closed
            with self.subTest(change=change),patch.object(Path,'exists',return_value=True),patch.object(N,'private_json',side_effect=read), \
                 patch.object(N,'fresh_listeners',return_value=sockets),self.assertRaises(ValueError):life.observe(sample())

    def test_ack_publish_is_exclusive_and_final_mode_is_readonly(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(N.os,'fchown'):
            path=Path(directory)/'ack';N.publish_ack(path,ready())
            self.assertEqual(path.stat().st_mode&0o777,0o440)
            self.assertEqual(json.loads(path.read_text()),ready())
            with self.assertRaises(FileExistsError):N.publish_ack(path,ready())
            self.assertEqual(list(Path(directory).iterdir()),[path])
