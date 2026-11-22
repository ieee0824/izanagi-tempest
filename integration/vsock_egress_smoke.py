"""NIC-free VM acceptance: production host daemon + gateway, dummy loopback TLS only."""
import json
import base64
import shutil
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import threading
import time

from remote_tls_host import HostController, control_request
from channel import canonical_json


class EgressController(HostController):
    def start(self, vm):
        import broker
        self.vm = vm
        self.maximum_window_ms = 300000
        self.refresh_stop = None
        self.refresh_thread = None
        self.delivery_lock = threading.Lock()
        self.pending_delivery = None
        self.delivery_ack = threading.Event()
        self.run_stop = None
        self.run_thread = None
        self.run_listeners = []
        self.original_handler = broker.serve_query
        def observed(connection, cid, registration, management, signer, deadline):
            if self.drop_responses:
                raise ConnectionError('dummy control response loss')
            signed = self.original_handler(connection, cid, registration, management, signer, deadline)
            operation = signed['payload']['request']['operation']
            self.counts[operation] = self.counts.get(operation, 0) + 1
            return signed
        broker.serve_query = observed
        key, cert = self.root / 'tls-key.pem', self.root / 'tls-cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=platform.claude.com',
                        '-addext', 'subjectAltName=DNS:platform.claude.com'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        self.cert = cert.read_text()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        tls = socket.socket()
        tls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls.bind(('127.0.0.1', 443))
        tls.listen(4); tls.settimeout(0.2)
        self.listeners.append(tls)
        def tls_loop():
            while not self.stopping.is_set():
                try:
                    peer, _ = tls.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.stopping.is_set(): return
                    raise
                self.counts['tcp_accepts'] = self.counts.get('tcp_accepts', 0) + 1
                try:
                    peer.settimeout(4)
                    with context.wrap_socket(peer, server_side=True) as connection:
                        self.counts['tls_accepts'] = self.counts.get('tls_accepts', 0) + 1
                        if connection.recv(4) != b'PING':
                            raise ValueError('dummy TLS payload mismatch')
                        connection.sendall(b'PONG')
                        connection.settimeout(120)
                        while connection.recv(1):
                            raise ValueError('unexpected dummy TLS payload')
                        self.counts['tls_closed'] = self.counts.get('tls_closed', 0) + 1
                except Exception as error:
                    self.errors.append(str(error))
        test = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        test.bind((socket.VMADDR_CID_HOST, 23102)); test.listen(4); test.settimeout(0.2)
        self.listeners.append(test)
        for target in (tls_loop, lambda: self.control_loop(test)):
            thread = threading.Thread(target=target, daemon=True)
            thread.start(); self.threads.append(thread)

    def stop_run(self):
        if self.refresh_stop is not None:
            self.refresh_stop.set()
            self.refresh_thread.join(11)
            if self.refresh_thread.is_alive():
                raise RuntimeError('refresh updater did not stop')
            self.refresh_stop = None
        if self.run_stop is not None:
            self.run_stop.set()
            self.run_thread.join(3)
            if self.run_thread.is_alive():
                raise RuntimeError('egress daemon workers did not recover')
            for listener in self.run_listeners:
                listener.close()
            self.run_listeners.clear()
            self.run_stop = None

    def prepare(self, value):
        from hashlib import sha256
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from egress_generation import CLI_SHA256, HANDOFF_DOMAIN, REVOCATION_DOMAIN
        from egress_authority import POLICY_DOMAIN
        from egress_daemon import load_run
        from egress_service import serve_both
        self.stop_run()
        reply = super().prepare(value)
        self.registration['boot_id'] = value['boot_id']
        reply['registration']['boot_id'] = value['boot_id']
        self.write('host-login-authority/channel-registration.json', self.registration)
        self.write('host-login-authority/channel-approval.json', dict(self.registration,
            communication_expires_unix_ms=value['expires_unix_ms'],
            permit_expires_unix_ms=value['expires_unix_ms'], generation_expires_unix_ms=value['expires_unix_ms']))
        now = int(time.time()); expires = now + value.get('operation_seconds', 25)
        fresh_expires = min(now+25, expires)
        public = lambda key: key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        handoff_key, revocation_key, policy_key = (Ed25519PrivateKey.generate() for _ in range(3))
        self.revocation_signer = revocation_key
        handoff = HANDOFF_DOMAIN + canonical_json(dict(permit_id=value['scope']['permit_id'],
            target_id=value['scope']['target_id'], approval_pair_sha256='a'*64,
            expires_unix_seconds=expires, executable_sha256=CLI_SHA256,
            arguments=['auth','login'], authority='platform.claude.com:443', approved_ips_revision=1))
        inputs = {'claude-manual-login.json': canonical_json(dict(version=2, authority='platform.claude.com:443',
                    approved_ips=dict(revision=1, addresses=['127.0.0.1']),
                    permit=dict(target_hostname='dummy-vm', authority='platform.claude.com:443',
                                approved_ips_revision=1, expires_unix_seconds=expires))),
                  'claude-login-diagnostic-handoff': handoff,
                  'claude-login-diagnostic-signature': handoff_key.sign(handoff),
                  'claude-login-diagnostic-trust-key': public(handoff_key),
                  'claude-login-diagnostic-target-registration': canonical_json(dict(target_hostname='dummy-vm', target_id=value['scope']['target_id']))}
        for name in ('claude-login-authority', 'claude-login-publication', 'claude-login-publication/1', 'host-login-signer'):
            (self.root/name).mkdir(mode=0o700, exist_ok=True)
        def raw(name, data):
            path = self.root/name; path.write_bytes(data); path.chmod(0o600)
        for name, data in inputs.items(): raw('claude-login-publication/1/'+name, data)
        manifest = canonical_json({name:sha256(data).hexdigest() for name,data in inputs.items()})
        digest = sha256(manifest).hexdigest()
        raw('claude-login-publication/1/manifest', manifest)
        raw('claude-login-publication/lock', b''); raw('claude-login-publication/current', b'1')
        raw('claude-login-authority/minimum', b'1')
        raw('claude-login-authority/trust-key', public(handoff_key))
        self.write('claude-login-authority/approved-generation', dict(revision=1, manifest_sha256=digest))
        state = REVOCATION_DOMAIN+canonical_json(dict(revision=1, revocation_revision=1,
            manifest_sha256=digest, permit_id=value['scope']['permit_id'], target_id=value['scope']['target_id'],
            issued_unix_seconds=now, expires_unix_seconds=fresh_expires, revoked=False))
        raw('claude-login-authority/revocation-state', state)
        raw('claude-login-authority/revocation-signature', revocation_key.sign(state))
        raw('claude-login-authority/revocation-key', public(revocation_key)); raw('claude-login-authority/revocation-minimum', b'1')
        self.write('claude-login-authority/revocation-committed', dict(revision=1, state_sha256=sha256(state).hexdigest()))
        raw('host-login-signer/signing-seed', self.signer.private_bytes_raw())
        raw('host-login-authority/egress-trust-key', public(policy_key))
        body=dict(version=1, scope=value['scope'], boot_id=value['boot_id'], manifest_sha256=digest,
                  approved_ips_revision=1, authority='platform.claude.com:443',
                  peer=dict(address='127.0.0.1',port=443), expires_unix_ms=min(value['expires_unix_ms'],expires*1000))
        self.write('host-login-authority/egress-policy.json',dict(payload=body,signature=policy_key.sign(POLICY_DOMAIN+canonical_json(body)).hex()))
        public_names = ['claude-login-authority/'+name for name in (
            'minimum','trust-key','approved-generation','revocation-state','revocation-signature',
            'revocation-key','revocation-minimum','revocation-committed')]
        public_names += ['claude-login-publication/'+name for name in ('lock','current','1/manifest')]
        public_names += ['claude-login-publication/1/'+name for name in inputs]
        self.bootstrap_source = {name:(self.root/name).read_bytes() for name in public_names}
        with self.delivery_lock:
            self.pending_delivery = None
            self.delivery_ack.clear()
        registration, policy, authorization, signer, deadline, originals=load_run(self.root)
        self.operation_deadline = deadline
        self.run_stop=threading.Event()
        control=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        data=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        control.bind((2,23100));data.bind((2,23105));control.listen(8);data.listen(4)
        self.run_listeners=[control,data]
        def run():
            try:
                serve_both(control,data,registration,self.root,policy,authorization,signer,deadline,originals.check,self.run_stop)
            except Exception as error:
                self.errors.append(str(error))
        self.run_thread=threading.Thread(target=run)
        self.run_thread.start()
        reply.update(request=dict(version=1,scope=value['scope'],boot_id=value['boot_id'],manifest_sha256=digest,
                     approved_ips_revision=1,authority='platform.claude.com:443'), peer='127.0.0.1:443', cert=self.cert, operation_expires_unix_ms=policy.expires_unix_ms)
        return reply

    def extra_control(self, value):
        operation = value['operation']
        if operation == 'time':
            return dict(host_unix_ns=time.time_ns())
        if operation == 'source-names':
            return dict(names=list(self.bootstrap_source))
        if operation == 'public-file':
            # Fixed bootstrap allowlist contains no signing seed or host ledger.
            data = self.bootstrap_source[value['name']]
            return dict(data=base64.b64encode(data).decode('ascii'))
        if operation == 'next-refresh':
            with self.delivery_lock:
                pending = self.pending_delivery
                return dict(refresh=None if pending is None else dict(
                    payload=base64.b64encode(pending.payload).decode('ascii'),
                    signature=pending.signature.hex()))
        if operation == 'ack-refresh':
            with self.delivery_lock:
                if self.pending_delivery is None:
                    raise ValueError('no pending refresh')
                state=json.loads(self.pending_delivery.payload.split(b'\0',1)[1])
                if value['revision'] != state['revocation_revision']:
                    raise ValueError('refresh acknowledgement mismatch')
                self.pending_delivery = None
                self.delivery_ack.set()
            self.counts['refresh_deliveries'] = self.counts.get('refresh_deliveries',0)+1
            return dict(acknowledged=True)
        if operation == 'begin-updates':
            from refresh_revocation import run_updater
            self.refresh_stop=threading.Event()
            def deliver(signed, deadline):
                self.delivery_ack.clear()
                with self.delivery_lock:
                    self.pending_delivery=signed
                if not self.delivery_ack.wait(max(0,deadline-time.monotonic())):
                    raise TimeoutError('guest did not acknowledge signed refresh')
            def run():
                try:
                    run_updater(self.root,self.registration,self.revocation_signer,deliver,
                                self.refresh_stop,self.operation_deadline)
                except Exception as error:
                    self.errors.append(str(error))
            self.refresh_thread=threading.Thread(target=run)
            self.refresh_thread.start()
            return dict(started=True)
        if operation == 'stop-updates':
            self.refresh_stop.set()
            return dict(stopped=True)
        raise ValueError('unknown dummy egress operation')

    def close(self):
        self.stop_run()
        super().close()


def bounded_line(process, deadline):
    data=bytearray()
    while not data.endswith(b'\n'):
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([process.stdout],[],[],remaining)[0]:
            raise RuntimeError('dummy process output deadline expired')
        byte=os.read(process.stdout.fileno(),1)
        if not byte: raise RuntimeError('dummy process output ended before marker')
        data.extend(byte)
        if len(data)>4096: raise RuntimeError('dummy process output line too long')
    return data.decode().strip()


def read_line(process, expected, timeout=8):
    line=bounded_line(process,time.monotonic()+timeout)
    if line != expected:
        raise RuntimeError(f'dummy process expected {expected}, got {line}')


def probe(context):
    # This UID999 client contains no real credential and only talks to the gateway.
    with socket.create_connection(('127.0.0.1',39271),timeout=3) as rejected:
        rejected.sendall(b'CONNECT other.invalid:443 HTTP/1.1\r\nHost: other.invalid:443\r\n\r\n')
        if rejected.recv(1): raise RuntimeError('unapproved CONNECT accepted')
    print('CONNECT_DENIED',flush=True)
    if sys.stdin.readline() != 'GO\n': raise RuntimeError('missing upstream-counter acknowledgement')
    with socket.create_connection(('127.0.0.1',39271),timeout=3) as raw:
        raw.sendall(b'CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\n\r\n')
        header=b''
        while not header.endswith(b'\r\n\r\n'):
            byte=raw.recv(1)
            if not byte: raise RuntimeError('gateway closed before CONNECT ready')
            header+=byte
            if len(header)>4096: raise RuntimeError('CONNECT response too large')
        if header != b'HTTP/1.1 200 Connection Established\r\n\r\n': raise RuntimeError('CONNECT not ready')
        tls=ssl.create_default_context(cadata=context['cert'])
        with tls.wrap_socket(raw,server_hostname='platform.claude.com') as stream:
            stream.sendall(b'PING')
            if stream.recv(4)!=b'PONG': raise RuntimeError('TLS exchange mismatch')
            print('TLS_UP',flush=True)
            stream.settimeout(120)
            if stream.recv(1): raise RuntimeError('TLS data survived stop')
            print('TLS_CLOSED',flush=True)


def guest():
    from refresh_revocation import Refresh, encode_refresh
    # Only this disposable, NIC-free fixture clock is aligned. No owner VM clock is changed.
    host_time=control_request(dict(operation='time'))['host_unix_ns']
    time.clock_settime(time.CLOCK_REALTIME,host_time/1_000_000_000+0.1)
    for index,mode in enumerate(('revoked','response-lost','freshness-lost','operation-deadline')):
        seconds = 90 if mode=='freshness-lost' else 50 if mode=='operation-deadline' else 25
        scope=dict(target_id='egress-vm',permit_id=f'{100+index:032x}',generation=1)
        reply=control_request(dict(operation='prepare',scope=scope,
            boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            expires_unix_ms=int((time.time()+seconds)*1000),operation_seconds=seconds))
        source=Path('/etc/tempest')
        source.mkdir(mode=0o700)
        for name in ('claude-login-authority','claude-login-publication','claude-login-publication/1'):
            (source/name).mkdir(mode=0o700)
        names=control_request(dict(operation='source-names'))['names']
        for name in names:
            relative=Path(name)
            if relative.is_absolute() or '..' in relative.parts or relative.parts[0] not in ('claude-login-authority','claude-login-publication'):
                raise RuntimeError('unexpected fixture public source path')
            value=base64.b64decode(control_request(dict(operation='public-file',name=name))['data'],validate=True)
            path=source/relative;path.write_bytes(value);path.chmod(0o600)
        registration=source/'host-channel.json'
        registration.write_bytes(canonical_json(reply['registration']));registration.chmod(0o600)
        reply['source_root']=str(source)
        config=Path('/run/tempest-egress-fixture.json'); config.write_text(json.dumps(reply));config.chmod(0o600)
        stopfile=Path('/run/tempest-egress-stop');stopfile.unlink(missing_ok=True)
        deliveries_stop=threading.Event()
        delivery_errors=[]
        def receive_updates():
            while not deliveries_stop.wait(0.05):
                try:
                    value=control_request(dict(operation='next-refresh'))['refresh']
                    if value is None:continue
                    signed=Refresh(base64.b64decode(value['payload'],validate=True),bytes.fromhex(value['signature']))
                    installed=subprocess.run(['/usr/bin/python3','-B',
                        '/opt/tempest/tools/host_ledger/refresh_revocation.py','--publish-stdin'],
                        input=encode_refresh(signed),capture_output=True,timeout=10)
                    if installed.returncode==75:continue
                    if installed.returncode!=0:raise RuntimeError('guest signed publisher refused update')
                    revision=json.loads(installed.stdout)['revision']
                    control_request(dict(operation='ack-refresh',revision=revision))
                except Exception as error:
                    delivery_errors.append(str(error));return
        deliveries=threading.Thread(target=receive_updates)
        deliveries.start()
        control_request(dict(operation='begin-updates'))
        until=time.monotonic()+5
        while control_request(dict(operation='stats'))['counts'].get('refresh_deliveries',0)<1:
            if delivery_errors or time.monotonic()>=until:raise RuntimeError(f'initial signed delivery failed: {delivery_errors}')
            time.sleep(0.02)
        gateway=subprocess.Popen(['/opt/bin/libtest','--ignored','--exact',
            'claude_offline::login_egress::tests::gateway_vsock_fixture','--nocapture'],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=0)
        client=None
        try:
            until=time.monotonic()+8
            while 'VSOCK_GATEWAY_READY' not in bounded_line(gateway,until):pass
            client=subprocess.Popen(['setpriv','--reuid=999','--regid=999','--clear-groups',
                '/usr/bin/python3',__file__,'probe'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,bufsize=0)
            client.stdin.write((json.dumps(reply)+'\n').encode());client.stdin.flush()
            read_line(client,'CONNECT_DENIED')
            stats=control_request(dict(operation='stats'))['counts']
            if stats.get('tcp_accepts',0)!=0: raise RuntimeError(f'rejected CONNECT dialed upstream: {stats}')
            client.stdin.write(b'GO\n');client.stdin.flush()
            read_line(client,'TLS_UP')
            stats=control_request(dict(operation='stats'))['counts']
            if stats.get('tls_accepts')!=1 or stats.get('tcp_accepts')!=1:
                raise RuntimeError(f'unapproved upstream dial: {stats}')
            until=time.monotonic()+2
            while stats.get('query',0)<2 and time.monotonic()<until:
                time.sleep(0.05);stats=control_request(dict(operation='stats'))['counts']
            if stats.get('query',0)<2: raise RuntimeError('control was not renewing')
            if mode in ('freshness-lost','operation-deadline'):
                alive=time.monotonic()+35
                while time.monotonic()<alive:
                    if gateway.poll() is not None or client.poll() is not None or delivery_errors:
                        raise RuntimeError(f'long-lived route stopped before 35 seconds: {delivery_errors}')
                    time.sleep(0.1)
                stats=control_request(dict(operation='stats'))['counts']
                if stats.get('refresh_deliveries',0)<3:raise RuntimeError('signed freshness was not renewing')
                print(f'VSOCK_EGRESS_LIVE_OVER_30 mode={mode} counts={stats}',flush=True)
            began=time.monotonic()
            if mode=='operation-deadline':
                remaining=max(0,reply['operation_expires_unix_ms']/1000-time.time())
                wait=remaining+4
            else:
                control_request(dict(operation={'revoked':'revoke','response-lost':'lose-response',
                    'freshness-lost':'stop-updates'}[mode]))
                wait=34 if mode=='freshness-lost' else 4
            read_line(client,'TLS_CLOSED',wait)
            if client.wait(timeout=2)!=0: raise RuntimeError(client.stderr.read())
            stopfile.touch()
            if gateway.wait(timeout=3)!=0: raise RuntimeError(gateway.stdout.read())
            until=time.monotonic()+2
            while time.monotonic()<until:
                stats=control_request(dict(operation='stats'))['counts']
                if stats.get('tls_closed')==1:break
                time.sleep(0.02)
            if stats.get('tls_closed')!=1:raise RuntimeError('host TLS endpoint stayed open')
            if delivery_errors:raise RuntimeError(delivery_errors)
            if mode=='operation-deadline' and time.time()+0.3 < reply['operation_expires_unix_ms']/1000:
                raise RuntimeError('route closed before operation deadline')
            print(f'VSOCK_EGRESS_ACCEPTED mode={mode} stop_ms={(time.monotonic()-began)*1000:.0f} counts={stats}',flush=True)
        finally:
            stopfile.touch()
            for process in (client,gateway):
                if process is not None and process.poll() is None:process.kill();process.wait()
            control_request(dict(operation='stop-updates'))
            deliveries_stop.set();deliveries.join(3)
            if deliveries.is_alive():raise RuntimeError('guest refresh delivery thread survived')
            config.unlink(missing_ok=True);stopfile.unlink(missing_ok=True);shutil.rmtree(source)
    print('VSOCK_EGRESS_VM_OK',flush=True)


if __name__=='__main__':
    if sys.argv[1:]==['guest'] and os.geteuid()==0:guest()
    elif sys.argv[1:]==['probe'] and os.geteuid()==999:probe(json.loads(sys.stdin.readline()))
    else:raise SystemExit('isolated VM fixture only')
