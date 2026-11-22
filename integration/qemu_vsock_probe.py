"""Boot a minimal diskless VM and verify the actual vsock peer CID."""

import argparse
import gzip
import json
import sys
import time
import hashlib
import sqlite3
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--kernel-release', required=True)
    parser.add_argument("--native-verifier", type=Path)
    parser.add_argument("--stop-mode", choices=("revoke", "disconnect", "silence", "renew", "late-receipt", "wrong-cid", "old-boot", "old-process", "wrong-device-cid"), default="revoke")
    parser.add_argument("--supervisor-test", action="store_true")
    parser.add_argument("--caller-deadline-test", action="store_true")
    parser.add_argument("--managed-ledger", action="store_true")
    args = parser.parse_args()
    if args.managed_ledger and args.native_verifier is None:
        parser.error("--managed-ledger requires --native-verifier")
    if args.caller_deadline_test and not (args.managed_ledger and args.supervisor_test):
        parser.error("--caller-deadline-test requires --managed-ledger --supervisor-test")
    native = args.native_verifier is not None
    with tempfile.TemporaryDirectory(prefix='tempest-vsock-', dir='/var/lib' if args.managed_ledger else None) as temporary:
        root = Path(temporary)
        guest = root / 'guest'
        for name in ('bin', 'dev', 'proc', 'sys', 'modules'):
            (guest / name).mkdir(parents=True)
        shutil.copyfile('/usr/bin/busybox', guest / 'bin/busybox')
        (guest / 'bin/busybox').chmod(0o755)
        subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(Path(__file__).parent / 'fixtures/vsock_probe.c'),
                        '-o', str(guest / 'bin/probe')], check=True)
        dependencies = subprocess.check_output([
            'modprobe', '-S', args.kernel_release, '--show-depends',
            'vmw_vsock_virtio_transport'], text=True)
        modules = []
        for line in dependencies.splitlines():
            if not line.startswith('insmod '):
                continue
            source = Path(line.split()[1])
            name = source.name.removesuffix('.zst')
            modules.append(name)
            data = (subprocess.check_output(['zstd', '-dc', str(source)])
                    if source.suffix == '.zst' else source.read_bytes())
            (guest / 'modules' / name).write_bytes(data)
        init = ('#!/bin/busybox sh\nset -eu\n'
                '/bin/busybox mount -t proc proc /proc\n'
                '/bin/busybox mount -t sysfs sysfs /sys\n'
                '/bin/busybox mount -t devtmpfs devtmpfs /dev\n')
        init += ''.join('/bin/busybox insmod /modules/' + name + '\n' for name in modules)
        if native:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
            from channel import canonical_json, RECEIPT_DOMAIN
            signer = Ed25519PrivateKey.generate()
            request = dict(version=1, operation='query', target_id='vm', boot_id='boot1',
                           permit_id='a' * 32, generation=1, challenge='b' * 64)
            (guest / 'key').write_bytes(signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            (guest / 'request').write_bytes(canonical_json(request))
            shutil.copyfile(args.native_verifier.resolve(), guest / 'bin/verify')
            (guest / 'bin/verify').chmod(0o755)
            libraries = subprocess.check_output(['ldd', str(args.native_verifier.resolve())], text=True)
            for line in libraries.splitlines():
                for token in line.split():
                    if token.startswith('/'):
                        target = guest / token.lstrip('/')
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(token, target)
                        target.chmod(0o755)
            if args.supervisor_test:
                config = guest / 'etc/tempest'
                config.mkdir(parents=True, mode=0o700)
                registration = dict(target_id='vm', permit_id='a'*32, generation=1,
                                    boot_id='boot1', ledger_id='fixture', minimum_sequence=1)
                (config / 'host-channel.json').write_bytes(canonical_json(registration))
                (config / 'host-channel-key').write_bytes((guest / 'key').read_bytes())
                for entry in config.iterdir():
                    entry.chmod(0o600)
                (guest / 'expected-queries').write_text('6' if args.stop_mode == 'renew' else '3')
                test_name = ('remote_channel_obeys_short_caller_deadline' if args.caller_deadline_test
                             else 'remote_channel_stops_and_reaps_dummy_namespace')
                init += f'/bin/verify --ignored --exact claude_offline::tests::{test_name} --nocapture\n/bin/busybox poweroff -f\n'
            else:
                init += '/bin/verify /key /request 0 fixture --vsock\necho NATIVE_RECEIPT_OK\n/bin/busybox poweroff -f\n'

        else:
            init += '/bin/probe\n/bin/busybox poweroff -f\n'

        (guest / 'init').write_text(init)
        (guest / 'init').chmod(0o755)
        names = ['.'] + [str(path.relative_to(guest)) for path in guest.rglob('*')]
        archive = subprocess.check_output(['cpio', '-o', '-H', 'newc', '--quiet'],
                                          cwd=guest, input=('\n'.join(names) + '\n').encode())
        image = root / 'initrd.gz'
        image.write_bytes(gzip.compress(archive))
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
            listener.settimeout(40)
            listener.bind((socket.VMADDR_CID_HOST, 23100 if native else 23101))
            listener.listen(1)
            with (root / 'serial.log').open('wb') as log:
                vm = subprocess.Popen([
                    'qemu-system-x86_64', '-machine', 'q35,accel=kvm:tcg', '-m', '512',
                    '-nodefaults', '-display', 'none', '-serial', 'stdio', '-no-reboot',
                    '-net', 'none', '-qmp', 'unix:' + str(root / 'qmp.sock') + ',server=on,wait=off', '-kernel', str(args.kernel), '-initrd', str(image),
                    '-append', 'console=ttyS0 panic=-1 quiet',
                    '-device', 'vhost-vsock-pci,id=ledger,guest-cid=232'],
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    connection, peer = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        if args.managed_ledger:
                            from channel import serve_query
                            from write_transition import advance
                            management = root / 'management'
                            management.mkdir(mode=0o700)
                            for name in ('host-login-authority', 'host-login-recovery', 'host-login-ledger-source', 'host-login-ledger'):
                                (management / name).mkdir(mode=0o700)
                            scope = {key: request[key] for key in ('target_id', 'permit_id', 'generation')}
                            record = dict(ledger_id='fixture', scope=scope, sequence=0, state='empty')
                            checkpoint = dict(sequence=0, digest=hashlib.sha256(canonical_json(record)).hexdigest())
                            for name, value in [('host-login-authority/scope.json', scope),
                                                ('host-login-authority/ledger-id.json', 'fixture'),
                                                ('host-login-recovery/checkpoint.json', checkpoint)]:
                                (management / name).write_bytes(canonical_json(value))
                                (management / name).chmod(0o600)
                            (management / 'host-login-ledger/lock').touch(mode=0o600)
                            database = management / 'host-login-ledger-source/ledger.sqlite3'
                            with sqlite3.connect(database) as db:
                                db.executescript((Path(__file__).resolve().parents[1] / 'tools/host_ledger/schema.sql').read_text())
                            database.chmod(0o600)
                            advance(management, 'issue')
                            if not args.supervisor_test:
                                advance(management, 'consume')
                            process_stat = Path(f'/proc/{vm.pid}/stat').read_text()
                            ticks = int(process_stat[process_stat.rindex(')')+2:].split()[19])
                            registration = dict(scope, boot_id='boot1', cid=232, qemu_pid=vm.pid,
                                                qemu_start_ticks=ticks, qmp_socket=str(root / 'qmp.sock'),
                                                qemu_device_id='ledger', expires_unix_ms=time.time_ns()//1_000_000+10000)
                            approval = dict(registration, communication_expires_unix_ms=registration['expires_unix_ms'],
                                            permit_expires_unix_ms=registration['expires_unix_ms'],
                                            generation_expires_unix_ms=registration['expires_unix_ms'])
                            path = management / 'host-login-authority/channel-approval.json'
                            path.write_bytes(canonical_json(approval))
                            path.chmod(0o600)
                            if args.caller_deadline_test:
                                serve_query(connection, peer[0], registration, management, signer, time.monotonic()+2)
                                caller_connection, caller_peer = listener.accept()
                                with caller_connection:
                                    from channel import read_frame, REQUEST_LIMIT, RESPONSE_LIMIT
                                    raw = read_frame(caller_connection, REQUEST_LIMIT, time.monotonic()+2)
                                    upstream, downstream = socket.socketpair()
                                    with upstream, downstream:
                                        upstream.sendall(raw + b'\n')
                                        serve_query(downstream, caller_peer[0], registration, management,
                                                    signer, time.monotonic()+2)
                                        receipt = read_frame(upstream, RESPONSE_LIMIT, time.monotonic()+2)
                                    envelope = json.loads(receipt)
                                    signer.public_key().verify(bytes.fromhex(envelope['signature']),
                                        RECEIPT_DOMAIN + canonical_json(envelope['payload']))
                                    fault_at = time.monotonic()
                                    time.sleep(0.3)
                                    try:
                                        caller_connection.sendall(receipt + b'\n')
                                    except (BrokenPipeError, ConnectionResetError):
                                        pass
                                    print('valid preflight response delayed 300ms against caller 100ms', flush=True)
                            else:
                                serve_query(connection, peer[0], registration, management, signer, time.monotonic()+2)
                            if args.supervisor_test and not args.caller_deadline_test:
                                print('accepted preflight from actual guest CID', peer[0], flush=True)
                                phases = ['consume'] + ['query'] * (6 if args.stop_mode == 'renew' else 3) + ['stop']
                                for phase_index, phase in enumerate(phases):
                                    next_connection, next_peer = listener.accept()
                                    with next_connection:
                                        if phase == 'query' and args.stop_mode == 'renew':
                                            time.sleep(0.4)
                                        if args.stop_mode == 'late-receipt' and phase_index == 3:
                                            time.sleep(0.6)
                                        if phase == 'stop':
                                            fault_at = time.monotonic()
                                            print('injected', args.stop_mode, 'after normal queries', flush=True)
                                            if args.stop_mode == 'late-receipt':
                                                # Generate a valid fresh signed response while the VM is live,
                                                # then deliver after the previous lease but before this
                                                # response's own two-second lifetime ends.
                                                from channel import read_frame, REQUEST_LIMIT, RESPONSE_LIMIT
                                                raw = read_frame(next_connection, REQUEST_LIMIT, time.monotonic()+2)
                                                upstream, downstream = socket.socketpair()
                                                with upstream, downstream:
                                                    upstream.sendall(raw + b'\n')
                                                    serve_query(downstream, next_peer[0], registration,
                                                                management, signer, time.monotonic()+2)
                                                    receipt = read_frame(upstream, RESPONSE_LIMIT, time.monotonic()+2)
                                                envelope = json.loads(receipt)
                                                signer.public_key().verify(bytes.fromhex(envelope['signature']),
                                                    RECEIPT_DOMAIN + canonical_json(envelope['payload']))
                                                time.sleep(1.6)
                                                if time.time_ns()//1_000_000 >= envelope['payload']['expires_unix_ms']:
                                                    raise RuntimeError('late receipt expired independently; invalid control')
                                                try:
                                                    next_connection.sendall(receipt + b'\n')
                                                except (BrokenPipeError, ConnectionResetError):
                                                    pass
                                                print('late valid receipt withheld beyond prior lease', flush=True)
                                                break
                                            if args.stop_mode == 'disconnect':
                                                break
                                            if args.stop_mode == 'silence':
                                                time.sleep(2.5)
                                                break
                                            if args.stop_mode == 'wrong-cid':
                                                registration['cid'] = 233
                                            elif args.stop_mode == 'old-boot':
                                                registration['boot_id'] = 'boot2'
                                                approval['boot_id'] = 'boot2'
                                                path.write_bytes(canonical_json(approval))
                                            elif args.stop_mode == 'old-process':
                                                registration['qemu_start_ticks'] += 1
                                            elif args.stop_mode == 'wrong-device-cid':
                                                from channel import require_live_instance
                                                # Preserve the true transport peer while testing QMP's
                                                # independent device-CID check against a wrong registry CID.
                                                wrong = dict(registration, cid=233)
                                                try:
                                                    descriptor = require_live_instance(wrong, time.monotonic()+2)
                                                except ValueError as error:
                                                    if str(error) != 'QEMU channel CID assignment mismatch':
                                                        raise
                                                    print('independent QMP CID rejection:', error, flush=True)
                                                else:
                                                    import os
                                                    os.close(descriptor)
                                                    raise RuntimeError('wrong QMP CID accepted')
                                                break
                                            else:
                                                time.sleep(0.2)
                                                advance(management, 'revoke')
                                        try:
                                            serve_query(next_connection, next_peer[0], registration,
                                                        management, signer, time.monotonic()+2)
                                            print('accepted', phase, 'at', round(time.monotonic(), 3), flush=True)
                                        except ValueError as error:
                                            if phase != 'stop':
                                                raise
                                            expected = {
                                                'wrong-cid': 'management peer mismatch',
                                                'old-boot': 'management identity mismatch',
                                                'old-process': 'QEMU process lifetime mismatch',
                                            }.get(args.stop_mode)
                                            if expected is not None and str(error) != expected:
                                                raise RuntimeError(f'wrong rejection: {error}') from error
                                            print('rejected stop query:', error, flush=True)
                                        else:
                                            if phase == 'stop':
                                                raise RuntimeError('stop query unexpectedly accepted')

                        else:
                            with connection.makefile('rb') as stream:
                                data = stream.readline(1025)
                            if peer[0] != 232:
                                raise RuntimeError('vsock peer mismatch')
                            if native:
                                if json.loads(data) != request:
                                    raise RuntimeError('native request mismatch')
                                now = time.time_ns() // 1_000_000
                                scope = {key: request[key] for key in ('target_id', 'permit_id', 'generation')}
                                body = dict(request=request, commit=dict(scope=scope, ledger_id='fixture',
                                            sequence=2, state='consumed'), issued_unix_ms=now, expires_unix_ms=now+2000)
                                reply = dict(payload=body, signature=signer.sign(RECEIPT_DOMAIN + canonical_json(body)).hex())
                                connection.sendall(canonical_json(reply) + b'\n')
                            else:
                                if data != b'tempest-channel-probe\n':
                                    raise RuntimeError('probe mismatch')
                                connection.sendall(b'ok\n')
                    if vm.wait(timeout=20) != 0:
                        raise RuntimeError('probe VM failed')
                    if args.supervisor_test:
                        print("fault_to_vm_exit_seconds", round(time.monotonic() - fault_at, 3), flush=True)
                except Exception:
                    log.flush()
                    print((root / 'serial.log').read_text(errors='replace')[-6000:])
                    raise
                finally:
                    if vm.poll() is None:
                        vm.kill()
                        vm.wait()
            output = (root / 'serial.log').read_text(errors='replace')
            if ('HOST_CHANNEL_CALLER_DEADLINE_OK' if args.caller_deadline_test else 'HOST_CHANNEL_SUPERVISION_OK' if args.supervisor_test else 'NATIVE_RECEIPT_OK' if native else 'VSOCK_PROBE_OK') not in output:
                raise RuntimeError(output[:1500])
        for line in output.splitlines():
            if 'HOST_CHANNEL_SUPERVISION_OK' in line or 'HOST_CHANNEL_CALLER_DEADLINE_OK' in line:
                print(line)
        print('Actual guest CID 232 verified; guest exchange and shutdown succeeded')


if __name__ == '__main__':
    main()
