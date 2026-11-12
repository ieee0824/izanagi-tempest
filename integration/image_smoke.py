#!/usr/bin/env python3
"""Boot the M3 image through pinned Izanagi and collect private VM evidence."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'image'))
from transport import Mailbox


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--izanagi', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--build-inputs', type=Path, help='prepare.py inputs.json; defaults to the standard build layout')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    inputs_path = (args.build_inputs or args.image.resolve().parents[2] / 'inputs.json').resolve()
    build_inputs = json.loads(inputs_path.read_bytes())
    box = Mailbox(output / 'workspace')
    # Agent-readable, deliberately writable mode: actual write must still be EROFS.
    public = box.workspace / 'readonly-check'
    public.mkdir(mode=0o777)
    from transport import mapped_metadata
    import stat
    mapped_metadata(public, stat.S_IFDIR | 0o777)
    config = output / 'izanagi.toml'
    template = (ROOT / 'tools/m0/izanagi.example.toml').read_text()
    config.write_text(template.replace('image = "default"', 'image = ' + json.dumps(str(args.image.resolve()))))
    base = [str(args.izanagi.resolve()), '--config', str(config)]
    report = {'schema_version': 1, 'status': 'incomplete', 'checks': {},
              'image_sha256': sha(args.image), 'izanagi_sha256': sha(args.izanagi),
              'build_inputs_sha256': sha(inputs_path), 'restrict_network': True}
    def save():
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    def execute(*command, timeout=30):
        return subprocess.run(base + ['exec', '--', *command], cwd=box.workspace,
                              capture_output=True, text=True, timeout=timeout)
    def check(name, command, expected=0):
        result = execute('/bin/sh', '-c', command)
        report['checks'][name] = {'passed': result.returncode == expected,
                                  'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
        save()
        if result.returncode != expected:
            raise RuntimeError('VM check failed: ' + name)
        return result.stdout
    def call(operation, authorization=None, expected_error=False, **fields):
        if authorization is not None:
            fields['authorization'] = authorization
        request = box.prepare(operation, **fields)
        secret_markers.append(base64.b64encode(request.key).decode())
        deadline = time.monotonic() + 260
        try:
            while time.monotonic() < deadline:
                result = execute('/usr/bin/doas', '-n', '/usr/local/bin/tempest-guest', 'deliver', request.guest_path)
                if result.returncode == 0:
                    value = request.decode(result.stdout)
                    if operation in {'claim', 'seed', 'export'}:
                        # Give the actor the valid ID: confidentiality must not rely on hiding it.
                        code = ("import os,errno\ntry:\n os.open(" + repr(request.guest_path)
                                + ",os.O_RDONLY)\nexcept OSError as e:\n assert e.errno==errno.EACCES"
                                + "\nelse:\n raise AssertionError('private request readable')")
                        denied = execute('/usr/bin/python3', '-c', code)
                        if denied.returncode != 0:
                            raise RuntimeError('actor can read private request: ' + operation)
                        # Actor obtains the ciphertext first/repeatedly; no destructive read.
                        repeated = execute('/usr/bin/doas', '-n', '/usr/local/bin/tempest-guest', 'deliver', request.guest_path)
                        if repeated.returncode != 0 or repeated.stdout != result.stdout:
                            raise RuntimeError('reply retrieval is destructive or unstable')
                        attack_code = ("import concurrent.futures,subprocess,hashlib,json\n"
                                       "command=['/usr/bin/doas','-n','/usr/local/bin/tempest-guest','deliver'," + repr(request.guest_path) + "]\n"
                                       "def invoke(_):\n r=subprocess.run(command,capture_output=True,timeout=20); return [r.returncode,hashlib.sha256(r.stdout).hexdigest()]\n"
                                       "with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:\n print(json.dumps(list(pool.map(invoke,range(3)))))")
                        attack = execute('/usr/bin/python3', '-c', attack_code)
                        expected_frame = hashlib.sha256(result.stdout.encode()).hexdigest()
                        if attack.returncode != 0 or json.loads(attack.stdout) != [[0, expected_frame]] * 3:
                            raise RuntimeError('parallel actor retrieval changed or consumed saved reply')
                        if request.decode(repeated.stdout) != value:
                            raise RuntimeError('saved response changed')
                        report['checks']['known_id_' + operation] = {'private_read_denied': True,
                                                                     'saved_ciphertext_stable': True, 'parallel_actor_retrievals': 3}
                        save()
                    if not value['ok']:
                        if expected_error:
                            return {'rejected': True, 'error': value['error']}
                        raise RuntimeError(operation + ': ' + value['error'])
                    if expected_error:
                        raise RuntimeError(operation + ': unauthorized or invalid-phase operation succeeded')
                    return value['result']
                time.sleep(0.2)
            raise RuntimeError(operation + ': response lost; discard VM, do not repeat operation')
        finally:
            request.remove()
    secret_markers = ['PRIVATE-DUMMY']
    process = None
    try:
        with (output / 'up.stdout').open('w') as stdout, (output / 'up.stderr').open('w') as stderr:
            process = subprocess.Popen(base + ['up'], cwd=box.workspace, stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline and process.poll() is None:
            if 'サンドボックスを起動しました' in (output / 'up.stdout').read_text():
                result = execute('/bin/echo', 'ready', timeout=10)
                if result.returncode == 0 and result.stdout.strip() == 'ready':
                    break
            time.sleep(0.5)
        else:
            raise RuntimeError('VM boot failed')
        check('inventory', 'id; cat /etc/tempest/image.json; stat -c "%u %g %a %n" /workspace /workspace/.tempest-control; cat /proc/mounts')
        image_manifest = json.loads(check('image_manifest', 'cat /etc/tempest/image.json'))
        for field in ['izanagi_commit', 'lws_commit', 'tempest_guest_version', 'tempest_guest_source_commit',
                      'tempest_guest_source_tree_sha256', 'tempest_guest_source_dirty', 'input_sha256', 'derivation_sha256']:
            assert image_manifest[field] == build_inputs[field], 'build/guest provenance mismatch: ' + field
        assert image_manifest['installed_sha256']['/usr/local/libexec/tempest-guest-native'] == build_inputs['input_sha256']['guest']
        assert image_manifest['installed_sha256']['/usr/local/bin/lws'] == build_inputs['input_sha256']['lws']
        assert image_manifest['installed_sha256']['/usr/local/bin/tempest-guest'] == build_inputs['derivation_sha256']['dispatcher.py']
        report['checks']['build_guest_binding'] = {'passed': True}
        metadata_code = ("import json,os,hashlib,stat; from pathlib import Path; "
                         "m=json.loads(Path('/etc/tempest/image.json').read_bytes()); "
                         "assert m['izanagi_commit']=='16d0b55947006a166cfa29dcb8bfe71f65f8c36a'; "
                         "assert m['lws_commit']=='2c0ea463f334f10a562e54f1cdc7ba8a474029e2'; "
                         "assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==v for p,v in m['installed_sha256'].items()); "
                         "assert os.stat('/workspace/.tempest-control').st_uid==0; "
                         "assert stat.S_IMODE(os.stat('/workspace/.tempest-control').st_mode)==0o700; "
                         "assert m['service_uid'] not in (0,os.getuid()); print('metadata-and-mapping-verified')")
        check('metadata_and_mapping', 'python3 -c ' + shlex.quote(metadata_code))
        check('private_directories', 'test ! -r /var/lib/lws && test ! -r /var/lib/tempest && test ! -r /run/tempest-control/state.json && test ! -w /run/tempest-control')
        readonly_code = ("import os,errno\ntry:\n os.open('/workspace/readonly-check/x',os.O_WRONLY|os.O_CREAT,0o600)"
                         "\nexcept OSError as e:\n assert e.errno==errno.EROFS\nelse:\n raise AssertionError('write succeeded')")
        check('readonly', 'python3 -c ' + shlex.quote(readonly_code))
        call('ping')
        credential = call('claim')['token']
        secret_markers.append(credential)
        report['checks']['claim_nonreissue'] = call('claim', expected_error=True)
        bundle = {'users': [{'name': 'worker', 'policy': {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': 'arn:aws:s3:::public-data/*'}]}}],
            'buckets': [{'name': 'public-data', 'objects': [{'key': 'readme.txt', 'body': 'PUBLIC-DUMMY'}, {'key': 'end.txt', 'body': 'PUBLIC-END-DUMMY'}]},
                        {'name': 'private-data', 'objects': [{'key': 'secret.txt', 'body': 'PRIVATE-DUMMY'}]}]}
        report['checks']['wrong_token_seed'] = call('seed', '0' * 64, expected_error=True, setup=bundle)
        seeded = call('seed', credential, setup=bundle)
        worker = seeded['access_keys']['worker']
        assert seeded['admin_key_rotated'] and seeded['new_key_verified'] and seeded['old_key_rejected']
        report['checks']['seed'] = {'passed': True}
        check('preseal_closed', "python3 -c \"import socket; s=socket.socket(); s.settimeout(2); assert s.connect_ex(('127.0.0.1',4566))!=0\"")
        for name, api, resource in [('allow', 's3:GetObject', 'arn:aws:s3:::public-data/readme.txt'),
                                    ('deny', 's3:GetObject', 'arn:aws:s3:::private-data/secret.txt'),
                                    ('unsupported', 's3:PutBucketNotification', 'arn:aws:s3:::public-data')]:
            probe = call('probe', credential, probe={'access_key_id': worker, 'api': api, 'resource': resource})
            assert (probe['outcome'], probe['status'], probe['complete']) == (name, {'allow': 200, 'deny': 403, 'unsupported': 501}[name], True)
            report['checks']['probe_' + name] = probe
        check('backend_denied', "python3 -c \"import socket; s=socket.socket(); s.settimeout(2); assert s.connect_ex(('127.0.0.1',4567))!=0\"")
        check('lws_environ_denied', 'p=$(pgrep -x lws); test -n "$p" && ! cat /proc/$p/environ')
        uid_code = ("import json,subprocess; from pathlib import Path; "
                    "m=json.loads(Path('/etc/tempest/image.json').read_text()); "
                    "pids=subprocess.check_output(['pgrep','-x','lws'],text=True).split(); assert pids; "
                    "assert all(int(next(x for x in Path('/proc/'+p+'/status').read_text().splitlines() if x.startswith('Uid:')).split()[1])==m['service_uid'] for p in pids)")
        check('lws_service_uid', 'python3 -c ' + shlex.quote(uid_code))
        ipc_code = ("import socket,errno\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect('/run/tempest-control/control.sock')"
                    "\nexcept OSError as e:\n assert e.errno==errno.EACCES\nelse:\n raise AssertionError('private socket accessible')")
        check('private_socket_denied', 'python3 -c ' + shlex.quote(ipc_code))
        fd_code = ("import os,subprocess,errno\npid=subprocess.check_output(['systemctl','show','tempest-mailbox.service','-p','MainPID','--value'],text=True).strip()\n"
                   "assert int(pid)>0\nfor suffix in ['fd','environ','mem']:\n"
                   " try:\n  p='/proc/'+pid+'/'+suffix\n  value=os.listdir(p) if suffix=='fd' else open(p,'rb').read(1)\n"
                   " except OSError as e:\n  assert e.errno in (errno.EACCES,errno.EPERM)\n"
                   " else:\n  raise AssertionError('root process private state accessible')")
        check('root_proc_private_denied', 'python3 -c ' + shlex.quote(fd_code))
        check('doas_other_denied', '! doas -n /bin/true')
        check('doas_native_denied', '! doas -n /usr/local/libexec/tempest-guest-native claim')
        check('doas_watch_denied', '! doas -n /usr/local/bin/tempest-guest --watch')
        check('tokenless_seed_denied', '! doas -n /usr/local/bin/tempest-guest seed')
        # Exercise surviving descendants across three parent termination modes.
        # This measures these concrete cases; the M4 general lifecycle stays separate.
        for mode in ['normal', 'timeout', 'abnormal']:
            import secrets
            result_path = '/tmp/tempest-actor-' + secrets.token_hex(16) + '.json'
            child_code = ("import os,time,json,errno\nfrom pathlib import Path\n"
                          "denied=0; unexpected=[]\n"
                          "for iteration in range(30):\n"
                          " for p in ['/run/tempest-control/state.json','/var/lib/lws','/var/lib/tempest']:\n"
                          "  try:\n   fd=os.open(p,os.O_RDONLY);os.close(fd);unexpected.append(p)\n"
                          "  except OSError as e:\n   denied+=int(e.errno==errno.EACCES)\n"
                          " time.sleep(0.1)\n"
                          "Path(" + repr(result_path) + ").write_text(json.dumps({'denied':denied,'unexpected':unexpected}))")
            parent_code = ("import subprocess,sys,os,time,signal; "
                           "p=subprocess.Popen([sys.executable,'-c'," + repr(child_code) + "],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); "
                           "print(p.pid,flush=True); ")
            if mode == 'timeout':
                parent_code += 'time.sleep(10)'
                argv = ['/usr/bin/timeout', '1', '/usr/bin/python3', '-c', parent_code]
            else:
                if mode == 'abnormal':
                    parent_code += 'os.kill(os.getpid(),signal.SIGKILL)'
                argv = ['/usr/bin/python3', '-c', parent_code]
            parent = execute(*argv)
            child_pid = int(parent.stdout.strip())
            alive = execute('/bin/kill', '-0', str(child_pid)).returncode == 0
            assert alive, 'descendant did not survive parent termination'
            call('ping')
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                outcome = execute('/bin/cat', result_path)
                if outcome.returncode == 0:
                    observed = json.loads(outcome.stdout)
                    assert observed['denied'] == 90 and not observed['unexpected']
                    report['checks']['descendant_' + mode] = {'parent_returncode': parent.returncode,
                        'survived_parent': alive, 'private_opens_denied': observed['denied']}
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('descendant observation failed: ' + mode)
            # Reap is owned by guest init after parent exit; ensure no live descendant
            # remains before evidence finalization (a zombie cannot generate traffic).
            stopped = execute('/usr/bin/python3', '-c',
                              "from pathlib import Path; p=Path('/proc/" + str(child_pid) + "/stat'); assert not p.exists() or p.read_text().split()[2]=='Z'")
            assert stopped.returncode == 0, 'live descendant remains before export'
            save()
        call('seal', credential)
        header = 'AWS4-HMAC-SHA256 Credential=' + worker + '/local/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=LOCAL-DUMMY'
        check('agent_proxy', 'curl -fsS -H ' + shlex.quote('Authorization: ' + header) + ' http://127.0.0.1:4566/public-data/readme.txt')
        report['checks']['sealed_seed_rejected'] = call('seed', credential, expected_error=True, setup=bundle)
        check('agent_proxy_final', 'curl -fsS -H ' + shlex.quote('Authorization: ' + header) + ' http://127.0.0.1:4566/public-data/end.txt')
        exported = call('export', credential)
        assert exported['complete'], 'recorder finalization incomplete'
        report['checks']['export'] = exported
        evidence = output / 'guest-evidence'
        evidence.mkdir(mode=0o700)
        for name, metadata in exported['files'].items():
            offset = 0
            with (evidence / name).open('xb') as stream:
                while offset < metadata['bytes']:
                    chunk = call('fetch', credential, export_id=exported['export_id'], file=name, offset=offset)
                    data = base64.b64decode(chunk['data_base64'], validate=True)
                    assert data and hashlib.sha256(data).hexdigest() == chunk['chunk_sha256']
                    stream.write(data)
                    offset += len(data)
            assert offset == metadata['bytes'] and sha(evidence / name) == metadata['sha256']
        rows = [json.loads(line) for line in (evidence / 'api.jsonl').read_text().splitlines()]
        assert len(rows) == 2 and all(row['status'] == 200 for row in rows)
        assert [row['path'] for row in rows] == ['/public-data/readme.txt', '/public-data/end.txt']
        assert credential not in (evidence / 'api.jsonl').read_text()
        assert (evidence / 'capture.pcap').stat().st_size > 24
        parsed = subprocess.run([shutil.which('tcpdump') or '/usr/sbin/tcpdump', '-nn', '-r', str(evidence / 'capture.pcap')],
                                capture_output=True, text=True, timeout=20)
        assert parsed.returncode == 0 and '127.0.0.1.4566' in parsed.stdout and '127.0.0.1.4567' in parsed.stdout
        payload_capture = (evidence / 'capture.pcap').read_bytes()
        for path in [b'/public-data/readme.txt', b'/public-data/end.txt']:
            assert b'GET ' + path + b' HTTP/1.1' in payload_capture, 'expected HTTP request absent from capture'
        for body in [b'PUBLIC-DUMMY', b'PUBLIC-END-DUMMY']:
            assert body in payload_capture, 'expected HTTP response absent from capture'
        report['checks']['capture_proxy_and_backend'] = {'passed': True, 'decoded_packet_lines': len(parsed.stdout.splitlines())}
        report['checks']['recording_boundary'] = {'passed': True, 'agent_api_rows': len(rows)}
        report['status'] = 'collected_requires_review'
        save()
    except Exception as error:
        report['failure'] = str(error)
        save()
        raise
    finally:
        if process is not None:
            try:
                subprocess.run(base + ['down'], cwd=box.workspace, capture_output=True, timeout=30)
            finally:
                # up can still be in startup retries without a registered session.
                # Its private process group includes only this test's supervisor/VM.
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                process.wait(timeout=30)
    instance = Path.home() / '.izanagi/instances' / hashlib.sha256(str(box.workspace).encode()).hexdigest()
    logs = output / 'izanagi-logs'
    logs.mkdir(mode=0o700)
    for name in ['events.log', 'alerts.log']:
        source = instance / 'logs' / name
        if source.is_file():
            shutil.copyfile(source, logs / name)
    observations = list(logs.glob('*')) + [output / 'up.stdout', output / 'up.stderr']
    leaked = [path.name for path in observations if any(marker.encode() in path.read_bytes() for marker in secret_markers)]
    report['checks']['host_logs_private_markers'] = {'passed': not leaked, 'files_examined': [p.name for p in observations], 'leaked_files': leaked}
    save()
    if leaked:
        raise RuntimeError('private marker found in observed logs')
    print(output / 'summary.json')


if __name__ == '__main__':
    main()
