#!/usr/bin/env python3
"""Collect M0 prerequisites; optional isolated QEMU boot, never a benchmark pass."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import signal
import secrets
import subprocess
import sys
import time
import tomllib


def validate_config(path):
    config = tomllib.loads(path.read_text())
    sandbox = config.get('sandbox', {})
    if (sandbox.get('backend') != 'qemu'
            or sandbox.get('tracer') != 'vm-agent'
            or sandbox.get('require_auth') is not True
            or sandbox.get('qemu', {}).get('restrict_network') is not True):
        raise ValueError('QEMU, vm-agent, require_auth=true, restrict_network=true required')
    share = config.get('share', {})
    if share.get('paths') != ['.'] or share.get('read_only') is not True:
        raise ValueError('Only the empty sandbox cwd may be shared, read-only')
    if config.get('behavior', {}).get('enabled') or config.get('dns_proxy') or config.get('http_capture'):
        raise ValueError('M0 baseline must not enable proxies or behavior export')
    return config


def capture(argv, cwd, timeout=30, input_text=None):
    start = time.time_ns()
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                                timeout=timeout, input=input_text)
        return dict(argv=argv, start_ns=start, end_ns=time.time_ns(),
                    returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired as error:
        def decode(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        return dict(argv=argv, start_ns=start, end_ns=time.time_ns(), returncode=None,
                    stdout=decode(error.stdout), stderr=decode(error.stderr), error='timeout')
    except OSError as error:
        return dict(argv=argv, start_ns=start, end_ns=time.time_ns(), returncode=None,
                    stdout='', stderr=str(error), error='spawn_failed')


def wait_ready(process, probe, timeout=90):
    """up is a foreground supervisor; readiness is an authenticated guest exec."""
    deadline = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < deadline:
        result = probe()
        if result['returncode'] == 0 and result['stdout'].strip() == 'tempest-m0-ready':
            return True
        time.sleep(0.5)
    return False


def mcp_probe(base, cwd, marker=None):
    requests = [
        {'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2024-11-05', 'capabilities': {},
            'clientInfo': {'name': 'tempest-m0', 'version': '1'}}},
        {'method': 'notifications/initialized'},
        {'id': 2, 'method': 'tools/list'},
        {'id': 3, 'method': 'tools/call', 'params': {'name': 'sandbox_status', 'arguments': {}}},
    ]
    if marker is not None:
        requests.append({'id': 4, 'method': 'tools/call', 'params': {
            'name': 'sandbox_exec', 'arguments': {
                'command': '/bin/cat', 'args': [f'/tmp/tempest-m0-{marker}']}}})
    wire = ''.join(json.dumps({'jsonrpc': '2.0', **request}) + '\n' for request in requests)
    result = capture(base + ['mcp'], cwd, input_text=wire)
    result['requests'] = requests
    return result


def upload_guest_file(base, cwd, source):
    """Transfer through authenticated exec; do not add a host network/share path."""
    destination = '/tmp/tempest-m0-assets/' + source.name
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    entries = []
    script = ('from pathlib import Path; import sys; p=Path(sys.argv[1]); '
              'p.parent.mkdir(mode=0o700,exist_ok=True); p.write_bytes(b"")')
    entry = capture(base + ['exec', '--', 'python3', '-c', script, destination], cwd)
    entries.append(entry)
    if entry['returncode'] != 0:
        return {'path': destination, 'sha256': digest, 'status': 'failed'}, entries
    for offset in range(0, len(data), 32768):
        chunk = data[offset:offset + 32768]
        encoded = base64.b64encode(chunk).decode('ascii')
        script = ('import base64,sys; '
                  'open(sys.argv[1],"ab").write(base64.b64decode(sys.argv[2]))')
        entry = capture(base + ['exec', '--', 'python3', '-c', script, destination, encoded], cwd)
        # Payload is reproducible from the retained source digest and offset. Avoid huge JSON logs.
        entry['argv'][-1] = '<base64 payload omitted>'
        entry['payload'] = {'offset': offset, 'bytes': len(chunk),
                            'sha256': hashlib.sha256(chunk).hexdigest()}
        entries.append(entry)
        if entry['returncode'] != 0:
            return {'path': destination, 'sha256': digest, 'status': 'failed'}, entries
    script = ('import hashlib,sys; from pathlib import Path; p=Path(sys.argv[1]); '
              'assert hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[2]; '
              'p.chmod(0o700); print(sys.argv[2])')
    entry = capture(base + ['exec', '--', 'python3', '-c', script, destination, digest], cwd)
    entries.append(entry)
    return {'path': destination, 'sha256': digest, 'bytes': len(data),
            'status': 'verified' if entry['returncode'] == 0 else 'failed'}, entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New private evidence directory')
    parser.add_argument('--config', type=Path, help='Explicit QEMU baseline config for --boot')
    parser.add_argument('--boot', action='store_true', help='Start and stop a fresh QEMU session')
    parser.add_argument('--izanagi', type=Path, help='Explicit pinned izanagi executable')
    parser.add_argument('--guest-probe', type=Path, help='Local shell script to execute in the disposable guest')
    parser.add_argument('--guest-file', type=Path, action='append', default=[],
                        help='File to upload into /tmp/tempest-m0-assets/ through authenticated exec')
    parser.add_argument('--agent-probe', action='append', choices=['codex', 'claude'], default=[],
                        help='Run local-stub host isolation probes while the VM is running')
    parser.add_argument('--guest-capture', action='store_true',
                        help='Export /run/tempest-m0/loopback.pcap from the M0 investigation image')
    parser.add_argument('--probe-share-readonly', action='store_true',
                        help='Give the empty nested share mode 0777 to distinguish read-only from permission denial')
    args = parser.parse_args()
    if args.boot and not args.config:
        parser.error('--boot requires --config')
    if (args.guest_probe or args.guest_file or args.agent_probe or args.guest_capture
            or args.probe_share_readonly) and not args.boot:
        parser.error('Guest and agent probes require --boot')
    if len(set(args.agent_probe)) != len(args.agent_probe):
        parser.error('--agent-probe agents must be unique')
    if len({p.name for p in args.guest_file}) != len(args.guest_file):
        parser.error('--guest-file basenames must be unique')
    for source in args.guest_file:
        if not source.is_file():
            parser.error(f'guest file does not exist: {source}')
    guest_script = args.guest_probe.read_text() if args.guest_probe else None
    config_path = args.config.resolve() if args.config else None
    config = validate_config(config_path) if config_path else None
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sandbox = output / 'sandbox'
    sandbox.mkdir(mode=0o700)
    if args.probe_share_readonly:
        sandbox.chmod(0o777)  # The enclosing evidence directory remains private (0700).
    summary = {'schema_version': 1, 'status': 'unverified', 'checks': {},
               'commands': [], 'note': 'Boot success does not prove observation or host isolation.'}
    summary['share_mode'] = oct(sandbox.stat().st_mode & 0o777)
    summary_path = output / 'summary.json'

    def save():
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')

    def run(argv, timeout=30):
        entry = capture(argv, sandbox, timeout)
        summary['commands'].append(entry)
        save()
        return entry

    for name in ['izanagi', 'qemu-system-aarch64', 'qemu-system-x86_64']:
        executable = (str(args.izanagi.resolve()) if name == 'izanagi' and args.izanagi
                      else shutil.which(name))
        summary['checks'][name] = {'path': executable, 'status': 'available' if executable else 'missing'}
        if executable:
            with Path(executable).open('rb') as stream:
                summary['checks'][name]['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            run([executable, '--version'])
    for check in ['loopback_syscalls', 'loopback_pcap', 'api_results',
                  'host_tool_isolation', 'session_binding', 'shared_mounts', 'clock_source']:
        summary['checks'][check] = {'status': 'unverified'}
    save()
    if not args.boot:
        print(summary_path)
        return 0
    izanagi = str(args.izanagi.resolve()) if args.izanagi else shutil.which('izanagi')
    if not izanagi:
        summary['status'] = 'blocked'
        save()
        return 1
    summary['config_sha256'] = hashlib.sha256(config_path.read_bytes()).hexdigest()
    summary['image'] = config['sandbox']['qemu']['image']
    image = Path(summary['image'])
    if image.is_absolute() and image.is_file():
        with image.open('rb') as stream:
            summary['image_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    # Config may contain private values. Store its digest, never copy its contents.
    base = [izanagi, '--config', str(config_path)]
    process = None
    boot_start = time.time_ns()
    boot_argv = base + ['up', '--pcap', str(output / 'control.pcap')]
    try:
        with (output / 'up.stdout').open('w') as stdout, (output / 'up.stderr').open('w') as stderr:
            process = subprocess.Popen(boot_argv, cwd=sandbox, stdout=stdout, stderr=stderr)
        def probe_ready():
            # exec can auto-start a VM when no session exists. Never race up's lock.
            if 'サンドボックスを起動しました' not in (output / 'up.stdout').read_text():
                return {'returncode': None, 'stdout': ''}
            return run(base + ['exec', '--', '/bin/echo', 'tempest-m0-ready'], 5)

        ready = wait_ready(process, probe_ready)
        summary['checks']['boot'] = {'status': 'passed' if ready else 'failed'}
        if ready:
            probe = run(base + ['exec', '--', '/bin/sh', '-c',
                'id; date -u; cat /proc/mounts; '
                'for c in aws curl python3 tcpdump iptables; do command -v "$c" || true; done'])
            summary['checks']['guest_inventory'] = {
                'status': 'collected' if probe['returncode'] == 0 else 'failed'}
            for _ in range(3):
                run(base + ['exec', '--', '/bin/date', '+%s%N'])
            marker = secrets.token_hex(16)
            created = run(base + ['exec', '--', '/bin/sh', '-c',
                                 f'printf %s {marker} > /tmp/tempest-m0-{marker}'])
            same = mcp_probe(base, sandbox, marker)
            summary['commands'].append(same)
            other_cwd = output / 'other-cwd'
            other_cwd.mkdir(mode=0o700)
            other = mcp_probe(base, other_cwd)
            summary['commands'].append(other)
            # Save raw protocol evidence; semantic review is required, never infer a pass from rc=0.
            summary['checks']['session_binding'] = {'status': 'collected',
                                                    'marker_created': created['returncode'] == 0}
            for agent in args.agent_probe:
                agent_result = run([sys.executable, str(Path(__file__).with_name('probe-agent.py')),
                                    '--agent', agent, '--output', str(output / f'agent-{agent}'),
                                    '--mcp-command', izanagi, '--mcp-cwd', str(sandbox)], 75)
                summary['checks'][f'agent_{agent}'] = {
                    'status': 'collected' if agent_result['returncode'] == 0 else 'failed'}
                if agent_result['returncode'] != 0:
                    summary['status'] = 'blocked'
            summary['guest_files'] = []
            for source in args.guest_file:
                asset, entries = upload_guest_file(base, sandbox, source)
                summary['guest_files'].append(asset)
                summary['commands'].extend(entries)
                save()
                if asset['status'] != 'verified':
                    summary['status'] = 'blocked'
                    return 1
            if guest_script is not None:
                summary['guest_probe_sha256'] = hashlib.sha256(guest_script.encode()).hexdigest()
                guest_result = run(base + ['exec', '--', '/bin/sh', '-c', guest_script], 120)
                summary['checks']['guest_probe'] = {
                    'status': 'collected' if guest_result['returncode'] == 0 else 'failed'}
                if guest_result['returncode'] != 0:
                    summary['status'] = 'blocked'
            if args.guest_capture:
                # tcpdump -U flushes packet writes, but libpcap may buffer up to one second.
                # Allow the final CLI requests to reach the capture before taking a file snapshot.
                time.sleep(1.5)
                marker = run(base + ['exec', '--', '/bin/sh', '-c',
                                    'cat /run/tempest-m0/startup.uid /run/tempest-m0/startup.epoch'])
                script = ('import base64; from pathlib import Path; '
                          'print(base64.b64encode(Path("/run/tempest-m0/loopback.pcap").read_bytes()).decode())')
                exported = run(base + ['exec', '--', 'python3', '-c', script])
                check = {'status': 'failed', 'startup_marker_returncode': marker['returncode'],
                         'quiescence_wait_seconds': 1.5}
                if exported['returncode'] == 0:
                    try:
                        data = base64.b64decode(exported['stdout'].strip(), validate=True)
                        (output / 'loopback.pcap').write_bytes(data)
                        check.update(status='collected', bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                    except ValueError as error:
                        check['error'] = str(error)
                summary['checks']['loopback_pcap'] = check
                if check['status'] == 'failed' or marker['returncode'] != 0:
                    summary['status'] = 'blocked'
        else:
            summary['status'] = 'blocked'
    except OSError as error:
        summary['status'] = 'blocked'
        summary['checks']['collection_error'] = {'status': 'failed', 'error': str(error)}
    finally:
        if process is not None:
            stopped = run(base + ['down'], 30)
            summary['checks']['cleanup'] = {'status': 'passed' if stopped['returncode'] == 0 else 'failed'}
            if stopped['returncode'] != 0:
                summary['status'] = 'blocked'
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                summary['checks']['cleanup']['supervisor_forced'] = True
                summary['status'] = 'blocked'
            summary['commands'].append(dict(
                argv=boot_argv, start_ns=boot_start, end_ns=time.time_ns(),
                returncode=process.returncode,
                stdout=(output / 'up.stdout').read_text(),
                stderr=(output / 'up.stderr').read_text()))
        save()
        instance = Path.home() / '.izanagi' / 'instances' / hashlib.sha256(
            str(sandbox).encode()).hexdigest()
        summary['instance_path'] = str(instance)
        logs = output / 'izanagi-logs'
        logs.mkdir(mode=0o700, exist_ok=True)
        for name in ['events.log', 'alerts.log']:
            source = instance / 'logs' / name
            if source.is_file():
                shutil.copyfile(source, logs / name)
        save()
    print(summary_path)
    return 1 if summary['status'] == 'blocked' else 0


if __name__ == '__main__':
    raise SystemExit(main())
