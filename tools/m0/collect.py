#!/usr/bin/env python3
"""Collect M0 prerequisites; optional isolated QEMU boot, never a benchmark pass."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
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


def capture(argv, cwd, timeout=30):
    start = time.time_ns()
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New private evidence directory')
    parser.add_argument('--config', type=Path, help='Explicit QEMU baseline config for --boot')
    parser.add_argument('--boot', action='store_true', help='Start and stop a fresh QEMU session')
    args = parser.parse_args()
    if args.boot and not args.config:
        parser.error('--boot requires --config')
    config_path = args.config.resolve() if args.config else None
    config = validate_config(config_path) if config_path else None
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sandbox = output / 'sandbox'
    sandbox.mkdir(mode=0o700)
    summary = {'schema_version': 1, 'status': 'unverified', 'checks': {},
               'commands': [], 'note': 'Boot success does not prove observation or host isolation.'}
    summary_path = output / 'summary.json'

    def save():
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')

    def run(argv, timeout=30):
        entry = capture(argv, sandbox, timeout)
        summary['commands'].append(entry)
        save()
        return entry

    for name in ['izanagi', 'qemu-system-aarch64', 'qemu-system-x86_64']:
        executable = shutil.which(name)
        summary['checks'][name] = {'path': executable, 'status': 'available' if executable else 'missing'}
        if executable:
            run([executable, '--version'])
    for check in ['loopback_syscalls', 'loopback_pcap', 'api_results',
                  'host_tool_isolation', 'session_binding', 'shared_mounts', 'clock_source']:
        summary['checks'][check] = {'status': 'unverified'}
    save()
    if not args.boot:
        print(summary_path)
        return 0
    izanagi = shutil.which('izanagi')
    if not izanagi:
        summary['status'] = 'blocked'
        save()
        return 1
    summary['config_sha256'] = hashlib.sha256(config_path.read_bytes()).hexdigest()
    summary['image'] = config['sandbox']['qemu']['image']
    # Config may contain private values. Store its digest, never copy its contents.
    base = [izanagi, '--config', str(config_path)]
    attempted = False
    try:
        attempted = True
        started = run(base + ['up', '--pcap', str(output / 'control.pcap')], 90)
        summary['checks']['boot'] = {'status': 'passed' if started['returncode'] == 0 else 'failed'}
        if started['returncode'] == 0:
            probe = run(base + ['exec', '--', '/bin/sh', '-c',
                'id; date -u; cat /proc/mounts; '
                'for c in aws curl python3 tcpdump iptables; do command -v "$c" || true; done'])
            summary['checks']['guest_inventory'] = {
                'status': 'collected' if probe['returncode'] == 0 else 'failed'}
        else:
            summary['status'] = 'blocked'
    finally:
        if attempted:
            stopped = run(base + ['down'], 30)
            summary['checks']['cleanup'] = {'status': 'passed' if stopped['returncode'] == 0 else 'failed'}
            if stopped['returncode'] != 0:
                summary['status'] = 'blocked'
        save()
    print(summary_path)
    return 1 if summary['status'] == 'blocked' else 0


if __name__ == '__main__':
    raise SystemExit(main())
