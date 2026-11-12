#!/usr/bin/env python3
"""Compare a pinned real MCP server with the proxy without starting a VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tempest', type=Path, required=True)
    parser.add_argument('--izanagi', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sandbox = output / 'sandbox'
    sandbox.mkdir(mode=0o700)
    tempest, izanagi = args.tempest.resolve(), args.izanagi.resolve()
    requests = [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}]
    wire = ''.join(json.dumps(value) + '\n' for value in requests)
    baseline = subprocess.run([str(izanagi), 'mcp'], input=wire, text=True,
                              capture_output=True, cwd=sandbox, timeout=20)
    (output / 'baseline.stdout').write_text(baseline.stdout)
    (output / 'baseline.stderr').write_text(baseline.stderr)
    assert baseline.returncode == 0, 'baseline metadata request failed'
    blocked = {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {
        'name': 'sandbox_exec', 'arguments': {'command': '/bin/echo', 'args': ['NEVER-RUN']}}}
    command = [str(tempest), 'mcp-proxy', '--log', str(output / 'mcp.jsonl'),
               '--summary', str(output / 'proxy.json'), '--stderr', str(output / 'upstream.stderr'),
               '--cwd', str(sandbox), '--max-calls', '0', '--', str(izanagi), 'mcp']
    proxied = subprocess.run(command, input=wire + json.dumps(blocked) + '\n',
                             text=True, capture_output=True, timeout=20)
    (output / 'proxy.stdout').write_text(proxied.stdout)
    (output / 'proxy.stderr').write_text(proxied.stderr)
    assert proxied.returncode == 0, 'proxy metadata request failed'
    expected = [json.loads(line) for line in baseline.stdout.splitlines()]
    observed = [json.loads(line) for line in proxied.stdout.splitlines()]
    assert observed[:2] == expected and len(observed) == 3, 'metadata changed'
    assert observed[2]['id'] == 3 and observed[2]['error']['code'] == -32001
    state = json.loads((output / 'proxy.json').read_text())
    assert state['relay']['admitted_calls'] == 0 and not state['relay']['uncertain']
    events = [json.loads(line) for line in (output / 'mcp.jsonl').read_text().splitlines()]
    assert not any(event['event'] == 'forwarded' and event['data']['sequence'] is not None
                   for event in events), 'tool reached upstream'
    report = {'scope': 'metadata_and_admission_only_no_vm', 'status': 'passed',
              'tempest_sha256': digest(tempest), 'izanagi_sha256': digest(izanagi),
              'tool_names': [tool['name'] for tool in observed[1]['result']['tools']],
              'matched_initialize': True, 'matched_tool_definitions': True, 'zero_budget_blocked': True}
    (output / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print(output / 'comparison.json')


if __name__ == '__main__':
    main()
