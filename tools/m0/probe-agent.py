#!/usr/bin/env python3
"""Probe CLI host-tool rejection using a local deterministic API stub, no real model."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time

DISABLED = ['shell_tool', 'apps', 'view_image', 'multi_agent', 'plugins', 'remote_plugin',
            'plugin_sharing', 'plugin_discovery_prefetch', 'skill_search',
            'skill_mcp_dependency_install', 'hooks', 'goals', 'image_generation']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', choices=['codex', 'claude'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mcp-command', type=Path, help='Pinned izanagi executable for an allowed MCP status call')
    parser.add_argument('--mcp-cwd', type=Path, help='cwd of the already running investigation VM')
    args = parser.parse_args()
    if bool(args.mcp_command) != bool(args.mcp_cwd):
        parser.error('--mcp-command and --mcp-cwd must be provided together')
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cwd = output / 'agent-cwd'
    cwd.mkdir(mode=0o700)
    canary = output / 'host-canary.txt'
    canary_value = secrets.token_hex(16)
    canary.write_text(canary_value)
    write_canary = output / 'write-canary.txt'
    catalog = []
    outputs = []
    count = 0
    mcp_namespace = None
    guest_attempt = 'cat ' + shlex.quote(str(canary)) + '; printf dummy > ' + shlex.quote(str(write_canary))
    if args.agent == 'codex':
        attempts = [('exec_command', {'cmd': 'cat ' + shlex.quote(str(canary))}),
                    ('apply_patch', {'patch': '*** Begin Patch\n*** Add File: ' + str(write_canary)
                                             + '\n+dummy\n*** End Patch'}),
                    ('view_image', {'path': str(canary)})]
    else:
        attempts = [('Bash', {'command': 'cat ' + shlex.quote(str(canary))}),
                    ('Read', {'file_path': str(canary)}),
                    ('Write', {'file_path': str(write_canary), 'content': 'dummy'})]

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            # Codex custom-provider model discovery. No actual model is used.
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"models": []}')

        def do_POST(self):
            nonlocal count, mcp_namespace
            data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
            # Do not retain prompts, headers, environment variables or authentication data.
            catalog.append(data.get('tools', []))
            if args.mcp_command and len(attempts) == 3:
                for tool in data.get('tools', []):
                    if tool.get('type') == 'namespace' and tool.get('name') == 'mcp__tempest':
                        mcp_namespace = tool['name']
                        attempts.extend([('sandbox_status', {}),
                                         ('sandbox_exec', {'command': '/bin/sh', 'args': ['-c', guest_attempt]}),
                                         ('sandbox_shell', {'command': 'id -u; ' + guest_attempt}),
                                         ('read_mcp_resource', {'server': 'tempest', 'uri': canary.as_uri()})])
                        break
                    if tool.get('name') == 'mcp__tempest__sandbox_status':
                        attempts.extend([(tool['name'], {}),
                                         ('mcp__tempest__sandbox_exec', {'command': '/bin/sh', 'args': ['-c', guest_attempt]}),
                                         ('mcp__tempest__sandbox_shell', {'command': 'id -u; ' + guest_attempt}),
                                         ('mcp__other__read', {'file_path': str(canary)})])
                        break
            if args.agent == 'codex':
                tool_outputs = [item for item in data.get('input', [])
                                if item.get('type') == 'function_call_output']
            else:
                tool_outputs = [item for message in data.get('messages', [])
                                if isinstance(message.get('content'), list)
                                for item in message['content'] if item.get('type') == 'tool_result']
            outputs.append(tool_outputs)
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            index = count
            count += 1
            if args.agent == 'codex':
                items = []
                if index < len(attempts):
                    name, parameters = attempts[index]
                    items = [{'type': 'function_call', 'id': f'fc_{index}',
                              'call_id': f'call_{index}', 'name': name,
                              'arguments': json.dumps(parameters)}]
                    if name.startswith('sandbox_') and mcp_namespace:
                        items[0]['namespace'] = mcp_namespace
                events = [{'type': 'response.created', 'response': {
                    'id': f'resp_{index}', 'object': 'response', 'status': 'in_progress', 'output': []}}]
                for item in items:
                    events.extend([{'type': 'response.output_item.added', 'output_index': 0, 'item': item},
                                   {'type': 'response.output_item.done', 'output_index': 0, 'item': item}])
                events.append({'type': 'response.completed', 'response': {
                    'id': f'resp_{index}', 'object': 'response', 'status': 'completed', 'output': items,
                    'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}})
                for event in events:
                    self.wfile.write(('data: ' + json.dumps(event) + '\n\n').encode())
            else:
                message = {'id': f'msg_{index}', 'type': 'message', 'role': 'assistant',
                           'model': 'm0-probe', 'content': [], 'stop_reason': None,
                           'usage': {'input_tokens': 1, 'output_tokens': 1}}
                events = [('message_start', {'type': 'message_start', 'message': message})]
                if index < len(attempts):
                    name, parameters = attempts[index]
                    block = {'type': 'tool_use', 'id': f'call_{index}', 'name': name, 'input': {}}
                    delta = {'type': 'input_json_delta', 'partial_json': json.dumps(parameters)}
                    reason = 'tool_use'
                else:
                    block = {'type': 'text', 'text': ''}
                    delta = {'type': 'text_delta', 'text': 'M0 probe complete.'}
                    reason = 'end_turn'
                events.extend([
                    ('content_block_start', {'type': 'content_block_start', 'index': 0, 'content_block': block}),
                    ('content_block_delta', {'type': 'content_block_delta', 'index': 0, 'delta': delta}),
                    ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
                    ('message_delta', {'type': 'message_delta', 'delta': {'stop_reason': reason,
                                                                       'stop_sequence': None},
                                       'usage': {'output_tokens': 1}}),
                    ('message_stop', {'type': 'message_stop'})])
                for name, event in events:
                    self.wfile.write(('event: ' + name + '\ndata: ' + json.dumps(event) + '\n\n').encode())

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint = f'http://127.0.0.1:{server.server_port}'
    env = {key: value for key, value in os.environ.items()
           if key in ['PATH', 'HOME', 'TMPDIR', 'LANG', 'USER']}
    mcp = {}
    if args.mcp_command:
        script = ('import os; os.chdir(' + repr(str(args.mcp_cwd.resolve())) + '); '
                  'os.execv(' + repr(str(args.mcp_command.resolve())) + ', '
                  + repr([str(args.mcp_command.resolve()), 'mcp']) + ')')
        mcp = {'command': sys.executable, 'args': ['-c', script]}
        if os.environ.get('IZANAGI_SECRET_FILE'):
            mcp['env'] = {'IZANAGI_SECRET_FILE': os.environ['IZANAGI_SECRET_FILE']}
    if args.agent == 'codex':
        command = ['codex', 'exec', '--ignore-user-config', '--ignore-rules', '--ephemeral',
                   '--skip-git-repo-check', '--json', '-s', 'read-only', '-m', 'm0-probe']
        for feature in DISABLED:
            command += ['--disable', feature]
        for override in ['model_provider="m0"', 'model_providers.m0.name="M0 local stub"',
                         f'model_providers.m0.base_url="{endpoint}"',
                         'model_providers.m0.wire_api="responses"',
                         'model_providers.m0.requires_openai_auth=false', 'web_search="disabled"']:
            command += ['-c', override]
        if mcp:
            command += ['-c', 'mcp_servers.tempest.command=' + json.dumps(mcp['command']),
                        '-c', 'mcp_servers.tempest.args=' + json.dumps(mcp['args']),
                        '-c', 'mcp_servers.tempest.enabled_tools=["sandbox_status","sandbox_exec","sandbox_shell"]',
                        '-c', 'mcp_servers.tempest.default_tools_approval_mode="approve"']
            for name, value in mcp.get('env', {}).items():
                command += ['-c', 'mcp_servers.tempest.env.' + name + '=' + json.dumps(value)]
        command += ['Reply done.']
    else:
        env.update(ANTHROPIC_BASE_URL=endpoint, ANTHROPIC_API_KEY='dummy-local-stub-key')  # placeholder for the local stub
        command = ['claude', '-p', 'Reply done.', '--model', 'm0-probe', '--bare',
                   '--tools', '', '--strict-mcp-config', '--mcp-config',
                   json.dumps({'mcpServers': {'tempest': mcp} if mcp else {}}),
                   '--setting-sources', '', '--disable-slash-commands', '--permission-mode', 'dontAsk',
                   '--no-session-persistence', '--output-format', 'stream-json', '--verbose']
        if mcp:
            command += ['--allowedTools', 'mcp__tempest__sandbox_status',
                        'mcp__tempest__sandbox_exec', 'mcp__tempest__sandbox_shell']
    start = time.time_ns()
    result = {'agent': args.agent, 'argv': command, 'start_ns': start, 'status': 'unverified'}
    executable = shutil.which(args.agent)
    if executable:
        with Path(executable).open('rb') as stream:
            result['executable_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        version = subprocess.run([executable, '--version'], env=env,
                                 capture_output=True, text=True, timeout=10)
        result['version'] = version.stdout.strip()
    try:
        process = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, timeout=60)
        result.update(returncode=process.returncode, stdout=process.stdout, stderr=process.stderr)
    except (OSError, subprocess.TimeoutExpired) as error:
        result['error'] = str(error)
    finally:
        server.shutdown()
        server.server_close()
        result.update(end_ns=time.time_ns(), requests=count, catalogs=catalog, tool_outputs=outputs,
                      attempts=[{'name': name, 'arguments': parameters} for name, parameters in attempts],
                      canary_unchanged=canary.read_text() == canary_value,
                      write_canary_exists=write_canary.exists())
        (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(output / 'summary.json')
    return 0 if result.get('returncode') == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
