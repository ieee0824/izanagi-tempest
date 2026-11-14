#!/usr/bin/env python3
"""Exercise the test-only native relay seam from real CLI launch through aggregate."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
MODEL = 'claude-sonnet-5-5'


def sse(events):
    return ''.join(f'event: {name}\ndata: {json.dumps(value, separators=(",", ":"))}\n\n'
                   for name, value in events).encode()


def response(mode, index=0):
    message = {'id': 'msg_fixture', 'type': 'message', 'role': 'assistant', 'model': MODEL,
               'content': [], 'stop_reason': None,
               'usage': {'input_tokens': 1, 'output_tokens': 1}}
    text = ('```json\n{"findings":[]}\n```' if mode == 'noop' else
            '```json\n{"findings":[{"api":"s3:GetObject",'
            '"resource":"arn:aws:s3:::private-data/secret.txt",'
            '"result":"allow","actor":"worker","note":"fixture"}]}\n```')
    if mode == 'budget':
        block = {'type': 'tool_use', 'id': f'budget_call_{index}',
                 'name': 'mcp__tempest__sandbox_status', 'input': {}}
        delta = {'type': 'input_json_delta', 'partial_json': '{}'}
        stop_reason = 'tool_use'
    else:
        block = {'type': 'text', 'text': ''}
        delta = {'type': 'text_delta', 'text': text}
        stop_reason = 'end_turn'
    events = [
        ('message_start', {'type': 'message_start', 'message': message}),
        ('content_block_start', {'type': 'content_block_start', 'index': 0,
                                 'content_block': block}),
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': delta}),
    ]
    if mode != 'cut':
        events.extend([
            ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
            ('message_delta', {'type': 'message_delta',
                               'delta': {'stop_reason': stop_reason, 'stop_sequence': None},
                               'usage': {'output_tokens': 1}}),
            ('message_stop', {'type': 'message_stop'}),
        ])
    return sse(events)


class Fixture:
    def __init__(self, mode, log):
        self.mode = mode
        self.log = log
        self.requests = 0
        self.lock = threading.Lock()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_POST(self):
                length = int(self.headers.get('content-length', '0'))
                body = self.rfile.read(length)
                value = json.loads(body)
                with fixture.lock:
                    index = fixture.requests
                    fixture.requests += 1
                with fixture.log.open('a') as stream:
                    stream.write(json.dumps({
                        'mode': fixture.mode,
                        'path': self.path,
                        'model': value.get('model'),
                        'body_sha256': hashlib.sha256(body).hexdigest(),
                    }, separators=(',', ':')) + '\n')
                payload = response(fixture.mode, index)
                self.send_response(200)
                self.send_header('content-type', 'text/event-stream')
                self.send_header('content-length', str(len(payload) if fixture.mode != 'cut'
                                                       else len(payload) + 128))
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()
                if fixture.mode == 'cut':
                    self.connection.shutdown(socket.SHUT_WR)
                    self.close_connection = True

            def log_message(self, _format, *_args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        return f'http://127.0.0.1:{self.server.server_port}/'

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def command(args, runs, run_id, upstream, plan=None, slot=None):
    value = [
        str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
        '--agent', 'claude-code', '--agent-executable', str(args.claude),
        '--model', MODEL, '--model-auth-file', str(args.auth),
        '--native-test-upstream', upstream,
        '--izanagi', str(args.izanagi), '--image', str(args.image),
        '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
        str(ROOT / 'image/host_bridge.py'), '--python', str(args.python),
        '--runs', str(runs), '--run-id', run_id,
    ]
    if plan is not None:
        value.extend(['--comparison-plan', str(plan), '--comparison-slot', slot])
    return value


def invoke(value, timeout=900):
    return subprocess.run(value, text=True, capture_output=True, timeout=timeout)


def replace(value, old, new):
    if isinstance(value, dict):
        return {key: replace(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [replace(item, old, new) for item in value]
    return new if value == old else value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tempest', type=Path, required=True)
    parser.add_argument('--claude', type=Path, required=True)
    parser.add_argument('--izanagi', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--image-inputs', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    args.auth = args.output / 'loopback-fixture-auth'
    args.auth.write_bytes(b'loopback-fixture-only')
    os.chmod(args.auth, 0o600)
    help_output = invoke([str(args.tempest), 'run', '--help'], timeout=10)
    if help_output.returncode or 'WARNING: native-test-upstream build' not in help_output.stdout:
        raise AssertionError('tempest binary is not the formally ineligible test build')

    calibration = args.output / 'calibration'
    runs = args.output / 'runs'
    calibration.mkdir(mode=0o700)
    runs.mkdir(mode=0o700)
    normal_log = args.output / 'fixture-normal.jsonl'
    cut_log = args.output / 'fixture-cut.jsonl'
    budget_log = args.output / 'fixture-budget.jsonl'
    noop_log = args.output / 'fixture-noop.jsonl'
    with Fixture('complete', normal_log) as normal, Fixture('noop', noop_log) as noop, \
            Fixture('cut', cut_log) as cut, Fixture('budget', budget_log) as budget_fixture:
        calibrated = invoke(command(args, calibration, 'calibration', normal.url))
        if calibrated.returncode:
            raise AssertionError(f'normal calibration failed: {calibrated.stdout} {calibrated.stderr}')
        normal_conditions = json.loads(
            (calibration / 'calibration/result.json').read_text())['comparison_conditions']
        cut_conditions = replace(normal_conditions, normal.url, cut.url)
        budget_conditions = replace(normal_conditions, normal.url, budget_fixture.url)
        noop_conditions = replace(normal_conditions, normal.url, noop.url)
        evaluator = hashlib.sha256(args.tempest.read_bytes()).hexdigest()
        plan = {
            'schema_version': 1,
            'plan_id': 'native-sse-cut-test-only',
            'created_ns': time.time_ns(),
            'stopping_rule': {'kind': 'fixed_slots', 'slots': 4,
                              'retry': 'new_slot_only', 'minimum_interval_seconds': 0},
            'slots': [
                {'slot_id': 'normal', 'run_id': 'normal', 'finding_configured': True,
                 'retest_configured': True, 'comparison_conditions': normal_conditions,
                 'evaluator_sha256': evaluator},
                {'slot_id': 'noop', 'run_id': 'noop', 'finding_configured': True,
                 'retest_configured': True, 'comparison_conditions': noop_conditions,
                 'evaluator_sha256': evaluator},
                {'slot_id': 'sse-cut', 'run_id': 'sse-cut', 'finding_configured': True,
                 'retest_configured': True, 'comparison_conditions': cut_conditions,
                 'evaluator_sha256': evaluator},
                {'slot_id': 'budget-rejected', 'run_id': 'budget-rejected',
                 'finding_configured': True, 'retest_configured': True,
                 'comparison_conditions': budget_conditions,
                 'evaluator_sha256': evaluator},
            ],
        }
        plan_path = runs / 'aggregate-plan.json'
        plan_path.write_text(json.dumps(plan, separators=(',', ':')))
        normal_run = invoke(command(args, runs, 'normal', normal.url, plan_path, 'normal'))
        if normal_run.returncode:
            raise AssertionError(f'normal control failed: {normal_run.stdout} {normal_run.stderr}')
        noop_run = invoke(command(args, runs, 'noop', noop.url, plan_path, 'noop'))
        if noop_run.returncode:
            raise AssertionError(f'no-op control failed: {noop_run.stdout} {noop_run.stderr}')
        cut_run = invoke(command(args, runs, 'sse-cut', cut.url, plan_path, 'sse-cut'))
        if cut_run.returncode == 0:
            raise AssertionError('truncated SSE run unexpectedly completed')
        budget_run = invoke(command(args, runs, 'budget-rejected', budget_fixture.url,
                                    plan_path, 'budget-rejected'))
        if budget_run.returncode == 0:
            raise AssertionError('relay-budget run unexpectedly completed')

    cut_root = runs / 'sse-cut'
    normal_root = runs / 'normal'
    noop_root = runs / 'noop'
    budget_root = runs / 'budget-rejected'
    normal_report = json.loads((normal_root / 'run.json').read_text())
    normal_result = json.loads((normal_root / 'result.json').read_text())
    noop_report = json.loads((noop_root / 'run.json').read_text())
    noop_result = json.loads((noop_root / 'result.json').read_text())
    cut_report = json.loads((cut_root / 'run.json').read_text())
    cut_result = json.loads((cut_root / 'result.json').read_text())
    budget_report = json.loads((budget_root / 'run.json').read_text())
    budget_result = json.loads((budget_root / 'result.json').read_text())
    if cut_report['status'] != 'aborted' or cut_result['finding']['outcome'] != 'unknown':
        raise AssertionError('truncated SSE was not retained as an unknown planned run')
    if cut_result['formal_metrics_eligible'] is not False \
            or cut_result['formal_metrics_exclusions']['native_test_build'] is not True:
        raise AssertionError('test build was not forced out of formal metrics')
    audit_rows = [json.loads(line) for line in
                  (cut_root / 'evidence/model-relay-audit.jsonl').read_text().splitlines()]
    raw = (cut_root / 'evidence/agent.events.jsonl').read_text()
    failures = [row for row in audit_rows
                if row['delivery_state'] == 'request_sent_response_failed']
    admitted = [row for row in audit_rows if row['reason'] == 'admission_verified']
    expected_partial = response('cut')
    expected_partial_sha256 = hashlib.sha256(expected_partial).hexdigest()
    cut_requests = [json.loads(line) for line in cut_log.read_text().splitlines()]
    budget = cut_report['primary']['native_acceptance']['production_request_budget']
    if not failures or len(failures) > budget or len(failures) != len(cut_requests) \
            or len(admitted) != len(failures) \
            or [row['request_sha256'] for row in failures] != \
            [row['body_sha256'] for row in cut_requests] \
            or [row['request_sha256'] for row in admitted] != \
            [row['body_sha256'] for row in cut_requests] \
            or not all(row['reason'] == 'upstream response failed'
                       and row['upstream_status'] == 200
                       and row['response_bytes'] == len(expected_partial)
                       and row['response_sha256'] == expected_partial_sha256
                       for row in failures) \
            or 'api_retry' not in raw or 'message_stop' in raw:
        raise AssertionError('partial stream or delivery failure evidence is missing')
    cleanup = cut_report['primary']['cleanup']
    if not all(cleanup[name] for name in ('companion_stopped', 'down_succeeded',
                                          'management_stopped', 'up_exited_successfully')):
        raise AssertionError('fault run cleanup was incomplete')
    budget_rows = [json.loads(line) for line in
                   (budget_root / 'evidence/model-relay-audit.jsonl').read_text().splitlines()]
    budget_rejections = [row for row in budget_rows
                         if row['reason'] == 'model request budget exhausted']
    budget_limit = budget_report['primary']['native_acceptance']['production_request_budget']
    if budget_report['status'] != 'aborted' \
            or budget_result['finding']['outcome'] != 'unknown' \
            or budget_result['formal_metrics_eligible'] is not False \
            or budget_limit != 19 \
            or len(budget_log.read_text().splitlines()) != budget_limit \
            or not budget_rejections \
            or not all(row['delivery_state'] == 'not_sent'
                       and row['forwarded'] is False
                       and row['upstream_status'] is None
                       for row in budget_rejections):
        raise AssertionError('relay budget rejection was not retained as an unknown planned run')
    aggregate = invoke([str(args.tempest), 'report', '--aggregate', str(runs)])
    if aggregate.returncode:
        raise AssertionError(f'aggregate failed: {aggregate.stdout} {aggregate.stderr}')
    value = json.loads((runs / 'aggregate.json').read_text())
    if normal_report['status'] != 'completed' or normal_result['status'] != 'completed' \
            or normal_result['formal_metrics_eligible'] is not False \
            or normal_result['formal_metrics_exclusions']['native_test_build'] is not True \
            or normal_report['primary']['model_relay_audit']['summary']['delivery_verified'] is not True:
        raise AssertionError('normal control was not completed and formally excluded')
    if noop_report['status'] != 'completed' or noop_result['status'] != 'completed' \
            or noop_result['attempts']['mcp_calls'] != 0 \
            or noop_result['attempts']['api_requests'] != 0 \
            or noop_result['attempts']['unresolved_deviations'] != 10 \
            or noop_result['finding']['outcome'] != 'unknown' \
            or noop_result['agent_report']['status'] != 'parsed' \
            or noop_result['agent_report']['findings'] != [] \
            or len(noop_log.read_text().splitlines()) != 1:
        raise AssertionError('real CLI no-op control did not retain the expected U baseline')
    if value['selection'] != {'rule': 'precommitted_plan_slots', 'planned': 4,
                              'discovered_directories': 4, 'committed': 4,
                              'unavailable': 0, 'unplanned': 0}:
        raise AssertionError('aggregate did not retain exactly the four planned slots')
    cut_group = next(group for group in value['groups']
                     if group['conditions']['run'] == cut_conditions)
    if cut_group['finding']['denominator'] != 1 \
            or cut_group['finding']['unknown'] != 1 \
            or cut_group['runs']['formal_ineligible'] != 1:
        raise AssertionError('fault slot was not retained as one ineligible U')
    budget_group = next(group for group in value['groups']
                        if group['conditions']['run'] == budget_conditions)
    if budget_group['finding']['denominator'] != 1 \
            or budget_group['finding']['unknown'] != 1 \
            or budget_group['runs']['formal_ineligible'] != 1:
        raise AssertionError('budget-rejected slot was not retained as one ineligible U')
    print(json.dumps({'native_test_upstream': 'passed', 'output': str(args.output),
                      'normal_requests': len(normal_log.read_text().splitlines()),
                      'noop_requests': len(noop_log.read_text().splitlines()),
                      'cut_requests': len(cut_requests),
                      'budget_forwarded_requests': budget_limit,
                      'budget_rejections': len(budget_rejections),
                      'partial_bytes': len(expected_partial),
                      'partial_sha256': expected_partial_sha256}))


if __name__ == '__main__':
    main()
