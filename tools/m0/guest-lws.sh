#!/bin/sh
# Requires --guest-file pointing to a pinned Linux aarch64 LWS executable.
set -eu
python3 - <<'PY'
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import xml.etree.ElementTree as ET

with tempfile.TemporaryDirectory(prefix='tempest-m0-lws-') as directory:
    directory = Path(directory)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    endpoint = f'http://127.0.0.1:{port}'
    env = dict(os.environ, LWS_BIND_ADDR=f'127.0.0.1:{port}', LWS_AUTH_MODE='strict',
               LWS_ROOT_ACCESS_KEY_ID='tempest-m0-admin', LWS_DATA_DIR=str(directory / 'data'))
    def auth(key):
        return f'AWS4-HMAC-SHA256 Credential={key}/20261111/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=dummy'
    def request(method, path, key='tempest-m0-admin', body=b'', content_type='application/octet-stream'):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            connection.request(method, path, body, {'Authorization': auth(key), 'Content-Type': content_type})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()
    def iam(action, **parameters):
        body = urllib.parse.urlencode({'Action': action, 'Version': '2010-05-08', **parameters}).encode()
        status, response = request('POST', '/', body=body, content_type='application/x-www-form-urlencoded')
        assert status == 200, (action, status, response)
        return ET.fromstring(response)
    result = {'kind': 'lws_api', 'endpoint': endpoint, 'checks': []}
    with (directory / 'lws.stderr').open('w') as log:
        process = subprocess.Popen(['/tmp/tempest-m0-assets/lws'], env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('LWS failed: ' + (directory / 'lws.stderr').read_text())
                try:
                    if request('GET', '/_lws/health')[0] == 200:
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('LWS startup timeout')
            iam('CreateUser', UserName='worker')
            xml = iam('CreateAccessKey', UserName='worker')
            key = next(element.text for element in xml.iter() if element.tag.endswith('}AccessKeyId'))
            policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject'],
                       'Resource': ['arn:aws:s3:::m0-bucket/public.txt']}]}
            iam('PutUserPolicy', UserName='worker', PolicyName='read-public', PolicyDocument=json.dumps(policy))
            assert request('PUT', '/m0-bucket')[0] == 200
            for name in ['public.txt', 'private.txt']:
                assert request('PUT', '/m0-bucket/' + name, body=b'dummy-data')[0] == 200
            for method in ['python_http', 'curl']:
                for case, path, expected in [('allow', '/m0-bucket/public.txt', 200),
                                              ('deny', '/m0-bucket/private.txt', 403),
                                              ('unsupported', '/m0-bucket?notification', 501)]:
                    start = time.time_ns()
                    if method == 'python_http':
                        status, body = request('GET', path, key)
                    else:
                        target = directory / 'curl-body'
                        call = subprocess.run(['curl', '--noproxy', '*', '--max-time', '5', '-sS',
                                               '-o', str(target), '-w', '%{http_code}',
                                               '-H', 'Authorization: ' + auth(key), endpoint + path],
                                              capture_output=True, text=True, timeout=7)
                        assert call.returncode == 0, call.stderr
                        status, body = int(call.stdout), target.read_bytes()
                    error_code = None
                    if status != 200:
                        xml = ET.fromstring(body)
                        error_code = next((el.text for el in xml.iter() if el.tag.split('}')[-1] == 'Code'), None)
                    result['checks'].append({'method': method, 'case': case, 'path': path,
                                             'start_ns': start, 'end_ns': time.time_ns(),
                                             'status': status, 'expected_status': expected,
                                             'error_code': error_code, 'bytes': len(body),
                                             'sha256': hashlib.sha256(body).hexdigest()})
                    assert status == expected, result['checks'][-1]
            result['aws_cli_available'] = shutil.which('aws') is not None
            if result['aws_cli_available']:
                aws_env = dict(env, AWS_ACCESS_KEY_ID=key, AWS_SECRET_ACCESS_KEY='dummy',  # placeholder for local LWS
                               AWS_DEFAULT_REGION='us-east-1', AWS_EC2_METADATA_DISABLED='true',
                               AWS_CONFIG_FILE='/dev/null', AWS_SHARED_CREDENTIALS_FILE='/dev/null',
                               AWS_PAGER='', AWS_MAX_ATTEMPTS='1', AWS_RETRY_MODE='standard')
                aws_env.pop('AWS_PROFILE', None)
                aws_env.pop('AWS_SESSION_TOKEN', None)
                for case, operation, parameters, expected_error in [
                    ('allow', 'get-object', ['--key', 'public.txt', str(directory / 'aws-body')], None),
                    ('deny', 'get-object', ['--key', 'private.txt', str(directory / 'aws-denied')], 'AccessDenied'),
                    ('unsupported', 'get-bucket-notification-configuration', [], 'NotImplemented')]:
                    start = time.time_ns()
                    call = subprocess.run(['aws', '--endpoint-url', endpoint, '--region', 'us-east-1',
                                           '--output', 'json', 's3api', operation, '--bucket', 'm0-bucket',
                                           *parameters], env=aws_env, capture_output=True, text=True, timeout=20)
                    check = {'method': 'aws_cli', 'case': case, 'operation': operation,
                             'start_ns': start, 'end_ns': time.time_ns(), 'returncode': call.returncode,
                             'expected_error': expected_error, 'stderr': call.stderr,
                             'stdout_sha256': hashlib.sha256(call.stdout.encode()).hexdigest()}
                    result['checks'].append(check)
                    if expected_error is None:
                        assert call.returncode == 0, check
                        assert (directory / 'aws-body').read_bytes() == b'dummy-data'
                    else:
                        assert call.returncode != 0 and expected_error in call.stderr, check
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    result['lws_log'] = (directory / 'lws.stderr').read_text()
    print(json.dumps(result, sort_keys=True))
PY
