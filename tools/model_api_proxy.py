#!/usr/bin/env python3
"""Fail-closed model API relay that admits only an exact tool catalog."""

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request


MAX_REQUEST = 16 * 1024 * 1024
HOP_HEADERS = {
    'connection', 'content-length', 'host', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade',
}
CREDENTIAL_HEADERS = {'authorization', 'x-api-key'}
FORBIDDEN_CAPABILITY_KEYS = {
    'attachments', 'conversation', 'conversation_id', 'file', 'file_id', 'files',
    'image_url', 'previous_response_id', 'remote_mcp', 'url', 'urls',
}


def unique_object(pairs):
    value = {}
    for name, child in pairs:
        if name in value:
            raise ValueError(f'duplicate JSON key: {name}')
        value[name] = child
    return value


def forbidden_capability(value):
    if isinstance(value, dict):
        for name, child in value.items():
            if name in FORBIDDEN_CAPABILITY_KEYS:
                return name
            found = forbidden_capability(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = forbidden_capability(child)
            if found:
                return found
    return None


def tool_identity(tool):
    if not isinstance(tool, dict):
        raise ValueError('tool is not an object')
    kind = tool.get('type')
    if kind == 'namespace' and isinstance(tool.get('name'), str):
        return f'namespace:{tool["name"]}'
    if isinstance(tool.get('name'), str):
        return f'{kind or "tool"}:{tool["name"]}'
    function = tool.get('function')
    if kind == 'function' and isinstance(function, dict) \
            and isinstance(function.get('name'), str):
        return f'function:{function["name"]}'
    raise ValueError('unknown tool representation')


def canonical_catalog(tools):
    if not isinstance(tools, list):
        raise ValueError('tool catalog is not an array')
    catalog = sorted(
        (tool_identity(tool), json.dumps(tool, sort_keys=True, separators=(',', ':')))
        for tool in tools)
    identities = [identity for identity, _ in catalog]
    if len(identities) != len(set(identities)):
        raise ValueError('duplicate tool identity')
    return catalog


def admitted_request(body, policy, path):
    value = json.loads(body, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or not isinstance(value.get('tools'), list):
        raise ValueError('request has no explicit tool catalog')
    if path not in policy['paths']:
        raise ValueError('request path is not allowed')
    if value.get('model') not in policy['models']:
        raise ValueError('request model is not allowed')
    unknown = sorted(set(value) - set(policy['top_level_fields']))
    if unknown:
        raise ValueError(f'unknown top-level request fields: {unknown}')
    forbidden = forbidden_capability(value)
    if forbidden:
        raise ValueError(f'forbidden request capability: {forbidden}')
    actual = canonical_catalog(value['tools'])
    if actual != policy['tools']:
        raise ValueError('tool catalog mismatch')
    return [identity for identity, _ in actual]


def validated_policy(policy):
    if not isinstance(policy, dict) or policy.get('schema_version') != 1 \
            or set(policy) != {'schema_version', 'paths', 'models',
                               'top_level_fields', 'tools'}:
        raise ValueError('invalid relay policy shape')
    for name in ['paths', 'models', 'top_level_fields']:
        values = policy.get(name)
        if not isinstance(values, list) or not values \
                or not all(isinstance(value, str) and value for value in values) \
                or sorted(values) != values or len(values) != len(set(values)):
            raise ValueError(f'invalid relay policy {name}')
    if any(not path.startswith('/') or '?' in path or '#' in path for path in policy['paths']):
        raise ValueError('invalid relay policy path')
    if 'model' not in policy['top_level_fields'] or 'tools' not in policy['top_level_fields']:
        raise ValueError('relay policy must require model and tools')
    tools = policy.get('tools')
    if not isinstance(tools, list) or not tools:
        raise ValueError('invalid expected tool catalog')
    return {**policy, 'tools': canonical_catalog(tools)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Relay(http.server.BaseHTTPRequestHandler):
    server_version = 'tempest-model-relay/1'

    def log_message(self, _format, *_args):
        return

    def reject(self, status, reason):
        data = json.dumps({'error': 'request_rejected', 'reason': reason}).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        prefix = '/' + self.server.path_capability
        if self.path != prefix and not self.path.startswith(prefix + '/'):
            self.reject(404, 'invalid relay capability')
            return
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            self.reject(400, 'invalid content length')
            return
        if length < 0 or length > MAX_REQUEST:
            self.reject(413, 'request too large')
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.reject(400, 'truncated request')
            return
        suffix = self.path[len(prefix):] or '/'
        try:
            tools = admitted_request(body, self.server.policy, suffix)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            self.server.record(False, body, str(error), [])
            self.reject(409, str(error))
            return
        target = urllib.parse.urljoin(self.server.upstream.rstrip('/') + '/', suffix.lstrip('/'))
        parsed = urllib.parse.urlparse(target)
        if (parsed.scheme, parsed.netloc) != self.server.upstream_authority:
            self.server.record(False, body, 'upstream authority changed', tools)
            self.reject(502, 'upstream authority changed')
            return
        headers = {
            name: value for name, value in self.headers.items()
            if name.lower() not in HOP_HEADERS | CREDENTIAL_HEADERS
        }
        headers[self.server.auth_header] = self.server.auth_value
        request = urllib.request.Request(target, data=body, headers=headers, method='POST')
        try:
            response = self.server.opener.open(request, timeout=self.server.upstream_timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError) as error:
            self.server.record(False, body, 'upstream transport failed', tools)
            self.reject(502, 'upstream transport failed')
            return
        if 300 <= response.status < 400:
            self.server.record(False, body, f'upstream redirect {response.status}', tools)
            response.close()
            self.reject(502, 'upstream redirect rejected')
            return
        self.server.record(True, body, None, tools)
        self.send_response(response.status)
        for name, value in response.headers.items():
            if name.lower() not in HOP_HEADERS:
                self.send_header(name, value)
        self.end_headers()
        try:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            response.close()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, upstream, path_capability, policy, audit, timeout,
                 auth_header, auth_value):
        super().__init__(address, Relay)
        parsed = urllib.parse.urlparse(upstream)
        if parsed.scheme not in {'http', 'https'} or not parsed.netloc \
                or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('invalid upstream URL')
        self.upstream = upstream
        self.upstream_authority = (parsed.scheme, parsed.netloc)
        self.path_capability = path_capability
        self.policy = validated_policy(policy)
        self.audit = audit
        self.upstream_timeout = timeout
        if auth_header.lower() not in CREDENTIAL_HEADERS or not auth_value:
            raise ValueError('invalid upstream authentication configuration')
        self.auth_header = auth_header
        self.auth_value = auth_value
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def record(self, forwarded, body, reason, tools):
        event = {
            'forwarded': forwarded,
            'request_sha256': hashlib.sha256(body).hexdigest(),
            'request_bytes': len(body),
            'tools': tools,
            'reason': reason,
        }
        encoded = (json.dumps(event, separators=(',', ':')) + '\n').encode()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(self.audit, flags, 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def private_file(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() \
            or metadata.st_mode & 0o077:
        raise ValueError(f'{path} must be an owner-private regular file')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', required=True)
    parser.add_argument('--capability-file', type=Path, required=True)
    parser.add_argument('--policy-file', type=Path, required=True)
    parser.add_argument('--audit', type=Path, required=True)
    parser.add_argument('--ready-file', type=Path, required=True)
    parser.add_argument('--upstream-auth-file', type=Path, required=True)
    parser.add_argument('--upstream-auth-header', choices=['Authorization', 'x-api-key'], required=True)
    parser.add_argument('--timeout-seconds', type=float, default=330)
    args = parser.parse_args()
    private_file(args.capability_file)
    private_file(args.policy_file)
    private_file(args.upstream_auth_file)
    path_capability = args.capability_file.read_text().strip()
    if len(path_capability) < 32 or not path_capability.isascii() \
            or not path_capability.replace('-', '').replace('_', '').isalnum():
        raise SystemExit('invalid relay path capability')
    policy = json.loads(args.policy_file.read_text(), object_pairs_hook=unique_object)
    try:
        validated_policy(policy)
    except ValueError as error:
        raise SystemExit(f'invalid relay policy: {error}') from error
    server = Server(('127.0.0.1', 0), args.upstream, path_capability, policy,
                    args.audit, args.timeout_seconds, args.upstream_auth_header,
                    args.upstream_auth_file.read_text().strip())
    ready = {'schema_version': 1, 'host': '127.0.0.1',
             'port': server.server_address[1], 'path_prefix': '/' + path_capability}
    descriptor = os.open(
        args.ready_file,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0),
        0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(ready, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    server.serve_forever()


if __name__ == '__main__':
    raise SystemExit(main())
