"""Cover a bounded enumerated PID set in bounded actor-readable pages."""
from collections import Counter
import json
import os
from pathlib import Path
import sys
import time

# Also used as a read-only guest test script under python -I.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import proc_evidence as core

MAX_ENUMERATED = 4096
PAGE_TARGETS = core.MAX_PIDS - 1
MAX_PAGES = (MAX_ENUMERATED + PAGE_TARGETS - 1) // PAGE_TARGETS
MAX_STAGE_BYTES = (MAX_PAGES + 1) * core.MAX_OUTPUT
MODE_KEY = 'TEMPEST_PROC_MODE'
PAGE_KEY = 'TEMPEST_PROC_PAGE'
STAGE_KEY = 'TEMPEST_PROC_STAGE'
INDEX_KEY = 'TEMPEST_PROC_INDEX'
STAGES = ('before_claim', 'after_seed', 'before_export')


def frame(value):
    encoded = json.dumps(value, separators=(',', ':'))
    if len(encoded.encode()) + 1 > core.MAX_OUTPUT:
        raise RuntimeError('proc response exceeds bounded frame')
    return encoded


def validate_pairs(pairs, limit):
    if not isinstance(pairs, list) or not pairs or len(pairs) > limit:
        raise ValueError('invalid proc PID set size')
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2 or type(pair[0]) is not int or pair[0] <= 0 \
                or (pair[1] is not None and (type(pair[1]) is not int or pair[1] < 0)):
            raise ValueError('invalid proc PID identity')
    ids = [pair[0] for pair in pairs]
    if ids != sorted(set(ids)):
        raise ValueError('proc PID set is not sorted and unique')


def enumerate_processes(proc=Path('/proc'), stage='test'):
    started = time.monotonic_ns()
    ids = sorted(int(path.name) for path in proc.iterdir() if path.name.isdecimal())
    if not ids or len(ids) > MAX_ENUMERATED:
        raise RuntimeError('proc enumeration exceeds finite PID budget')
    pairs, unbound = [], {}
    for pid in ids:
        identity = core.identity(proc / str(pid))
        pairs.append([pid, identity.get('starttime_ticks')])
        if 'starttime_ticks' not in identity:
            unbound[str(pid)] = identity['status']
    result = {'schema_version': 2, 'kind': 'proc_enumeration', 'stage': stage,
              'actor_uid': os.getuid(), 'processes': pairs, 'unbound': unbound,
              'started_monotonic_ns': started, 'ended_monotonic_ns': time.monotonic_ns()}
    frame(result)
    return result


def page_requests(enumeration):
    if enumeration['schema_version'] != 2 or enumeration['kind'] != 'proc_enumeration' \
            or enumeration['actor_uid'] != 1000:
        raise ValueError('unexpected proc enumeration')
    frame(enumeration)
    pairs = enumeration['processes']
    validate_pairs(pairs, MAX_ENUMERATED)
    unbound = enumeration['unbound']
    if set(unbound) != {str(pid) for pid, start in pairs if start is None} \
            or any(status not in ('denied', 'vanished') for status in unbound.values()):
        raise ValueError('unknown proc enumeration identity result')
    return [pairs[offset:offset + PAGE_TARGETS] for offset in range(0, len(pairs), PAGE_TARGETS)]


def observe_page(pairs, proc=Path('/proc'), own_pid=None, stage='test', index=0):
    validate_pairs(pairs, PAGE_TARGETS)
    result = core.snapshot(proc, own_pid=own_pid, requested_pids=[pid for pid, _ in pairs])
    result.update(schema_version=2, kind='proc_page', stage=stage, page_index=index, requested=pairs)
    frame(result)
    return result


def binding_status(row, expected):
    before = row['identity_before']
    if expected is None:
        return 'unbound_at_enumeration'
    if before.get('status') == 'vanished':
        return 'vanished'
    if 'starttime_ticks' not in before:
        return 'unobserved'
    if before['starttime_ticks'] != expected:
        return 'replaced'
    return 'matched' if row['identity_stable'] else 'unstable'


def summarize_pages(enumeration, pages, wire_bytes):
    requested = page_requests(enumeration)
    if len(pages) != len(requested) or len(pages) > MAX_PAGES:
        raise ValueError('missing or extra proc page')
    if type(wire_bytes) is not int or wire_bytes <= 0 or wire_bytes > MAX_STAGE_BYTES:
        raise ValueError('proc stage exceeds finite byte budget')
    previous = enumeration['ended_monotonic_ns']
    if (type(previous) is not int or type(enumeration['started_monotonic_ns']) is not int
            or enumeration['started_monotonic_ns'] <= 0 or enumeration['started_monotonic_ns'] > previous):
        raise ValueError('invalid proc enumeration interval')
    summaries, bindings, rows = [], Counter(), []
    for index, (pairs, page) in enumerate(zip(requested, pages, strict=True)):
        if page['schema_version'] != 2 or page['kind'] != 'proc_page' \
                or page['stage'] != enumeration['stage'] or page['page_index'] != index \
                or type(page['page_index']) is not int or page['requested'] != pairs:
            raise ValueError('proc page request binding mismatch')
        ids = [row['pid'] for row in page['records']]
        if any(type(pid) is not int or pid <= 0 for pid in ids) or len(ids) != len(set(ids)) or set(ids) != {page['own_pid'], *(pid for pid, _ in pairs)}:
            raise ValueError('proc page PID coverage mismatch')
        if (type(page['started_monotonic_ns']) is not int or type(page['ended_monotonic_ns']) is not int
                or page['started_monotonic_ns'] < previous or page['ended_monotonic_ns'] < page['started_monotonic_ns']):
            raise ValueError('proc page interval changed order')
        previous = page['ended_monotonic_ns']
        frame(page)
        for row in page['records']:
            if type(row['identity_stable']) is not bool:
                raise ValueError('invalid proc identity stability')
            for name in ('cmdline', 'environ', 'fd'):
                allowed = ('listed', 'denied', 'vanished', 'error') if name == 'fd' else ('read', 'denied', 'vanished', 'error')
                if row[name]['status'] not in allowed:
                    raise ValueError('unknown proc observation status')
                if row[name]['status'] == 'read' and (not isinstance(row[name]['text'], str)
                                                     or type(row[name]['truncated']) is not bool):
                    raise ValueError('invalid proc observation stream')
        summary = core.summarize(page)
        summaries.append(summary)
        by_pid = {row['pid']: row for row in page['records']}
        for pid, expected in pairs:
            bindings[binding_status(by_pid[pid], expected)] += 1
        rows.extend(page['records'])
    errors = sum(row[side].get('status') == 'error' for row in rows
                 for side in ('identity_before', 'identity_after'))
    return {'passed': all(summary['passed'] for summary in summaries) and not errors,
            'pages': len(pages), 'enumerated_processes': len(enumeration['processes']),
            'covered_requested_processes': sum(bindings.values()), 'requested_binding': dict(bindings),
            'records': len(rows), 'positive_controls': {key: all(s['positive_controls'][key] for s in summaries)
                                                       for key in ('cmdline', 'environ', 'fd_list')},
            'stable_identities': sum(row['identity_stable'] for row in rows),
            'cmdline_status': dict(Counter(row['cmdline']['status'] for row in rows)),
            'environ_status': dict(Counter(row['environ']['status'] for row in rows)),
            'fd_status': dict(Counter(row['fd']['status'] for row in rows)),
            'truncated_streams': sum(s['truncated_streams'] for s in summaries),
            'unexpected_errors': errors + sum(s['unexpected_errors'] for s in summaries),
            'wire_bytes': wire_bytes,
            'started_monotonic_ns': enumeration['started_monotonic_ns'], 'ended_monotonic_ns': previous,
            'scope': 'paged actor observations of enumerated identities; counts include observer per page; not simultaneous or complete lifetime'}


def main():
    core.require_guest()
    stage = os.environ.get(STAGE_KEY)
    if stage not in STAGES:
        raise ValueError('unknown proc observation stage')
    mode = os.environ.get(MODE_KEY)
    if mode == 'enumerate':
        value = enumerate_processes(stage=stage)
    elif mode == 'page':
        index = int(os.environ[INDEX_KEY])
        if not 0 <= index < MAX_PAGES:
            raise ValueError('invalid proc page index')
        value = observe_page(json.loads(os.environ[PAGE_KEY]), stage=stage, index=index)
    else:
        raise ValueError('unknown proc observation mode')
    print(frame(value))


if __name__ == '__main__':
    main()
