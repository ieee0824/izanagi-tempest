"""Read saved new-large evidence; never start a VM or change its expectation."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tomllib

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-capture-large-001')
UNIT = ROOT.name + '.service'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--invocation', required=True)
    for name in ('caller-session', 'caller-exit', 'observer-session', 'observer-exit'):
        parser.add_argument('--' + name, type=int, required=True)
    args = parser.parse_args()
    assert os.getuid() == 0 and args.caller_exit == 0
    os.umask(0o077)
    base = module('base', REPO/'docs/evidence/runtime-normal-001/collect_result.py')
    snapshot = base.verify_snapshot(ROOT)
    for path, digest in snapshot['external_runtime_sha256'].items(): assert sha(path) == digest
    for path, digest in json.loads((REPO/'docs/LINUX_X86_CAPTURE_LARGE_SOURCE_001.json').read_text())['files'].items(): assert sha(REPO/path) == digest
    for directory in snapshot['directories_mode0750_root_group']:
        st=Path(directory).stat();assert (st.st_uid,st.st_gid,st.st_mode & 0o777)==(0,988,0o750)
    old_verifier=REPO/'docs/evidence/host-endpoint-001/collect_result.py'
    code=old_verifier.read_text().split("    output = ROOT / 'work/output'",1)[0]+'\nmain()\n'
    exec(compile(code,str(old_verifier),'exec'),{'__name__':'old_verification','__file__':str(old_verifier)})
    previous = json.loads((ROOT/'inputs/previous-failed-control.json').read_text())
    assert previous['runtime_status'] == 'aborted' and previous['collection']['complete'] is False
    for path, receipt in previous['files'].items(): assert sha(path) == receipt['sha256']
    build = json.loads((ROOT/'inputs/image-build-provenance.json').read_text())
    for path, receipt in build['files'].items(): assert sha(path) == receipt['sha256']
    hardlink = json.loads((ROOT/'inputs/hardlink-exception-provenance.json').read_text())
    for row in hardlink['after']:
        s = Path(row['path']).lstat()
        assert (s.st_dev, s.st_ino, s.st_nlink) == (row['file']['device'], row['file']['inode'], 8)
    observer = module('fixed_observer', ROOT/'inputs/repo/integration/capture_large_observe.py')
    replay = observer.Sessions('capture-large')
    observed_path = Path('/tmp/tempest-capture-large-observation-001.jsonl')
    samples, saved, invocations = [], [], set()
    for line in observed_path.read_text().splitlines():
        envelope = json.loads(line)
        if set(envelope) == {'sample'}:
            row = envelope['sample']; samples.append(row); replay.observe(row)
            if row['unit'].get('InvocationID'): invocations.add(row['unit']['InvocationID'])
        else:
            assert set(envelope) == {'observed_sessions'}
            saved = envelope['observed_sessions']
            assert len(saved) == len(replay.identities)
            for i, stage in enumerate(saved):
                assert (stage['pid'], stage['starttime_ticks']) == replay.identities[i]
                assert stage['workspace'] == replay.stages[i]
                if stage['binding'] is not None: replay.bind(i, {'state':'running', **stage['binding']})
    replay.require_complete()
    assert replay.snapshot() == saved and len(saved) == 1 and invocations == {args.invocation}
    last_unit=samples[-1]['unit']
    if args.observer_exit == 0:
        assert last_unit['LoadState']=='loaded' and last_unit['InvocationID']==args.invocation and last_unit['ActiveState'] in ('inactive','failed')
        observer_terminal='same Invocation terminal observed'
    else:
        assert args.observer_exit==1 and last_unit['LoadState']=='not-found'
        observer_terminal='unknown after unit GC; independent trusted termination checked separately'
    run_root = ROOT/'work/runs/forced-delivery-race'
    def load(name): return json.loads((run_root/name).read_text())
    run, result = load('run.json'), load('result.json')
    assert run['status'] == 'completed' and run['evaluation'] == 'performed'
    assert run['agent']['outcome']['calls_attempted'] == 1
    assert run['retest']['configured'] is False and run['retest']['performed'] is False
    assert result['formal_metrics_eligible'] is False and result['contaminated'] is False
    assert result['control_integrity'] == result['control_request_integrity'] == 'matched'
    assert result['failed_control_operations'] == {} and load('artifact-inventory.json')['complete'] is True
    assert not list(run_root.rglob('transport-hmac'))
    scenario = load('scenario.yaml')
    assert sha(run_root/'scenario.yaml') == run['scenario_sha256']
    assert scenario['budget'] == {'max_calls':1, 'timeout':'120s'}
    assert scenario['setup']['buckets'] == [{'name':'large-data','objects':[{'key':'dummy','body':'A'*1048576}]}]
    assert scenario['expect'] == [{'api':'s3:GetObject','resource':'arn:aws:s3:::large-data/dummy','result':'allow'}]
    assert 'retest' not in scenario and 'expected_finding' not in scenario
    config=tomllib.loads((run_root/'izanagi.toml').read_text())
    # Exact generated config is retained; parse the known top-level VM resource keys.
    assert config['sandbox']['qemu']['cpus']==2 and config['sandbox']['qemu']['memory']=='4G'
    assert 'range(29)' in json.dumps(load('mock-script.json'))
    binding = {k:run['primary']['vm_binding'][k] for k in ('boot_nonce','supervisor_pid','session_fingerprint')}
    assert binding == saved[0]['binding']
    inputs = json.loads((ROOT/'inputs/build-inputs.json').read_text())
    assert run['primary']['daemon_identity']['exe_sha256'] == inputs['input_sha256']['agent']
    cleanup = run['primary']['cleanup']
    assert all(cleanup[k] for k in ('companion_stopped','down_succeeded','management_stopped','up_exited_successfully'))
    assert not cleanup['forced_group_stop'] and not cleanup['missing_logs']
    exported, index, collection = run['primary']['export'], load('evidence/export-index.json'), load('evidence/collection.json')
    assert all(exported[k] == v for k,v in index.items())
    manifest = load('evidence/manifest.json')
    assert manifest == index['manifest'] and manifest['complete'] is True and manifest['finalized'] is True
    assert manifest['failures'] == [] and manifest['api_rows'] == 29 and manifest['incomplete_rows'] == 0
    assert manifest['capture_buffer_kib_requested'] == 16384 and manifest['capture_immediate_mode'] is True
    assert manifest['capture_filter'] is None and manifest['capture_contains_payloads'] is True
    assert manifest['capture_statistics']['dropped'] == 0 and manifest['capture_statistics']['read_failed'] is False
    assert manifest['capture_statistics']['captured'] > 0
    assert manifest['recorder_statistics'] == {'accepted_connections':29,'admission_rejected':0,'connection_errors':0,'http_parse_errors':0,'task_errors':0}
    assert exported['complete'] is True and exported['collection_complete'] is True and collection['complete'] is True
    assert collection['export_id'] == index['export_id']
    assert set(index['files']) == {'manifest.json','api.jsonl','capture.pcap'}
    mtimes = {}
    for name, receipt in index['files'].items():
        p = run_root/'evidence'/name; item = collection['files'][name]
        assert p.stat().st_size == receipt['bytes'] and sha(p) == receipt['sha256']
        assert item['verified'] is True and item['received_bytes'] == item['expected_bytes'] == receipt['bytes']
        assert item['observed_sha256'] == item['expected_sha256'] == receipt['sha256']
        mtimes[name] = p.stat().st_mtime_ns
    assert 56*1024**2 <= index['files']['capture.pcap']['bytes'] <= 64*1024**2
    assert len((run_root/'evidence/api.jsonl').read_text().splitlines()) == 29
    parse=subprocess.run(['/usr/bin/tcpdump','-nn','-r',str(run_root/'evidence/capture.pcap'),'-w','/dev/null'],capture_output=True,timeout=30)
    assert parse.returncode==0
    controls = [json.loads(l) for l in (run_root/'evidence/control.jsonl').read_text().splitlines()]
    exports = [r for r in controls if r['operation'] == 'export']
    starts = [r for r in exports if r['state'] == 'started']
    assert len(starts) == 1 and {r['id'] for r in exports} == {starts[0]['id']}
    assert sum(r['state'] == 'completed' for r in exports) == 1
    categories = [r['category'] for r in exports if r['state'] == 'delivery_read_observed']
    assert 'execution_error' in categories and categories[-1] == 'ciphertext_received'
    expected = [(r['id'],r['operation']) for r in controls if r['state']=='started' and r['operation'] in ('claim','seed','probe','seal','export')]
    intents = manifest['control_operation_intents']
    assert all(r['authorized'] is True for r in intents) and manifest['control_operation_intents_overflow'] == 0
    assert Counter(expected) == Counter((r['audit_id'],r['operation']) for r in intents)
    assert manifest['control_transitions']==['claimed','seeding','seeded','sealing','sealed','finalizing']
    barrier = index['quiesce']
    assert barrier['forced_reader_pid'] > 0 and barrier['forced_reader_pid'] in barrier['moved_pids']
    assert barrier['frozen_duration_ns'] > 0 and barrier['descendants_empty'] and barrier['service_frozen']
    exited = json.loads((ROOT/'work/evidence/exit-status.json').read_text())
    assert exited['invocation_id'] == exited['unit']['InvocationID'] == args.invocation
    assert exited['service_result'] == 'success' and exited['exit_status'] == '0'
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-','')
    journal = subprocess.check_output(['journalctl','-u',UNIT,'-o','json','--no-pager'],text=True)
    trusted = []
    for line in journal.splitlines():
        r = json.loads(line)
        if r.get('_PID')=='1' and r.get('_UID')=='0' and r.get('UNIT')==UNIT and r.get('INVOCATION_ID')==args.invocation and r.get('_BOOT_ID')==boot:
            trusted.append({k:r.get(k) for k in ('MESSAGE_ID','UNIT','INVOCATION_ID','_BOOT_ID','_PID','_UID','__REALTIME_TIMESTAMP')})
    assert {'7d4958e842da4a758f6c1cdc7b36dcc5','39f53479d3a045ac8e11786248231fbf','7ad2d189f7e94e70a38c781354912448'} <= {r['MESSAGE_ID'] for r in trusted}
    assert not Path('/sys/fs/cgroup/system.slice',UNIT).exists()
    assert subprocess.run(['pgrep','-u','999'],capture_output=True).returncode == 1
    ports = {int(l['local'].rsplit(':',1)[1]) for r in samples for l in r['listeners']}
    for port in ports:
        with socket.socket() as sock:
            sock.settimeout(1);assert sock.connect_ex(('127.0.0.1',port)) != 0
    paths = [run_root/n for n in ('run.json','result.json','scenario.yaml','mock-script.json','artifact-inventory.json','evidence/control.jsonl','evidence/export-index.json','evidence/collection.json','evidence/manifest.json','evidence/api.jsonl','evidence/capture.pcap')]
    paths += [observed_path,ROOT/'work/evidence/exit-status.json',Path('/tmp/tempest-capture-large-001.log')]
    files = {str(p):{'sha256':sha(p),'bytes':p.stat().st_size} for p in paths}
    fetches = [r for r in controls if r['operation']=='fetch']
    projection = {'status':'completed_capture_and_transfer_verified','handles':vars(args),'unit':UNIT,'boot_id':boot,'observed_sessions':saved,'samples':len(samples),'observer_terminal':observer_terminal,'trusted_lifecycle':trusted,'cleanup_receipt':cleanup,'actual_resources_reclaimed':True,'runtime_status':run['status'],'formal_metrics_eligible':False,'control_integrity':result['control_integrity'],'collection':collection,'manifest_capture_statistics':manifest['capture_statistics'],'recorder_statistics':manifest['recorder_statistics'],'buffer_kib_requested':16384,'quiesce':{k:barrier[k] for k in ('forced_reader_pid','moved_pids','frozen_duration_ns','descendants_empty','service_frozen')},'host_control_id':starts[0]['id'],'native_export_id':index['export_id'],'export_read_categories':categories,'file_mtimes_support_only':mtimes,'collection_order_scope':'Pinned host source dictates manifest/API/PCAP order; audit without file IDs does not directly prove fetch order.','fetch_state_counts':dict(Counter(r['state'] for r in fetches)),'fetch_timestamp_span_ns':max(r['host_ns'] for r in fetches)-min(r['host_ns'] for r in fetches),'per_file_allowance_ms':{n:min(600000,30000+((v['bytes']+32767)//32768)*250) for n,v in index['files'].items()},'export_collection_budget_seconds':600,'pcap_parse_exit':parse.returncode,'files':files}
    with (ROOT/'work/evidence/journal.private.jsonl').open('x') as stream: stream.write(journal)
    with Path('/tmp/tempest-capture-large-result-001.json').open('x') as stream: json.dump(projection,stream,indent=2);stream.write('\n')
    print('Saved completed control independently verified; no trial started or retried.')


if __name__ == '__main__':
    main()
