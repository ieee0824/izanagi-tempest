from pathlib import Path
import json,hashlib,os,stat,socket,subprocess,shutil
root=Path('/var/lib/tempest-izanagi-image-smoke-002');repo=Path('/home/ubuntu/izanagi-tempest')
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
meta=json.loads((root/'snapshot.json').read_text())
for row in meta['files']:
 p=Path(row['path']);s=p.lstat();assert s.st_uid==0 and s.st_gid==988
 if row['type']=='file':assert sha(p)==row['sha256'] and stat.S_IMODE(s.st_mode)==int(row['mode'],8)
 else:assert os.readlink(p)==row['target']
for p,h in meta['external_runtime_sha256'].items():assert sha(p)==h
for n in ['001','002','003']:
 for r in json.loads((repo/('docs/LINUX_X86_FULL_SNAPSHOT_'+n+'.json')).read_text()):assert sha(r['path'])==r['sha256']
 for p,r in json.loads((repo/('docs/LINUX_X86_FULL_BUILD_'+n+'_RESULT.json')).read_text())['files'].items():assert sha(p)==r['sha256']
for old in ['001','001-v2']:
 previous=json.loads(Path('/var/lib/tempest-izanagi-image-smoke-'+old+'/snapshot.json').read_text())
 for r in previous['files']:
  if r['type']=='file':assert sha(r['path'])==r['sha256']
  else:assert os.readlink(r['path'])==r['target']
d=json.loads((root/'work/output/summary.json').read_text());inv='6724ab53f2dd4acfb9f9499281466071'
e=json.loads((root/'work/evidence/exit-status.json').read_text());assert e['invocation_id']==inv and e['exit_status']=='0' and e['service_result']=='success'
trusted=[]
for line in Path('/tmp/tempest-image-smoke-journal-002.private.jsonl').read_text().splitlines():
 r=json.loads(line)
 if r.get('_PID')=='1' and r.get('_UID')=='0' and r.get('_BOOT_ID')=='30389abc903c40ae89a5c6268ec1c432' and r.get('UNIT')=='tempest-izanagi-image-smoke-002.service' and r.get('INVOCATION_ID')==inv:
  trusted.append({k:r.get(k) for k in ['UNIT','MESSAGE_ID','__REALTIME_TIMESTAMP','_BOOT_ID','_PID','_UID','INVOCATION_ID']})
assert len(trusted)==4
samples=[json.loads(x) for x in Path('/tmp/tempest-image-smoke-observation-002.jsonl').read_text().splitlines()]
assert not any(x['external_listener_observed'] for x in samples)
assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-image-smoke-002.service').exists()
assert not subprocess.run(['ps','-u','999','-o','pid='],capture_output=True,text=True).stdout.strip()
s=socket.socket();s.settimeout(1);assert s.connect_ex(('127.0.0.1',44571))!=0;s.close()
checks={k:{field:v[field] for field in ['passed','returncode'] if field in v} for k,v in d['checks'].items() if isinstance(v,dict)}
selected={k:d['checks'][k] for k in ['installed_artifact_binding','running_agent_build_binding','ebpf_trace_probe','recording_boundary','host_logs_private_markers','runtime_abi_unreadable_paths']}
for name in ['probe_allow','probe_deny','probe_unsupported']:
 selected[name]={key:d['checks'][name][key] for key in ['outcome','status','complete']}
for name in ['descendant_normal','descendant_timeout','descendant_abnormal']:
 selected[name]={key:d['checks'][name][key] for key in ['parent_returncode','survived_parent','private_opens_denied']}
selected['capture_proxy_and_backend']=d['checks']['capture_proxy_and_backend']
files={}
for p in [root/'work/output/summary.json',root/'work/evidence/exit-status.json',Path('/tmp/tempest-image-smoke-002.log'),Path('/tmp/tempest-image-smoke-observation-002.jsonl')]:files[str(p)]={'sha256':sha(p),'bytes':p.stat().st_size}
result={'status':'collected_requires_review_observer_terminal_unknown','caller_exit':0,'observer_exit':1,'observer_failure':'same-invocation terminal attributes not captured after GC','unit':'tempest-izanagi-image-smoke-002.service','invocation_id':inv,'host_boot_id':'30389abc903c40ae89a5c6268ec1c432','exit_recorder':e,'trusted_lifecycle':trusted,'observed_samples':len(samples),'observed_qemu':{'pid':285545,'starttime_ticks':35315195,'cwd':str(root/'work/output/workspace')},'check_results':checks,'selected_evidence':selected,'input_count_unchanged':len(meta['files']),'old_inputs_evidence_unchanged':True,'external_runtime_unchanged':True,'cgroup_absent':True,'uid999_absent':True,'agent_port_closed':True,'free_bytes':shutil.disk_usage(root).free,'files':files,'dummy_transport_key':'retained private pending result review; no standalone hash published'}
Path('/tmp/tempest-image-smoke-result-002.json').write_text(json.dumps(result,indent=2)+'\n');print('result metadata saved; no raw private summary published')
