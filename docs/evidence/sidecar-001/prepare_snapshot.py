from pathlib import Path
import os,stat,hashlib,json,shutil,subprocess,pwd,grp
assert os.geteuid()==0
os.umask(0o077)
root=Path('/var/lib/tempest-izanagi-sidecar-001');assert not os.path.lexists(root)
uid=pwd.getpwnam('tempest-kvm').pw_uid;gid=grp.getgrnam('tempest-kvm').gr_gid;assert (uid,gid)==(999,988)
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while b:=f.read(1048576):h.update(b)
 return h.hexdigest()
repo=Path('/home/ubuntu/izanagi-tempest')
assert '--sidecar-evidence' in (repo/'integration/image_smoke.py').read_text(), 'wait for reviewed proc evidence implementation'
assert sha(repo/'image/proc_evidence.py')=='6044bfb59240318dbc63888c6460adfe22ff479fc5003ef13ff10558b2d091e0', 'requires reviewed PR57 source before root creation'
assert sha(repo/'image/proc_paging.py')=='bd1ece774f2099eaad2d765aecca53e7ab5c869292b5b4bdf8423894e9035713', 'requires reviewed PR57 source before root creation'
assert sha(repo/'integration/image_smoke.py')=='37f3f058f7ffc849775b9b67dfc3b39e0cb635c275f86bf65541912212c89dce', 'requires reviewed PR57 source before root creation'
assert sha(repo/'image/sidecar_probe.py')=='83fd831b373d75f799ea5d7a3ec89db1fc967559f3cc28a69bf572158a8a3c39', 'requires reviewed sidecar source before root creation'
assert sha(repo/'image/sidecar_evidence.py')=='d95b794f2ea4e7e891f6c1e238ab226ed2d121a6f5c9c2150f02f42b1c3319f5', 'requires reviewed sidecar source before root creation'
for n in ['001','002','003']:
 for r in json.loads((repo/('docs/LINUX_X86_FULL_SNAPSHOT_'+n+'.json')).read_text()):assert sha(r['path'])==r['sha256']
 for p,r in json.loads((repo/('docs/LINUX_X86_FULL_BUILD_'+n+'_RESULT.json')).read_text())['files'].items():assert sha(p)==r['sha256']
for p,rev in [('/tmp/tempest-izanagi-upstream-review','16d0b55947006a166cfa29dcb8bfe71f65f8c36a'),('/tmp/tempest-lws-upstream-review','2c0ea463f334f10a562e54f1cdc7ba8a474029e2')]:
 assert subprocess.check_output(['git','-C',p,'rev-parse','HEAD'],text=True).strip()==rev
 assert not subprocess.check_output(['git','-C',p,'status','--porcelain'])
preserved=json.loads(Path('/var/lib/tempest-izanagi-image-smoke-001-v2/snapshot.json').read_text())
for row in preserved['files']:
 p=Path(row['path'])
 if row['type']=='file':assert sha(p)==row['sha256']
 else:assert p.is_symlink() and os.readlink(p)==row['target']
previous_proc=Path('/var/lib/tempest-izanagi-proc-exposure-001')
for row in json.loads((previous_proc/'snapshot.json').read_text())['files']:
 if row['type']=='file':assert sha(row['path'])==row['sha256']
 else:assert os.readlink(row['path'])==row['target']
for path,metadata in json.loads((repo/'docs/LINUX_X86_PROC_EXPOSURE_001_RESULT.json').read_text())['files'].items():assert sha(path)==metadata['sha256']
proc_cleanup=json.loads((repo/'docs/LINUX_X86_PROC_EXPOSURE_001_KEY_CLEANUP.json').read_text());assert proc_cleanup['absence_verified'] and not os.path.lexists(proc_cleanup['path'])
previous_proc2=Path('/var/lib/tempest-izanagi-proc-exposure-002')
for row in json.loads((previous_proc2/'snapshot.json').read_text())['files']:
 if row['type']=='file':assert sha(row['path'])==row['sha256']
 else:assert os.readlink(row['path'])==row['target']
for path,metadata in json.loads((repo/'docs/LINUX_X86_PROC_EXPOSURE_002_RESULT.json').read_text())['files'].items():assert sha(path)==metadata['sha256']
cleanup2=json.loads((repo/'docs/LINUX_X86_PROC_EXPOSURE_002_KEY_CLEANUP.json').read_text());assert cleanup2['absence_verified'] and not os.path.lexists(cleanup2['path'])
previous_proc3=Path('/var/lib/tempest-izanagi-proc-exposure-003')
for row in json.loads((previous_proc3/'snapshot.json').read_text())['files']:
 if row['type']=='file':assert sha(row['path'])==row['sha256']
 else:assert os.readlink(row['path'])==row['target']
for path,metadata in json.loads((repo/'docs/LINUX_X86_PROC_EXPOSURE_003_RESULT.json').read_text())['files'].items():assert sha(path)==metadata['sha256']
cleanup3=json.loads((repo/'docs/LINUX_X86_PROC_EXPOSURE_003_KEY_CLEANUP.json').read_text());assert cleanup3['absence_verified'] and not os.path.lexists(cleanup3['path'])
root.mkdir(mode=0o750);os.chown(root,0,gid);root.chmod(0o750)
inputs=root/'inputs';inputs.mkdir(mode=0o750);os.chown(inputs,0,gid);inputs.chmod(0o750)
work=root/'work';work.mkdir(mode=0o700);os.chown(work,uid,gid)
for name in ['home','tmp','evidence']:
 p=work/name;p.mkdir(mode=0o700);os.chown(p,uid,gid)
source_image=Path('/var/lib/tempest-izanagi-full-build-003/work/output-debian/debian-x86_64.qcow2')
assert sha(source_image)=='5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7e'
shutil.copyfile(source_image,inputs/'image.qcow2')
cli=Path('/tmp/tempest-izanagi-bootstrap-host-target/release/izanagi');assert sha(cli)=='088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8';shutil.copyfile(cli,inputs/'izanagi');os.chmod(inputs/'izanagi',0o550)
shutil.copyfile('/var/lib/tempest-izanagi-full-build-003/inputs/definition/inputs.json',inputs/'build-inputs.json')
for name in ['integration/image_smoke.py','integration/image_smoke_observe.py','integration/izanagi-bootstrap/observe.py','image/transport.py','image/trace_evidence.py','image/artifact_evidence.py','image/exec_evidence.py','image/proc_evidence.py','image/proc_paging.py','image/sidecar_probe.py','image/sidecar_evidence.py','tools/m0/izanagi.example.toml']:
 src=repo/name;assert src.is_file() and not src.is_symlink();dest=inputs/'repo'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
offline=repo/'docs/evidence/image-offline-001/report.json'
assert sha(offline)==sha('/var/lib/tempest-izanagi-image-offline-001/work/report.json')
shutil.copyfile(offline,inputs/'offline-artifacts.json')
for previous in ['/var/lib/tempest-izanagi-image-smoke-002','/var/lib/tempest-izanagi-runtime-normal-001']:
 for row in json.loads((Path(previous)/'snapshot.json').read_text())['files']:
  if row['type']=='file':assert sha(row['path'])==row['sha256']
  else:assert os.readlink(row['path'])==row['target']
presence=Path('/var/lib/tempest-izanagi-runtime-presence-001')
for row in json.loads((presence/'snapshot-v2.json').read_text())['files']:
 if row['type']=='file':assert sha(row['path'])==row['sha256']
 else:assert os.readlink(row['path'])==row['target']
for document in ['LINUX_X86_RUNTIME_PRESENCE_001_RESULT.json','LINUX_X86_RUNTIME_NORMAL_001_RESULT.json','LINUX_X86_RUNTIME_RESERVATION_001_RESULT.json']:
 for path,metadata in json.loads((repo/'docs'/document).read_text())['files'].items():assert sha(path)==metadata['sha256']
import importlib.util
reservation=Path('/var/lib/tempest-izanagi-runtime-reservation-001')
spec=importlib.util.spec_from_file_location('tree',reservation/'inputs/tree_manifest.py');tree=importlib.util.module_from_spec(spec);spec.loader.exec_module(tree)
assert tree.inventory('/var/lib/tempest-izanagi-runtime-seed-loss-001')==json.loads((reservation/'baseline.private.json').read_text())
previous=Path('/var/lib/tempest-izanagi-exec-exposure-001')
for row in json.loads((previous/'snapshot.json').read_text())['files']:
 if row['type']=='file':assert sha(row['path'])==row['sha256']
 else:assert os.readlink(row['path'])==row['target']
for path,metadata in json.loads((repo/'docs/LINUX_X86_EXEC_EXPOSURE_001_RESULT.json').read_text())['files'].items():assert sha(path)==metadata['sha256']
cleanup=json.loads((repo/'docs/LINUX_X86_EXEC_EXPOSURE_001_KEY_CLEANUP.json').read_text());assert cleanup['absence_verified'] and not os.path.lexists(cleanup['path'])
recorder=(repo/'integration/izanagi-bootstrap/record_exit.py').read_text().replace('tempest-izanagi-bootstrap-boot-002.service','tempest-izanagi-sidecar-001.service').replace('/run/tempest-izanagi-bootstrap-002/evidence/exit-status.json',str(work/'evidence/exit-status.json'))
(inputs/'record_exit.py').write_text(recorder)
wheelmeta=json.loads((repo/'docs/LINUX_X86_PYTHON_WHEELS.json').read_text());wh=inputs/'wheelhouse';wh.mkdir()
for row in wheelmeta['wheels']:
 src=Path('/tmp/tempest-x86-full-python-002/wheelhouse')/row['filename'];assert not src.is_symlink() and sha(src)==row['sha256'];shutil.copyfile(src,wh/src.name)
shutil.copyfile(repo/'docs/locks/python-x86-full-002.txt',inputs/'requirements.lock')
env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','PIP_CONFIG_FILE':'/dev/null','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
with (root/'venv-install.log').open('xb') as log:
 subprocess.run(['/usr/bin/python3','-I','-B','-m','venv',str(inputs/'python')],env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
 subprocess.run([str(inputs/'python/bin/python'),'-I','-B','-m','pip','--disable-pip-version-check','--no-cache-dir','install','--no-index','--find-links',str(wh),'--only-binary=:all:','--require-hashes','--requirement',str(inputs/'requirements.lock')],env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
os.chmod(root/'venv-install.log',0o600)
rows=[];directories=[]
for p in sorted(inputs.rglob('*')):
 if p.is_symlink():
  resolved=p.resolve();assert resolved.is_relative_to(inputs) or resolved==Path('/usr/bin/python3.12'),str(p)
  os.lchown(p,0,gid);rows.append({'path':str(p),'type':'symlink','target':os.readlink(p),'owner':'root:tempest-kvm'});continue
 os.chown(p,0,gid)
 if p.is_dir():os.chmod(p,0o750);directories.append(str(p));continue
 executable=bool(p.stat().st_mode&0o111);os.chmod(p,0o550 if executable else 0o440)
 rows.append({'path':str(p),'type':'file','sha256':sha(p),'mode':format(stat.S_IMODE(p.stat().st_mode),'04o'),'owner':'root:tempest-kvm'})
assert sha(inputs/'image.qcow2')==sha(source_image)
external={}
for name in ['/usr/bin/python3.12','/usr/bin/qemu-system-x86_64','/usr/bin/qemu-img','/usr/bin/tcpdump','/usr/bin/ss','/usr/bin/systemctl','/lib64/ld-linux-x86-64.so.2','/lib/x86_64-linux-gnu/libc.so.6','/lib/x86_64-linux-gnu/libgcc_s.so.1']:
 external[name]=sha(name)
meta={'schema_version':1,'source_commit':subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip(),'unit':'tempest-izanagi-sidecar-001.service','root':str(root),'files':rows,'directories_mode0750_root_group':directories,'external_runtime_sha256':external,'wheel_versions_hashes':wheelmeta['wheels'],'input_rows_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'old_build_inputs_and_evidence_unchanged':True,'vm_boot_executed':False,'dummy_transport_key':'not created; fresh per-run key generated inside image_smoke.py output'}
(root/'snapshot.json').write_text(json.dumps(meta,indent=2)+'\n');os.chown(root/'snapshot.json',0,gid);os.chmod(root/'snapshot.json',0o440)
Path('/tmp/tempest-sidecar-snapshot-001.json').write_text(json.dumps(meta,indent=2)+'\n')
print('snapshot_created files',len(rows),'directories',len(directories),'input_tree',meta['input_rows_sha256'])
