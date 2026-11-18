from pathlib import Path
import os,stat,hashlib,json,shutil,subprocess,pwd,grp
assert os.geteuid()==0
root=Path('/var/lib/tempest-izanagi-runtime-normal-001');assert not os.path.lexists(root)
uid=pwd.getpwnam('tempest-kvm').pw_uid;gid=grp.getgrnam('tempest-kvm').gr_gid;assert (uid,gid)==(999,988)
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while b:=f.read(1048576):h.update(b)
 return h.hexdigest()
repo=Path('/home/ubuntu/izanagi-tempest')
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
root.mkdir(mode=0o750);os.chown(root,0,gid)
inputs=root/'inputs';inputs.mkdir(mode=0o750);os.chown(inputs,0,gid)
work=root/'work';work.mkdir(mode=0o700);os.chown(work,uid,gid)
for name in ['home','tmp','evidence']:
 p=work/name;p.mkdir(mode=0o700);os.chown(p,uid,gid)
source_image=Path('/var/lib/tempest-izanagi-full-build-003/work/output-debian/debian-x86_64.qcow2')
assert sha(source_image)=='5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7e'
shutil.copyfile(source_image,inputs/'image.qcow2')
cli=Path('/tmp/tempest-izanagi-bootstrap-host-target/release/izanagi');assert sha(cli)=='088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8';shutil.copyfile(cli,inputs/'izanagi');os.chmod(inputs/'izanagi',0o550)
shutil.copyfile('/var/lib/tempest-izanagi-full-build-003/inputs/definition/inputs.json',inputs/'build-inputs.json')
for name in ['integration/runtime_smoke.py','integration/runtime_normal_observe.py','integration/izanagi-bootstrap/observe.py','image/transport.py','image/host_bridge.py','scenarios/s3-overread-001.yaml','integration/mock-s3-overread-reset.json']:
 src=repo/name;assert src.is_file() and not src.is_symlink();dest=inputs/'repo'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
host_build=json.loads((repo/'docs/LINUX_X86_HOST_CLI_001_RESULT.json').read_text())
assert host_build['exit_code']==0
for name,digest in host_build['source_files_sha256'].items():
 if name.startswith('crates/') or name in ('Cargo.toml','Cargo.lock','tools/m0/izanagi.example.toml'):
  assert sha(repo/name)==digest,'host build source changed: '+name
host=Path(host_build['binary']['path']);assert sha(host)==host_build['binary']['sha256']
shutil.copyfile(host,inputs/'tempest');os.chmod(inputs/'tempest',0o550)
shutil.copyfile(repo/'docs/evidence/runtime-normal-001/run_normal.py',inputs/'run_normal.py')
old2=json.loads(Path('/var/lib/tempest-izanagi-image-smoke-002/snapshot.json').read_text())
for row in old2['files']:
 if row['type']=='file':assert sha(row['path'])==row['sha256']
 else:assert os.readlink(row['path'])==row['target']
recorder=(repo/'integration/izanagi-bootstrap/record_exit.py').read_text().replace('tempest-izanagi-bootstrap-boot-002.service','tempest-izanagi-runtime-normal-001.service').replace('/run/tempest-izanagi-bootstrap-002/evidence/exit-status.json',str(work/'evidence/exit-status.json'))
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
meta={'schema_version':1,'source_commit':subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip(),'unit':'tempest-izanagi-runtime-normal-001.service','root':str(root),'files':rows,'directories_mode0750_root_group':directories,'external_runtime_sha256':external,'wheel_versions_hashes':wheelmeta['wheels'],'input_rows_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'old_build_inputs_and_evidence_unchanged':True,'vm_boot_executed':False,'dummy_transport_key':'not created; runtime generates separate fresh per-stage dummy keys'}
(root/'snapshot.json').write_text(json.dumps(meta,indent=2)+'\n');os.chown(root/'snapshot.json',0,gid);os.chmod(root/'snapshot.json',0o440)
Path('/tmp/tempest-runtime-normal-snapshot-001.json').write_text(json.dumps(meta,indent=2)+'\n')
print('snapshot_created files',len(rows),'directories',len(directories),'input_tree',meta['input_rows_sha256'])
