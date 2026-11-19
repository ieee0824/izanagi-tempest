from pathlib import Path
import os,subprocess,json,hashlib,shutil,time,tarfile,io,signal
os.umask(0o077)
root=Path('/tmp/tempest-host-cli-build-002-v2');assert not (root/'started.json').exists() and not (root/'target').exists();assert shutil.disk_usage(root.parent).free >= 8*1024**3;root.mkdir(exist_ok=True);(root/'home').mkdir(exist_ok=True);source=root/'source';source.mkdir(exist_ok=True)
repo='/home/ubuntu/izanagi-tempest';tool='/home/ubuntu/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin'
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
rev=subprocess.check_output(['git','-C',repo,'rev-parse','fa3f1d9^{commit}'],text=True).strip();assert rev == subprocess.check_output(['git','-C',repo,'rev-parse','origin/pr-66'],text=True).strip()
archive=subprocess.check_output(['git','-C',repo,'archive','--format=tar',rev])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(source,filter='data')
files={str(p.relative_to(source)):sha(p) for p in sorted(source.rglob('*')) if p.is_file()}
lock=source/'Cargo.lock';lock_before=sha(lock)
old=json.loads(Path('/tmp/tempest-host-cli-build-001/result.json').read_text())
assert lock_before == hashlib.sha256(subprocess.check_output(['git','-C',repo,'show',rev+':Cargo.lock'])).hexdigest()
for name,digest in old['tool_sha256'].items():assert sha(tool+'/'+name)==digest
for name,version in old['tool_versions'].items():assert subprocess.check_output([tool+'/'+name,'--version'],text=True).strip()==version
old_paths={old['binary']['path']:old['binary']['sha256']}
for document in ['LINUX_X86_DELIVERY_RACE_LARGE_001_RESULT.json','LINUX_X86_DELIVERY_RACE_COMPLETED_001_RESULT.json']:
 for path,metadata in json.loads((Path(repo)/'docs'/document).read_text())['files'].items():old_paths[path]=metadata['sha256']
for path,digest in old_paths.items():assert subprocess.check_output(['sudo','-n','sha256sum',path],text=True).split()[0]==digest

env={'HOME':str(root/'home'),'CARGO_HOME':'/tmp/tempest-x86-userspace-001/cargo','PATH':tool+':/usr/bin:/bin','RUSTC':tool+'/rustc','CARGO_BUILD_JOBS':'2','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
cmd=[tool+'/cargo','build','--manifest-path',str(source/'Cargo.toml'),'--release','--locked','--offline','-p','tempest','--target','x86_64-unknown-linux-gnu','--jobs','2','--target-dir',str(root/'target')]
r={'source_revision':rev,'source_git_tree':subprocess.check_output(['git','-C',repo,'rev-parse',rev+'^{tree}'],text=True).strip(),'source_files_sha256':files,'source_rows_sha256':hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'tool_sha256':{name:sha(tool+'/'+name) for name in ['cargo','rustc']},'tool_versions':{name:subprocess.check_output([tool+'/'+name,'--version'],text=True).strip() for name in ['cargo','rustc']},'argv':cmd,'env':env,'lock_before':lock_before,'started':time.time(),'free_before':shutil.disk_usage(root).free,'vm_executed':False,'old_evidence_sha256':old_paths,'target_budget_bytes_planned':3*1024**3}
(root/'started.json').write_text(json.dumps(r,indent=2)+'\n')
with (root/'build.log').open('xb') as log:
 p=subprocess.Popen(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 try:r['exit_code']=p.wait(timeout=1800)
 except subprocess.TimeoutExpired:
  os.killpg(p.pid,signal.SIGTERM)
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
  r['exit_code']=124
r.update(finished=time.time(),lock_after=sha(lock),free_after=shutil.disk_usage(root).free)
assert r['lock_after']==lock_before
assert all(subprocess.check_output(['sudo','-n','sha256sum',path],text=True).split()[0]==digest for path,digest in old_paths.items())
assert all(sha(source/name)==value for name,value in files.items())
if r['exit_code']==0:
 binary=root/'target/x86_64-unknown-linux-gnu/release/tempest';r['binary']={'path':str(binary),'sha256':sha(binary),'bytes':binary.stat().st_size}
 for name,args in [('elf',['/usr/bin/readelf','--file-header','--program-headers','--dynamic',str(binary)]),('ldd',['/usr/bin/ldd',str(binary)])]:
  o=subprocess.run(args,capture_output=True,text=True,check=True);(root/(name+'.txt')).write_text(o.stdout);r[name]=o.stdout
(root/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'exit_code':r['exit_code'],'binary':r.get('binary')}));raise SystemExit(r['exit_code'])
