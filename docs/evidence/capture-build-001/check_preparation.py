"""Dedicated UID fixed-input/full-validate check; never starts a build."""
from pathlib import Path
import hashlib,json,os,stat,subprocess
ROOT=Path('/var/lib/tempest-izanagi-capture-build-001')
assert os.getuid()==999
meta=json.loads((ROOT/'snapshot.json').read_text())
for row in meta['files']:
 path=Path(row['path']);s=path.lstat()
 assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(0,988,int(row['mode'],8))
 assert os.access(path,os.R_OK) and not os.access(path,os.W_OK)
 with path.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==row['sha256']
for name,digest in meta['external_runtime_sha256'].items():
 with Path(name).open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==digest
for name in meta['directories']:
 s=Path(name).stat();assert (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(0,988,0o750)
for name in ('home','tmp','cache','evidence'):
 s=(ROOT/'work'/name).stat();assert (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(999,988,0o700)
for name in ('output-debian','packer-debug.log','installer-serial.log','evidence/exit-status.json'):
 assert not os.path.lexists(ROOT/'work'/name)
assert not os.path.lexists('/tmp/tempest-capture-build-001.log')
env={'PATH':'/usr/bin:/bin','HOME':str(ROOT/'work/home'),'TMPDIR':str(ROOT/'work/tmp'),'PACKER_CACHE_DIR':str(ROOT/'work/cache'),'PACKER_PLUGIN_PATH':str(ROOT/'inputs/plugins'),'CHECKPOINT_DISABLE':'1'}
argv=[str(ROOT/'inputs/packer'),'validate','-var-file='+str(ROOT/'inputs/definition/packer/tempest.pkrvars.json'),str(ROOT/'inputs/definition/packer/debian.pkr.hcl')]
result=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=60)
assert result.returncode==0
print(json.dumps({'input_files_checked':len(meta['files']),'input_rows_sha256':meta['input_rows_sha256'],'all_inputs_readable_nonwritable':True,'argv':argv,'env':env,'uid':os.getuid(),'full_validate_exit':result.returncode,'build_executed':False,'vm_executed':False},indent=2))
