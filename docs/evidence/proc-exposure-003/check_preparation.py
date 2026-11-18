from pathlib import Path
import os,json,hashlib,stat,subprocess
assert os.getuid()==999
root=Path('/var/lib/tempest-izanagi-proc-exposure-003');inputs=root/'inputs'
meta=json.loads((root/'snapshot.json').read_bytes())
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
for row in meta['files']:
 p=Path(row['path']);s=p.lstat();assert s.st_uid==0 and s.st_gid==988
 assert os.access(p,os.R_OK) and not os.access(p,os.W_OK)
 if row['type']=='file':assert stat.S_IMODE(s.st_mode)==int(row['mode'],8) and sha(p)==row['sha256']
 else:assert p.is_symlink() and os.readlink(p)==row['target']
for path in meta['directories_mode0750_root_group']:
 p=Path(path);s=p.stat();assert (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(0,988,0o750)
for path,digest in meta['external_runtime_sha256'].items():assert sha(path)==digest
for name in ['home','tmp','evidence']:
 s=(root/'work'/name).stat();assert (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(999,988,0o700)
assert not os.path.lexists(root/'work/output') and not os.path.lexists(root/'work/evidence/exit-status.json')
assert not os.path.lexists('/tmp/tempest-proc-exposure-003.log') and not os.path.lexists('/tmp/tempest-proc-exposure-observation-003.jsonl')
code="import sys,json,cryptography,cffi,pycparser;from cryptography.hazmat.primitives.ciphers.aead import AESGCM;a=AESGCM(bytes(32));assert a.decrypt(bytes(12),a.encrypt(bytes(12),b'dummy',None),None)==b'dummy';assert sys.prefix=="+repr(str(inputs/'python'))+";print(json.dumps({'prefix':sys.prefix,'cryptography':cryptography.__version__,'cffi':cffi.__version__,'pycparser':pycparser.__version__}))"
env={'PATH':'/usr/bin:/bin','TZ':'UTC','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','HOME':str(root/'work/home'),'TMPDIR':str(root/'work/tmp')}
r=subprocess.run([str(inputs/'python/bin/python'),'-I','-B','-c',code],env=env,capture_output=True,text=True,check=True)
versions=json.loads(r.stdout);assert versions['cryptography']=='50.0.2' and versions['cffi']=='2.1.1' and versions['pycparser']=='3.12'
subprocess.run([str(inputs/'python/bin/python'),'-I','-B',str(inputs/'repo/integration/image_smoke.py'),'--help'],env=env,stdout=subprocess.DEVNULL,check=True)
p=root/'work/xattr-preflight';fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
try:
 os.setxattr(p,'user.virtfs.uid',b'\xe8\x03\x00\x00');assert os.getxattr(p,'user.virtfs.uid')==b'\xe8\x03\x00\x00'
finally:p.unlink()
print(json.dumps({'input_files_checked':len(meta['files']),'input_rows_sha256':meta['input_rows_sha256'],'versions':versions,'all_inputs_readable_nonwritable':True,'runtime_hashes_match':True,'work_private':True,'xattr_roundtrip':True,'output_absent':True,'vm_boot_executed':False},indent=2))
