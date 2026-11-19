from pathlib import Path
import os,json,hashlib,subprocess,stat,re
os.umask(0o077);assert os.getuid()==999
root=Path('/var/lib/tempest-izanagi-image-offline-001');work=root/'work';partition=work/'root.partition'
def sha(path):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
plan=json.loads((root/'plan.json').read_text());before=sha(plan['source_image']);assert before==plan['expected_sha256']
t=json.loads((work/'partition-table.json').read_text())['partitiontable'];assert t['label']=='dos' and t['sectorsize']==512
raw_bytes=(work/'disk.raw').stat().st_size;parts=t['partitions'];assert len({p['node'] for p in parts})==len(parts)
containers=[p for p in parts if p['type'].lower() in ('5','05','f','0f','85')];data=[p for p in parts if p not in containers]
for p in parts:assert p['start']>=0 and p['size']>0 and (p['start']+p['size'])*512<=raw_bytes
spans=sorted((p['start'],p['start']+p['size']) for p in data)
assert all(a[1]<=b[0] for a,b in zip(spans,spans[1:]))
for p in data:
 assert p['node'].startswith(t['device']);number=int(p['node'][len(t['device']):])
 if number>4:assert sum(c['start']<=p['start'] and p['start']+p['size']<=c['start']+c['size'] for c in containers)==1
selection=json.loads((work/'partition-selection.json').read_text());assert sha(partition)==selection['sha256']
inputs=json.loads(Path('/var/lib/tempest-izanagi-image-smoke-001-v2/inputs/build-inputs.json').read_text())
paths={'agent':'/usr/local/bin/izanagi-agent','http':'/usr/local/bin/izanagi-http-capture','ebpf':'/opt/izanagi/izanagi-ebpf.o','image_metadata':'/etc/tempest/image.json'}
for name in paths:assert not os.path.lexists(work/'artifacts'/name) and not os.path.lexists(work/(name+'.stat.txt'))
results={};commands=[]
for name,guest in paths.items():
 cmd=['/usr/sbin/debugfs','-R','stat '+guest,str(partition)];commands.append(cmd)
 r=subprocess.run(cmd,capture_output=True,text=True,check=True,timeout=30);(work/(name+'.stat.txt')).write_text(r.stdout);(work/(name+'.stat.stderr')).write_text(r.stderr)
 kind=re.search(r'Type:\s*(\w+)',r.stdout);mode=re.search(r'Mode:\s*([0-7]+)',r.stdout);uid=re.search(r'User:\s*(\d+)',r.stdout);gid=re.search(r'Group:\s*(\d+)',r.stdout);size=re.search(r'\bSize:\s*(\d+)',r.stdout)
 assert kind and kind[1]=='regular' and mode and uid and gid and size and 0<int(size[1])<128*1024*1024
 dest=work/'artifacts'/name;cmd=['/usr/sbin/debugfs','-R','dump '+guest+' '+str(dest),str(partition)];commands.append(cmd)
 dumped=subprocess.run(cmd,capture_output=True,text=True,check=True,timeout=30);(work/(name+'.dump.log')).write_text(dumped.stdout+dumped.stderr)
 s=dest.lstat();assert stat.S_ISREG(s.st_mode) and not s.st_mode&0o111 and s.st_size==int(size[1])
 observed={'guest_path':guest,'guest_mode':mode[1],'guest_uid':int(uid[1]),'guest_gid':int(gid[1]),'bytes':s.st_size,'sha256':sha(dest),'extracted_path':str(dest),'host_mode':format(stat.S_IMODE(s.st_mode),'04o')}
 if name!='image_metadata':
  assert observed['sha256']==inputs['input_sha256'][name],name+' installed hash mismatch'
  with dest.open('rb') as f:header=f.read(20)
  assert header[:6]==b'\x7fELF\x02\x01';machine=int.from_bytes(header[18:20],'little');assert machine==(247 if name=='ebpf' else 62);observed['elf_machine']=machine
  elf=subprocess.run(['/usr/bin/readelf','--file-header',str(dest)],capture_output=True,text=True,check=True,timeout=30);(work/(name+'.elf.txt')).write_text(elf.stdout)
 results[name]=observed
metadata=json.loads((work/'artifacts/image_metadata').read_text());live=json.loads(Path('/var/lib/tempest-izanagi-image-smoke-001-v2/work/output/summary.json').read_text())['checks']['image_manifest']['stdout'];assert metadata==json.loads(live)
after=sha(plan['source_image']);assert after==before and sha(partition)==selection['sha256']
report={'schema_version':1,'source_image':plan['source_image'],'source_image_sha256_before':before,'source_image_sha256_after':after,'raw_disk':{'path':str(work/'disk.raw'),'bytes':raw_bytes,'sha256':sha(work/'disk.raw')},'partition':selection,'data_partitions_nonoverlapping':True,'extended_logical_containment_verified':True,'debugfs_write_flag_used':False,'commands':commands,'artifacts':results,'offline_metadata_matches_guest_read':True,'guest_runtime_hashes_attested':False,'vm_boot_executed_for_inspection':False,'extracted_files_executed':False}
(work/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'artifacts':results,'source_image_unchanged':True,'metadata_matches_guest':True},indent=2))
