from pathlib import Path
import os,json,hashlib
os.umask(0o077)
assert os.getuid()==999
work=Path('/var/lib/tempest-izanagi-image-offline-001/work');raw=work/'disk.raw'
table=json.loads((work/'partition-table.json').read_text())['partitiontable']
assert table['unit']=='sectors' and table['sectorsize']==512
length=raw.stat().st_size;assert length==4294967296
candidates=[]
with raw.open('rb') as source:
 for part in table['partitions']:
  start=part['start']*512;size=part['size']*512
  assert type(start)is int and type(size)is int and start>=0 and size>0 and start+size<=length
  source.seek(start+1024+56)
  if source.read(2)==b'\x53\xef':candidates.append({'start_sector':part['start'],'sectors':part['size'],'byte_offset':start,'bytes':size})
 assert len(candidates)==1,'root filesystem candidate ambiguous or unsupported'
 selected=candidates[0];source.seek(selected['byte_offset']);remaining=selected['bytes'];h=hashlib.sha256()
 target=work/'root.partition';fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as output:
  while remaining:
   chunk=source.read(min(16*1024*1024,remaining));assert chunk,'unexpected EOF'
   assert output.write(chunk)==len(chunk);h.update(chunk);remaining-=len(chunk)
  output.flush();os.fsync(output.fileno())
 assert target.stat().st_size==selected['bytes']
 selected.update(sha256=h.hexdigest(),ext4_magic='53ef',image_virtual_bytes=length)
(work/'partition-selection.json').write_text(json.dumps(selected,indent=2)+'\n')
print(json.dumps(selected))
