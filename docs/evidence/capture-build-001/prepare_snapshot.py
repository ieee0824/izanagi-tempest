"""Prepare reviewed fixture build inputs only; never invokes Packer or a VM."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-capture-build-001')
PARENT = Path('/var/lib/tempest-izanagi-full-build-003')
DEFINITION = Path('/tmp/tempest-capture-definition-001')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    assert os.geteuid() == 0
    os.umask(0o077)
    assert not os.path.lexists(ROOT)
    assert shutil.disk_usage('/var/lib').free >= 20*1024**3
    assert not subprocess.run(['ps','-u','999','-o','pid='],capture_output=True,text=True).stdout.strip()
    unit = subprocess.check_output(['systemctl','show','tempest-izanagi-capture-build-001.service','-p','LoadState','-p','ActiveState','-p','InvocationID'],text=True)
    assert dict(line.split('=',1) for line in unit.splitlines()) == {'LoadState':'not-found','ActiveState':'inactive','InvocationID':''}
    for number in ('001','002','003'):
        for row in json.loads((REPO / ('docs/LINUX_X86_FULL_SNAPSHOT_'+number+'.json')).read_text()):
            assert sha(row['path']) == row['sha256']
        for path, value in json.loads((REPO / ('docs/LINUX_X86_FULL_BUILD_'+number+'_RESULT.json')).read_text())['files'].items():
            assert sha(path) == value['sha256']
    report = json.loads((REPO / 'docs/LINUX_X86_CAPTURE_DEFINITION_001.json').read_text())
    for row in report['files']:
        path = Path(row['path']);metadata = path.lstat()
        assert path.is_relative_to(DEFINITION) and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        assert (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode)) == (0,988,0o440)
        assert sha(path) == row['sha256']
    assert len(report['files']) == 16
    expected = {row['relative'] for row in report['files']}
    assert {str(p.relative_to(DEFINITION)) for p in DEFINITION.rglob('*') if p.is_file()} == expected
    old_inputs = json.loads((DEFINITION/'inputs.json').read_text())
    image = json.loads((DEFINITION/'packer/image.json').read_text())
    binding = json.loads((REPO/'docs/LINUX_X86_CAPTURE_COMPILE_BINDING_001.json').read_text())
    for key,value in binding['parent_compile'].items():
        assert old_inputs[key] == image[key] == value
    assert old_inputs['delivery_race_fixture'] is True and image['delivery_race_fixture'] is True
    for name,digest in old_inputs['input_sha256'].items():
        assert sha(Path(old_inputs['inputs'][name])) == digest
    assert sha(PARENT/'inputs/base.iso') == old_inputs['iso_sha256']
    for name in ('dispatcher.py','quiesce.py'):
        assert sha(DEFINITION/'packer'/name) == old_inputs['derivation_sha256'][name] == image['derivation_sha256'][name]
    # Reuse the existing read-only snapshot verifier without invoking old collectors.
    spec=importlib.util.spec_from_file_location('old_snapshot',REPO/'docs/evidence/runtime-normal-001/collect_result.py')
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    for attempt in ('host-endpoint-001','sidecar-001','proc-exposure-001','proc-exposure-002','proc-exposure-003','exec-exposure-001','runtime-normal-001','image-smoke-001','image-smoke-001-v2','image-smoke-002'):
        base.verify_snapshot(Path('/var/lib/tempest-izanagi-'+attempt))
    for document in ('HOST_ENDPOINT_001','SIDECAR_001','PROC_EXPOSURE_001','PROC_EXPOSURE_002','PROC_EXPOSURE_003','EXEC_EXPOSURE_001','RUNTIME_NORMAL_001','RUNTIME_PRESENCE_001','RUNTIME_RESERVATION_001'):
        for path,value in json.loads((REPO/('docs/LINUX_X86_'+document+'_RESULT.json')).read_text())['files'].items():
            assert sha(path) == value['sha256']
    reservation=Path('/var/lib/tempest-izanagi-runtime-reservation-001')
    spec=importlib.util.spec_from_file_location('tree',reservation/'inputs/tree_manifest.py');tree=importlib.util.module_from_spec(spec);spec.loader.exec_module(tree)
    assert tree.inventory('/var/lib/tempest-izanagi-runtime-seed-loss-001') == json.loads((reservation/'baseline.private.json').read_text())
    for attempt in ('host-endpoint-001','sidecar-001','proc-exposure-001','proc-exposure-002','proc-exposure-003','exec-exposure-001'):
        assert not os.path.lexists('/var/lib/tempest-izanagi-'+attempt+'/work/output/izanagi-hmac')
    for row in json.loads(Path('/var/lib/tempest-izanagi-runtime-presence-001/snapshot-v2.json').read_text())['files']:
        if row['type']=='file':assert sha(row['path']) == row['sha256']
        else:assert os.readlink(row['path']) == row['target']
    kvm=Path('/dev/kvm').stat()
    assert stat.S_ISCHR(kvm.st_mode) and (kvm.st_uid,kvm.st_gid,stat.S_IMODE(kvm.st_mode)) == (0,993,0o660)
    # Source bytes must match the separately reviewed observer/builder scripts.
    source_hashes = json.loads((REPO/'docs/LINUX_X86_CAPTURE_BUILD_SOURCE_001.json').read_text())
    for name,digest in source_hashes.items():assert sha(REPO/name) == digest
    # Preserve content while accepting only the explicitly recorded physical identity exception.
    hardlink = json.loads((REPO/'docs/LINUX_X86_IMAGE_HARDLINK_001_RESULT.json').read_text())
    assert hardlink['exit_code'] == 0 and len(hardlink['replaced_paths']) == 7
    for row in hardlink['after']:
        path=Path(row['path']);metadata=path.lstat()
        assert (metadata.st_dev,metadata.st_ino,metadata.st_nlink)==(row['file']['device'],row['file']['inode'],8)
    for path,metadata in json.loads((REPO/'docs/LINUX_X86_DELIVERY_RACE_LARGE_001_RESULT.json').read_text())['files'].items():
        assert sha(path)==metadata['sha256']
    ROOT.mkdir(mode=0o750);ROOT.chmod(0o750);os.chown(ROOT,0,988)
    inputs=ROOT/'inputs';inputs.mkdir(mode=0o750);inputs.chmod(0o750);os.chown(inputs,0,988)
    work=ROOT/'work';work.mkdir(mode=0o700);os.chown(work,999,988)
    for name in ('home','tmp','cache','evidence'):
        path=work/name;path.mkdir(mode=0o700);os.chown(path,999,988)
    for name in ('base.iso','agent','ebpf','http','lws','guest','packer'):
        shutil.copyfile(Path(old_inputs['inputs']['guest']) if name == 'guest' else PARENT/'inputs'/name,inputs/name)
    shutil.copytree(PARENT/'inputs/plugins',inputs/'plugins')
    shutil.copytree(DEFINITION,inputs/'definition')
    old_prefix=str(PARENT/'inputs')+'/'
    new_prefix=str(inputs)+'/'
    template=inputs/'definition/packer/debian.pkr.hcl'
    text=template.read_text();assert text.count(old_prefix)==2
    old_guest=old_inputs['inputs']['guest'];assert text.count(old_guest)==1
    template.chmod(0o600);template.write_text(text.replace(old_prefix,new_prefix).replace(old_guest,new_prefix+'guest'))
    variables=inputs/'definition/packer/tempest.pkrvars.json'
    data=json.loads(variables.read_text());assert data == {name+'_binary':old_prefix+name for name in ('agent','ebpf','http')}
    variables.chmod(0o600);variables.write_text(json.dumps({key:value.replace(old_prefix,new_prefix) for key,value in data.items()},indent=2)+'\n')
    manifest={**old_inputs,'inputs':{name:new_prefix+name for name in ('agent','ebpf','http','lws','guest')},'template_sha256':sha(template),'source_manifest_sha256':sha(DEFINITION/'inputs.json')}
    path=inputs/'definition/inputs.json';path.chmod(0o600);path.write_text(json.dumps(manifest,indent=2)+'\n')
    for name in ('integration/capture_build_observe.py','integration/izanagi-bootstrap/observe.py'):
        path=inputs/'repo'/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(REPO/name,path)
    recorder=(REPO/'integration/izanagi-bootstrap/record_exit.py').read_text().replace('tempest-izanagi-bootstrap-boot-002.service','tempest-izanagi-capture-build-001.service').replace('/run/tempest-izanagi-bootstrap-002/evidence/exit-status.json',str(work/'evidence/exit-status.json'))
    (inputs/'record_exit.py').write_text(recorder)
    provenance={'parent_inputs_sha256':sha(PARENT/'inputs/definition/inputs.json'),'parent_image_metadata_sha256':sha(PARENT/'inputs/definition/packer/image.json'),'standard_prepare_inputs_sha256':sha(DEFINITION/'inputs.json'),'standard_prepare_image_metadata_sha256':sha(DEFINITION/'packer/image.json'),'snapshot_guest_metadata_unchanged':sha(inputs/'definition/packer/image.json')==sha(DEFINITION/'packer/image.json'),'parent_compile_source_preserved':binding['parent_compile'],'source_hashes':source_hashes,'allowed_path_replacement':{'from':old_prefix,'to':new_prefix},'hardlink_exception_report_sha256':sha(REPO/'docs/LINUX_X86_IMAGE_HARDLINK_001_RESULT.json'),'guest_build_report_sha256':sha(REPO/'docs/LINUX_X86_CAPTURE_GUEST_BUILD_001_RESULT.json'),'guest_path_replacement':{'from':old_guest,'to':new_prefix+'guest'},'build_executed':False}
    (inputs/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    rows=[];directories=[]
    for path in sorted(inputs.rglob('*')):
        assert not path.is_symlink()
        os.chown(path,0,988)
        if path.is_dir():path.chmod(0o750);directories.append(str(path));continue
        executable = path == inputs/'packer' or path.name.startswith('packer-plugin-qemu_') and not path.name.endswith('SHA256SUM')
        path.chmod(0o550 if executable else 0o440)
        rows.append({'path':str(path),'sha256':sha(path),'bytes':path.stat().st_size,'uid':0,'gid':988,'mode':format(stat.S_IMODE(path.stat().st_mode),'04o')})
    assert shutil.disk_usage(ROOT).free >= 18*1024**3
    external={name:sha(name) for name in ('/usr/bin/python3.12','/usr/bin/qemu-system-x86_64','/usr/bin/qemu-img','/usr/bin/systemctl','/usr/bin/ss','/lib64/ld-linux-x86-64.so.2','/lib/x86_64-linux-gnu/libc.so.6')}
    snapshot={'external_runtime_sha256':external,'schema_version':1,'root':str(ROOT),'unit':'tempest-izanagi-capture-build-001.service','source_commit':subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),'files':rows,'directories':directories,'input_rows_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'provenance':provenance,'build_executed':False}
    (ROOT/'snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n');os.chown(ROOT/'snapshot.json',0,988);(ROOT/'snapshot.json').chmod(0o440)
    Path('/tmp/tempest-capture-build-snapshot-001.json').write_text(json.dumps(snapshot,indent=2)+'\n')
    print('build input snapshot only:',len(rows),snapshot['input_rows_sha256'])


if __name__ == '__main__':
    main()
