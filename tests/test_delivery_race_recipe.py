import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('race_recipe', ROOT / 'docs/evidence/delivery-race-build-001/derive.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def fixture():
    metadata = {'delivery_race_fixture': False, 'tempest_guest_source_commit':'parent-compile',
                'tempest_guest_source_tree_sha256':'parent-tree', 'tempest_guest_source_dirty':False,
                'input_sha256':{'guest':'guest-binary-hash'}, 'derivation_sha256':dict(R.PARENT_SCRIPTS)}
    image=R.encoded(metadata)
    metadata['inputs']={name:R.PARENT+'/'+name for name in ('agent','ebpf','guest','http','lws')}
    template=('path='+R.PARENT+'/base.iso\npath='+R.PARENT+'/agent\npath='+R.PARENT+'/http\n').encode()
    return {'inputs.json':R.encoded(metadata),'packer/image.json':image,
            'packer/dispatcher.py':(ROOT/'image/dispatcher.py').read_bytes(),
            'packer/quiesce.py':(ROOT/'image/quiesce.py').read_bytes(),
            'packer/debian.pkr.hcl':template,
            'packer/tempest.pkrvars.json':R.encoded({name+'_binary':R.PARENT+'/'+name for name in ('agent','ebpf','http')}),
            'packer/provision.sh':b'unchanged-public-provision'}


class RecipeTests(unittest.TestCase):
    def test_actual_instrumenter_preserves_compile_identity_and_unrelated_files(self):
        parent=fixture();before=dict(parent)
        child=R.derive(parent,(ROOT/'image/delivery_race_fixture.py').read_bytes(),'a'*40)
        self.assertEqual(parent,before)
        self.assertEqual(child['packer/provision.sh'],parent['packer/provision.sh'])
        for name in ('inputs.json','packer/image.json'):
            old,new=json.loads(parent[name]),json.loads(child[name])
            self.assertTrue(new['delivery_race_fixture'])
            for key in ('tempest_guest_source_commit','tempest_guest_source_tree_sha256','input_sha256'):
                self.assertEqual(old[key],new[key])
            self.assertEqual(new['derivation_sha256']['dispatcher.py'],R.CHILD_SCRIPTS['dispatcher.py'])
            self.assertEqual(new['fixture_provenance']['parent_inputs_sha256'],R.sha(parent['inputs.json']))
        self.assertEqual(json.loads(child['inputs.json'])['template_sha256'],R.sha(child['packer/debian.pkr.hcl']))

    def test_changed_parent_or_false_provenance_is_rejected(self):
        instrumenter=(ROOT/'image/delivery_race_fixture.py').read_bytes()
        for change in ('script','fixture','compile','paths','instrumenter','revision'):
            parent=fixture();source=instrumenter;revision='a'*40
            if change=='script':parent['packer/dispatcher.py']+=b'\n'
            elif change in ('fixture','compile','paths'):
                metadata=json.loads(parent['inputs.json'])
                if change=='fixture':metadata['delivery_race_fixture']=True
                elif change=='compile':metadata['tempest_guest_source_commit']='invented-current-build'
                else:metadata['inputs']['guest']='/unrelated/guest'
                parent['inputs.json']=R.encoded(metadata)
            elif change=='instrumenter':source+=b'\n'
            else:revision='not-a-commit'
            with self.subTest(change=change),self.assertRaises(ValueError):R.derive(parent,source,revision)
