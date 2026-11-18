"""Pure proposed child-definition transform; no build or filesystem publication."""
import copy
import hashlib
import json
import re

PARENT = '/var/lib/tempest-izanagi-full-build-003/inputs'
CHILD = '/var/lib/tempest-izanagi-delivery-race-build-001/inputs'
PARENT_SCRIPTS = {'dispatcher.py': '2c785fa2d24841ed00e5807604343e31e9409c5b7ae9855d0e0adf5449622b09',
                  'quiesce.py': '34cbc78cfec3caedac52bcaa747df62342383612ee5f3f9aab9ab02bac5cb8b0'}
CHILD_SCRIPTS = {'dispatcher.py': 'faf0c5aef7e5ae7600e77c88df61d84edad6b3cdd39e5b765e65d7a96972e1b9',
                 'quiesce.py': '72fabf3ce527257ab2bb5fb8cb3b8a8ef7e706ff2715b29e5b7c0857bf5390a8'}
INSTRUMENTER = '562a44539935b975f3c9b1eba8e141579d12c5791d62206163578f4ddf170dc6'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def derive(files, instrumenter, recipe_revision):
    """Return child bytes and explicit provenance, retaining binary compile metadata."""
    if re.fullmatch('[0-9a-f]{40}', recipe_revision) is None or sha(instrumenter) != INSTRUMENTER:
        raise ValueError('unreviewed recipe or instrumenter')
    child = dict(files)
    inputs = json.loads(files['inputs.json'])
    image = json.loads(files['packer/image.json'])
    if inputs['delivery_race_fixture'] is not False or image['delivery_race_fixture'] is not False:
        raise ValueError('parent is not the normal full003 definition')
    for key in ('tempest_guest_source_commit', 'tempest_guest_source_tree_sha256', 'tempest_guest_source_dirty', 'input_sha256'):
        if inputs[key] != image[key]:
            raise ValueError('parent compile metadata mismatch')
    for name, digest in PARENT_SCRIPTS.items():
        if sha(files['packer/' + name]) != digest:
            raise ValueError('parent script differs from fixed full003')
    namespace = {'__name__': 'reviewed_delivery_race_transform'}
    exec(compile(instrumenter, 'reviewed-delivery-race-fixture', 'exec'), namespace)
    transformed = namespace['instrument'](files['packer/dispatcher.py'].decode(), files['packer/quiesce.py'].decode())
    for name, value in zip(PARENT_SCRIPTS, transformed, strict=True):
        compile(value, 'fixture-' + name, 'exec')
        if sha(value.encode()) != CHILD_SCRIPTS[name]:
            raise ValueError('unexpected instrumentation output')
        child['packer/' + name] = value.encode()
    template = files['packer/debian.pkr.hcl'].decode()
    if template.count(PARENT + '/') != 3:
        raise ValueError('unexpected parent template path set')
    child['packer/debian.pkr.hcl'] = template.replace(PARENT + '/', CHILD + '/').encode()
    variables = json.loads(files['packer/tempest.pkrvars.json'])
    if variables != {name + '_binary': PARENT + '/' + name for name in ('agent', 'ebpf', 'http')}:
        raise ValueError('unexpected parent artifact variables')
    child['packer/tempest.pkrvars.json'] = encoded({key: value.replace(PARENT + '/', CHILD + '/') for key, value in variables.items()})
    provenance = {'schema_version': 1, 'method': 'parent definition plus reviewed instrument; prepare CLI not rerun',
                  'recipe_source_commit': recipe_revision, 'instrumenter_sha256': sha(instrumenter),
                  'parent_inputs_sha256': sha(files['inputs.json']), 'parent_image_metadata_sha256': sha(files['packer/image.json']),
                  'parent_binary_compile_metadata_preserved': True,
                  'parent_image_sha256': '5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7e',
                  'parent_files_sha256': {name: sha(data) for name, data in sorted(files.items())}}
    for metadata in (inputs, image):
        metadata['delivery_race_fixture'] = True
        metadata['derivation_sha256'] = {**metadata['derivation_sha256'], **CHILD_SCRIPTS,
                                         'delivery_race_fixture.py': sha(instrumenter)}
        metadata['fixture_provenance'] = copy.deepcopy(provenance)
    expected = {name: PARENT + '/' + name for name in ('agent', 'ebpf', 'guest', 'http', 'lws')}
    if inputs['inputs'] != expected:
        raise ValueError('unexpected parent binary input paths')
    inputs['inputs'] = {name: value.replace(PARENT + '/', CHILD + '/') for name, value in expected.items()}
    inputs['source_manifest_sha256'] = sha(files['inputs.json'])
    inputs['template_sha256'] = sha(child['packer/debian.pkr.hcl'])
    child['inputs.json'], child['packer/image.json'] = encoded(inputs), encoded(image)
    child['fixture-provenance.json'] = encoded(provenance)
    changed = {name for name in files if child[name] != files[name]}
    if changed != {'inputs.json', 'packer/image.json', 'packer/dispatcher.py', 'packer/quiesce.py',
                   'packer/debian.pkr.hcl', 'packer/tempest.pkrvars.json'}:
        raise ValueError('unexpected child definition difference')
    return child
