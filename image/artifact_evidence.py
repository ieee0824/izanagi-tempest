"""Bind offline image bytes and actor observations without widening guest access."""

PATHS = {'agent': '/usr/local/bin/izanagi-agent',
         'http': '/usr/local/bin/izanagi-http-capture',
         'ebpf': '/opt/izanagi/izanagi-ebpf.o'}


def validate_offline(report, image_sha256, inputs):
    assert report['schema_version'] == 1
    assert report['source_image_sha256_before'] == image_sha256
    assert report['source_image_sha256_after'] == image_sha256
    machine = {'x86_64': 62, 'aarch64': 183}[inputs['architecture']]
    for name, path in PATHS.items():
        actual = report['artifacts'][name]
        assert actual['guest_path'] == path, 'offline artifact path mismatch'
        assert actual['sha256'] == inputs['input_sha256'][name], 'offline artifact hash mismatch'
        assert actual['elf_machine'] == (247 if name == 'ebpf' else machine), 'offline ELF mismatch'
    return report['artifacts']


def validate_actor(observed, inputs, offline=None):
    assert set(observed) == set(PATHS), 'actor artifact set mismatch'
    machine = {'x86_64': 62, 'aarch64': 183}[inputs['architecture']]
    for name, actual in observed.items():
        if actual.get('read_errno') == 13:
            assert offline is not None, 'actor read denied without offline evidence'
            # Only a validated offline report may discharge a denied byte read.
            assert offline[name]['sha256'] == inputs['input_sha256'][name]
        else:
            assert 'read_errno' not in actual, 'unexpected actor read error'
            assert actual['sha256'] == inputs['input_sha256'][name], 'actor artifact hash mismatch'
            assert actual['elf_machine'] == (247 if name == 'ebpf' else machine), 'actor ELF mismatch'
