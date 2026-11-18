import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
from artifact_evidence import PATHS, validate_actor, validate_offline


class ArtifactEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.inputs = {'architecture': 'x86_64', 'input_sha256': {name: str(i) * 64 for i, name in enumerate(PATHS, 1)}}
        self.artifacts = {name: {'guest_path': path, 'sha256': self.inputs['input_sha256'][name],
                                'elf_machine': 247 if name == 'ebpf' else 62} for name, path in PATHS.items()}
        self.report = {'schema_version': 1, 'source_image_sha256_before': 'a' * 64,
                       'source_image_sha256_after': 'a' * 64, 'artifacts': self.artifacts}

    def test_denial_requires_bound_offline_bytes(self):
        observed = copy.deepcopy(self.artifacts)
        observed['agent'] = {'read_errno': 13}
        with self.assertRaises(AssertionError):
            validate_actor(observed, self.inputs)
        offline = validate_offline(self.report, 'a' * 64, self.inputs)
        validate_actor(observed, self.inputs, offline)

    def test_offline_rejects_other_image_path_hash_and_machine(self):
        for target, key, value in [('report', 'source_image_sha256_before', 'b' * 64),
                                   ('report', 'source_image_sha256_after', 'b' * 64),
                                   ('artifact', 'guest_path', '/tmp/agent'),
                                   ('artifact', 'sha256', 'b' * 64),
                                   ('artifact', 'elf_machine', 183)]:
            with self.subTest(key=key):
                report = copy.deepcopy(self.report)
                (report if target == 'report' else report['artifacts']['agent'])[key] = value
                with self.assertRaises(AssertionError):
                    validate_offline(report, 'a' * 64, self.inputs)

    def test_readable_mismatch_is_not_overridden_by_offline_report(self):
        observed = copy.deepcopy(self.artifacts)
        observed['http']['sha256'] = '0' * 64
        with self.assertRaises(AssertionError):
            validate_actor(observed, self.inputs, self.artifacts)

    def test_unexpected_errno_and_missing_artifact_rejected(self):
        for observed in [dict(self.artifacts, agent={'read_errno': 2}),
                         {k: v for k, v in self.artifacts.items() if k != 'ebpf'}]:
            with self.assertRaises(AssertionError):
                validate_actor(observed, self.inputs, self.artifacts)
