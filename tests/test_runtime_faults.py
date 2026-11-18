import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

SPEC = importlib.util.spec_from_file_location(
    'runtime_faults', Path(__file__).resolve().parents[1] / 'integration/runtime_faults.py')
FAULTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FAULTS)


class ReservationRefusalTests(unittest.TestCase):
    def result(self, **changes):
        output = {'scope': 'm5_evaluation', 'runs': [],
                  'stopped': f'infrastructure:File exists (os error {FAULTS.errno.EEXIST})'}
        output.update(changes)
        return SimpleNamespace(returncode=1, stdout=json.dumps(output), stderr='')

    def test_structured_stdout_refusal_matches_run_cli_contract(self):
        witness = FAULTS.reservation_refusal(self.result())
        self.assertEqual(witness['error_kind'], 'EEXIST')
        self.assertEqual(witness['reported_runs'], 0)
        self.assertNotIn('File exists', json.dumps(witness))

    def test_unrelated_failures_and_created_runs_cannot_prove_reservation(self):
        cases = [self.result(stopped='infrastructure:No such file (os error 2)'),
                 self.result(stopped='cancelled:sigterm'), self.result(stopped=None),
                 self.result(scope='other'), self.result(runs=[{'run_directory': 'unexpected'}])]
        malformed = self.result()
        malformed.stdout = '[]'
        cases.append(malformed)
        stderr_only = self.result()
        stderr_only.stderr, stderr_only.stdout = stderr_only.stdout, ''
        cases.append(stderr_only)
        for status in (0, -9, 2):
            result = self.result()
            result.returncode = status
            cases.append(result)
        for result in cases:
            with self.subTest(result=result), self.assertRaises(AssertionError):
                FAULTS.reservation_refusal(result)
