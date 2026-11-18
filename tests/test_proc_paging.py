import ast
import copy
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('proc_paging',
    Path(__file__).resolve().parents[1] / 'image/proc_paging.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def process(root, pid, own=False):
    path = root / str(pid)
    path.mkdir()
    command = P.core.CONTROL_VALUE if own else 'parent-public'
    environment = P.core.CONTROL_KEY + '=' + P.core.CONTROL_VALUE if own else 'PUBLIC=1'
    (path / 'cmdline').write_bytes(command.encode() + b'\0')
    (path / 'environ').write_bytes(environment.encode() + b'\0')
    (path / 'fd').mkdir()
    (path / 'stat').write_text(str(pid) + ' (process) ' + ' '.join(['S', '1'] + ['0'] * 17 + [str(pid + 10000)]))


class PagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid in range(1, 261):
                process(root, pid)
            with patch.object(P.os, 'getuid', return_value=1000):
                cls.enumeration = P.enumerate_processes(root, stage='before_claim')
                cls.pages = []
                for index, pairs in enumerate(P.page_requests(cls.enumeration)):
                    own = 10000 + index
                    process(root, own, own=True)
                    cls.pages.append(P.observe_page(pairs, root, own_pid=own, stage='before_claim', index=index))
        cls.wire = sum(len(P.frame(value).encode()) + 1 for value in [cls.enumeration, *cls.pages])

    def test_260_enumerated_identities_are_fully_covered_in_three_bounded_pages(self):
        self.assertEqual([len(page['requested']) for page in self.pages], [127, 127, 6])
        self.assertTrue(all(len(page['records']) <= 128 and not page['pid_set_truncated'] for page in self.pages))
        summary = P.summarize_pages(self.enumeration, self.pages, self.wire)
        self.assertTrue(summary['passed'])
        self.assertEqual(summary['covered_requested_processes'], 260)
        self.assertEqual(summary['requested_binding'], {'matched': 260})
        self.assertEqual(summary['positive_controls'], {'cmdline': True, 'environ': True, 'fd_list': True})
        self.assertNotIn('parent-public', json.dumps(summary))

    def test_missing_extra_reordered_or_misbound_pages_never_pass(self):
        variants = [self.pages[:-1], self.pages + [self.pages[-1]], list(reversed(self.pages))]
        for field, value in [('stage', 'after_seed'), ('page_index', False), ('requested', [[1, 999]])]:
            changed = copy.deepcopy(self.pages)
            changed[0][field] = value
            variants.append(changed)
        for pages in variants:
            with self.subTest(pages=len(pages)), self.assertRaises(ValueError):
                P.summarize_pages(self.enumeration, pages, self.wire)

    def test_missing_duplicate_and_unknown_records_are_rejected(self):
        for change in ('missing', 'duplicate', 'status'):
            pages = copy.deepcopy(self.pages)
            if change == 'missing':
                pages[0]['records'].pop(0)
            elif change == 'duplicate':
                pages[0]['records'].append(copy.deepcopy(pages[0]['records'][0]))
            else:
                pages[0]['records'][0]['environ']['status'] = 'unknown'
            with self.subTest(change=change), self.assertRaises(ValueError):
                P.summarize_pages(self.enumeration, pages, self.wire)

    def test_vanished_and_reused_identity_are_kept_separate_from_matching_identity(self):
        for state in ('vanished', 'replaced'):
            pages = copy.deepcopy(self.pages)
            row = pages[0]['records'][0]
            if state == 'vanished':
                row['identity_before'] = row['identity_after'] = {'status': 'vanished', 'errno': 2}
                row['identity_stable'] = False
                for field in ('cmdline', 'environ', 'fd'):
                    row[field] = {'status': 'vanished', 'errno': 2}
            else:
                row['identity_before']['starttime_ticks'] += 1
                row['identity_after']['starttime_ticks'] += 1
            summary = P.summarize_pages(self.enumeration, pages, self.wire)
            self.assertTrue(summary['passed'])  # Complete observations, not proof all identities remained alive.
            self.assertEqual(summary['requested_binding'], {state: 1, 'matched': 259})

    def test_control_truncation_and_identity_errors_do_not_complete(self):
        for change in ('control', 'truncated', 'identity_error'):
            pages = copy.deepcopy(self.pages)
            if change == 'control':
                own = next(row for row in pages[0]['records'] if row['pid'] == pages[0]['own_pid'])
                own['environ']['text'] = ''
            elif change == 'truncated':
                pages[0]['records'][0]['cmdline']['truncated'] = True
            else:
                pages[0]['records'][0]['identity_before'] = {'status': 'error', 'errno': 5}
                pages[0]['records'][0]['identity_stable'] = False
            self.assertFalse(P.summarize_pages(self.enumeration, pages, self.wire)['passed'])

    def test_enumeration_and_wire_budgets_remain_finite(self):
        for wire in (0, P.MAX_STAGE_BYTES + 1):
            with self.assertRaises(ValueError):
                P.summarize_pages(self.enumeration, self.pages, wire)
        with self.assertRaises(ValueError):
            P.validate_pairs([[pid, 1] for pid in range(1, P.MAX_ENUMERATED + 2)], P.MAX_ENUMERATED)
        with self.assertRaises(ValueError):
            P.validate_pairs([[1, 1], [1, 1]], P.PAGE_TARGETS)
        with self.assertRaises(RuntimeError):
            P.frame({'data': 'X' * P.core.MAX_OUTPUT})

    def test_guard_failure_precedes_any_proc_enumeration(self):
        with patch.object(P.core, 'require_guest', side_effect=RuntimeError('guard')), \
             patch.object(P, 'enumerate_processes') as read:
            with self.assertRaisesRegex(RuntimeError, 'guard'):
                P.main()
        read.assert_not_called()

    def test_actual_host_probe_requests_every_page_and_keeps_raw_records_private(self):
        source = Path(__file__).resolve().parents[1] / 'integration/image_smoke.py'
        tree = ast.parse(source.read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        probe = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'proc_probe')
        calls = []
        def execute(*argv):
            calls.append(argv)
            mode = next(arg.split('=', 1)[1] for arg in argv if arg.startswith(P.MODE_KEY + '='))
            self.assertIn('/workspace/readonly-check/proc-probe.py', argv)
            self.assertIn('-I', argv)
            self.assertIn('-B', argv)
            if mode == 'enumerate':
                value = self.enumeration
            else:
                index = int(next(arg.split('=', 1)[1] for arg in argv if arg.startswith(P.INDEX_KEY + '=')))
                pairs = json.loads(next(arg.split('=', 1)[1] for arg in argv if arg.startswith(P.PAGE_KEY + '=')))
                self.assertEqual(pairs, self.pages[index]['requested'])
                value = self.pages[index]
            return subprocess.CompletedProcess(argv, 0, P.frame(value) + '\n', '')
        report = {'checks': {}}
        namespace = {'args': type('Args', (), {'proc_evidence': True})(), 'proc_paging': P,
                     'CONTROL_KEY': P.core.CONTROL_KEY, 'CONTROL_VALUE': P.core.CONTROL_VALUE,
                     'execute': execute, 'json': json, 'report': report, 'save': lambda: None}
        exec(compile(ast.Module(body=[probe], type_ignores=[]), str(source), 'exec'), namespace)
        namespace['proc_probe']('before_claim')
        self.assertEqual(len(calls), 4)
        self.assertTrue(report['checks']['proc_before_claim']['passed'])
        self.assertNotIn('parent-public', json.dumps(report))


class PublicHelperTests(unittest.TestCase):
    def test_actual_setup_copies_only_probe_sources_readonly(self):
        repo = Path(__file__).resolve().parents[1]
        source = repo / 'integration/image_smoke.py'
        tree = ast.parse(source.read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        setup = next(n for n in main.body if isinstance(n, ast.If) and
                     isinstance(n.test, ast.Attribute) and n.test.attr == 'proc_evidence')
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            mapped = []
            namespace = {'args': type('Args', (), {'proc_evidence': True})(), 'public': public,
                         'ROOT': repo, 'stat': stat, 'mapped_metadata': lambda path, mode: mapped.append((path.name, mode))}
            exec(compile(ast.Module(body=[setup], type_ignores=[]), str(source), 'exec'), namespace)
            self.assertEqual({path.name for path in public.iterdir()}, {'proc_evidence.py', 'proc-probe.py'})
            self.assertEqual((public / 'proc-probe.py').read_bytes(), (repo / 'image/proc_paging.py').read_bytes())
            self.assertEqual((public / 'proc_evidence.py').read_bytes(), (repo / 'image/proc_evidence.py').read_bytes())
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in public.iterdir()))
            self.assertEqual({mode for _, mode in mapped}, {stat.S_IFREG | 0o444})
            with self.assertRaises(FileExistsError):
                exec(compile(ast.Module(body=[setup], type_ignores=[]), str(source), 'exec'), namespace)
