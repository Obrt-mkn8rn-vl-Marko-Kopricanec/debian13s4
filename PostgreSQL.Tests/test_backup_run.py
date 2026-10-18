"""Explicit command delivery with private lifecycle fixtures, never native PG."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import test_backup_lifecycle as fixture

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('private_backup_command_'+path.stem, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class BackupCommandTests(unittest.TestCase):
    def setUp(self):
        self.m = load(ROOT/'PostgreSQL/backup_run.py')

    def private(self):
        self.h = fixture.BackupLifecycleTests('runTest')
        self.addCleanup(self.h.doCleanups); self.h.setUp()
        self.status = load(ROOT/'PostgreSQL/backup_status.py')
        self.status.LIFECYCLE = self.h.m
        return self.h

    def call(self, args):
        output, errors = io.BytesIO(), io.BytesIO()
        with patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=output)), \
             patch.object(self.m.sys, 'stderr', types.SimpleNamespace(buffer=errors)):
            code = self.m.main(args)
        return code, output.getvalue(), errors.getvalue()

    def test_help_and_invalid_selectors_refuse_before_owned_graph_or_native_entry(self):
        for args, expected in ((['--help'], 0), (['run-once', '--help'], 0), ([], 2),
            (['run-once', '--directory', '/unobserved', '--application', 'mk8.dns'], 2),
            (['run-once', '--directory', '/unobserved', '--application', 'other', '--stderr-bytes', '1'], 2),
            (['run-once', '--directory', '/unobserved', '--application', 'mk8.dns', '--stderr-bytes', '01'], 2),
            (['run-once', '--directory', '/unobserved', '--application', 'mk8.dns', '--stderr-bytes', '1048577'], 2),
            (['run-once', '--directory', '/unobserved', '--application', 'mk8.dns', '--stderr-bytes', '1', '--retry'], 2)):
            with self.subTest(args=args), patch.object(self.m, 'owned', side_effect=AssertionError('owned graph')), \
                 patch.object(self.m.sys, 'stdout', io.StringIO()), patch.object(self.m.sys, 'stderr', io.StringIO()), \
                 self.assertRaises(SystemExit) as caught:
                self.m.main(args)
            self.assertEqual(caught.exception.code, expected)
        child = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'PostgreSQL/backup_run.py'), '--help'],
                               capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0); self.assertEqual(child.stderr, b'')
        self.assertIn(b'run-once', child.stdout)

    def test_private_single_attempt_and_history_status_never_reenter_after_reservation(self):
        h = self.private()
        args = ['run-once', '--directory', str(h.store), '--application', h.application, '--stderr-bytes', '4096']
        with patch.object(self.m, 'owned', return_value=self.status), \
             patch.object(h.m.BACKUP.ACCESS.LIVE, 'native', side_effect=h.h.h.read), \
             patch.object(h.m.LISTING.INSPECT, 'native', side_effect=h.listing):
            code, output, errors = self.call(args)
        self.assertEqual((code, errors), (0, b''))
        self.assertEqual(json.loads(output)['state'], 'single-attempt-selected-backup-source-only')
        self.assertEqual(len(h.h.h.ledger.read_text().splitlines()), 1)
        slot = h.store/h.m.ATTEMPT.LEAF; before = slot.read_bytes(), slot.stat().st_ino
        with patch.object(self.m, 'owned', return_value=self.status), \
             patch.object(h.m.SELECTED, 'stage_selected', side_effect=AssertionError('no retry')), \
             patch('subprocess.Popen', side_effect=AssertionError('no child')):
            code, output, errors = self.call(args)
            self.assertEqual((code, output), (75, b''))
            self.assertFalse(json.loads(errors)['retry_authorized'])
            code, output, errors = self.call(['status', '--directory', str(h.store)])
        self.assertEqual((code, errors), (0, b''))
        self.assertEqual(json.loads(output)['state'], 'historical-listing-recorded')
        self.assertFalse(json.loads(output)['backup_complete'])
        self.assertEqual((slot.read_bytes(), slot.stat().st_ino), before)

    def test_original_stage_refusal_and_separate_history_failure_survive_command_diagnostics(self):
        h = self.private(); original = OSError('private source refusal'); storage = OSError('private history refusal')
        captured, run_once = [], h.m.run_once
        def run(*args):
            try: return run_once(*args)
            except h.m.Blocked as error: captured.append(error); raise
        with patch.object(self.m, 'owned', return_value=self.status), \
             patch.object(h.m, 'run_once', side_effect=run), \
             patch.object(h.m.SELECTED, 'stage_selected', side_effect=original), \
             patch.object(h.m.FAILURE, 'record', side_effect=storage):
            code, output, errors = self.call(['run-once', '--directory', str(h.store),
                '--application', h.application, '--stderr-bytes', '4096'])
        self.assertEqual((code, output), (75, b'')); self.assertEqual(len(captured), 1)
        error = captured[0]
        self.assertIs(error.cause, original); self.assertIs(error.__cause__, original)
        self.assertIs(error.failure_record_error, storage); self.assertEqual(error.phase, 'stage')
        report = json.loads(errors)
        self.assertEqual(report['state'], 'reserved-backup-attempt-incomplete-no-retry')
        self.assertEqual(report['lifecycle']['phase'], 'stage')
        self.assertEqual(report['cause']['entries'][-1]['message_prefix'], 'private source refusal')
        self.assertEqual(report['lifecycle']['failure_record_error']['entries'][0]['message_prefix'], 'private history refusal')
        self.assertFalse(report['lifecycle']['failure_record']['returned'])
        self.assertTrue((h.store/h.m.ATTEMPT.LEAF).is_file())
        self.assertFalse(h.h.h.ledger.exists())

    def test_output_failure_retains_returned_result_commitment_without_repeating_delivery(self):
        raw = b'{"state":"MODEL-returned-source-receipt"}\n'
        calls = []
        lifecycle = types.SimpleNamespace(PREP=types.SimpleNamespace(APPLICATIONS=self.m.APPLICATIONS),
            SELECTED=types.SimpleNamespace(DUMP=types.SimpleNamespace(MAX_STDERR=self.m.MAX_STDERR)),
            MAX_OUTPUT=1024, Blocked=type('Blocked', (RuntimeError,), {}),
            run_once=lambda *args: calls.append(args) or raw)
        status = types.SimpleNamespace(LIFECYCLE=lifecycle)
        args = ['run-once', '--directory', '/unobserved', '--application', 'mk8.email', '--stderr-bytes', '19']
        for count in (True, len(raw)-1, None):
            errors = io.BytesIO(); before = len(calls)
            sink = types.SimpleNamespace(write=lambda value, count=count: count,
                flush=lambda: self.fail('short write must not flush'))
            with patch.object(self.m, 'owned', return_value=status), \
                 patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)), \
                 patch.object(self.m.sys, 'stderr', types.SimpleNamespace(buffer=errors)):
                self.assertEqual(self.m.main(args), 75)
            self.assertEqual(calls[before:], [(Path('/unobserved'), 'mk8.email', 19)])
            report = json.loads(errors.getvalue())
            self.assertEqual(report['phase'], 'output')
            self.assertEqual(report['known_result'], self.m.commitment(raw))
            self.assertFalse(report['backup_complete']); self.assertFalse(report['retry_authorized'])

    def test_bounded_diagnostic_formatting_does_not_replace_unprintable_or_cyclic_failure(self):
        class Unprintable(Exception):
            def __str__(self): raise ValueError('bad formatter')
        error = Unprintable(); error.__cause__ = error
        raw = self.m.failure(error, None, 'status', 'history-read', Path('/unobserved'), None)
        report = json.loads(raw)
        self.assertTrue(report['cause']['truncated_or_cyclic'])
        self.assertEqual(report['cause']['entries'][0]['type'], 'Unprintable')
        self.assertIn('unavailable', report['cause']['entries'][0]['message_prefix'])
        self.assertIs(error.__cause__, error)


if __name__ == '__main__':
    unittest.main()
