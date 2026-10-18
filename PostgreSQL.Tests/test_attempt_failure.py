"""Durable diagnostics for private lifecycle failures; never native backup proof."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_backup_lifecycle as fixture

ROOT = Path(__file__).resolve().parents[1]


class AttemptFailureTests(unittest.TestCase):
    def setUp(self):
        self.h = fixture.BackupLifecycleTests('runTest')
        self.addCleanup(self.h.doCleanups); self.h.setUp()
        self.m = self.h.m
        self.history = self.m.FAILURE

    def status(self):
        spec = importlib.util.spec_from_file_location('attempt_failure_status', ROOT/'PostgreSQL/backup_status.py')
        value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
        value.LIFECYCLE = self.m
        return value

    def test_listing_failure_retains_original_and_known_selection_then_status_reads_without_reentry(self):
        original = OSError('private listing refused')
        def listing(*args):
            raise original
        with self.assertRaises(self.m.Blocked) as caught:
            self.h.run_once(listing=listing)
        error = caught.exception
        self.assertIs(error.cause.cause, original)
        self.assertIs(error.__cause__, error.cause)
        self.assertIsNone(error.failure_record_error)
        record = json.loads(self.history.load(self.h.store))
        self.assertEqual(error.failure_record, self.history.load(self.h.store))
        self.assertEqual(record['phase'], 'listing')
        self.assertEqual(bytes.fromhex(record['known']['selection']['hex']), error.selection)
        self.assertIsNone(record['known']['listing']); self.assertIsNone(record['known']['manifest'])
        self.assertIn(['OSError', 'private listing refused'], record['cause'])
        status = self.status()
        with patch.object(self.m.SELECTED, 'stage_selected', side_effect=AssertionError('no retry')), patch('subprocess.Popen', side_effect=AssertionError('no child')):
            value = json.loads(status.inspect(self.h.store))
            with self.assertRaises(self.m.ATTEMPT.Blocked): self.h.run_once()
        self.assertEqual(value['state'], 'historical-attempt-incomplete-recorded')
        self.assertEqual(value['records']['failure']['phase'], 'listing')
        self.assertEqual(value['records']['failure']['diagnostic'], {'type': 'OSError', 'detail': 'private listing refused'})
        self.assertIs(value['retry_authorized'], False)
        self.assertEqual(len(self.h.h.h.ledger.read_text().splitlines()), 1)

    def test_final_validation_failure_keeps_returned_manifest_and_is_never_reported_complete(self):
        original = OSError('private final admission')
        intention = self.m.SELECTED.intention
        def final(*args):
            if (self.h.store/self.m.MANIFEST.LEAF).is_file(): raise original
            return intention(*args)
        with patch.object(self.m.SELECTED, 'intention', side_effect=final), self.assertRaises(self.m.Blocked) as caught:
            self.h.run_once()
        error = caught.exception
        self.assertIs(error.cause, original)
        self.assertIsNone(error.failure_record_error)
        record = json.loads(error.failure_record)
        self.assertEqual(record['phase'], 'final-validation')
        for tag in ('selection', 'listing', 'manifest'):
            self.assertEqual(bytes.fromhex(record['known'][tag]['hex']), getattr(error, tag))
        value = json.loads(self.status().inspect(self.h.store))
        self.assertTrue(value['records']['manifest']['present'])
        self.assertEqual(value['state'], 'historical-attempt-incomplete-recorded')
        self.assertIs(value['backup_complete'], False)

    def test_diagnostic_storage_failure_and_expiry_keep_original_exception_and_slot(self):
        original, storage_error = OSError('fresh source refusal'), OSError('diagnostic storage refusal')
        with patch.object(self.m.SELECTED, 'stage_selected', side_effect=original), patch.object(self.history, 'record', side_effect=storage_error), self.assertRaises(self.m.Blocked) as caught:
            self.h.run_once()
        error = caught.exception
        self.assertIs(error.cause, original); self.assertIs(error.__cause__, original)
        self.assertIs(error.failure_record_error, storage_error); self.assertIsNone(error.failure_record)
        self.assertIsNone(error.history_error)
        self.assertTrue((self.h.store/self.m.ATTEMPT.LEAF).is_file())
        self.assertEqual(json.loads(self.status().inspect(self.h.store))['state'], 'reserved-outcome-unknown')
        with patch.object(self.history, 'capture', side_effect=AssertionError('no capture')), self.assertRaises(ValueError):
            self.history.record(self.h.store, error.reservation, 'stage', original,
                {'selection': None, 'listing': None, 'manifest': None}, None, (),
                deadline=self.history._STORAGE.KERNEL.now()-1)

    def test_opaque_receipts_canonical_bounds_and_exact_reservation_binding(self):
        reservation = self.m.ATTEMPT.reserve(self.h.store, 'mk8.dns', 4711)
        original = OSError('original')
        known = {'selection': b'not a receipt\x00\xff', 'listing': None, 'manifest': None}
        raw = self.history.record(self.h.store, reservation, 'listing', original, known, None, ())
        value = json.loads(raw)
        self.assertEqual(bytes.fromhex(value['known']['selection']['hex']), known['selection'])
        self.assertEqual(value['state'], self.history.STATE)
        for change in ({'phase': 'retry'}, {'application': 'mk8.email'}, {'cause': []}, {'extra': 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.history.checked(self.history.PREP.canonical(value | change))
        changed = copy.deepcopy(value); changed['known']['selection']['bytes'] = True
        with self.assertRaises(ValueError): self.history.checked(self.history.PREP.canonical(changed))
        with patch.dict(self.history.LIMITS, selection=1), self.assertRaises(ValueError):
            self.history.capture(reservation, 'listing', original, known, None, ())
        bad_slot = json.loads(reservation); bad_slot['correlation_id'] = 'b'*64
        (self.h.store/self.m.ATTEMPT.LEAF).write_bytes(self.m.ATTEMPT.encoded(bad_slot))
        with self.assertRaises(ValueError): self.status().inspect(self.h.store)


if __name__ == '__main__':
    unittest.main()
