"""Private file/child cleanup faults retain primary failure and close ownership."""
import io
import json
import os
import unittest
from unittest.mock import patch

import test_archive_stage as stage_fixture
import test_backup_lifecycle as lifecycle_fixture
import test_selected_inspection as listing_fixture


class ArchiveCleanupTests(unittest.TestCase):
    def fixture(self, kind):
        value = kind('runTest')
        self.addCleanup(value.doCleanups)
        value.setUp()
        return value

    def test_write_and_both_close_failures_remain_distinct_and_reused_fds_survive(self):
        h = self.fixture(stage_fixture.ArchiveStageTests)
        original = OSError('original partial write')
        file_error, directory_error = OSError('stage file close'), OSError('stage directory close')
        realwrite, realclose, realopen = os.write, os.close, os.open
        replacements = [h.root/'replacement-file', h.root/'replacement-directory']
        for path in replacements: path.write_bytes(b'keep')
        writes, closes, reused = [], [], []
        def write(fd, data):
            writes.append(fd)
            if len(writes) == 1: return realwrite(fd, data[:3])
            raise original
        def close(fd):
            index = len(closes)
            self.assertLess(index, 2)
            closes.append(fd); realclose(fd)
            replacement = realopen(replacements[index], os.O_RDWR)
            reused.append(replacement); self.assertEqual(replacement, fd)
            raise (file_error, directory_error)[index]
        try:
            with patch.object(h.m.os, 'write', side_effect=write), \
                 patch.object(h.m.os, 'close', side_effect=close), \
                 self.assertRaises(h.m.CleanupFailure) as caught:
                h.stage(b'abcdef')
            failure = caught.exception
            self.assertIs(type(failure.cause), h.m.Blocked)
            self.assertIs(failure.__cause__, failure.cause)
            self.assertIs(failure.cause.__cause__, original)
            self.assertEqual(failure.cleanup, (file_error, directory_error))
            self.assertEqual(h.m.cleanup_errors(failure), (file_error, directory_error))
            self.assertEqual(len(closes), 2); self.assertEqual(len(set(closes)), 2)
            for fd in reused:
                self.assertEqual(os.read(fd, 4), b'keep')
                self.assertEqual(realwrite(fd, b'!'), 1)
            self.assertEqual(h.leaf.read_bytes(), b'abc')
        finally:
            for fd in reused: realclose(fd)
        with self.assertRaises(h.m.Blocked): h.stage()

    def test_real_readback_refusal_keeps_same_cause_when_retired_read_close_fails(self):
        h = self.fixture(stage_fixture.ArchiveStageTests)
        record = json.loads(h.stage(b'opaque'))
        directory = os.open(h.store, os.O_RDONLY | os.O_DIRECTORY)
        realclose, realopen, retiring = os.close, os.open, h.m.close_retired
        other = h.root/'replacement'; other.write_bytes(b'keep')
        original, reused, calls = [], [], []
        close_error = OSError('readback close')
        def retire(cause, *fds):
            original.append(cause)
            return retiring(cause, *fds)
        def close(fd):
            calls.append(fd); realclose(fd)
            replacement = realopen(other, os.O_RDONLY)
            reused.append(replacement); self.assertEqual(replacement, fd)
            raise close_error
        try:
            with patch.object(h.m, 'close_retired', side_effect=retire), \
                 patch.object(h.m.os, 'close', side_effect=close), \
                 self.assertRaises(h.m.CleanupFailure) as caught:
                h.m.readback(directory, h.name, tuple(record['identity']), record['bytes'],
                             '0'*64, h.m.KERNEL.now()+2)
            self.assertEqual(len(original), 1); self.assertIs(type(original[0]), h.m.Pending)
            self.assertIn('bytes or identity changed', str(original[0]))
            self.assertIs(caught.exception.cause, original[0])
            self.assertIs(caught.exception.__cause__, original[0])
            self.assertEqual(caught.exception.cleanup, (close_error,))
            self.assertEqual(len(calls), 1); self.assertEqual(os.read(reused[0], 4), b'keep')
            self.assertEqual(h.leaf.read_bytes(), b'opaque')
        finally:
            for fd in reused: realclose(fd)
            realclose(directory)

    def test_listing_refusal_and_directory_close_reach_outer_incomplete_separately(self):
        h = self.fixture(listing_fixture.SelectedInspectionTests)
        stage = h.m.STAGE; identity = h.h.store.stat()
        original, cleanup = OSError('original listing refusal'), OSError('listing directory close')
        realclose = os.close; closed = []
        def listing(*args): raise original
        def close(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                closed.append(fd); realclose(fd); raise cleanup
            return realclose(fd)
        with patch.object(stage.os, 'close', side_effect=close), \
             patch('subprocess.Popen', side_effect=AssertionError('no listing child')), \
             self.assertRaises(h.m.Incomplete) as caught:
            h.inspect(listing=listing)
        failure = caught.exception
        self.assertIs(type(failure.cause), stage.CleanupFailure)
        self.assertIs(failure.cause.cause, original)
        self.assertIs(failure.cause.__cause__, original)
        self.assertEqual(failure.cleanup, (cleanup,)); self.assertEqual(len(closed), 1)
        self.assertIs(failure.selection, h.raw); self.assertIsNone(failure.listing)
        self.assertEqual(h.h.leaf().read_bytes(), h.h.data)

    def test_reserved_failure_records_original_write_and_both_close_diagnostics(self):
        h = self.fixture(lifecycle_fixture.BackupLifecycleTests)
        stage = h.m.STAGE; leaf = h.h.h.leaf(); directory = h.h.h.store.stat()
        original = OSError('original lifecycle stage write')
        file_error, directory_error = OSError('lifecycle file close'), OSError('lifecycle directory close')
        realwrite, realclose = os.write, os.close
        writes, closed = [], []
        def write(fd, data):
            info = os.fstat(fd)
            if leaf.exists() and (info.st_dev, info.st_ino) == (leaf.stat().st_dev, leaf.stat().st_ino):
                writes.append(fd)
                if len(writes) == 1: return realwrite(fd, data[:3])
                raise original
            return realwrite(fd, data)
        def close(fd):
            info = os.fstat(fd); identity = info.st_dev, info.st_ino
            error = None
            if leaf.exists() and identity == (leaf.stat().st_dev, leaf.stat().st_ino): error = file_error
            elif identity == (directory.st_dev, directory.st_ino): error = directory_error
            realclose(fd)
            if error is not None: closed.append(error); raise error
        with patch.object(stage.os, 'write', side_effect=write), \
             patch.object(stage.os, 'close', side_effect=close), \
             self.assertRaises(h.m.Blocked) as caught:
            h.run_once()
        failure = caught.exception; selected = failure.cause
        self.assertIs(type(selected), h.m.SELECTED.Incomplete)
        self.assertIs(type(selected.cause), stage.CleanupFailure)
        self.assertIs(selected.cause.cause.__cause__, original)
        self.assertEqual(closed, [file_error, directory_error])
        self.assertEqual(selected.cleanup, (file_error, directory_error))
        self.assertEqual(failure.cleanup, (file_error, directory_error))
        self.assertIs(selected.uncertainty.cause, selected.cause)
        self.assertTrue(h.h.h.streams[-1].closed)
        self.assertIsNone(failure.history_error); self.assertIsNone(failure.failure_record_error)
        for raw in (h.m.UNCERTAINTY.load(h.store), h.m.FAILURE.load(h.store)):
            value = json.loads(raw)
            self.assertEqual(value['cleanup'], [h.m.UNCERTAINTY.describe(file_error), h.m.UNCERTAINTY.describe(directory_error)])
            self.assertEqual(value['cause'][-1], h.m.UNCERTAINTY.describe(original))
        self.assertEqual(leaf.read_bytes(), h.h.h.data[:3])
        self.assertEqual(len(h.h.h.ledger.read_text().splitlines()), 1)
        with patch.object(h.m.SELECTED, 'stage_selected', side_effect=AssertionError('no retry')), \
             self.assertRaises(h.m.Pending): h.run_once()


if __name__ == '__main__':
    unittest.main()
