"""Private history failures retain causes and retire descriptors without retry."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('private_history_'+name, ROOT/'PostgreSQL'/name)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class HistoryCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian-history-cleanup-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.store = self.root/'history'; self.store.mkdir(mode=0o700)
        self.m = load('private_storage.py'); self.bind(self.m)
        self.m.LEAF, self.m.MAX_BYTES = 'fixture-history', 1024
        self.m.envelope = lambda value: b'fixture:'+value
        def checked(raw):
            if not raw.startswith(b'fixture:'): raise self.m.Pending('fixture envelope')
            return raw[8:]
        self.m.checked = checked

    def bind(self, storage):
        storage.TRUST_ROOT, storage.TRUSTED_UID = self.root, os.geteuid()

    def test_owned_preparation_and_capture_cleanup_reach_historical_diagnostics(self):
        life = load('backup_lifecycle.py')
        original = OSError('original read refusal')
        read_close, capture_close = OSError('reader close'), OSError('capture close')
        reader = life.PREP.CleanupFailure(original, (read_close,))
        reader.__cause__ = original
        capture = life.BACKUP.ACCESS.LIVE.CleanupFailure(reader, (capture_close, read_close))
        capture.__cause__ = reader
        owned = (life.PREP.CleanupFailure, life.BACKUP.ACCESS.LIVE.CleanupFailure)
        self.assertIsNot(owned[0], owned[1])
        self.assertEqual(life.STAGE.cleanup_errors(capture, owned), (read_close, capture_close))
        self.assertEqual(life.cleanup_errors(capture), (read_close, capture_close))
        self.assertEqual([life.UNCERTAINTY.describe(error) for error in life.cleanup_errors(capture)],
            [['OSError', 'reader close'], ['OSError', 'capture close']])
        self.assertEqual(life.UNCERTAINTY.chain(capture)[-1], ['OSError', 'original read refusal'])
        self.assertEqual(life.STAGE.cleanup_errors(capture), ())
        foreign = load('prepare.py').CleanupFailure(original, (read_close,))
        self.assertIsNot(type(foreign), owned[0])
        self.assertEqual(life.cleanup_errors(foreign), ())
        self.assertIs(capture.cause, reader); self.assertIs(reader.cause, original)

    def test_history_success_resync_and_narrow_link_recovery_keep_exact_payload(self):
        self.assertEqual(self.m.create(self.store, b'opaque'), b'opaque')
        leaf = self.store/self.m.LEAF; before = leaf.stat()
        self.assertEqual(self.m.create(self.store, b'opaque'), b'opaque')
        self.assertEqual(leaf.stat().st_ino, before.st_ino)
        link = self.store/('.proposal-'+'a'*32); os.link(leaf, link)
        self.assertEqual(self.m.create(self.store, b'opaque'), b'opaque')
        self.assertFalse(link.exists()); self.assertEqual(leaf.stat().st_nlink, 1)
        self.assertEqual(self.m.load(self.store), b'opaque')
        with self.assertRaises(self.m.Pending): self.m.create(self.store, b'different')
        self.assertEqual(leaf.read_bytes(), b'fixture:opaque')

    def test_nested_read_and_directory_closes_preserve_original_and_reused_numbers(self):
        self.m.create(self.store, b'opaque')
        original = OSError('original history read')
        faults = (OSError('history read close'), OSError('history directory close'))
        realclose, realopen = os.close, os.open
        other = self.root/'replacement'; other.write_bytes(b'keep')
        reused, calls = [], []
        def close(fd):
            index = len(calls); self.assertLess(index, 2); calls.append(fd)
            realclose(fd); replacement = realopen(other, os.O_RDWR)
            self.assertEqual(replacement, fd); reused.append(replacement)
            raise faults[index]
        try:
            with patch.object(self.m.os, 'read', side_effect=original), \
                 patch.object(self.m.os, 'close', side_effect=close), self.assertRaises(self.m.CleanupFailure) as caught:
                self.m.load(self.store)
            error = caught.exception
            self.assertIs(type(error.cause), self.m.CleanupFailure)
            self.assertIs(error.cause.cause, original); self.assertIs(error.cause.__cause__, original)
            self.assertIs(error.__cause__, error.cause)
            self.assertEqual(self.m.cleanup_errors(error), faults)
            self.assertEqual(len(calls), 2); self.assertEqual(len(set(calls)), 2)
            for fd in reused:
                self.assertEqual(os.read(fd, 4), b'keep'); self.assertEqual(os.write(fd, b'!'), 1)
            self.assertEqual((self.store/self.m.LEAF).read_bytes(), b'fixture:opaque')
        finally:
            for fd in reused: realclose(fd)

    def test_partial_write_keeps_body_unlink_and_two_close_failures_separate(self):
        original = OSError('original history write')
        faults = tuple(OSError(name) for name in ('staging unlink', 'staging close', 'directory close'))
        realwrite, realclose = os.write, os.close; writes, closes, unlinks = [], [], []
        def write(fd, raw):
            writes.append(fd)
            if len(writes) == 1: return realwrite(fd, raw[:3])
            raise original
        def unlink(name, **kwargs): unlinks.append(name); raise faults[0]
        def close(fd):
            index = len(closes); self.assertLess(index, 2); closes.append(fd)
            realclose(fd); raise faults[index+1]
        with patch.object(self.m.os, 'write', side_effect=write), patch.object(self.m.os, 'unlink', side_effect=unlink), \
             patch.object(self.m.os, 'close', side_effect=close), self.assertRaises(self.m.CleanupFailure) as caught:
            self.m.create(self.store, b'opaque')
        error = caught.exception
        self.assertIs(error.cause, original); self.assertIs(error.__cause__, original)
        self.assertEqual(error.cleanup, faults); self.assertEqual(self.m.cleanup_errors(error), faults)
        self.assertEqual(len(unlinks), 1); self.assertEqual(len(closes), 2)
        self.assertFalse((self.store/self.m.LEAF).exists())
        self.assertEqual((self.store/unlinks[0]).read_bytes(), b'fix')
        for fd in closes:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_lock_and_status_refusals_survive_failed_directory_close(self):
        original, cleanup = OSError('nonblocking lock refusal'), OSError('directory close')
        realclose = os.close; calls = []
        def close(fd): calls.append(fd); realclose(fd); raise cleanup
        with patch.object(self.m.fcntl, 'flock', side_effect=original), patch.object(self.m.os, 'close', side_effect=close), \
             self.assertRaises(self.m.CleanupFailure) as caught:
            self.m.locked(self.store, self.m.KERNEL.now()+2)
        self.assertIs(caught.exception.cause, original); self.assertEqual(caught.exception.cleanup, (cleanup,))
        self.assertEqual(len(calls), 1)
        status = load('backup_status.py'); storage = status.LIFECYCLE.ATTEMPT._STORAGE
        for module in (status.LIFECYCLE.ATTEMPT, status.LIFECYCLE.MANIFEST,
                       status.LIFECYCLE.UNCERTAINTY, status.LIFECYCLE.FAILURE): self.bind(module._STORAGE)
        leaf = self.store/status.LIFECYCLE.MANIFEST.LEAF; leaf.write_bytes(b'unknown'); leaf.chmod(0o600)
        # Capture and rethrow the real missing-reservation/outcome guard.
        leaf.unlink(); refuses = []; classify = status.classify
        def classified(records):
            try: return classify(records)
            except status.Pending as error: refuses.append(error); raise
        records = {'reservation': None, 'manifest': {'application': 'mk8.dns'}, 'incomplete': None, 'failure': None}
        calls.clear()
        with patch.object(status, 'snapshot', return_value=({}, records)), patch.object(status, 'classify', side_effect=classified), \
             patch.object(status.os, 'close', side_effect=close), self.assertRaises(storage.CleanupFailure) as caught:
            status.inspect(self.store)
        self.assertEqual(len(refuses), 1); self.assertIs(caught.exception.cause, refuses[0])
        self.assertIs(caught.exception.__cause__, refuses[0]); self.assertEqual(caught.exception.cleanup, (cleanup,))
        self.assertEqual(len(calls), 1)

    def test_reservation_write_failure_and_two_closes_keep_closed_slot_and_original(self):
        attempt = load('backup_attempt.py'); self.bind(attempt._STORAGE)
        original = OSError('reservation write'); faults = (OSError('slot close'), OSError('directory close'))
        realclose, realwrite = os.close, os.write; writes, closes = [], []
        def write(fd, raw):
            writes.append(fd)
            if len(writes) == 1: return realwrite(fd, raw[:3])
            raise original
        def close(fd):
            index = len(closes); self.assertLess(index, 2); closes.append(fd)
            realclose(fd); raise faults[index]
        with patch.object(attempt.os, 'write', side_effect=write), patch.object(attempt.os, 'close', side_effect=close), \
             self.assertRaises(attempt.Blocked) as caught:
            attempt.reserve(self.store, 'mk8.dns', 4711)
        error = caught.exception.__cause__
        self.assertIs(type(error), attempt._STORAGE.CleanupFailure)
        self.assertIs(error.cause, original); self.assertEqual(error.cleanup, faults)
        leaf = self.store/attempt.LEAF; before = leaf.read_bytes(), leaf.stat().st_ino
        self.assertEqual(len(closes), 2)
        with self.assertRaises(attempt.Blocked): attempt.reserve(self.store, 'mk8.dns', 4711)
        self.assertEqual((leaf.read_bytes(), leaf.stat().st_ino), before)

    def test_failed_failure_record_keeps_original_lifecycle_and_own_storage_cleanup(self):
        life = load('backup_lifecycle.py')
        for module in (life.ATTEMPT, life.MANIFEST, life.UNCERTAINTY, life.FAILURE): self.bind(module._STORAGE)
        original, history = OSError('original fresh refusal'), OSError('failure record write')
        faults = (OSError('failure record close'), OSError('history directory close'))
        envelope = life.FAILURE._STORAGE.envelope; active = [False]; closes = []
        realwrite, realclose = os.write, os.close
        def encoded(payload):
            raw = envelope(payload); active[0] = True; return raw
        def write(fd, raw):
            if active[0]: raise history
            return realwrite(fd, raw)
        def close(fd):
            realclose(fd)
            if active[0]:
                index = len(closes); closes.append(fd)
                if len(closes) == 2: active[0] = False
                raise faults[index]
        with patch.object(life.KERNEL, 'namespace', return_value=4711), \
             patch.object(life.LISTING.INSPECT.KERNEL, 'namespace', return_value=4711), \
             patch.object(life.SELECTED, 'stage_selected', side_effect=original), \
             patch.object(life.FAILURE._STORAGE, 'envelope', side_effect=encoded), \
             patch.object(life.os, 'write', side_effect=write), patch.object(life.os, 'close', side_effect=close), \
             patch('subprocess.Popen', side_effect=AssertionError('no native child')), self.assertRaises(life.Blocked) as caught:
            life.run_once(self.store, 'mk8.dns', 4096)
        error = caught.exception
        self.assertIs(error.cause, original); self.assertIs(error.__cause__, original)
        self.assertIsNone(error.failure_record); self.assertIsNone(error.history_error)
        record_error = error.failure_record_error
        self.assertIs(type(record_error), life.FAILURE._STORAGE.CleanupFailure)
        self.assertIs(record_error.cause, history); self.assertEqual(record_error.cleanup, faults)
        self.assertEqual(life.cleanup_errors(record_error), faults)
        self.assertEqual(life.cleanup_errors(self.m.CleanupFailure(original, (history,))), ())
        self.assertTrue((self.store/life.ATTEMPT.LEAF).is_file())
        self.assertFalse((self.store/life.FAILURE.LEAF).exists()); self.assertEqual(len(closes), 2)
        with patch.object(life.KERNEL, 'namespace', return_value=4711), \
             patch.object(life.LISTING.INSPECT.KERNEL, 'namespace', return_value=4711), \
             patch.object(life.SELECTED, 'stage_selected', side_effect=AssertionError('no retry')), self.assertRaises(life.ATTEMPT.Blocked):
            life.run_once(self.store, 'mk8.dns', 4096)


if __name__ == '__main__':
    unittest.main()
