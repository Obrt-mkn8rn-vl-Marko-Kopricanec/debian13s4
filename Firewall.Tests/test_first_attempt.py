import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import test_first_create as plan_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_attempt', ROOT / 'Firewall/first_attempt.py')
ATTEMPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ATTEMPT)
BACKEND, STATE = ATTEMPT._STORAGE, ATTEMPT.STATE


class ReservationTests(unittest.TestCase):
    def setUp(self):
        helper = plan_fixture.PlanTests();helper.setUp()
        try:self.payload = helper.prepare()
        finally:helper.doCleanups()
        self.plan = json.loads(self.payload)
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-attempt-', dir='/dev/shm')
        self.addCleanup(directory.cleanup);self.root = Path(directory.name);self.root.chmod(0o700)
        self.store = self.root / 'history';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf = self.store / ATTEMPT.LEAF
        for setting in (patch.object(BACKEND, 'TRUST_ROOT', self.root), patch.object(BACKEND, 'TRUSTED_UID', os.geteuid())):
            setting.start();self.addCleanup(setting.stop)

    def test_complete_exclusive_slot_is_checked_synced_and_retains_original_plan(self):
        raw = ATTEMPT.reserve(self.store, self.payload);value = json.loads(raw)
        self.assertEqual(ATTEMPT.load(self.store), raw)
        self.assertEqual(value['state'], 'submission-reserved-no-retry')
        self.assertEqual(value['proposal'].encode(), self.payload)
        self.assertEqual(value['proposal_sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(value['transaction_sha256'], self.plan['transaction_sha256'])
        self.assertEqual(stat.S_IMODE(self.leaf.stat().st_mode), 0o600)
        self.assertEqual(self.leaf.stat().st_nlink, 1);self.assertEqual(self.leaf.stat().st_dev, self.store.stat().st_dev)
        self.assertEqual(raw, STATE.encoded(value) + b'\n')

    def test_identical_second_reservation_is_blocked_without_overwrite_or_removal(self):
        raw = ATTEMPT.reserve(self.store, self.payload);before = self.leaf.stat()
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
        self.assertEqual(self.leaf.read_bytes(), raw);self.assertEqual(self.leaf.stat().st_ino, before.st_ino)
        self.assertEqual({p.name for p in self.store.iterdir()}, {ATTEMPT.LEAF})

    def test_preexisting_empty_partial_and_foreign_sentinels_are_never_deleted(self):
        for raw in (b'', b'{"state":', b'unrelated sentinel'):
            self.leaf.write_bytes(raw);self.leaf.chmod(0o600);inode = self.leaf.stat().st_ino
            with self.subTest(raw=raw), patch.object(ATTEMPT.os, 'unlink', side_effect=AssertionError('delete')), self.assertRaises(ATTEMPT.Blocked):
                ATTEMPT.reserve(self.store, self.payload)
            self.assertEqual(self.leaf.read_bytes(), raw);self.assertEqual(self.leaf.stat().st_ino, inode)
            self.leaf.unlink()

    def test_symbolic_fifo_directory_and_external_linked_slots_block_without_following(self):
        target = self.root / 'unrelated';target.write_bytes(b'keep');target.chmod(0o600)
        self.leaf.symlink_to(target)
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
        self.assertEqual(target.read_bytes(), b'keep');self.leaf.unlink();os.mkfifo(self.leaf, 0o600)
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
        self.leaf.unlink();self.leaf.mkdir()
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
        self.leaf.rmdir();os.link(target, self.leaf)
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
        self.assertEqual(target.read_bytes(), b'keep');self.assertEqual(target.stat().st_nlink, 2)

    def test_invalid_inner_plan_never_acquires_a_slot_even_with_rehashed_outer_data(self):
        value = copy.deepcopy(self.plan);value['transaction'] += 'flush ruleset\n'
        value['transaction_sha256'] = hashlib.sha256(value['transaction'].encode()).hexdigest()
        with patch.object(BACKEND, 'locked', side_effect=AssertionError('disk')), self.assertRaises(ValueError):
            ATTEMPT.reserve(self.store, STATE.encoded(value) + b'\n')
        self.assertFalse(self.leaf.exists())

    def test_complete_record_types_commitments_and_canonical_bytes_are_required(self):
        raw = ATTEMPT.envelope(self.payload);value = json.loads(raw)
        for key, bad in (('namespace', True), ('namespace', self.plan['namespace'] + 1),
                         ('state', 'safe-to-retry'), ('correlation_id', '0' * 64),
                         ('transaction_sha256', '0' * 64), ('proposal_sha256', '0' * 64), ('proposal', None)):
            with self.subTest(key=key), self.assertRaises(ValueError):ATTEMPT.checked(STATE.encoded(value | {key: bad}) + b'\n')
        for changed in (raw[:-1], raw + b'\n', b' ' + raw, b'{"schema":1,"schema":2}', b'\xff', b'[]',
                        b'{"x":NaN}', b'x' * (ATTEMPT.MAX_BYTES + 1), bytearray(raw)):
            with self.subTest(kind=type(changed).__name__), self.assertRaises(ValueError):ATTEMPT.checked(changed)

    def test_invalid_expired_deadlines_and_protected_ancestry_precede_slot_creation(self):
        for deadline in (True, float('inf'), float('nan'), 'later', BACKEND.KERNEL.now() - 1):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):ATTEMPT.reserve(self.store, self.payload, deadline)
        self.store.chmod(0o770)
        with self.assertRaises(ValueError):ATTEMPT.reserve(self.store, self.payload)
        self.store.chmod(0o700);self.root.chmod(0o770)
        with self.assertRaises(ValueError):ATTEMPT.reserve(self.store, self.payload)
        self.root.chmod(0o700)
        with patch.object(BACKEND, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(ValueError):ATTEMPT.reserve(self.store, self.payload)
        self.assertFalse(self.leaf.exists())

    def test_nonblocking_cooperating_lock_refuses_without_creating_an_attempt(self):
        fd = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):ATTEMPT.reserve(self.store, self.payload)
            self.assertFalse(self.leaf.exists())
        finally:os.close(fd)

    def test_actual_short_writes_publish_exact_bytes_without_permitting_a_second_reservation(self):
        real = os.write;counts = []
        def short(fd, data):
            count = real(fd, data[:13]);counts.append(count);return count
        with patch.object(ATTEMPT.os, 'write', side_effect=short):raw = ATTEMPT.reserve(self.store, self.payload)
        self.assertGreater(len(counts), 1);self.assertEqual(sum(counts), len(raw));self.assertEqual(self.leaf.read_bytes(), raw)
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)

    def test_unknown_boolean_zero_or_oversized_write_result_leaves_a_blocking_slot(self):
        for result in (True, None, 0, -1, ATTEMPT.MAX_BYTES + 1):
            with self.subTest(result=result), patch.object(ATTEMPT.os, 'write', return_value=result), self.assertRaises(ATTEMPT.Blocked):
                ATTEMPT.reserve(self.store, self.payload)
            self.assertTrue(self.leaf.exists());self.assertEqual(self.leaf.read_bytes(), b'')
            with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
            self.leaf.unlink()  # TEST reset only; the production API has no reset

    def test_actual_partial_write_then_error_retains_exact_prefix_and_blocks_a_second_call(self):
        raw = ATTEMPT.envelope(self.payload);real = os.write;calls = []
        def interrupted(fd, data):
            calls.append(fd)
            if len(calls) == 1:return real(fd, data[:13])
            raise OSError('injected write error')
        with patch.object(ATTEMPT.os, 'write', side_effect=interrupted), self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
        self.assertEqual(self.leaf.read_bytes(), raw[:13])
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)

    def test_file_and_directory_sync_failures_retain_slot_and_withhold_success(self):
        real = os.fsync
        for directory in (False, True):
            def failure(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode) == directory:raise OSError('injected sync error')
                return real(fd)
            with self.subTest(directory=directory), patch.object(ATTEMPT.os, 'fsync', side_effect=failure), self.assertRaises(ATTEMPT.Blocked):
                ATTEMPT.reserve(self.store, self.payload)
            self.assertTrue(self.leaf.exists())
            with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
            self.leaf.unlink()

    def test_retired_reservation_descriptor_is_never_reclosed_after_number_reuse(self):
        close, opened = os.close, os.open;reused, calls = [], []
        other = self.root / 'independent';other.write_bytes(b'keep');other.chmod(0o600)
        def retire(fd):
            info = os.fstat(fd)
            if self.leaf.exists() and (info.st_dev, info.st_ino) == (self.leaf.stat().st_dev, self.leaf.stat().st_ino) and not calls:
                calls.append(fd);close(fd);new = opened(other, os.O_RDONLY);reused.append(new)
                self.assertEqual(new, fd);raise OSError('injected error AFTER actual descriptor retirement')
            close(fd)
        try:
            with patch.object(ATTEMPT.os, 'close', side_effect=retire), self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
            self.assertEqual(len(calls), 1);self.assertEqual(os.read(reused[0], 4), b'keep')
            self.assertEqual(os.fstat(reused[0]).st_ino, other.stat().st_ino)
        finally:
            for fd in reused:close(fd)
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)

    def test_readback_damage_never_removes_a_complete_reservation_or_returns_success(self):
        with patch.object(BACKEND, 'read_at', return_value=b'broken'), self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)
        self.assertEqual(self.leaf.read_bytes(), ATTEMPT.envelope(self.payload))
        with self.assertRaises(ATTEMPT.Blocked):ATTEMPT.reserve(self.store, self.payload)

    def test_private_loader_refuses_external_links_modes_and_partial_records_without_repair(self):
        ATTEMPT.reserve(self.store, self.payload);extra = self.root / 'external';os.link(self.leaf, extra)
        with self.assertRaises(ValueError):ATTEMPT.load(self.store)
        extra.unlink();self.leaf.chmod(0o660)
        with self.assertRaises(ValueError):ATTEMPT.load(self.store)
        self.leaf.chmod(0o600);self.leaf.write_bytes(b'partial')
        with self.assertRaises(ValueError):ATTEMPT.load(self.store)
        self.assertEqual(self.leaf.read_bytes(), b'partial')


if __name__ == '__main__':unittest.main()
