import ast
import fcntl
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import test_first_create as plan_fixture
import test_proposal_store as old_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_register', ROOT / 'Firewall/first_register.py')
REGISTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGISTER)
BACKEND, STATE, KERNEL = REGISTER._STORAGE, REGISTER.MATCH.STATE, REGISTER.KERNEL


def encoded(value):
    return STATE.encoded(value) + b'\n'


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        helper = plan_fixture.PlanTests();helper.setUp()
        try:self.payload = helper.prepare()
        finally:helper.doCleanups()
        self.plan = json.loads(self.payload)
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-register-', dir='/dev/shm');self.addCleanup(directory.cleanup)
        self.root = Path(directory.name);self.root.chmod(0o700)
        self.store = self.root / 'registration';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf = self.store / REGISTER.LEAF
        for setting in (patch.object(BACKEND, 'TRUST_ROOT', self.root), patch.object(BACKEND, 'TRUSTED_UID', os.geteuid())):
            setting.start();self.addCleanup(setting.stop)

    def test_real_prepared_intention_is_registered_and_loaded_as_exact_historical_bytes(self):
        self.assertEqual(REGISTER.create(self.store, self.payload), self.payload)
        self.assertEqual(REGISTER.load(self.store), self.payload)
        raw = self.leaf.read_bytes();value = json.loads(raw)
        self.assertEqual(raw, encoded(value));self.assertEqual(stat.S_IMODE(self.leaf.stat().st_mode), 0o600)
        self.assertEqual(self.leaf.stat().st_nlink, 1)
        self.assertEqual(value['schema'], 'debian13s4-first-create-registration-1')
        self.assertEqual(value['state'], 'historical-first-create-intention')
        self.assertEqual(value['payload'].encode('utf-8'), self.payload)
        self.assertEqual(value['payload_sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(value['namespace'], self.plan['namespace'])
        self.assertEqual(value['correlation_id'], self.plan['correlation_id'])
        self.assertEqual(value['transaction_sha256'], self.plan['transaction_sha256'])
        self.assertEqual({path.name for path in self.store.iterdir()}, {REGISTER.LEAF})

    def test_backend_has_separate_globals_and_preserves_all_closed_storage_function_bodies(self):
        old = old_fixture.STORE
        self.assertIsNot(BACKEND, old);self.assertIsNot(BACKEND.__dict__, old.__dict__)
        self.assertEqual(old.LEAF, 'proposal.json');self.assertEqual(REGISTER.LEAF, 'first-create.json')
        self.assertIsNot(old.envelope, REGISTER.envelope);self.assertIsNot(old.checked, REGISTER.checked)
        self.assertIs(BACKEND.envelope, REGISTER.envelope);self.assertIs(BACKEND.checked, REGISTER.checked)
        for name in ('create', 'load', 'window', 'admission', 'locked', 'read_at', 'reconcile_link',
                     'directory_identity', 'directory_matches', 'file_identity', 'staging_identity'):
            self.assertIs(getattr(BACKEND, name).__globals__, BACKEND.__dict__)
            self.assertEqual(ast.dump(ast.parse(inspect.getsource(getattr(BACKEND, name)))),
                             ast.dump(ast.parse(inspect.getsource(getattr(old, name)))))

    def test_same_bytes_resync_without_replacement_and_a_different_identifier_never_overwrites(self):
        REGISTER.create(self.store, self.payload);before = self.leaf.read_bytes();inode = self.leaf.stat().st_ino
        self.assertEqual(REGISTER.create(self.store, self.payload), self.payload);self.assertEqual(self.leaf.stat().st_ino, inode)
        helper = plan_fixture.PlanTests();helper.setUp()
        try:other = helper.prepare()
        finally:helper.doCleanups()
        self.assertNotEqual(json.loads(other)['correlation_id'], self.plan['correlation_id'])
        with self.assertRaises(ValueError):REGISTER.create(self.store, other)
        self.assertEqual(self.leaf.read_bytes(), before);self.assertEqual(self.leaf.stat().st_ino, inode)

    def test_load_is_historical_and_never_queries_current_scope_or_nft(self):
        REGISTER.create(self.store, self.payload)
        with (patch.object(KERNEL, 'namespace', side_effect=AssertionError('fresh context')),
              patch.object(REGISTER.MATCH.STATE.NFT, 'native_query', side_effect=AssertionError('nft query')),
              patch.object(REGISTER.MATCH, 'verify', side_effect=AssertionError('marked observer'))):
            self.assertEqual(REGISTER.load(self.store), self.payload)

    def test_old_and_new_protocols_refuse_each_others_bytes_without_widening_old_admission(self):
        with self.assertRaises(ValueError):old_fixture.STORE.envelope(self.payload)
        helper = old_fixture.automatic_fixture.AutomaticTests();helper.setUp()
        try:old = helper.prepare()
        finally:helper.doCleanups()
        with self.assertRaises(ValueError):REGISTER.create(self.store, old)
        with self.assertRaises(ValueError):REGISTER.checked(old_fixture.STORE.envelope(old))
        with self.assertRaises(ValueError):old_fixture.STORE.checked(REGISTER.envelope(self.payload))
        self.assertEqual(list(self.store.iterdir()), [])

    def test_invalid_plan_or_forged_transaction_never_opens_storage(self):
        for change in ('transaction', 'transaction_sha256', 'intention', 'namespace', 'profile', 'correlation_id'):
            plan = json.loads(self.payload)
            if change == 'transaction':
                plan[change] = plan[change].replace('create table', 'add table', 1)
                plan['transaction_sha256'] = hashlib.sha256(plan[change].encode()).hexdigest()
            elif change == 'intention':plan[change]['policy']['rules']['input'][0]['expr'][-1] = {'accept': None}
            elif change == 'namespace':plan[change] = True
            else:plan[change] = 'bad'
            with (self.subTest(change=change), patch.object(BACKEND, 'locked', side_effect=AssertionError('disk admission')),
                  self.assertRaises(ValueError)):REGISTER.create(self.store, encoded(plan))
        self.assertEqual(list(self.store.iterdir()), [])

    def test_required_envelope_fields_and_public_correlation_cannot_be_forged_applied_or_relabelled(self):
        original = json.loads(REGISTER.envelope(self.payload))
        for key in original:
            value = original.copy();del value[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):REGISTER.checked(encoded(value))
        for key, bad in (('schema', 'debian13s4-nft-intent-history-1'), ('state', 'installed'),
                         ('namespace', True), ('namespace', self.plan['namespace'] + 1),
                         ('correlation_id', 'a' * 64), ('transaction_sha256', '0' * 64),
                         ('payload_sha256', '0' * 64), ('payload', None)):
            with self.subTest(key=key), self.assertRaises(ValueError):REGISTER.checked(encoded(original | {key: bad}))
        with self.assertRaises(ValueError):REGISTER.checked(encoded(original | {'owned': True}))

    def test_noncanonical_duplicate_invalid_utf8_nonfinite_and_oversized_records_refuse(self):
        envelope = REGISTER.envelope(self.payload)
        for raw in (envelope[:-1], b' ' + envelope, envelope + b'\n', b'{"schema":1,"schema":2}',
                    b'{"namespace":NaN}', b'\xff', b'[]', b'null', bytearray(envelope), 'text',
                    b'x' * (REGISTER.MAX_BYTES + 1)):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(ValueError):REGISTER.checked(raw)
        with patch.object(REGISTER, 'MAX_BYTES', 1), self.assertRaises(ValueError):REGISTER.envelope(self.payload)

    def test_payload_encoding_damage_is_not_repaired_by_recomputing_an_outer_hash(self):
        original = json.loads(REGISTER.envelope(self.payload))
        for text in (self.payload.decode()[:-1], ' ' + self.payload.decode(), '{}\n', '\ud800'):
            value = original | {'payload': text}
            if text != '\ud800':value['payload_sha256'] = hashlib.sha256(text.encode()).hexdigest()
            raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode() + b'\n'
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):REGISTER.checked(raw)

    def test_private_directory_protected_ancestry_path_kind_mode_and_owner_remain_mandatory(self):
        self.store.chmod(0o770)
        with self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.store.chmod(0o700);alias = self.root / 'alias';alias.symlink_to(self.store, target_is_directory=True)
        for path in (alias, Path('relative'), self.root / 'missing'):
            with self.subTest(path=str(path)), self.assertRaises((ValueError, OSError)):REGISTER.create(path, self.payload)
        with patch.object(BACKEND, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.root.chmod(0o770)
        with self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.root.chmod(0o700);self.assertEqual(list(self.store.iterdir()), [])

    def test_symlink_fifo_directory_unsafe_and_external_linked_leaf_do_not_grant_registration(self):
        target = self.root / 'unrelated';target.write_bytes(b'keep');self.leaf.symlink_to(target)
        with self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.assertEqual(target.read_bytes(), b'keep');self.leaf.unlink();os.mkfifo(self.leaf, 0o600)
        with self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.leaf.unlink();self.leaf.mkdir()
        with self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.leaf.rmdir();REGISTER.create(self.store, self.payload);self.leaf.chmod(0o660)
        with self.assertRaises(ValueError):REGISTER.load(self.store)
        self.leaf.chmod(0o600);extra = self.root / 'external-link';os.link(self.leaf, extra)
        with self.assertRaises(ValueError):REGISTER.load(self.store)
        with self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.assertTrue(extra.exists())

    def test_nonblocking_directory_lock_refuses_without_mutation(self):
        fd = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):REGISTER.create(self.store, self.payload)
            self.assertEqual(list(self.store.iterdir()), [])
        finally:os.close(fd)

    def test_same_intent_file_and_directory_sync_complete_before_success(self):
        events = [];real = BACKEND.os.fsync
        def sync(fd):events.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file');return real(fd)
        with patch.object(BACKEND.os, 'fsync', side_effect=sync):REGISTER.create(self.store, self.payload)
        self.assertEqual(events, ['file', 'directory'])
        events.clear()
        with patch.object(BACKEND.os, 'fsync', side_effect=sync):REGISTER.create(self.store, self.payload)
        self.assertEqual(events, ['file', 'directory'])

    def test_short_writes_complete_exact_record_but_zero_or_io_failure_never_publishes(self):
        real = BACKEND.os.write
        with patch.object(BACKEND.os, 'write', side_effect=lambda fd, data: real(fd, data[:137])):
            self.assertEqual(REGISTER.create(self.store, self.payload), self.payload)
        self.assertEqual(REGISTER.load(self.store), self.payload);self.leaf.unlink()
        for result in (0, True, -1, None):
            with self.subTest(result=result), patch.object(BACKEND.os, 'write', return_value=result), self.assertRaises(ValueError):
                REGISTER.create(self.store, self.payload)
            self.assertEqual(list(self.store.iterdir()), [])
        with patch.object(BACKEND.os, 'write', side_effect=OSError('write refused')), self.assertRaises(OSError):REGISTER.create(self.store, self.payload)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_sync_failures_withhold_success_and_visible_history_is_only_same_intent_retryable(self):
        with patch.object(BACKEND.os, 'fsync', side_effect=OSError('file sync')), self.assertRaises(OSError):REGISTER.create(self.store, self.payload)
        self.assertEqual(list(self.store.iterdir()), [])
        real = BACKEND.os.fsync
        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('directory sync')
            return real(fd)
        with patch.object(BACKEND.os, 'fsync', side_effect=sync), self.assertRaises(OSError):REGISTER.create(self.store, self.payload)
        self.assertTrue(self.leaf.exists());before = self.leaf.read_bytes()
        self.assertEqual(REGISTER.create(self.store, self.payload), self.payload);self.assertEqual(self.leaf.read_bytes(), before)

    def test_no_replace_publication_preserves_a_leaf_appearing_before_link(self):
        real = BACKEND.os.link
        def link(*args, **kwargs):self.leaf.write_bytes(b'foreign');self.leaf.chmod(0o600);return real(*args, **kwargs)
        with patch.object(BACKEND.os, 'link', side_effect=link), self.assertRaises(FileExistsError):REGISTER.create(self.store, self.payload)
        self.assertEqual(self.leaf.read_bytes(), b'foreign');self.assertEqual({path.name for path in self.store.iterdir()}, {REGISTER.LEAF})

    def test_exclusive_collision_preserves_an_unowned_staging_inode_and_bytes(self):
        nonce = 'a' * 32;stage = self.store / ('.proposal-' + nonce);stage.write_bytes(b'orphan sentinel');stage.chmod(0o600)
        identity = (stage.stat().st_dev, stage.stat().st_ino)
        with patch.object(BACKEND.secrets, 'token_hex', return_value=nonce), self.assertRaises(FileExistsError):REGISTER.create(self.store, self.payload)
        self.assertEqual((stage.stat().st_dev, stage.stat().st_ino), identity);self.assertEqual(stage.read_bytes(), b'orphan sentinel')
        self.assertFalse(self.leaf.exists());self.assertEqual({path.name for path in self.store.iterdir()}, {stage.name})

    def test_create_close_error_preserves_an_independently_reused_fd_and_never_retries_it(self):
        unrelated = self.root / 'independent';unrelated.write_bytes(b'survive')
        real_open, real_close = BACKEND.os.open, BACKEND.os.close
        delivery = {'staging': None, 'replacement': None, 'closes': 0}
        def opened(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            if flags & os.O_EXCL:delivery['staging'] = fd
            return fd
        def closed(fd):
            if fd == delivery['staging']:
                delivery['closes'] += 1
                if delivery['closes'] == 1:
                    real_close(fd);delivery['replacement'] = real_open(unrelated, os.O_RDONLY | os.O_CLOEXEC)
                    self.assertEqual(delivery['replacement'], fd);raise OSError('close after retirement')
            return real_close(fd)
        try:
            with patch.object(BACKEND.os, 'open', side_effect=opened), patch.object(BACKEND.os, 'close', side_effect=closed), self.assertRaises(OSError):
                REGISTER.create(self.store, self.payload)
            self.assertEqual(delivery['closes'], 1);self.assertEqual(os.read(delivery['replacement'], 7), b'survive')
            self.assertEqual(os.fstat(delivery['replacement']).st_ino, unrelated.stat().st_ino);self.assertTrue(self.leaf.exists())
        finally:
            if delivery['replacement'] is not None:real_close(delivery['replacement'])

    def test_failed_write_cannot_unlink_a_replaced_staging_name(self):
        nonce = 'b' * 32;stage = self.store / ('.proposal-' + nonce);moved = self.store / 'held-inode'
        def write(fd, data):stage.rename(moved);stage.write_bytes(b'replacement');stage.chmod(0o600);raise OSError('interrupted')
        with patch.object(BACKEND.secrets, 'token_hex', return_value=nonce), patch.object(BACKEND.os, 'write', side_effect=write), self.assertRaises(ValueError):
            REGISTER.create(self.store, self.payload)
        self.assertEqual(stage.read_bytes(), b'replacement');self.assertTrue(moved.exists());self.assertFalse(self.leaf.exists())

    def test_same_intent_two_link_stage_recovers_but_different_or_unknown_links_are_retained(self):
        REGISTER.create(self.store, self.payload);stage = self.store / ('.proposal-' + 'c' * 32);os.link(self.leaf, stage)
        before = self.leaf.read_bytes();self.assertEqual(REGISTER.create(self.store, self.payload), self.payload)
        self.assertEqual(self.leaf.read_bytes(), before);self.assertFalse(stage.exists());self.assertEqual(self.leaf.stat().st_nlink, 1)
        unknown = self.store / '.unrecognized';os.link(self.leaf, unknown)
        with self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.assertTrue(unknown.exists());unknown.unlink();os.link(self.leaf, stage)
        changed = self.plan | {'namespace': self.plan['namespace'] + 1}
        with self.assertRaises(ValueError):REGISTER.create(self.store, encoded(changed))
        self.assertTrue(stage.exists());self.assertEqual(self.leaf.stat().st_nlink, 2)

    def test_interrupted_unlink_is_failure_and_same_registered_plan_can_recover(self):
        with patch.object(BACKEND.os, 'unlink', side_effect=OSError('unlink')), self.assertRaises(OSError):REGISTER.create(self.store, self.payload)
        self.assertEqual(self.leaf.stat().st_nlink, 2);before = self.leaf.read_bytes()
        self.assertEqual(REGISTER.create(self.store, self.payload), self.payload)
        self.assertEqual(self.leaf.read_bytes(), before);self.assertEqual(self.leaf.stat().st_nlink, 1)

    def test_oversized_recovery_inventory_does_not_guess_away_names(self):
        REGISTER.create(self.store, self.payload);stage = self.store / ('.proposal-' + 'd' * 32);os.link(self.leaf, stage)
        for index in range(31):(self.store / ('foreign-' + str(index))).write_bytes(b'keep')
        with self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.assertTrue(stage.exists());self.assertEqual(len(list(self.store.iterdir())), 33)

    def test_corrupt_oversized_and_changed_descriptor_path_fail_real_readback(self):
        REGISTER.create(self.store, self.payload);raw = self.leaf.read_bytes()
        for damage in (b'corrupt', b'x' * (REGISTER.MAX_BYTES + 1)):
            self.leaf.write_bytes(damage)
            with self.subTest(size=len(damage)), self.assertRaises(ValueError):REGISTER.load(self.store)
        self.leaf.write_bytes(raw);real = BACKEND.os.read;changed = []
        def read(fd, count):
            data = real(fd, count)
            if not changed:self.leaf.rename(self.store / 'old');self.leaf.write_bytes(raw);self.leaf.chmod(0o600);changed.append(True)
            return data
        with patch.object(BACKEND.os, 'read', side_effect=read), self.assertRaises(ValueError):REGISTER.load(self.store)

    def test_postpublication_damage_withholds_a_completed_registration(self):
        real = BACKEND.os.fsync
        def sync(fd):
            real(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):self.leaf.write_bytes(b'damaged');self.leaf.chmod(0o600)
        with patch.object(BACKEND.os, 'fsync', side_effect=sync), self.assertRaises(ValueError):REGISTER.create(self.store, self.payload)
        self.assertEqual(self.leaf.read_bytes(), b'damaged')

    def test_invalid_and_expired_inherited_deadlines_never_admit_storage(self):
        for deadline in (True, float('nan'), float('inf'), '10', KERNEL.now() - 1):
            with (self.subTest(deadline=deadline), patch.object(BACKEND, 'locked', side_effect=AssertionError('lock')),
                  self.assertRaises(ValueError)):REGISTER.create(self.store, self.payload, deadline=deadline)
        clock = [KERNEL.now()];original = REGISTER.envelope
        def envelope(payload):result = original(payload);clock[0] += 11;return result
        with (patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(BACKEND, 'envelope', side_effect=envelope),
              patch.object(BACKEND, 'locked', side_effect=AssertionError('expired lock')), self.assertRaises(ValueError)):
            REGISTER.create(self.store, self.payload)

    def test_create_and_load_keep_same_inherited_minimum_windows(self):
        now = KERNEL.now();seen = [];real = BACKEND.locked
        def locked(path, end):seen.append(end);return real(path, end)
        with patch.object(KERNEL, 'now', return_value=now), patch.object(BACKEND, 'locked', side_effect=locked):
            REGISTER.create(self.store, self.payload, deadline=now + 2);REGISTER.load(self.store, deadline=now + 50)
        self.assertEqual(seen, [now + 2, now + 10])

    def test_final_window_expiry_after_real_readback_withholds_success(self):
        now = KERNEL.now();clock = [now];real = BACKEND.read_at
        def read(*args, **kwargs):result = real(*args, **kwargs);clock[0] = now + 11;return result
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(BACKEND, 'read_at', side_effect=read), self.assertRaises(ValueError):
            REGISTER.create(self.store, self.payload)
        self.assertTrue(self.leaf.exists())


if __name__ == '__main__':unittest.main()
