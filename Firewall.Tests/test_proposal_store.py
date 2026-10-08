import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import test_auto_intent as automatic_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_proposal_store', ROOT / 'Firewall/proposal_store.py')
STORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORE)


class ProposalTests(unittest.TestCase):
    def setUp(self):
        helper = automatic_fixture.AutomaticTests();helper.setUp()
        try:self.payload = helper.prepare()
        finally:helper.doCleanups()
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-proposal-', dir='/dev/shm')
        self.root = Path(self.directory.name);self.root.chmod(0o700)
        self.store = self.root / 'state';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.settings = [patch.object(STORE, 'TRUST_ROOT', self.root), patch.object(STORE, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def test_real_automatic_proposal_compiler_check_create_and_load_preserve_exact_bytes(self):
        self.assertEqual(STORE.create(self.store, self.payload), self.payload)
        self.assertEqual(STORE.load(self.store), self.payload)
        leaf = self.store / STORE.LEAF
        self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o600)
        record = json.loads(leaf.read_bytes())
        self.assertEqual(record['state'], 'historical-proposal')
        self.assertEqual(record['payload'].encode(), self.payload)
        self.assertEqual(set(path.name for path in self.store.iterdir()), {STORE.LEAF})

    def test_existing_equal_proposal_is_idempotent_and_existing_different_intent_is_preserved(self):
        STORE.create(self.store, self.payload);leaf = self.store / STORE.LEAF;before = leaf.read_bytes();inode = leaf.stat().st_ino
        self.assertEqual(STORE.create(self.store, self.payload), self.payload);self.assertEqual(leaf.stat().st_ino, inode)
        value = json.loads(self.payload);value['namespace'] += 1
        other = STORE.MANIFEST.STATE.encoded(value) + b'\n'
        with self.assertRaises(STORE.Pending):STORE.create(self.store, other)
        self.assertEqual(leaf.read_bytes(), before);self.assertEqual(leaf.stat().st_ino, inode)

    def test_history_remains_readable_in_a_different_current_namespace_without_becoming_fresh(self):
        STORE.create(self.store, self.payload)
        with patch.object(STORE.KERNEL, 'namespace', side_effect=AssertionError('no fresh scope claim')):
            self.assertEqual(STORE.load(self.store), self.payload)
        self.assertEqual(json.loads((self.store / STORE.LEAF).read_bytes())['state'], 'historical-proposal')

    def test_real_intention_payload_tampering_and_boolean_numeric_alias_cannot_be_stored(self):
        for field in ('policy', 'fingerprint', 'compiler_sha256', 'topology_sha256'):
            value = json.loads(self.payload)
            if field == 'policy':value['intention'][field]['rules']['input'][0]['expr'][-1] = {'accept': None}
            else:value['intention'][field] = '0' * 64
            with self.subTest(field=field), self.assertRaises(STORE.Pending):STORE.create(self.store, STORE.MANIFEST.STATE.encoded(value) + b'\n')
        value = json.loads(self.payload)
        rule = value['intention']['policy']['rules']['input'][0]
        rule['expr'][0]['match']['right'] = True
        with self.assertRaises(STORE.Pending):STORE.intent(STORE.MANIFEST.STATE.encoded(value) + b'\n')
        self.assertEqual(list(self.store.iterdir()), [])

    def test_wrong_profile_state_namespace_schema_and_missing_fields_refuse_before_disk_mutation(self):
        for key, bad in (('schema', 'other'), ('profile', 'other'), ('admission_profile', 'other'),
                         ('namespace', True), ('namespace', 0), ('namespace', 1 << 64)):
            value = json.loads(self.payload);value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(STORE.Pending):STORE.create(self.store, STORE.MANIFEST.STATE.encoded(value) + b'\n')
        value = json.loads(self.payload);value.pop('topology')
        with self.assertRaises(STORE.Pending):STORE.create(self.store, STORE.MANIFEST.STATE.encoded(value) + b'\n')
        self.assertEqual(list(self.store.iterdir()), [])

    def test_noncanonical_duplicate_nonutf8_nonfinite_and_oversized_bytes_refuse(self):
        for payload in (self.payload[:-1], b' '+self.payload, b'{"x":1,"x":2}', b'\xff', b'{"x":NaN}',
                        b'x' * (STORE.AUTO.MAX_OUTPUT + 1), bytearray(self.payload), 'text'):
            with self.subTest(kind=type(payload).__name__), self.assertRaises(STORE.Pending):STORE.create(self.store, payload)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_existing_corrupt_payload_or_forged_applied_state_never_certifies_history(self):
        STORE.create(self.store, self.payload);leaf = self.store / STORE.LEAF
        for change in ('state', 'sha256', 'payload'):
            raw = json.loads(STORE.envelope(self.payload))
            raw[change] = 'applied' if change == 'state' else 'wrong'
            leaf.write_bytes(STORE.MANIFEST.STATE.encoded(raw) + b'\n')
            with self.subTest(change=change), self.assertRaises(STORE.Pending):STORE.load(self.store)

    def test_foreign_unsafe_symbolic_or_wrong_kind_directory_refuses(self):
        self.store.chmod(0o770)
        with self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)
        self.store.chmod(0o700);alias = self.root / 'alias';alias.symlink_to(self.store, target_is_directory=True)
        with self.assertRaises(STORE.Pending):STORE.create(alias, self.payload)
        with self.assertRaises((STORE.Pending, ValueError)):STORE.create(Path('relative'), self.payload)
        with patch.object(STORE, 'TRUSTED_UID', os.geteuid()+1), self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_leaf_symlink_fifo_directory_and_unsafe_mode_are_rejected_without_follow_or_truncate(self):
        leaf = self.store / STORE.LEAF;target = self.root / 'unrelated';target.write_bytes(b'keep')
        leaf.symlink_to(target)
        with self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)
        self.assertEqual(target.read_bytes(), b'keep');leaf.unlink()
        os.mkfifo(leaf, 0o600)
        with self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)
        leaf.unlink();leaf.mkdir()
        with self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)
        leaf.rmdir();STORE.create(self.store, self.payload);leaf.chmod(0o660)
        with self.assertRaises(STORE.Pending):STORE.load(self.store)

    def test_linked_leaf_is_not_admitted_as_a_unique_private_record(self):
        STORE.create(self.store, self.payload);os.link(self.store / STORE.LEAF, self.root / 'extra')
        with self.assertRaises(STORE.Pending):STORE.load(self.store)
        with self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)

    def test_directory_lock_contention_is_nonblocking_and_no_new_file_is_created(self):
        fd = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):STORE.create(self.store, self.payload)
            self.assertEqual(list(self.store.iterdir()), [])
        finally:os.close(fd)

    def test_expired_invalid_or_boolean_deadlines_refuse_before_directory_admission(self):
        for end in (True, float('nan'), float('inf'), 'later', STORE.KERNEL.now()-1, 10**10000):
            with (self.subTest(kind=type(end).__name__), patch.object(STORE, 'directory_identity', side_effect=AssertionError('directory')),
                  self.assertRaises(STORE.Pending)):STORE.create(self.store, self.payload, deadline=end)

    def test_short_writes_are_completed_and_zero_or_unknown_write_results_fail_closed(self):
        real = STORE.os.write
        def short(fd, data):return real(fd, data[:17])
        with patch.object(STORE.os, 'write', side_effect=short):self.assertEqual(STORE.create(self.store, self.payload), self.payload)
        for result in (0, True, None, -1):
            (self.store / STORE.LEAF).unlink()
            with self.subTest(result=result), patch.object(STORE.os, 'write', return_value=result), self.assertRaises(STORE.Pending):
                STORE.create(self.store, self.payload)
            self.assertEqual(list(self.store.iterdir()), [])
            if result != -1:STORE.create(self.store, self.payload)

    def test_file_and_directory_sync_are_checked_in_publication_order(self):
        real = STORE.os.fsync;events=[]
        def sync(fd):events.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file');return real(fd)
        with patch.object(STORE.os, 'fsync', side_effect=sync):STORE.create(self.store, self.payload)
        self.assertEqual(events, ['file', 'directory'])
        events.clear()
        with patch.object(STORE.os, 'fsync', side_effect=sync):STORE.create(self.store, self.payload)
        self.assertEqual(events, ['file', 'directory'])

    def test_file_sync_failure_withholds_publication_and_cleans_owned_staging(self):
        with patch.object(STORE.os, 'fsync', side_effect=OSError('fixture file sync')), self.assertRaises(OSError):STORE.create(self.store, self.payload)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_directory_sync_failure_remains_failure_but_published_history_survives_retry(self):
        real = STORE.os.fsync
        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('fixture directory sync')
            return real(fd)
        with patch.object(STORE.os, 'fsync', side_effect=sync), self.assertRaises(OSError):STORE.create(self.store, self.payload)
        self.assertTrue((self.store / STORE.LEAF).is_file())
        self.assertEqual(STORE.create(self.store, self.payload), self.payload)

    def test_no_replace_link_keeps_a_concurrently_appearing_leaf_unchanged(self):
        real = STORE.os.link;leaf = self.store / STORE.LEAF
        def link(*args, **kwargs):leaf.write_bytes(b'keep');leaf.chmod(0o600);return real(*args, **kwargs)
        with patch.object(STORE.os, 'link', side_effect=link), self.assertRaises(FileExistsError):STORE.create(self.store, self.payload)
        self.assertEqual(leaf.read_bytes(), b'keep');self.assertEqual([p.name for p in self.store.iterdir()], [STORE.LEAF])

    def test_positive_readback_rejects_postpublication_byte_damage(self):
        real = STORE.os.fsync
        def sync(fd):
            value = real(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                leaf = self.store / STORE.LEAF;leaf.write_bytes(b'corrupt');leaf.chmod(0o600)
            return value
        with patch.object(STORE.os, 'fsync', side_effect=sync), self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)

    def test_descriptor_path_change_during_read_refuses(self):
        STORE.create(self.store, self.payload);real = STORE.os.read;changed = [False]
        def read(fd, count):
            data = real(fd, count)
            if not changed[0]:
                changed[0]=True;leaf=self.store / STORE.LEAF;leaf.rename(self.store / 'old');leaf.write_bytes(STORE.envelope(self.payload));leaf.chmod(0o600)
            return data
        with patch.object(STORE.os, 'read', side_effect=read), self.assertRaises(STORE.Pending):STORE.load(self.store)

    def test_io_read_close_or_link_failure_never_reports_success(self):
        STORE.create(self.store, self.payload)
        with patch.object(STORE.os, 'read', side_effect=OSError('fixture read')), self.assertRaises(OSError):STORE.load(self.store)
        real = STORE.os.close
        def close(fd):
            regular = stat.S_ISREG(os.fstat(fd).st_mode);real(fd)
            if regular:raise OSError('fixture close')
        with patch.object(STORE.os, 'close', side_effect=close), self.assertRaises(OSError):STORE.load(self.store)
        (self.store / STORE.LEAF).unlink()
        with patch.object(STORE.os, 'link', side_effect=OSError('fixture link')), self.assertRaises(OSError):STORE.create(self.store, self.payload)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_interrupted_staging_unlink_retains_proposal_and_recovers_same_intent_on_retry(self):
        with patch.object(STORE.os, 'unlink', side_effect=OSError('fixture staging unlink')), self.assertRaises(OSError):
            STORE.create(self.store, self.payload)
        leaf = self.store / STORE.LEAF
        self.assertTrue(leaf.exists());self.assertEqual(leaf.stat().st_nlink, 2)
        before = leaf.read_bytes()
        self.assertEqual(STORE.create(self.store, self.payload), self.payload)
        self.assertEqual(leaf.read_bytes(), before);self.assertEqual(leaf.stat().st_nlink, 1)
        self.assertEqual({p.name for p in self.store.iterdir()}, {STORE.LEAF})

    def linked_stage(self):
        STORE.create(self.store, self.payload)
        stage = self.store / ('.proposal-' + 'a' * 32)
        os.link(self.store / STORE.LEAF, stage)
        return stage

    def test_staging_reconciliation_requires_exact_same_historical_intent(self):
        stage = self.linked_stage();value = json.loads(self.payload);value['namespace'] += 1
        other = STORE.MANIFEST.STATE.encoded(value) + b'\n'
        with self.assertRaises(STORE.Pending):STORE.create(self.store, other)
        self.assertTrue(stage.exists());self.assertEqual(stage.stat().st_nlink, 2)

    def test_unknown_extra_link_and_unbounded_inventory_do_not_delete_unrelated_names(self):
        stage = self.linked_stage()
        for index in range(31):(self.store / ('unrelated-' + str(index))).write_bytes(b'keep')
        with self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)
        self.assertTrue(stage.exists())
        self.assertEqual(len(list(self.store.iterdir())), 33)

    def test_unrecognized_staging_name_is_retained_as_pending(self):
        STORE.create(self.store, self.payload);stage = self.store / '.unknown-staging'
        os.link(self.store / STORE.LEAF, stage)
        with self.assertRaises(STORE.Pending):STORE.create(self.store, self.payload)
        self.assertTrue(stage.exists());self.assertEqual(stage.stat().st_nlink, 2)

    def test_reconciliation_sync_failure_withholds_success_and_next_retry_resyncs_history(self):
        self.linked_stage();real = STORE.os.fsync
        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('fixture reconcile directory sync')
            return real(fd)
        with patch.object(STORE.os, 'fsync', side_effect=sync), self.assertRaises(OSError):STORE.create(self.store, self.payload)
        self.assertEqual((self.store / STORE.LEAF).stat().st_nlink, 1)
        self.assertEqual(STORE.create(self.store, self.payload), self.payload)

    def test_exclusive_nonce_collision_preserves_unowned_staging_inode_and_bytes(self):
        nonce = 'b' * 32;stage = self.store / ('.proposal-' + nonce)
        stage.write_bytes(b'pre-existing orphan must survive');stage.chmod(0o600)
        before = stage.stat()
        with patch.object(STORE.secrets, 'token_hex', return_value=nonce), self.assertRaises(FileExistsError):
            STORE.create(self.store, self.payload)
        self.assertTrue(stage.exists())
        self.assertEqual((stage.stat().st_dev, stage.stat().st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(stage.read_bytes(), b'pre-existing orphan must survive')
        self.assertEqual({p.name for p in self.store.iterdir()}, {stage.name})
        self.assertFalse((self.store / STORE.LEAF).exists())

    def test_create_close_error_retires_owned_fd_once_and_preserves_actual_reused_descriptor(self):
        unrelated = self.root / 'independent-resource';unrelated.write_bytes(b'keep open')
        real_open, real_close = STORE.os.open, STORE.os.close
        delivery = {'staging':None, 'replacement':None, 'closes':0}
        def opened(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            if flags & os.O_EXCL:delivery['staging'] = fd
            return fd
        def closed(fd):
            if fd == delivery['staging']:
                delivery['closes'] += 1
                if delivery['closes'] == 1:
                    real_close(fd)
                    delivery['replacement'] = real_open(unrelated, os.O_RDONLY | os.O_CLOEXEC)
                    self.assertEqual(delivery['replacement'], fd)
                    raise OSError('fixture close error after descriptor retirement')
            return real_close(fd)
        try:
            with (patch.object(STORE.os, 'open', side_effect=opened), patch.object(STORE.os, 'close', side_effect=closed),
                  self.assertRaisesRegex(OSError, 'fixture close error after descriptor retirement')):
                STORE.create(self.store, self.payload)
            self.assertEqual(delivery['closes'], 1)
            self.assertEqual(os.read(delivery['replacement'], 9), b'keep open')
            self.assertEqual((os.fstat(delivery['replacement']).st_dev, os.fstat(delivery['replacement']).st_ino),
                             (unrelated.stat().st_dev, unrelated.stat().st_ino))
            self.assertTrue((self.store / STORE.LEAF).exists())
            self.assertEqual({p.name for p in self.store.iterdir()}, {STORE.LEAF})
        finally:
            if delivery['replacement'] is not None:
                try:info = os.fstat(delivery['replacement'])
                except OSError:pass
                else:
                    if (info.st_dev, info.st_ino) == (unrelated.stat().st_dev, unrelated.stat().st_ino):
                        real_close(delivery['replacement'])

    def test_failed_write_cleanup_preserves_a_replacement_at_the_owned_staging_name(self):
        nonce = 'c' * 32;stage = self.store / ('.proposal-' + nonce)
        moved = self.store / 'owned-but-renamed';replacement = {}
        def failed_write(fd, data):
            stage.rename(moved);stage.write_bytes(b'unrelated replacement');stage.chmod(0o600)
            replacement['identity'] = (stage.stat().st_dev, stage.stat().st_ino)
            raise OSError('fixture write interrupted after path replacement')
        with (patch.object(STORE.secrets, 'token_hex', return_value=nonce),
              patch.object(STORE.os, 'write', side_effect=failed_write), self.assertRaises(STORE.Pending)):
            STORE.create(self.store, self.payload)
        self.assertEqual((stage.stat().st_dev, stage.stat().st_ino), replacement['identity'])
        self.assertEqual(stage.read_bytes(), b'unrelated replacement')
        self.assertTrue(moved.exists())
        self.assertFalse((self.store / STORE.LEAF).exists())

    def test_unverifiable_acquired_staging_identity_withholds_cleanup_and_publication(self):
        nonce = 'd' * 32;stage = self.store / ('.proposal-' + nonce);real = STORE.os.fstat
        def unverifiable(fd):
            info = real(fd)
            if stat.S_ISREG(info.st_mode):raise OSError('fixture acquired identity unavailable')
            return info
        with (patch.object(STORE.secrets, 'token_hex', return_value=nonce),
              patch.object(STORE.os, 'fstat', side_effect=unverifiable),
              self.assertRaisesRegex(OSError, 'fixture acquired identity unavailable')):
            STORE.create(self.store, self.payload)
        self.assertTrue(stage.exists());self.assertEqual(stage.read_bytes(), b'')
        self.assertEqual({p.name for p in self.store.iterdir()}, {stage.name})
        self.assertFalse((self.store / STORE.LEAF).exists())


if __name__ == '__main__':unittest.main()
