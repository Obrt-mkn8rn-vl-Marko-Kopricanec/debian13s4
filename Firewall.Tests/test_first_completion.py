import ast
import copy
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
import test_first_register as registration_fixture
import test_first_uncertainty as uncertainty_fixture
import test_proposal_store as old_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_completion', ROOT / 'Firewall/first_completion.py')
HISTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HISTORY)
TRANSPORT, BACKEND, STATE, KERNEL = HISTORY.TRANSPORT, HISTORY._STORAGE, HISTORY.STATE, HISTORY.KERNEL


class CompletionTests(unittest.TestCase):
    def setUp(self):
        helper = plan_fixture.PlanTests();helper.setUp()
        try:self.payload = helper.prepare()
        finally:helper.doCleanups()
        self.plan = json.loads(self.payload)
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-completion-', dir='/dev/shm')
        self.addCleanup(directory.cleanup);self.root = Path(directory.name);self.root.chmod(0o700)
        self.store = self.root / 'history';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf, self.binary = self.store / HISTORY.LEAF, self.root / 'nft'
        for setting in (patch.object(BACKEND, 'TRUST_ROOT', self.root), patch.object(BACKEND, 'TRUSTED_UID', os.geteuid()),
                        patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid()),
                        patch.object(TRANSPORT, 'BINARY', self.binary)):
            setting.start();self.addCleanup(setting.stop)

    def encode(self, value):return STATE.encoded(value) + b'\n'

    def model(self, **changes):
        value = {'schema': 'debian13s4-first-create-native-transport-1', 'state': 'native-zero-exit-empty-capture',
            'profile': 'checked-historical-first-create-batch-1', 'namespace': self.plan['namespace'],
            'proposal_sha256': hashlib.sha256(self.payload).hexdigest(), 'correlation_id': self.plan['correlation_id'],
            'transaction_sha256': self.plan['transaction_sha256'], 'input_bytes': len(self.plan['transaction'].encode()),
            'source': {'binary': str(self.binary), 'argv': ['--file', '-'],
                       'identity': [1, 2, stat.S_IFREG | 0o700, os.geteuid(), os.getegid(), 99, 0, 0]}}
        value.update(changes);return self.encode(value)

    def capture(self, completion=None):return HISTORY.capture(self.payload, self.model() if completion is None else completion)

    def executable(self, after=''):
        self.binary.write_text('#!/usr/bin/python3 -B\nimport json,os,sys\ndata=sys.stdin.buffer.read()\n' +
            f'open({str(self.root / "input")!r},"wb").write(data)\n' +
            f'open({str(self.root / "entries")!r},"ab").write(b"entry\\n")\n' +
            f'open({str(self.root / "ledger")!r},"w").write(json.dumps([sys.argv[1:],dict(os.environ),os.getpid(),os.getsid(0)]))\n' + after + '\n')
        self.binary.chmod(0o700)

    def test_complete_original_plan_and_receipt_bytes_are_preserved_as_history_only(self):
        completion = self.model();raw = self.capture(completion);value = HISTORY.checked(raw)
        self.assertEqual(raw, self.encode(value));self.assertIs(type(raw), bytes)
        self.assertEqual(value['state'], 'historical-transport-receipt-only')
        self.assertEqual(value['proposal'].encode(), self.payload);self.assertEqual(value['receipt'].encode(), completion)
        self.assertEqual(value['proposal_sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(value['receipt_sha256'], hashlib.sha256(completion).hexdigest())
        self.assertEqual(json.loads(value['receipt'])['state'], 'native-zero-exit-empty-capture')

    def test_real_private_storage_load_keeps_unique_private_canonical_leaf(self):
        raw = HISTORY.record(self.store, self.payload, self.model())
        self.assertEqual(HISTORY.load(self.store), raw);self.assertEqual(HISTORY.stored(self.leaf.read_bytes()), raw)
        self.assertEqual(stat.S_IMODE(self.leaf.stat().st_mode), 0o600);self.assertEqual(self.leaf.stat().st_nlink, 1)
        self.assertEqual({item.name for item in self.store.iterdir()}, {HISTORY.LEAF})

    def test_all_closed_backend_functions_and_other_protocol_globals_stay_separate(self):
        old = old_fixture.STORE;register = registration_fixture.REGISTER;uncertain = uncertainty_fixture.HISTORY
        for instance in (old, register._STORAGE, uncertain._STORAGE):self.assertIsNot(BACKEND.__dict__, instance.__dict__)
        self.assertEqual((old.LEAF, register.LEAF, uncertain.LEAF, HISTORY.LEAF),
            ('proposal.json', 'first-create.json', 'first-uncertain.json', 'first-completion.json'))
        for name in ('create', 'load', 'window', 'admission', 'locked', 'read_at', 'reconcile_link',
                     'directory_identity', 'directory_matches', 'file_identity', 'staging_identity'):
            self.assertIs(getattr(BACKEND, name).__globals__, BACKEND.__dict__)
            self.assertEqual(ast.dump(ast.parse(inspect.getsource(getattr(BACKEND, name)))),
                             ast.dump(ast.parse(inspect.getsource(getattr(old, name)))))
        for instance in (old, register, uncertain):
            with self.subTest(protocol=instance.LEAF), self.assertRaises(ValueError):instance.envelope(self.capture())

    def test_receipt_schema_state_profile_and_every_exact_field_are_required(self):
        value = json.loads(self.model())
        for key in value:
            other = copy.deepcopy(value);other.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):self.capture(self.encode(other))
        for change in ({'schema': 'debian13s4-first-create-uncertainty-1'}, {'state': 'applied'},
                       {'profile': 'automatic-empty-source-compiler-intent-1'}, {'pid': 1}, {'returncode': 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):self.capture(self.encode(value | change))

    def test_namespace_is_true_integer_and_matches_the_original_plan(self):
        for value in (True, False, 0, -1, 1 << 64, str(self.plan['namespace']), self.plan['namespace'] + 1):
            with self.subTest(namespace=value), self.assertRaises(ValueError):self.capture(self.model(namespace=value))

    def test_all_original_proposal_transaction_and_correlation_commitments_are_bound(self):
        for key in ('proposal_sha256', 'transaction_sha256', 'correlation_id'):
            for value in ('0' * 64, True, None, [], ''):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):self.capture(self.model(**{key: value}))

    def test_reported_complete_input_is_true_integer_and_exact_utf8_transaction_length(self):
        count = len(self.plan['transaction'].encode())
        for value in (True, float(count), str(count), 0, -1, count - 1, count + 1):
            with self.subTest(count=value), self.assertRaises(ValueError):self.capture(self.model(input_bytes=value))

    def test_fixed_binary_and_exact_list_argv_refuse_other_native_operations(self):
        source = json.loads(self.model())['source']
        for changes in ({'binary': '/other/nft'}, {'argv': ['-c', '--file', '-']}, {'argv': ['-', '--file']},
                        {'argv': ['flush', 'ruleset']}, {'argv': '--file -'}, {'argv': ['--file', '-', 'extra']}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):self.capture(self.model(source=source | changes))
        for key in source:
            other = source.copy();other.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):self.capture(self.model(source=other))
        with self.assertRaises(ValueError):self.capture(self.model(source=source | {'version': 'trusted'}))

    def test_signature_has_all_eight_true_integer_fields_and_native_widths(self):
        source = json.loads(self.model())['source'];identity = source['identity']
        for replacement in (None, {}, identity[:-1], identity + [0], list(map(str, identity))):
            with self.subTest(shape=replacement), self.assertRaises(ValueError):self.capture(self.model(source=source | {'identity': replacement}))
        for index in range(8):
            for replacement in (True, 1.0, None, 1 << 64):
                other = identity.copy();other[index] = replacement
                with self.subTest(index=index, replacement=replacement), self.assertRaises(ValueError):self.capture(self.model(source=source | {'identity': other}))
        for index in (2, 3, 4):
            other = identity.copy();other[index] = 1 << 32
            with self.subTest(index=index), self.assertRaises(ValueError):self.capture(self.model(source=source | {'identity': other}))
        other = identity.copy();other[5] = 1 << 63
        with self.assertRaises(ValueError):self.capture(self.model(source=source | {'identity': other}))

    def test_signature_requires_executable_regular_trusted_owner_and_protected_modes(self):
        source = json.loads(self.model())['source'];identity = source['identity']
        for index, replacement in ((1, 0), (2, stat.S_IFDIR | 0o700), (2, stat.S_IFREG | 0o600),
                                    (2, stat.S_IFREG | 0o720), (2, stat.S_IFREG | 0o702), (3, os.geteuid() + 1)):
            other = identity.copy();other[index] = replacement
            with self.subTest(index=index, replacement=replacement), self.assertRaises(ValueError):self.capture(self.model(source=source | {'identity': other}))
        other = identity.copy();other[6:] = [-1, -(1 << 63)]
        self.assertEqual(HISTORY.receipt(self.payload, self.model(source=source | {'identity': other}))['source']['identity'], other)

    def test_true_bytes_canonical_utf8_lf_duplicate_and_nonfinite_admission(self):
        class Bytes(bytes):pass
        raw = self.model()
        for value in (None, {}, bytearray(raw), memoryview(raw), raw.decode(), Bytes(raw), b'', raw[:-1],
                      raw + b'\n', raw.replace(b'{', b'{"namespace":0,', 1), b'\xff', b'{"schema":NaN}', b'[]'):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):self.capture(value) if value is not None else HISTORY.capture(self.payload, value)

    def test_unicode_binary_bytes_remain_exact_under_explicit_utf8_encoding(self):
        target = self.root / 'nft-é'
        with patch.object(TRANSPORT, 'BINARY', target):
            completion = self.model(source=json.loads(self.model())['source'] | {'binary': str(target)})
            raw = self.capture(completion)
        self.assertIn('nft-é'.encode(), raw);self.assertEqual(json.loads(raw)['receipt'].encode(), completion)

    def test_receipt_limit_is_checked_before_the_real_plan_compiler(self):
        with patch.object(HISTORY.MATCH, 'checked', side_effect=AssertionError('compiler')), self.assertRaises(ValueError):
            self.capture(b' ' * (TRANSPORT.MAX_RECEIPT + 1))

    def test_unsafe_rehashed_original_policy_and_destructive_transaction_are_refused(self):
        for change in ('transaction', 'policy'):
            value = copy.deepcopy(self.plan)
            if change == 'transaction':
                value['transaction'] += 'flush ruleset\n';value['transaction_sha256'] = hashlib.sha256(value['transaction'].encode()).hexdigest()
            else:value['intention']['policy']['rules']['input'][0]['expr'] = [{'accept': None}]
            other = self.encode(value);receipt = json.loads(self.model())
            receipt.update(proposal_sha256=hashlib.sha256(other).hexdigest(), transaction_sha256=value['transaction_sha256'], input_bytes=len(value['transaction'].encode()))
            with self.subTest(change=change), self.assertRaises(ValueError):HISTORY.capture(other, self.encode(receipt))

    def test_a_different_valid_plan_cannot_reuse_another_receipt(self):
        helper = plan_fixture.PlanTests();helper.setUp()
        try:other = helper.prepare()
        finally:helper.doCleanups()
        self.assertNotEqual(json.loads(other)['correlation_id'], self.plan['correlation_id'])
        with self.assertRaises(ValueError):HISTORY.capture(other, self.model())

    def test_record_checks_all_fields_states_and_whole_inner_hashes(self):
        value = json.loads(self.capture())
        for key in value:
            other = value.copy();other.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):HISTORY.checked(self.encode(other))
        for change in ({'state': 'applied'}, {'state': 'resolved'}, {'proposal_sha256': '0' * 64},
                       {'receipt_sha256': '0' * 64}, {'extra': True}, {'receipt': '\ud800'}):
            raw = json.dumps(value | change, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'
            with self.subTest(change=change), self.assertRaises(ValueError):HISTORY.checked(raw)

    def test_recomputed_outer_hashes_do_not_repair_unsafe_inner_receipts(self):
        value = json.loads(HISTORY.envelope(self.capture()));record = json.loads(value['payload']);completion = json.loads(record['receipt'])
        completion['source']['argv'] = ['flush', 'ruleset'];record['receipt'] = self.encode(completion).decode()
        record['receipt_sha256'] = hashlib.sha256(record['receipt'].encode()).hexdigest()
        value['payload'] = self.encode(record).decode();value['payload_sha256'] = hashlib.sha256(value['payload'].encode()).hexdigest()
        with self.assertRaises(ValueError):HISTORY.stored(self.encode(value))

    def test_record_and_envelope_bounds_withhold_publication(self):
        completion = self.model();raw = self.capture(completion)
        with patch.object(HISTORY, 'MAX_RECORD', len(raw) - 1), self.assertRaises(ValueError):HISTORY.record(self.store, self.payload, completion)
        with patch.object(HISTORY, 'MAX_BYTES', 1), self.assertRaises(ValueError):HISTORY.record(self.store, self.payload, completion)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_capture_privately_keeps_original_bytes_after_caller_object_mutation(self):
        caller = json.loads(self.model());completion = self.encode(caller);raw = self.capture(completion)
        caller['source']['identity'][1] += 1;caller['source']['argv'].append('other')
        self.assertEqual(json.loads(raw)['receipt'].encode(), completion);self.assertEqual(HISTORY.checked(raw)['proposal'].encode(), self.payload)

    def test_same_record_resync_preserves_inode_and_different_facts_never_overwrite(self):
        completion = self.model();raw = HISTORY.record(self.store, self.payload, completion);inode = self.leaf.stat().st_ino;before = self.leaf.read_bytes()
        self.assertEqual(HISTORY.record(self.store, self.payload, completion), raw);self.assertEqual(self.leaf.stat().st_ino, inode)
        source = json.loads(completion)['source'];source['identity'][7] += 1
        with self.assertRaises(ValueError):HISTORY.record(self.store, self.payload, self.model(source=source))
        self.assertEqual(self.leaf.read_bytes(), before);self.assertEqual(self.leaf.stat().st_ino, inode)

    def test_capture_storage_and_load_never_observe_or_submit_or_attest_receipt_origin(self):
        # Deliberately shaped trusted in-process data is accepted; this is NOT
        # proof a transport entry happened or that any native policy exists.
        with (patch.object(TRANSPORT, 'transmit', side_effect=AssertionError('submit')),
              patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')),
              patch.object(KERNEL, 'namespace', side_effect=AssertionError('current context')),
              patch.object(KERNEL, 'trusted_binary', side_effect=AssertionError('current executable')),
              patch.object(STATE.NFT, 'native_query', side_effect=AssertionError('query'))):
            raw = HISTORY.record(self.store, self.payload, self.model());self.assertEqual(HISTORY.load(self.store), raw)
            self.assertEqual(json.loads(raw)['state'], 'historical-transport-receipt-only')

    def test_uncertainty_exception_and_history_cannot_be_relabelled_as_completion(self):
        error = TRANSPORT.Uncertain('uncertain', {});error.__cause__ = OSError('failed capture')
        for value in (error, self.encode({'schema': 'debian13s4-first-create-uncertainty-1', 'state': 'historical-uncertain-no-retry'})):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):self.capture(value)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_invalid_deadline_precedes_capture_and_one_shared_window_bounds_storage(self):
        start = BACKEND.KERNEL.now();completion = self.model()
        for end in (True, start, start - 1, float('inf'), float('nan'), 'later'):
            with self.subTest(end=end), patch.object(HISTORY, 'capture', side_effect=AssertionError('capture')), self.assertRaises(ValueError):
                HISTORY.record(self.store, self.payload, completion, deadline=end)
        real = HISTORY.capture;clock = [start]
        def expired(*args):
            raw = real(*args);clock[0] += 11;return raw
        with patch.object(BACKEND.KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(HISTORY, 'capture', side_effect=expired), self.assertRaises(ValueError):
            HISTORY.record(self.store, self.payload, completion, deadline=start + 2)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_no_native_executor_scope_config_or_hash_override_is_available(self):
        for key in ('executor', 'scope', 'binary', 'config', 'verifier', 'compiler', 'hash'):
            with self.subTest(key=key), self.assertRaises(TypeError):HISTORY.record(self.store, self.payload, self.model(), **{key: lambda: True})

    def test_missing_nonprivate_symbolic_corrupt_and_external_links_refuse(self):
        with self.assertRaises(FileNotFoundError):HISTORY.load(self.store)
        HISTORY.record(self.store, self.payload, self.model());before = self.leaf.read_bytes()
        self.leaf.chmod(0o640)
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        self.leaf.chmod(0o600);extra = self.root / 'outside';os.link(self.leaf, extra)
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        extra.unlink();self.leaf.write_bytes(b'broken')
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        self.leaf.write_bytes(before);self.leaf.unlink();self.leaf.symlink_to(extra)
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        self.leaf.unlink();self.store.chmod(0o750)
        with self.assertRaises(ValueError):HISTORY.record(self.store, self.payload, self.model())

    def test_cooperating_directory_lock_refuses_without_replacement(self):
        completion = self.model();HISTORY.record(self.store, self.payload, completion);before = self.leaf.read_bytes()
        fd = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):HISTORY.load(self.store)
            with self.assertRaises(BlockingIOError):HISTORY.record(self.store, self.payload, completion)
        finally:os.close(fd)
        self.assertEqual(self.leaf.read_bytes(), before)

    def test_directory_sync_failure_can_leave_history_visible_without_success(self):
        fsync = BACKEND.os.fsync;calls = []
        def fail(fd):
            calls.append(fd)
            if len(calls) == 2:raise OSError('directory sync')
            return fsync(fd)
        with patch.object(BACKEND.os, 'fsync', side_effect=fail), self.assertRaises(OSError):HISTORY.record(self.store, self.payload, self.model())
        self.assertTrue(self.leaf.exists());self.assertEqual(json.loads(HISTORY.load(self.store))['state'], 'historical-transport-receipt-only')

    def test_same_intent_two_link_recovery_uses_the_preserved_backend(self):
        completion = self.model();raw = HISTORY.record(self.store, self.payload, completion)
        stage = self.store / ('.proposal-' + 'a' * 32);os.link(self.leaf, stage)
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        self.assertEqual(HISTORY.record(self.store, self.payload, completion), raw)
        self.assertFalse(stage.exists());self.assertEqual(self.leaf.stat().st_nlink, 1);self.assertEqual(HISTORY.load(self.store), raw)

    def test_actual_private_returned_receipt_is_recorded_after_exact_input_without_resubmission(self):
        self.executable()
        with patch.dict(os.environ, {'TASK_SECRET': 'private', 'NFT_CTX_FLAGS': 'bad'}):completion = TRANSPORT.transmit(self.payload)
        with patch.object(TRANSPORT, 'transmit', side_effect=AssertionError('resubmit')):
            raw = HISTORY.record(self.store, self.payload, completion);self.assertEqual(HISTORY.load(self.store), raw)
        self.assertEqual(self.root.joinpath('input').read_bytes(), self.plan['transaction'].encode())
        self.assertEqual(self.root.joinpath('entries').read_bytes(), b'entry\n')
        argv, environment, pid, session = json.loads(self.root.joinpath('ledger').read_bytes())
        self.assertEqual(argv, ['--file', '-']);self.assertEqual(pid, session);self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})
        self.assertEqual(json.loads(raw)['receipt'].encode(), completion)

    def test_actual_private_unicode_receipt_preserves_signature_without_current_reattestation(self):
        self.binary = self.root / 'nft-é';self.executable()
        with patch.object(TRANSPORT, 'BINARY', self.binary):
            completion = TRANSPORT.transmit(self.payload);identity = list(KERNEL.signature(self.binary.stat()))
            self.binary.unlink()
            with patch.object(KERNEL, 'trusted_binary', side_effect=AssertionError('reattest')):
                raw = HISTORY.record(self.store, self.payload, completion);self.assertEqual(HISTORY.load(self.store), raw)
        self.assertEqual(json.loads(completion)['source']['identity'], identity)
        self.assertIn('nft-é'.encode(), completion);self.assertEqual(json.loads(raw)['receipt'].encode(), completion)

    def test_actual_private_warning_keeps_uncertainty_and_cannot_be_recorded_as_completion(self):
        self.executable('os.write(2,b"warning")')
        with self.assertRaises(TRANSPORT.Uncertain) as caught:TRANSPORT.transmit(self.payload)
        self.assertEqual(caught.exception.evidence['returncode'], 0);self.assertEqual(caught.exception.evidence['stderr'], b'warning')
        with self.assertRaises(ValueError):HISTORY.record(self.store, self.payload, caught.exception)
        self.assertEqual(list(self.store.iterdir()), []);self.assertEqual(self.root.joinpath('entries').read_bytes(), b'entry\n')

    def test_actual_private_receipt_context_damage_withholds_history_without_second_entry(self):
        self.executable();completion = json.loads(TRANSPORT.transmit(self.payload));completion['namespace'] += 1
        with self.assertRaises(ValueError):HISTORY.record(self.store, self.payload, self.encode(completion))
        self.assertEqual(list(self.store.iterdir()), []);self.assertEqual(self.root.joinpath('entries').read_bytes(), b'entry\n')

    def test_actual_private_completion_storage_failure_never_reenters_transport(self):
        self.executable();completion = TRANSPORT.transmit(self.payload);fsync = BACKEND.os.fsync;calls = []
        def fail(fd):
            calls.append(fd)
            if len(calls) == 2:raise OSError('directory sync after returned receipt')
            return fsync(fd)
        with patch.object(TRANSPORT, 'transmit', side_effect=AssertionError('resubmit')), patch.object(BACKEND.os, 'fsync', side_effect=fail), self.assertRaises(OSError):
            HISTORY.record(self.store, self.payload, completion)
        self.assertEqual(self.root.joinpath('entries').read_bytes(), b'entry\n')
        self.assertEqual(json.loads(HISTORY.load(self.store))['receipt'].encode(), completion)
