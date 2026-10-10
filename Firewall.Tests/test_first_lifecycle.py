import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import test_auto_intent as automatic_fixture
import test_first_create as plan_fixture
import test_first_match as match_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_lifecycle', ROOT / 'Firewall/first_lifecycle.py')
LIFE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFE)
REFRESH, REGISTER, ATTEMPT = LIFE.REFRESH, LIFE.REGISTER, LIFE.ATTEMPT
TRANSPORT, COMPLETION, HISTORY = LIFE.TRANSPORT, LIFE.COMPLETION, LIFE.UNCERTAINTY
STATE = LIFE.STATE


def storage_settings(root):
    for backend in (REGISTER._STORAGE, ATTEMPT._STORAGE, COMPLETION._STORAGE, HISTORY._STORAGE):
        yield patch.object(backend, 'TRUST_ROOT', root)
        yield patch.object(backend, 'TRUSTED_UID', os.geteuid())


def transport_settings(root, binary):
    for transport in (TRANSPORT, COMPLETION.TRANSPORT):
        yield patch.object(transport, 'BINARY', binary)
        yield patch.object(transport.KERNEL, 'TRUST_ROOT', root)
        yield patch.object(transport.KERNEL, 'TRUSTED_UID', os.geteuid())


class FixtureCleanupTests(unittest.TestCase):
    def test_setup_failure_cleanup_keeps_native_delivery_globals_isolated(self):
        watched = [(automatic_fixture.KERNEL, 'TRUST_ROOT'),
                   (automatic_fixture.ASSEMBLY.LEGACY, 'PROC'),
                   (automatic_fixture.ASSEMBLY.BPF.ctypes, 'CDLL'),
                   (REFRESH, 'ASSEMBLY'), (LIFE, 'KERNEL'), (TRANSPORT, 'BINARY'),
                   (REGISTER._STORAGE, 'TRUST_ROOT'), (ATTEMPT._STORAGE, 'TRUST_ROOT')]
        before = [getattr(owner, key) for owner, key in watched]
        fixture = NativeLifecycleTests('test_complete_private_native_capture_abi_join_one_delivery_and_two_postsource_reads')
        try:
            with patch.object(fixture, 'install_nft', side_effect=OSError('injected fixture failure after real preparation and registration')):
                with self.assertRaisesRegex(OSError, 'injected fixture failure'):fixture.setUp()
            # unittest calls doCleanups even when setUp failed and tearDown is
            # skipped. Exercise that protocol WITHOUT entering another test body.
            fixture.doCleanups()
            for (owner, key), old in zip(watched, before):
                with self.subTest(field=key):self.assertIs(getattr(owner, key), old)
        finally:
            # Also contain the deliberately failing prototype's leaked patches.
            if hasattr(fixture, 'settings'):automatic_fixture.PrivateNative.tearDown(fixture)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.helper = plan_fixture.PlanTests();self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        self.payload = self.helper.prepare();self.plan = json.loads(self.payload)
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-lifecycle-', dir='/dev/shm')
        self.addCleanup(directory.cleanup);self.root = Path(directory.name);self.root.chmod(0o700)
        self.store = self.root / 'history';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.binary, self.input, self.entries = self.root / 'nft', self.root / 'input', self.root / 'entries'
        settings = [patch.object(REFRESH, 'ASSEMBLY', automatic_fixture.ASSEMBLY),
                    patch.object(LIFE, 'KERNEL', automatic_fixture.KERNEL)]
        settings.extend(storage_settings(self.root));settings.extend(transport_settings(self.root, self.binary))
        for setting in settings:setting.start();self.addCleanup(setting.stop)
        REGISTER.create(self.store, self.payload)
        self.native = match_fixture.marked(self.plan);self.queries = []
        self.executable()

    def executable(self, after=''):
        self.binary.write_text('#!/usr/bin/python3 -B\nimport json,os,sys\ndata=sys.stdin.buffer.read()\n' +
            f'open({str(self.input)!r},"wb").write(data)\n' +
            f'open({str(self.entries)!r},"a").write(json.dumps([sys.argv[1:],dict(os.environ),os.getpid(),os.getsid(0)])+"\\n")\n' + after + '\n')
        self.binary.chmod(0o700)

    def query(self, end):
        self.queries.append(end);return copy.deepcopy(self.native)

    def submit(self, **settings):
        return LIFE.submit_once(self.store, **({'query': self.query} | self.helper.helper.readers() | settings))

    def assert_blocked_again(self):
        with patch.object(REFRESH, 'prepare', side_effect=AssertionError('second admission')), \
                patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('second entry')), self.assertRaises(ATTEMPT.Blocked):
            self.submit()

    def test_complete_registration_fresh_admission_one_entry_durable_receipt_and_whole_postsource_join(self):
        value = json.loads(self.submit())
        self.assertEqual(value['state'], 'single-submission-source-correspondence-no-retry')
        self.assertEqual(value['admission']['proposal'].encode(), self.payload)
        self.assertEqual(value['comparison']['intention'], self.plan['intention'])
        self.assertEqual(value['comparison']['observation']['comment'], REFRESH.PLAN.COMMENT_PREFIX + self.plan['correlation_id'])
        self.assertEqual(value['transport']['input_bytes'], len(self.plan['transaction'].encode()))
        self.assertEqual(self.input.read_bytes(), self.plan['transaction'].encode());self.assertEqual(len(self.queries), 2)
        rows = [json.loads(line) for line in self.entries.read_text().splitlines()]
        self.assertEqual(len(rows), 1);self.assertEqual(rows[0][0], ['--file', '-']);self.assertEqual(rows[0][2], rows[0][3])
        self.assertEqual({p.name for p in self.store.iterdir()}, {REGISTER.LEAF, ATTEMPT.LEAF, COMPLETION.LEAF})
        self.assertEqual(json.loads(COMPLETION.load(self.store))['state'], 'historical-transport-receipt-only')
        self.assertEqual(json.loads(ATTEMPT.load(self.store))['proposal'].encode(), self.payload)
        self.assert_blocked_again();self.assertEqual(len(rows), 1)

    def test_reservation_precedes_every_new_source_and_entry_and_encoding_precedes_final_loads(self):
        events = [];encoded = STATE.encoded
        settings = []
        for owner, name, label in ((ATTEMPT, 'reserve', 'reserve'), (REFRESH, 'prepare', 'fresh'),
                                   (TRANSPORT, 'transmit', 'entry'), (COMPLETION, 'record', 'history'),
                                   (LIFE.MATCH, 'verify', 'post'), (ATTEMPT, 'load', 'slot-load'), (REGISTER, 'load', 'registration-load')):
            real = getattr(owner, name)
            def call(*args, real=real, label=label, **kwargs):
                events.append(label);return real(*args, **kwargs)
            setting = patch.object(owner, name, side_effect=call);setting.start();settings.append(setting)
        def encode(value):
            raw = encoded(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-lifecycle-1':events.append('result')
            return raw
        try:
            with patch.object(STATE, 'encoded', side_effect=encode):self.submit()
        finally:
            for setting in reversed(settings):setting.stop()
        self.assertLess(events.index('reserve'), events.index('fresh'));self.assertLess(events.index('fresh'), events.index('entry'))
        self.assertLess(events.index('entry'), events.index('history'));self.assertLess(events.index('history'), events.index('post'))
        self.assertEqual(events[-3:], ['result', 'slot-load', 'registration-load'])
        self.assertEqual(events.count('registration-load'), 4)

    def test_empty_partial_foreign_and_completed_reservations_refuse_before_observers_or_entry(self):
        leaf = self.store / ATTEMPT.LEAF
        for raw in (b'', b'partial', b'foreign', ATTEMPT.envelope(self.payload)):
            leaf.write_bytes(raw);leaf.chmod(0o600);inode = leaf.stat().st_ino
            with self.subTest(raw=raw[:20]):self.assert_blocked_again()
            self.assertEqual(leaf.read_bytes(), raw);self.assertEqual(leaf.stat().st_ino, inode);leaf.unlink()
        self.assertFalse(self.input.exists())

    def test_preentry_source_failure_retains_closed_slot_and_never_calls_transport(self):
        def missing(deadline):raise OSError('missing native reporting')
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('entry')), self.assertRaises(LIFE.Blocked) as caught:
            self.submit(legacy=missing)
        self.assertIsInstance(caught.exception.__cause__, OSError);self.assertIsNone(caught.exception.completion)
        self.assertTrue((self.store / ATTEMPT.LEAF).exists());self.assertFalse(self.input.exists());self.assert_blocked_again()

    def test_existing_nft_objects_even_matching_registered_marker_do_not_reach_entry(self):
        def nonempty(deadline):return automatic_fixture.nft_receipt(self.plan['namespace']) | {'empty': False}
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('entry')), self.assertRaises(LIFE.Blocked):self.submit(nft=nonempty)
        self.assertFalse(self.input.exists());self.assert_blocked_again()

    def test_final_program_or_link_presence_after_compilation_prevents_native_submission(self):
        readers = self.helper.helper.readers();count = []
        def program(deadline):
            count.append(1)
            if len(count) == 3:raise ValueError('postcompiler registered program present')
            return readers['bpf'](deadline)
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('entry')), self.assertRaises(LIFE.Blocked):self.submit(bpf=program)
        self.assertEqual(len(count), 3);self.assertFalse(self.input.exists());self.assert_blocked_again()

    def test_healthy_changed_current_dns_cannot_rewrite_historical_transaction_or_reach_entry(self):
        self.helper.helper.records['dns']['dns'][0]['address'] = '1.1.1.1'
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('entry')), self.assertRaises(LIFE.Blocked):self.submit()
        self.assertEqual(REGISTER.load(self.store), self.payload);self.assertFalse(self.input.exists());self.assert_blocked_again()

    def test_missing_unsafe_native_binary_still_leaves_reserved_slot_without_a_submission(self):
        self.binary.unlink()
        with self.assertRaises(LIFE.Blocked) as caught:self.submit()
        self.assertIsInstance(caught.exception.__cause__, OSError);self.assertFalse(self.input.exists())
        self.assertFalse((self.store / COMPLETION.LEAF).exists());self.assert_blocked_again()

    def test_actual_zero_exit_with_raw_warning_is_durable_uncertainty_not_completion_or_retry(self):
        self.executable('sys.stderr.buffer.write(b"warning\\r\\n\\0\\xff")')
        with self.assertRaises(LIFE.Blocked) as caught:self.submit()
        cause = caught.exception.__cause__;self.assertIs(type(cause), TRANSPORT.Uncertain)
        self.assertEqual(cause.evidence['returncode'], 0);self.assertEqual(cause.evidence['input'], self.plan['transaction'].encode())
        value = json.loads(HISTORY.load(self.store));self.assertEqual(value['state'], 'historical-uncertain-no-retry')
        self.assertEqual(bytes.fromhex(value['evidence']['stderr_hex']), b'warning\r\n\0\xff')
        self.assertEqual(self.queries, []);self.assertFalse((self.store / COMPLETION.LEAF).exists())
        self.assert_blocked_again();self.assertEqual(len(self.entries.read_text().splitlines()), 1)

    def test_actual_nonzero_exit_keeps_uncertainty_and_no_postsource_or_second_entry(self):
        self.executable('sys.exit(1)')
        with self.assertRaises(LIFE.Blocked) as caught:self.submit()
        self.assertEqual(caught.exception.__cause__.evidence['returncode'], 1)
        self.assertEqual(json.loads(HISTORY.load(self.store))['evidence']['returncode'], 1)
        self.assertEqual(self.queries, []);self.assert_blocked_again()

    def test_uncertainty_storage_failure_preserves_original_error_and_closed_attempt(self):
        self.executable('sys.stderr.write("warning")');leaf = self.store / HISTORY.LEAF
        leaf.write_bytes(b'foreign');leaf.chmod(0o600)
        with self.assertRaises(LIFE.Blocked) as caught:self.submit()
        self.assertIs(type(caught.exception.__cause__), TRANSPORT.Uncertain)
        self.assertIsInstance(caught.exception.history_error, ValueError);self.assertEqual(leaf.read_bytes(), b'foreign')
        self.assertEqual(self.input.read_bytes(), self.plan['transaction'].encode());self.assert_blocked_again()

    def test_completion_storage_failure_after_real_zero_exit_cannot_return_success_or_retry(self):
        leaf = self.store / COMPLETION.LEAF;leaf.write_bytes(b'foreign');leaf.chmod(0o600)
        with self.assertRaises(LIFE.Blocked) as caught:self.submit()
        self.assertEqual(json.loads(caught.exception.completion)['state'], 'native-zero-exit-empty-capture')
        self.assertEqual(leaf.read_bytes(), b'foreign');self.assertEqual(self.queries, []);self.assert_blocked_again()

    def test_postsource_wrong_policy_and_extra_foreign_objects_leave_durable_receipt_and_block_success(self):
        self.native['nftables'].append({'table': {'family': 'inet', 'name': 'foreign', 'handle': 999}})
        with self.assertRaises(LIFE.Blocked) as caught:self.submit()
        self.assertIsNotNone(caught.exception.completion);self.assertEqual(len(self.queries), 1)
        self.assertTrue((self.store / COMPLETION.LEAF).exists());self.assert_blocked_again()

    def test_postsource_read_failure_does_not_erase_zero_exit_receipt_or_allow_resubmission(self):
        def missing(deadline):raise OSError('post-entry read failed')
        with self.assertRaises(LIFE.Blocked) as caught:self.submit(query=missing)
        self.assertIsInstance(caught.exception.__cause__, OSError);self.assertIsNotNone(caught.exception.completion)
        self.assertEqual(json.loads(COMPLETION.load(self.store))['state'], 'historical-transport-receipt-only');self.assert_blocked_again()

    def test_whole_postsource_handle_drift_is_refused_after_two_real_comparisons(self):
        def drift(end):
            value = self.query(end)
            if len(self.queries) == 2:value['nftables'][1]['table']['handle'] += 1
            return value
        with self.assertRaises(LIFE.Blocked):self.submit(query=drift)
        self.assertEqual(len(self.queries), 2);self.assert_blocked_again()

    def test_final_changed_registration_or_reservation_withholds_result_after_one_submission(self):
        real = STATE.encoded
        def encode(value):
            raw = real(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-lifecycle-1':
                leaf = self.store / ATTEMPT.LEAF;leaf.write_bytes(b'changed');leaf.chmod(0o600)
            return raw
        with patch.object(STATE, 'encoded', side_effect=encode), self.assertRaises(LIFE.Blocked):self.submit()
        self.assertEqual(len(self.entries.read_text().splitlines()), 1);self.assertTrue((self.store / COMPLETION.LEAF).exists())
        self.assert_blocked_again()

    def test_registration_drift_after_postsource_is_not_an_owned_or_current_result(self):
        real = STATE.encoded
        def encode(value):
            raw = real(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-lifecycle-1':
                other = self.plan | {'correlation_id': '0' * 64,
                    'transaction': self.plan['transaction'].replace(self.plan['correlation_id'], '0' * 64)}
                other['transaction_sha256'] = hashlib.sha256(other['transaction'].encode()).hexdigest()
                leaf = self.store / REGISTER.LEAF;leaf.write_bytes(REGISTER.envelope(real(other) + b'\n'));leaf.chmod(0o600)
            return raw
        with patch.object(STATE, 'encoded', side_effect=encode), self.assertRaises(LIFE.Blocked):self.submit()
        self.assertEqual(len(self.entries.read_text().splitlines()), 1);self.assert_blocked_again()

    def test_result_size_and_final_scope_failures_never_promote_one_entry_to_success(self):
        with patch.object(LIFE, 'MAX_OUTPUT', 1), self.assertRaises(LIFE.Blocked):self.submit()
        self.assertEqual(len(self.entries.read_text().splitlines()), 1);self.assert_blocked_again()

    def test_true_boolean_final_namespace_withholds_result_after_immutable_encoding(self):
        real = STATE.encoded;context = [self.plan['namespace']]
        def encode(value):
            raw = real(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-lifecycle-1':context[0] = True
            return raw
        with patch.object(LIFE.KERNEL, 'namespace', side_effect=lambda: context[0]), \
                patch.object(STATE, 'encoded', side_effect=encode), self.assertRaises(LIFE.Blocked):self.submit()
        self.assertEqual(len(self.entries.read_text().splitlines()), 1);self.assert_blocked_again()

    def test_final_clock_expiry_after_encoding_and_real_store_loads_withholds_result(self):
        real = STATE.encoded;clock = [LIFE.KERNEL.now()]
        def encode(value):
            raw = real(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-lifecycle-1':clock[0] += LIFE.ATTEMPT_SECONDS + 1
            return raw
        with patch.object(LIFE.KERNEL, 'now', side_effect=lambda: clock[0]), \
                patch.object(STATE, 'encoded', side_effect=encode), self.assertRaises(LIFE.Blocked):self.submit()
        self.assertEqual(len(self.entries.read_text().splitlines()), 1);self.assert_blocked_again()

    def test_actual_thirteen_pipe_bytes_before_interruption_remain_zero_reported_and_no_retry(self):
        real = os.write;actual = []
        def interrupted(fd, raw):
            if stat.S_ISFIFO(os.fstat(fd).st_mode):
                actual.append(real(fd, raw[:13]));raise OSError('injected AFTER actual pipe write before count delivery')
            return real(fd, raw)
        with patch.object(TRANSPORT.os, 'write', side_effect=interrupted), \
                patch.object(TRANSPORT.subprocess, 'Popen', wraps=TRANSPORT.subprocess.Popen) as entered, self.assertRaises(LIFE.Blocked) as caught:
            self.submit()
        self.assertEqual(actual, [13]);self.assertEqual(entered.call_count, 1)
        self.assertIs(type(caught.exception.__cause__), TRANSPORT.Uncertain)
        self.assertEqual(caught.exception.__cause__.evidence['input_written'], 0)
        record = json.loads(HISTORY.load(self.store));self.assertEqual(record['evidence']['input_written'], 0)
        self.assertEqual(bytes.fromhex(record['evidence']['input_hex']), self.plan['transaction'].encode())
        self.assertEqual(record['state'], 'historical-uncertain-no-retry');self.assert_blocked_again()

    def test_deadline_expiry_after_reservation_refuses_before_any_native_entry(self):
        real = ATTEMPT.reserve;clock = [LIFE.KERNEL.now()]
        def reserve(*args, **kwargs):
            raw = real(*args, **kwargs);clock[0] += LIFE.ATTEMPT_SECONDS + 1;return raw
        with patch.object(LIFE.KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(ATTEMPT, 'reserve', side_effect=reserve), \
                patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('expired entry')), self.assertRaises(LIFE.Blocked):self.submit()
        self.assertTrue((self.store / ATTEMPT.LEAF).exists());self.assertFalse(self.input.exists());self.assert_blocked_again()

    def test_invalid_arguments_deadlines_or_context_refuse_before_registration_or_reservation(self):
        with patch.object(REGISTER, 'load', side_effect=AssertionError('history')):
            for settings in ({'executor': lambda: 0}, {'compiler': lambda: ''}, {'scope': lambda: 1},
                             {'topology': {}}, {'nft': None}, {'query': None}):
                with self.subTest(settings=settings), self.assertRaises(ValueError):self.submit(**settings)
            for deadline in (True, float('inf'), float('nan'), 'later', LIFE.KERNEL.now() - 1):
                with self.subTest(deadline=deadline), self.assertRaises(ValueError):self.submit(deadline=deadline)
            for namespace in (True, 0, -1, 1 << 64, '1'):
                with self.subTest(namespace=namespace), patch.object(LIFE.KERNEL, 'namespace', return_value=namespace), self.assertRaises(ValueError):self.submit()
        self.assertFalse((self.store / ATTEMPT.LEAF).exists())

    def test_history_from_another_namespace_refuses_without_claiming_or_observing(self):
        other = STATE.encoded(self.plan | {'namespace': self.plan['namespace'] + 1}) + b'\n'
        leaf = self.store / REGISTER.LEAF;leaf.write_bytes(REGISTER.envelope(other));leaf.chmod(0o600)
        with patch.object(REFRESH, 'prepare', side_effect=AssertionError('observe')), self.assertRaises(ValueError):self.submit()
        self.assertFalse((self.store / ATTEMPT.LEAF).exists());self.assertFalse(self.input.exists())

    def test_admission_receipt_complete_bytes_types_hashes_and_supported_profile_are_required(self):
        raw = REFRESH.prepare(self.store, **self.helper.helper.readers());value = json.loads(raw)
        for key, bad in (('namespace', True), ('schema', 'bad'), ('state', 'healthy'),
                         ('proposal', self.payload.decode()[:-1]), ('proposal_sha256', '0' * 64),
                         ('transaction_sha256', '0' * 64), ('correlation_id', '0' * 64), ('admission_profile', 'all-empty')):
            with self.subTest(key=key), self.assertRaises(ValueError):LIFE.fresh_receipt(STATE.encoded(value | {key: bad}) + b'\n', self.payload, self.plan)
        with self.assertRaises(ValueError):LIFE.fresh_receipt(raw[:-1], self.payload, self.plan)


class NativeLifecycleTests(automatic_fixture.PrivateNative):
    def setUp(self):
        super().setUp()
        self.addCleanup(super().tearDown)
        self.store = self.root / 'lifecycle';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.input, self.entries, self.present = self.root / 'submitted-input', self.root / 'entries', self.root / 'present'
        for setting in [patch.object(REFRESH, 'ASSEMBLY', automatic_fixture.ASSEMBLY),
                        patch.object(plan_fixture.PLAN, 'ASSEMBLY', automatic_fixture.ASSEMBLY),
                        patch.object(LIFE, 'KERNEL', automatic_fixture.KERNEL),
                        *storage_settings(self.root), *transport_settings(self.root, self.nft),
                        patch.object(LIFE.MATCH.STATE.NFT, 'BINARY', self.nft),
                        patch.object(LIFE.MATCH.STATE.NFT.KERNEL, 'TRUST_ROOT', self.root),
                        patch.object(LIFE.MATCH.STATE.NFT.KERNEL, 'TRUSTED_UID', os.geteuid())]:
            setting.start();self.settings.append(setting)
        self.fixtures(tc_kind='fq_codel');self.payload = plan_fixture.PLAN.prepare();self.plan = json.loads(self.payload)
        REGISTER.create(self.store, self.payload);self.bpf_calls.clear();self.link_calls.clear()
        self.ledger.write_text('');self.install_nft()

    def tearDown(self):
        self.doCleanups()  # also runs when unittest skips tearDown after failed setUp

    def install_nft(self, after=''):
        native = match_fixture.marked(self.plan)
        empty = {'nftables': [{'metainfo': {'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}}]}
        self.executable_native = '#!/usr/bin/python3 -B\nimport json,os,sys\n'
        self.executable_native += 'if sys.argv[1:]==["--file","-"]:\n data=sys.stdin.buffer.read()\n'
        self.executable_native += f' open({str(self.input)!r},"wb").write(data)\n open({str(self.present)!r},"w").write("present")\n'
        self.executable_native += f' open({str(self.entries)!r},"a").write(json.dumps([sys.argv[1:],dict(os.environ),os.getpid(),os.getsid(0)])+"\\n")\n'
        self.executable_native += ''.join(' ' + line + '\n' for line in after.splitlines())
        self.executable_native += 'else:\n'
        self.executable_native += f' open({str(self.ledger)!r},"a").write(json.dumps(["nft",sys.argv[1:],dict(os.environ)])+"\\n")\n'
        self.executable_native += f' print(json.dumps({native!r} if os.path.exists({str(self.present)!r}) else {empty!r}))\n'
        self.nft.write_text(self.executable_native);self.nft.chmod(0o700)

    def submit(self):
        return LIFE.submit_once(self.store, query=LIFE.MATCH.STATE.NFT.native_query)

    def test_complete_private_native_capture_abi_join_one_delivery_and_two_postsource_reads(self):
        value = json.loads(self.submit());rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'ip' for kind, _, _ in rows), 258)
        self.assertEqual(sum(kind == 'bus' for kind, _, _ in rows), 100)
        self.assertEqual(sum(kind == 'tc' for kind, _, _ in rows), 12)
        self.assertEqual(sum(kind == 'nft' for kind, _, _ in rows), 8)
        self.assertEqual(len(self.bpf_calls), 6);self.assertEqual(len(self.link_calls), 6)
        self.assertEqual(self.input.read_bytes(), self.plan['transaction'].encode());entries = [json.loads(line) for line in self.entries.read_text().splitlines()]
        self.assertEqual(len(entries), 1);self.assertEqual(entries[0][0], ['--file', '-']);self.assertEqual(entries[0][2], entries[0][3])
        self.assertEqual(value['comparison']['intention'], self.plan['intention'])
        for kind, argv, environment in rows:
            if kind == 'nft':self.assertEqual(argv, list(automatic_fixture.ASSEMBLY.NFT.COMMAND))
            self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})
        with self.assertRaises(ATTEMPT.Blocked):self.submit()
        self.assertEqual(len(self.entries.read_text().splitlines()), 1)

    def test_actual_private_registered_link_permission_refusal_prevents_entry_and_preserves_slot(self):
        self.link_error = errno.EPERM
        with self.assertRaises(LIFE.Blocked):self.submit()
        self.assertEqual(len(self.link_calls), 1);self.assertFalse(self.input.exists());self.assertTrue((self.store / ATTEMPT.LEAF).exists())
        with self.assertRaises(ATTEMPT.Blocked):self.submit()

    def test_actual_private_existing_matching_marker_refuses_in_empty_admission(self):
        self.present.write_text('present')
        with self.assertRaises(LIFE.Blocked):self.submit()
        self.assertFalse(self.input.exists());self.assertEqual(len(self.bpf_calls), 0)
        self.assertFalse(any(json.loads(line)[0] == 'bus' for line in self.ledger.read_text().splitlines()))

    def test_actual_private_zero_exit_warning_retains_uncertainty_and_one_entry(self):
        self.install_nft('sys.stderr.buffer.write(b"warning\\xff")')
        with self.assertRaises(LIFE.Blocked) as caught:self.submit()
        self.assertIs(type(caught.exception.__cause__), TRANSPORT.Uncertain)
        self.assertEqual(json.loads(HISTORY.load(self.store))['evidence']['returncode'], 0)
        self.assertEqual(bytes.fromhex(json.loads(HISTORY.load(self.store))['evidence']['stderr_hex']), b'warning\xff')
        with self.assertRaises(ATTEMPT.Blocked):self.submit()
        self.assertEqual(len(self.entries.read_text().splitlines()), 1)


if __name__ == '__main__':unittest.main()
