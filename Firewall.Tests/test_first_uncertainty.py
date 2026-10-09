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
import test_proposal_store as old_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_uncertainty', ROOT / 'Firewall/first_uncertainty.py')
HISTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HISTORY)
TRANSPORT, BACKEND, STATE, KERNEL = HISTORY.TRANSPORT, HISTORY._STORAGE, HISTORY.STATE, HISTORY.KERNEL


class UncertaintyTests(unittest.TestCase):
    def setUp(self):
        helper = plan_fixture.PlanTests();helper.setUp()
        try:self.payload = helper.prepare()
        finally:helper.doCleanups()
        self.plan = json.loads(self.payload)
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-uncertainty-', dir='/dev/shm')
        self.addCleanup(directory.cleanup);self.root = Path(directory.name);self.root.chmod(0o700)
        self.store = self.root / 'history';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf, self.binary = self.store / HISTORY.LEAF, self.root / 'nft'
        for setting in (patch.object(BACKEND, 'TRUST_ROOT', self.root), patch.object(BACKEND, 'TRUSTED_UID', os.geteuid()),
                        patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid()),
                        patch.object(TRANSPORT, 'BINARY', self.binary)):
            setting.start();self.addCleanup(setting.stop)

    def model(self, **changes):
        evidence = {'command': (str(self.binary), '--file', '-'), 'namespace': self.plan['namespace'],
            'deadline': KERNEL.now() + 3, 'proposal_sha256': hashlib.sha256(self.payload).hexdigest(),
            'correlation_id': self.plan['correlation_id'], 'transaction_sha256': self.plan['transaction_sha256'],
            'input': self.plan['transaction'].encode('utf-8'), 'input_written': 0,
            'stdout': b'', 'stderr': b'', 'received': {'stdout': 0, 'stderr': 0},
            'returncode': None, 'cleanup_errors': ()}
        evidence.update(changes)
        error = TRANSPORT.Uncertain('modeled native uncertainty', evidence)
        error.__cause__ = HISTORY.Pending('modeled capture failure')
        return error

    def capture(self, error=None):return HISTORY.capture(self.payload, self.model() if error is None else error)

    def encode(self, value):return STATE.encoded(value) + b'\n'

    def executable(self, after):
        self.binary.write_text('#!/usr/bin/python3 -B\nimport os,sys\ndata=sys.stdin.buffer.read()\n' +
            f'open({str(self.root / "input")!r},"wb").write(data)\n' + after + '\n')
        self.binary.chmod(0o700)

    def test_checked_history_retains_complete_plan_input_and_uncertain_state(self):
        error = self.model();raw = HISTORY.record(self.store, self.payload, error)
        self.assertEqual(HISTORY.load(self.store), raw)
        value = HISTORY.checked(raw);self.assertEqual(raw, self.encode(value))
        self.assertEqual(value['state'], 'historical-uncertain-no-retry')
        self.assertEqual(value['proposal'].encode('utf-8'), self.payload)
        row = value['evidence'];self.assertEqual(bytes.fromhex(row['input_hex']), error.evidence['input'])
        self.assertEqual(row['proposal_sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(row['correlation_id'], self.plan['correlation_id'])
        self.assertEqual(row['transaction_sha256'], self.plan['transaction_sha256'])
        self.assertIsNone(row['returncode']);self.assertEqual(row['input_written'], 0)
        self.assertEqual(stat.S_IMODE(self.leaf.stat().st_mode), 0o600)
        self.assertEqual(self.leaf.stat().st_nlink, 1)

    def test_zero_exit_empty_capture_and_full_reported_input_remain_uncertain(self):
        error = self.model(returncode=0, input_written=len(self.plan['transaction'].encode()))
        raw = HISTORY.record(self.store, self.payload, error)
        self.assertEqual(json.loads(HISTORY.load(self.store))['state'], 'historical-uncertain-no-retry')
        self.assertEqual(json.loads(raw)['evidence']['returncode'], 0)

    def test_raw_invalid_utf8_crlf_nul_and_partial_sequences_round_trip_exactly(self):
        out, err = b'out\r\n\0\xff', b'err\r\xe2\x82'
        error = self.model(stdout=out, stderr=err, received={'stdout': len(out), 'stderr': len(err)})
        raw = HISTORY.record(self.store, self.payload, error);row = json.loads(HISTORY.load(self.store))['evidence']
        self.assertEqual(bytes.fromhex(row['stdout_hex']), out);self.assertEqual(bytes.fromhex(row['stderr_hex']), err)
        self.assertEqual(row['received'], error.evidence['received']);self.assertEqual(HISTORY.load(self.store), raw)

    def test_overflow_prefix_counts_remain_distinct_from_complete_child_output(self):
        data = b'\xff' * TRANSPORT.MAX_BYTES
        error = self.model(stdout=data, received={'stdout': len(data) + 65536, 'stderr': 0})
        row = json.loads(self.capture(error))['evidence']
        self.assertEqual(bytes.fromhex(row['stdout_hex']), data)
        self.assertEqual(row['received']['stdout'], len(data) + 65536)

    def test_original_cause_and_cleanup_diagnostics_are_bounded_projections(self):
        error = self.model(cleanup_errors=(('OSError', 'close\0é'), ('TimeoutExpired', 'cleanup wait')))
        error.__cause__ = OSError('capture é' + 'x' * 2000)
        value = json.loads(self.capture(error))
        self.assertEqual(value['cause'], ['OSError', str(error.__cause__)[:1024]])
        self.assertEqual(value['evidence']['cleanup_errors'], [['OSError', 'close\0é'], ['TimeoutExpired', 'cleanup wait']])

    def test_exception_type_original_cause_and_raw_delivery_types_are_required(self):
        class Foreign(TRANSPORT.Uncertain):pass
        model = self.model();foreign = Foreign('other', model.evidence);foreign.__cause__ = ValueError('other')
        for error in (None, ValueError('pending'), foreign, TRANSPORT.Uncertain('no cause', model.evidence)):
            with self.subTest(kind=type(error).__name__), self.assertRaises(ValueError):self.capture(error) if error is not None else HISTORY.capture(self.payload, error)
        for key, replacement in (('command', list(model.evidence['command'])), ('input', bytearray(model.evidence['input'])),
                                 ('stdout', ''), ('stderr', memoryview(b'')), ('cleanup_errors', [])):
            with self.subTest(key=key), self.assertRaises(ValueError):self.capture(self.model(**{key: replacement}))

    def test_real_compiler_refuses_rehashed_unsafe_or_foreign_original_intentions(self):
        value = json.loads(self.payload);value['transaction'] += 'flush ruleset\n'
        value['transaction_sha256'] = hashlib.sha256(value['transaction'].encode()).hexdigest()
        other = self.encode(value)
        with self.assertRaises(ValueError):HISTORY.capture(other, self.model(proposal_sha256=hashlib.sha256(other).hexdigest()))
        value = json.loads(self.payload);value['intention']['policy']['rules']['input'][0]['expr'] = [{'accept': None}]
        with self.assertRaises(ValueError):HISTORY.capture(self.encode(value), self.model())

    def test_all_repeated_context_and_hash_facts_are_bound_to_real_plan(self):
        for change in ({'namespace': True}, {'namespace': 0}, {'namespace': self.plan['namespace'] + 1},
                       {'proposal_sha256': '0' * 64}, {'correlation_id': '0' * 64}, {'transaction_sha256': '0' * 64}):
            with self.subTest(change=change), self.assertRaises(ValueError):self.capture(self.model(**change))

    def test_fixed_actual_command_refuses_reordered_extra_or_other_operations(self):
        for command in ((str(self.binary), '-c', '--file', '-'), (str(self.binary), '-', '--file'),
                        (str(self.binary), 'flush', 'ruleset'), ('/other/nft', '--file', '-')):
            with self.subTest(command=command), self.assertRaises(ValueError):self.capture(self.model(command=command))

    def test_input_is_exact_transaction_not_a_prefix_or_hash_only_shortcut(self):
        data = self.plan['transaction'].encode()
        for raw in (b'', data[:-1], data + b'\n', b'other'):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):self.capture(self.model(input=raw))

    def test_reported_write_ledger_is_typed_bounded_and_never_inferred(self):
        data = self.plan['transaction'].encode()
        for count in (True, False, -1, 1.0, None, len(data) + 1):
            with self.subTest(count=count), self.assertRaises(ValueError):self.capture(self.model(input_written=count))
        self.assertEqual(json.loads(self.capture(self.model(input_written=13)))['evidence']['input_written'], 13)
        self.assertEqual(json.loads(self.capture())['evidence']['input_written'], 0)

    def test_received_counts_require_complete_bounded_raw_prefix_consistency(self):
        for received in ({'stdout': True, 'stderr': 0}, {'stdout': -1, 'stderr': 0}, {'stdout': 2, 'stderr': 0},
                         {'stdout': 0, 'stderr': 0}, {'stdout': 1}, {'stdout': 1, 'stderr': 0, 'extra': 0}):
            with self.subTest(received=received), self.assertRaises(ValueError):self.capture(self.model(stdout=b'x', received=received))
        with self.assertRaises(ValueError):self.capture(self.model(stdout=b'x' * TRANSPORT.MAX_BYTES,
            received={'stdout': TRANSPORT.MAX_BYTES + 65537, 'stderr': 0}))

    def test_binary_hex_is_canonical_not_whitespace_uppercase_or_replaced_text(self):
        raw = self.capture(self.model(stdout=b'\xff', received={'stdout': 1, 'stderr': 0}));value = json.loads(raw)
        for text in ('FF', 'ff ', 'f', 'zz', 255, True):
            modified = copy.deepcopy(value);modified['evidence']['stdout_hex'] = text
            with self.subTest(text=text), self.assertRaises(ValueError):HISTORY.checked(self.encode(modified))

    def test_known_exit_is_true_integer_or_null_and_is_never_synthesized(self):
        for code in (True, False, 0.0, '0', -(1 << 31) - 1, 1 << 31):
            with self.subTest(code=code), self.assertRaises(ValueError):self.capture(self.model(returncode=code))
        for code in (None, 0, 1, -9):self.assertEqual(json.loads(self.capture(self.model(returncode=code)))['evidence']['returncode'], code)

    def test_historical_deadline_is_finite_typed_context_not_freshness_authority(self):
        for end in (True, False, None, '1', 0, -1, float('nan'), float('inf')):
            with self.subTest(end=end), self.assertRaises(ValueError):self.capture(self.model(deadline=end))
        self.assertEqual(json.loads(self.capture(self.model(deadline=1)))['evidence']['deadline'], 1)

    def test_cleanup_inventory_shape_types_and_limits_are_not_silent_truncation(self):
        for cleanup in ((('OSError',),), (('bad type', 'message'),), (('OSError', 'x' * 1025),),
                        tuple(('OSError', '') for _ in range(5)), (('OSError', '\ud800'),)):
            with self.subTest(cleanup=repr(cleanup)), self.assertRaises(ValueError):self.capture(self.model(cleanup_errors=cleanup))

    def test_unknown_missing_and_cross_profile_fields_refuse(self):
        value = json.loads(self.capture())
        for modified in ({**value, 'extra': None}, {key: item for key, item in value.items() if key != 'cause'},
                         {**value, 'state': 'native-zero-exit-empty-capture'}, {**value, 'schema': 'other'}):
            with self.subTest(keys=list(modified)), self.assertRaises(ValueError):HISTORY.checked(self.encode(modified))
        modified = copy.deepcopy(value);modified['evidence']['extra'] = True
        with self.assertRaises(ValueError):HISTORY.checked(self.encode(modified))

    def test_payload_json_duplicate_keys_utf8_and_canonical_newline_refuse(self):
        raw = self.capture()
        for delivery in (None, raw.decode(), bytearray(raw), b'', b'\xff', raw.rstrip(), b' ' + raw,
                         b'{"schema":1,"schema":2}\n', self.encode({'schema': 'other'})):
            with self.subTest(kind=type(delivery).__name__), self.assertRaises(ValueError):HISTORY.checked(delivery)

    def test_raw_channel_and_record_limits_refuse_before_publication(self):
        for label in ('stdout', 'stderr'):
            with self.subTest(label=label), self.assertRaises(ValueError):self.capture(self.model(**{label: b'x' * (TRANSPORT.MAX_BYTES + 1)}))
        with patch.object(HISTORY, 'MAX_RECORD', 1), self.assertRaises(ValueError):HISTORY.record(self.store, self.payload, self.model())
        self.assertFalse(self.leaf.exists());self.assertEqual(list(self.store.iterdir()), [])

    def test_stored_outer_checksum_cannot_repair_an_invalid_inner_intention(self):
        raw = self.capture();outer = json.loads(HISTORY.envelope(raw));inner = json.loads(raw)
        inner['evidence']['transaction_sha256'] = '0' * 64
        corrupted = self.encode(inner);outer['payload'] = corrupted.decode();outer['payload_sha256'] = hashlib.sha256(corrupted).hexdigest()
        with self.assertRaises(ValueError):HISTORY.stored(self.encode(outer))
        outer = json.loads(HISTORY.envelope(raw));outer['payload_sha256'] = '0' * 64
        with self.assertRaises(ValueError):HISTORY.stored(self.encode(outer))

    def test_captured_bytes_privately_preserve_facts_after_exception_mutation(self):
        error = self.model();raw = self.capture(error);value = json.loads(raw)
        error.evidence['received']['stdout'] = 999;error.evidence['input'] = b'bad';error.evidence['namespace'] = 0
        self.assertEqual(HISTORY.checked(raw), value)
        self.assertEqual(value['evidence']['received']['stdout'], 0)

    def test_same_record_resync_is_same_inode_and_changed_facts_never_overwrite(self):
        error = self.model();raw = HISTORY.record(self.store, self.payload, error)
        inode = self.leaf.stat().st_ino;before = self.leaf.read_bytes()
        self.assertEqual(HISTORY.record(self.store, self.payload, error), raw)
        self.assertEqual(self.leaf.stat().st_ino, inode)
        different = self.model(returncode=0)
        with self.assertRaises(ValueError):HISTORY.record(self.store, self.payload, different)
        self.assertEqual(self.leaf.read_bytes(), before);self.assertEqual(self.leaf.stat().st_ino, inode)

    def test_store_load_and_capture_never_query_native_or_grant_retry(self):
        with (patch.object(TRANSPORT, 'transmit', side_effect=AssertionError('submission')),
              patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')),
              patch.object(KERNEL, 'namespace', side_effect=AssertionError('fresh scope')),
              patch.object(STATE.NFT, 'native_query', side_effect=AssertionError('nft query'))):
            raw = HISTORY.record(self.store, self.payload, self.model())
            self.assertEqual(HISTORY.load(self.store), raw)
            self.assertEqual(json.loads(raw)['state'], 'historical-uncertain-no-retry')

    def test_separate_backend_preserves_closed_storage_functions_and_old_protocols(self):
        old = old_fixture.STORE
        self.assertIsNot(BACKEND.__dict__, old.__dict__);self.assertEqual(old.LEAF, 'proposal.json')
        self.assertEqual(HISTORY.LEAF, 'first-uncertain.json')
        for name in ('create', 'load', 'locked', 'read_at', 'reconcile_link', 'staging_identity', 'directory_identity'):
            self.assertIs(getattr(BACKEND, name).__globals__, BACKEND.__dict__)
            self.assertEqual(ast.dump(ast.parse(inspect.getsource(getattr(BACKEND, name)))), ast.dump(ast.parse(inspect.getsource(getattr(old, name)))))
        with self.assertRaises(ValueError):old.envelope(self.capture())
        with self.assertRaises(ValueError):HISTORY.stored(self.payload)

    def test_missing_nonprivate_symbolic_corrupt_or_externally_linked_history_refuses(self):
        with self.assertRaises(FileNotFoundError):HISTORY.load(self.store)
        raw = HISTORY.record(self.store, self.payload, self.model());before = self.leaf.read_bytes()
        self.leaf.chmod(0o640)
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        self.leaf.chmod(0o600);extra = self.root / 'extra';os.link(self.leaf, extra)
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        extra.unlink();self.leaf.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        self.leaf.write_bytes(before);self.leaf.unlink();self.leaf.symlink_to(extra)
        with self.assertRaises(ValueError):HISTORY.load(self.store)
        self.assertEqual(json.loads(raw)['state'], 'historical-uncertain-no-retry')

    def test_cooperating_lock_refuses_without_wait_or_replacement(self):
        error = self.model();HISTORY.record(self.store, self.payload, error);before = self.leaf.read_bytes()
        fd = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):HISTORY.load(self.store)
            with self.assertRaises(BlockingIOError):HISTORY.record(self.store, self.payload, error)
        finally:os.close(fd)
        self.assertEqual(self.leaf.read_bytes(), before)

    def test_shared_deadline_precedes_capture_and_cannot_be_reset_for_storage(self):
        start = BACKEND.KERNEL.now();error = self.model()
        for end in (True, '1', start, start - 1, float('inf')):
            with self.subTest(end=end), patch.object(HISTORY, 'capture', side_effect=AssertionError('capture')), self.assertRaises(ValueError):
                HISTORY.record(self.store, self.payload, error, deadline=end)
        real = HISTORY.capture;clock = [start]
        def expired(*args):
            raw = real(*args);clock[0] += 11;return raw
        with patch.object(BACKEND.KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(HISTORY, 'capture', side_effect=expired), self.assertRaises(ValueError):
            HISTORY.record(self.store, self.payload, error, deadline=start + 2)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_sync_failure_retains_visible_uncertain_data_without_claiming_success(self):
        fsync = BACKEND.os.fsync;calls = []
        def fail(fd):
            calls.append(fd)
            if len(calls) == 2:raise OSError('directory synchronization')
            return fsync(fd)
        with patch.object(BACKEND.os, 'fsync', side_effect=fail), self.assertRaises(OSError):HISTORY.record(self.store, self.payload, self.model())
        self.assertTrue(self.leaf.exists());self.assertEqual(json.loads(HISTORY.load(self.store))['state'], 'historical-uncertain-no-retry')

    def test_actual_private_transport_warning_is_stored_once_without_second_submission(self):
        out, err = b'out\r\n\xff', b'err\r\n\xe2\x82'
        self.executable(f'os.write(1,{out!r});os.write(2,{err!r})')
        with patch.object(TRANSPORT.subprocess, 'Popen', wraps=TRANSPORT.subprocess.Popen) as spawn:
            with self.assertRaises(TRANSPORT.Uncertain) as caught:TRANSPORT.transmit(self.payload)
            raw = HISTORY.record(self.store, self.payload, caught.exception);self.assertEqual(HISTORY.load(self.store), raw)
            self.assertEqual(spawn.call_count, 1)
        row = json.loads(raw)['evidence'];self.assertEqual(row['returncode'], 0)
        self.assertEqual(row['input_written'], len(self.plan['transaction'].encode()))
        self.assertEqual((self.root / 'input').read_bytes(), bytes.fromhex(row['input_hex']))
        self.assertEqual(bytes.fromhex(row['stdout_hex']), out);self.assertEqual(bytes.fromhex(row['stderr_hex']), err)

    def test_actual_private_interrupted_write_preserves_zero_ledger_and_nonempty_input(self):
        self.executable('')
        write = TRANSPORT.os.write;sent = []
        def interrupted(fd, data):
            sent.append(write(fd, data[:13]));raise KeyboardInterrupt('delivery interrupted')
        with patch.object(TRANSPORT.os, 'write', side_effect=interrupted), self.assertRaises(TRANSPORT.Uncertain) as caught:TRANSPORT.transmit(self.payload)
        raw = HISTORY.record(self.store, self.payload, caught.exception);value = json.loads(raw)
        self.assertEqual(sent, [13]);self.assertEqual(value['evidence']['input_written'], 0)
        self.assertEqual(value['cause'][0], 'KeyboardInterrupt')
        self.assertEqual(bytes.fromhex(value['evidence']['input_hex']), self.plan['transaction'].encode())

    def test_actual_private_spawn_failure_keeps_unknown_exit_and_never_retries(self):
        self.executable('')
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=OSError('exec unavailable')) as spawn, self.assertRaises(TRANSPORT.Uncertain) as caught:
            TRANSPORT.transmit(self.payload)
        raw = HISTORY.record(self.store, self.payload, caught.exception)
        self.assertEqual(spawn.call_count, 1);self.assertIsNone(json.loads(raw)['evidence']['returncode'])
        self.assertEqual(json.loads(raw)['cause'][0], 'OSError')
