import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_auto_intent as automatic_fixture
import test_nft_manifest as manifest_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_proposal_audit', ROOT / 'Firewall/proposal_audit.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
STORE, MANIFEST, KERNEL = AUDIT.STORE, AUDIT.MANIFEST, AUDIT.KERNEL
NFT, STATE = AUDIT.STATE.NFT, AUDIT.STATE


class PrivateAudit:
    def __init__(self, test):
        helper = automatic_fixture.AutomaticTests();helper.setUp()
        try:self.payload = helper.prepare()
        finally:helper.doCleanups()
        self.record = json.loads(self.payload);self.namespace = self.record['namespace']
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-proposal-audit-', dir='/dev/shm')
        test.addCleanup(directory.cleanup)
        self.root = Path(directory.name);self.root.chmod(0o700)
        self.store = self.root / 'state';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf = self.store / STORE.LEAF
        for setting in (patch.object(STORE, 'TRUST_ROOT', self.root), patch.object(STORE, 'TRUSTED_UID', os.geteuid())):
            setting.start();test.addCleanup(setting.stop)
        STORE.create(self.store, self.payload)
        # This is an intention-derived SOURCE model, not a native formatter
        # oracle or independently observed live policy/lease/ownership proof.
        self.native = manifest_fixture.native(self.record['topology'])

    def query(self, deadline):
        return copy.deepcopy(self.native)

    def audit(self, **options):
        return AUDIT.audit(self.store, query=options.pop('query', self.query),
                           scope=options.pop('scope', lambda: self.namespace), **options)

    def replace(self, namespace):
        record = copy.deepcopy(self.record);record['namespace'] = namespace
        payload = STATE.encoded(record) + b'\n'
        self.leaf.write_bytes(STORE.envelope(payload));return payload


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateAudit(self)

    def clock(self):
        value = [KERNEL.now()]
        for kernel in (KERNEL, STORE.KERNEL):
            setting = patch.object(kernel, 'now', side_effect=lambda: value[0])
            setting.start();self.addCleanup(setting.stop)
        return value

    def test_real_store_and_compiler_comparison_produce_exact_immutable_historical_receipt(self):
        before = self.fixture.leaf.read_bytes();inode = self.fixture.leaf.stat().st_ino
        calls = []
        def query(deadline):calls.append(deadline);return self.fixture.query(deadline)
        raw = self.fixture.audit(query=query);result = json.loads(raw)
        self.assertIs(type(raw), bytes);self.assertEqual(raw, STATE.encoded(result) + b'\n')
        self.assertEqual(result['schema'], 'debian13s4-historical-nft-source-audit-1')
        self.assertEqual(result['profile'], 'historical-proposal-compiler-source-correspondence-1')
        self.assertEqual(result['state'], 'historical-source-correspondence')
        self.assertEqual(result['namespace'], self.fixture.namespace)
        self.assertEqual(result['historical_admission_profile'], self.fixture.record['admission_profile'])
        self.assertEqual(result['proposal_sha256'], hashlib.sha256(self.fixture.payload).hexdigest())
        for key, value in self.fixture.record['intention'].items():self.assertEqual(result['comparison'][key], value)
        self.assertEqual(len(calls), 2);self.assertEqual(calls[0], calls[1])
        self.assertEqual(self.fixture.leaf.read_bytes(), before);self.assertEqual(self.fixture.leaf.stat().st_ino, inode)
        self.assertEqual([path.name for path in self.fixture.store.iterdir()], [STORE.LEAF])

    def test_missing_corrupt_or_forged_applied_history_refuses_before_native_delivery(self):
        for data in (None, b'broken', STATE.encoded({'state': 'applied'}) + b'\n'):
            if data is None:self.fixture.leaf.unlink()
            else:self.fixture.leaf.write_bytes(data);self.fixture.leaf.chmod(0o600)
            with self.subTest(data=data), self.assertRaises((OSError, ValueError)):
                self.fixture.audit(query=lambda deadline: self.fail('unexpected native read'))

    def test_real_recompiler_rejects_tampered_expected_policy_before_native_delivery(self):
        record = copy.deepcopy(self.fixture.record)
        record['intention']['policy']['rules']['input'][0]['expr'][-1] = {'accept': None}
        payload = STATE.encoded(record) + b'\n'
        self.fixture.leaf.write_bytes(STATE.encoded({'schema': 'debian13s4-nft-intent-history-1',
            'state': 'historical-proposal', 'payload': payload.decode(), 'sha256': hashlib.sha256(payload).hexdigest()}) + b'\n')
        with self.assertRaises(ValueError):self.fixture.audit(query=lambda deadline: self.fail('unexpected native read'))

    def test_valid_history_from_different_caller_context_is_not_a_current_source_match(self):
        other = self.fixture.replace(self.fixture.namespace + 1)
        self.assertEqual(STORE.load(self.fixture.store), other)
        with self.assertRaises(AUDIT.Pending):self.fixture.audit(query=lambda deadline: self.fail('unexpected native read'))

    def test_namespace_requires_true_positive_uint64_before_disk_or_native_reads(self):
        with patch.object(STORE, 'load', side_effect=AssertionError('disk read')):
            for namespace in (True, False, 0, -1, 1 << 64, '1', None):
                with self.subTest(namespace=namespace), self.assertRaises(ValueError):self.fixture.audit(scope=lambda: namespace)

    def test_bad_deadlines_and_noncallable_adapters_refuse_before_any_disk_read(self):
        with patch.object(STORE, 'load', side_effect=AssertionError('disk read')):
            for deadline in (True, False, float('nan'), float('inf'), KERNEL.now() - 1, '10'):
                with self.subTest(deadline=deadline), self.assertRaises(AUDIT.Pending):self.fixture.audit(deadline=deadline)
            for key in ('query', 'scope'):
                with self.subTest(key=key), self.assertRaises(AUDIT.Pending):self.fixture.audit(**{key: None})

    def test_all_real_loads_and_both_queries_share_minimum_inherited_deadline(self):
        clock = self.clock();original = STORE.load
        for parent, expected in ((clock[0] + 2, clock[0] + 2), (clock[0] + 50, clock[0] + 10)):
            loads, queries = [], []
            def load(path, deadline):loads.append(deadline);return original(path, deadline=deadline)
            def query(deadline):queries.append(deadline);return self.fixture.query(deadline)
            with patch.object(STORE, 'load', side_effect=load):self.fixture.audit(query=query, deadline=parent)
            self.assertEqual(loads, [expected, expected]);self.assertEqual(queries, [expected, expected])

    def test_valid_changed_history_after_comparison_withholds_receipt(self):
        original = MANIFEST.verify
        def verify(*args, **kwargs):
            result = original(*args, **kwargs);self.fixture.replace(self.fixture.namespace + 1);return result
        with patch.object(MANIFEST, 'verify', side_effect=verify), self.assertRaisesRegex(AUDIT.Pending, 'bytes changed'):
            self.fixture.audit()

    def test_actual_corruption_after_comparison_fails_the_final_real_store_read(self):
        original = MANIFEST.verify
        def verify(*args, **kwargs):
            result = original(*args, **kwargs);self.fixture.leaf.write_bytes(b'corrupt');return result
        with patch.object(MANIFEST, 'verify', side_effect=verify), self.assertRaises(ValueError):self.fixture.audit()

    def test_unsafe_final_leaf_cannot_be_hidden_by_a_matching_nft_record(self):
        original = MANIFEST.verify
        def verify(*args, **kwargs):
            result = original(*args, **kwargs);self.fixture.leaf.chmod(0o660);return result
        with patch.object(MANIFEST, 'verify', side_effect=verify), self.assertRaises(ValueError):self.fixture.audit()

    def test_final_caller_context_is_checked_after_the_second_real_store_load(self):
        for last in (True, self.fixture.namespace + 1):
            calls = []
            def scope():
                calls.append(len(calls) + 1);return last if len(calls) == 5 else self.fixture.namespace
            with self.subTest(last=last), patch.object(STORE, 'load', wraps=STORE.load) as load, self.assertRaises(AUDIT.Pending):
                self.fixture.audit(scope=scope)
            self.assertEqual(load.call_count, 2);self.assertEqual(calls, [1, 2, 3, 4, 5])

    def test_inner_namespace_drift_refuses_even_when_the_final_context_would_return(self):
        for turn in (2, 3, 4):
            count = [0]
            def scope():
                count[0] += 1;return self.fixture.namespace + 1 if count[0] == turn else self.fixture.namespace
            with self.subTest(turn=turn), self.assertRaises(AUDIT.Pending):self.fixture.audit(scope=scope)

    def test_structurally_admitted_accept_all_is_not_a_match_to_historical_intention(self):
        value = copy.deepcopy(self.fixture.native)
        for row in manifest_fixture.objects(value, 'rule'):
            if row['chain'] == 'input':row['expr'] = [{'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]
        self.assertTrue(STATE.project(value))
        with self.assertRaisesRegex(AUDIT.Pending, 'intention'):self.fixture.audit(query=lambda deadline: value)

    def test_complete_match_checks_order_verdict_selectors_and_static_set_elements(self):
        for change in ('order', 'verdict', 'selector', 'set'):
            value = copy.deepcopy(self.fixture.native);rules = manifest_fixture.objects(value, 'rule')
            if change == 'order':rules[0]['expr'][0:2] = list(reversed(rules[0]['expr'][0:2]))
            elif change == 'verdict':rules[0]['expr'][-1] = {'accept': None}
            elif change == 'selector':rules[0]['expr'][0]['match']['left'] = {'meta': {'key': 'oifname'}}
            else:manifest_fixture.objects(value, 'set')[0]['elem'] = ['203.0.113.250']
            with self.subTest(change=change), self.assertRaises(ValueError):self.fixture.audit(query=lambda deadline: value)

    def test_foreign_missing_and_empty_rulesets_never_certify_stored_history(self):
        for value in ({'nftables': [self.fixture.native['nftables'][0]]}, {'nftables': []},
                      {'nftables': self.fixture.native['nftables'] + [{'flowtable': {}}]}):
            with self.subTest(value=str(value)[:50]), self.assertRaises(ValueError):self.fixture.audit(query=lambda deadline: value)

    def test_second_observation_handle_and_metadata_drift_are_not_discarded(self):
        for change in ('handle', 'metadata'):
            value = copy.deepcopy(self.fixture.native)
            if change == 'handle':manifest_fixture.objects(value, 'table')[0]['handle'] += 100
            else:value['nftables'][0]['metainfo']['release_name'] = 'changed'
            deliveries = iter([self.fixture.native, value])
            with self.subTest(change=change), self.assertRaises(AUDIT.Pending):self.fixture.audit(query=lambda deadline: next(deliveries))

    def test_only_counter_statistics_may_vary_and_last_values_are_retained(self):
        first = copy.deepcopy(self.fixture.native);second = copy.deepcopy(first)
        for row in manifest_fixture.objects(second, 'rule'):
            for statement in row['expr']:
                if 'counter' in statement:statement['counter'] = {'packets': 0, 'bytes': 0}
        deliveries = iter([first, second]);result = json.loads(self.fixture.audit(query=lambda deadline: next(deliveries)))
        self.assertEqual(result['comparison']['statistics'], STATE.project(second)['statistics'])
        self.assertEqual(result['comparison']['identity'], STATE.project(second)['identity'])

    def test_query_mutation_of_its_old_delivery_cannot_rewrite_checked_policy(self):
        first = copy.deepcopy(self.fixture.native);calls = [0]
        def query(deadline):
            calls[0] += 1
            if calls[0] == 1:return first
            manifest_fixture.objects(first, 'rule')[0]['expr'][-1] = {'accept': None}
            return self.fixture.query(deadline)
        result = json.loads(self.fixture.audit(query=query))
        self.assertEqual(result['comparison']['policy'], self.fixture.record['intention']['policy'])

    def test_receipt_byte_bound_is_enforced_before_final_store_read(self):
        with patch.object(AUDIT, 'MAX_OUTPUT', 1), patch.object(STORE, 'load', wraps=STORE.load) as load, self.assertRaises(AUDIT.Pending):
            self.fixture.audit()
        self.assertEqual(load.call_count, 1)

    def test_full_receipt_encoding_precedes_final_store_and_expiry_fences(self):
        clock = self.clock();original = STATE.encoded
        def encode(value):
            result = original(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-historical-nft-source-audit-1':clock[0] += 11
            return result
        with patch.object(STATE, 'encoded', side_effect=encode), patch.object(STORE, 'load', wraps=STORE.load) as load, self.assertRaises(AUDIT.Pending):
            self.fixture.audit()
        self.assertEqual(load.call_count, 1)

    def test_expired_initial_real_load_cannot_admit_native_queries(self):
        clock = self.clock();original = STORE.load
        def load(*args, **kwargs):result = original(*args, **kwargs);clock[0] += 11;return result
        with patch.object(STORE, 'load', side_effect=load), self.assertRaises(AUDIT.Pending):
            self.fixture.audit(query=lambda deadline: self.fail('expired native admission'))

    def test_expired_final_real_load_withholds_completed_receipt(self):
        clock = self.clock();original = STORE.load;calls = [0]
        def load(*args, **kwargs):
            result = original(*args, **kwargs);calls[0] += 1
            if calls[0] == 2:clock[0] += 11
            return result
        with patch.object(STORE, 'load', side_effect=load), self.assertRaises(AUDIT.Pending):self.fixture.audit()
        self.assertEqual(calls[0], 2)

    def test_read_only_audit_has_no_create_sync_link_unlink_or_write_delivery(self):
        settings = [patch.object(STORE.os, name, side_effect=AssertionError(name)) for name in ('write', 'fsync', 'link', 'unlink', 'fchmod')]
        for setting in settings:setting.start()
        try:self.assertIs(type(self.fixture.audit()), bytes)
        finally:
            for setting in reversed(settings):setting.stop()

    def test_actual_cooperating_directory_lock_failure_does_not_reach_nft(self):
        descriptor = os.open(self.fixture.store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.fixture.audit(query=lambda deadline: self.fail('locked native read'))
        finally:os.close(descriptor)


class NativeAuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateAudit(self)
        self.binary = self.fixture.root / 'nft';self.ledger = self.fixture.root / 'ledger'
        for setting in (patch.object(NFT, 'BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.fixture.root),
                        patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())):
            setting.start();self.addCleanup(setting.stop)

    def executable(self, value=None, body=None):
        prefix = f'import json,os,sys\nwith open({str(self.ledger)!r},"a") as stream:stream.write(json.dumps([sys.argv[1:],dict(os.environ)])+"\\n")\n'
        self.binary.write_text('#!/usr/bin/python3 -B\n' + prefix + (body if body is not None else 'print(' + repr(json.dumps(self.fixture.native if value is None else value)) + ')') + '\n')
        self.binary.chmod(0o700)

    def audit(self):
        return AUDIT.audit(self.fixture.store)

    def test_complete_private_file_capture_parser_compiler_and_final_readback_path(self):
        self.executable();before = self.fixture.leaf.read_bytes()
        with patch.dict(os.environ, {'TASK_SECRET': 'bad', 'NFT_CTX_FLAGS': 'bad'}), patch.object(STORE, 'load', wraps=STORE.load) as load:
            raw = self.audit()
        result = json.loads(raw);self.assertEqual(load.call_count, 2)
        self.assertEqual(result['comparison']['policy'], self.fixture.record['intention']['policy'])
        self.assertEqual(result['comparison']['source']['binary'], str(self.binary))
        self.assertEqual(result['namespace'], KERNEL.namespace());self.assertEqual(self.fixture.leaf.read_bytes(), before)
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()];self.assertEqual(len(rows), 2)
        for argv, environment in rows:
            self.assertEqual(argv, list(NFT.COMMAND));self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})

    def test_actual_native_warning_exit_and_foreign_delivery_cannot_produce_receipt(self):
        foreign = copy.deepcopy(self.fixture.native);foreign['nftables'].append({'flowtable': {}})
        for body in ('raise SystemExit(1)', "print('{')", f'print({json.dumps(foreign)!r})',
                     f'import sys;print({json.dumps(self.fixture.native)!r});print("warning",file=sys.stderr)'):
            self.executable(body=body)
            with self.subTest(body=body), self.assertRaises((OSError, ValueError)):self.audit()

    def test_actual_matching_shape_with_wrong_verdict_is_not_historical_correspondence(self):
        value = copy.deepcopy(self.fixture.native);manifest_fixture.objects(value, 'rule')[0]['expr'][-1] = {'accept': None}
        self.executable(value)
        with self.assertRaisesRegex(AUDIT.Pending, 'intention'):self.audit()

    def test_actual_changed_second_handle_is_refused_with_both_queries_recorded(self):
        counter = self.fixture.root / 'turn'
        self.executable(body=f'from pathlib import Path\np=Path({str(counter)!r});n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))\nv=json.loads({json.dumps(self.fixture.native)!r});v["nftables"][1]["table"]["handle"]+=n\nprint(json.dumps(v))')
        with self.assertRaisesRegex(AUDIT.Pending, 'changed'):self.audit()
        self.assertEqual(counter.read_text(), '2');self.assertEqual(len(self.ledger.read_text().splitlines()), 2)

    def test_real_store_damage_by_second_native_delivery_withholds_all_receipt_bytes(self):
        counter = self.fixture.root / 'turn'
        self.executable(body=f'from pathlib import Path\np=Path({str(counter)!r});n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))\nif n==2:Path({str(self.fixture.leaf)!r}).write_bytes(b"damaged")\nprint({json.dumps(self.fixture.native)!r})')
        with self.assertRaises(ValueError):self.audit()
        self.assertEqual(counter.read_text(), '2');self.assertEqual(self.fixture.leaf.read_bytes(), b'damaged')

    def test_nonascii_native_identity_is_preserved_in_exact_utf8_receipt_bytes(self):
        self.binary = self.fixture.root / 'nft-é';setting = patch.object(NFT, 'BINARY', self.binary)
        setting.start();self.addCleanup(setting.stop);self.executable()
        raw = self.audit();self.assertIn('nft-é'.encode('utf-8'), raw)
        self.assertEqual(json.loads(raw)['comparison']['source']['binary'], str(self.binary))


if __name__ == '__main__':unittest.main()
