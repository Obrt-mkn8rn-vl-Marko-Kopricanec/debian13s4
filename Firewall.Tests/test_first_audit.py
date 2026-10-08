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

import test_first_create as plan_fixture
import test_first_match as match_fixture
import test_nft_manifest as native_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_audit', ROOT / 'Firewall/first_audit.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
REGISTER, MATCH, STATE, KERNEL = AUDIT.REGISTER, AUDIT.MATCH, AUDIT.STATE, AUDIT.KERNEL
BACKEND, NFT = REGISTER._STORAGE, STATE.NFT


def encoded(value):
    return STATE.encoded(value) + b'\n'


class PrivateAudit:
    def __init__(self, test):
        helper = plan_fixture.PlanTests();helper.setUp()
        try:self.payload = helper.prepare()
        finally:helper.doCleanups()
        self.plan = json.loads(self.payload);self.namespace = self.plan['namespace']
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-audit-', dir='/dev/shm');test.addCleanup(directory.cleanup)
        self.root = Path(directory.name);self.root.chmod(0o700)
        self.store = self.root / 'registration';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf = self.store / REGISTER.LEAF
        for setting in (patch.object(BACKEND, 'TRUST_ROOT', self.root), patch.object(BACKEND, 'TRUSTED_UID', os.geteuid())):
            setting.start();test.addCleanup(setting.stop)
        REGISTER.create(self.store, self.payload)
        # This complete marked SOURCE reply is an intention-derived MODEL,
        # not an independent native formatter, owner or fresh-admission oracle.
        self.native = match_fixture.marked(self.plan)

    def query(self, deadline):
        return copy.deepcopy(self.native)

    def audit(self, **settings):
        return AUDIT.audit(self.store, **({'query': self.query, 'scope': lambda: self.namespace} | settings))

    def replace(self, namespace):
        plan = self.plan | {'namespace': namespace};payload = encoded(plan)
        self.leaf.write_bytes(REGISTER.envelope(payload));return payload


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateAudit(self)

    def clock(self):
        value = [KERNEL.now()]
        for kernel in (KERNEL, MATCH.KERNEL):
            setting = patch.object(kernel, 'now', side_effect=lambda: value[0]);setting.start();self.addCleanup(setting.stop)
        return value

    def test_real_registration_loader_compiler_and_marked_comparison_return_complete_historical_bytes(self):
        before = self.fixture.leaf.read_bytes();inode = self.fixture.leaf.stat().st_ino
        calls = []
        with patch.object(REGISTER, 'load', wraps=REGISTER.load) as load:
            raw = self.fixture.audit(query=lambda end: calls.append(end) or self.fixture.query(end))
        result = json.loads(raw)
        self.assertIs(type(raw), bytes);self.assertEqual(raw, encoded(result));self.assertLessEqual(len(raw), AUDIT.MAX_OUTPUT)
        self.assertEqual(result['schema'], 'debian13s4-registered-first-create-source-audit-1')
        self.assertEqual(result['state'], 'historical-source-correspondence')
        self.assertEqual(result['profile'], 'historical-registration-marked-source-correspondence-1')
        self.assertEqual(result['namespace'], self.fixture.namespace)
        self.assertEqual(result['historical_admission_profile'], self.fixture.plan['admission_profile'])
        self.assertEqual(result['proposal_sha256'], hashlib.sha256(self.fixture.payload).hexdigest())
        for key in ('correlation_id', 'transaction_sha256'):self.assertEqual(result[key], self.fixture.plan[key])
        self.assertEqual(result['comparison']['intention'], self.fixture.plan['intention'])
        self.assertEqual(result['comparison']['observation']['comment'], MATCH.PLAN.COMMENT_PREFIX + self.fixture.plan['correlation_id'])
        self.assertEqual(load.call_count, 2);self.assertEqual(len(calls), 2);self.assertEqual(calls[0], calls[1])
        self.assertEqual(self.fixture.leaf.read_bytes(), before);self.assertEqual(self.fixture.leaf.stat().st_ino, inode)
        self.assertEqual({p.name for p in self.fixture.store.iterdir()}, {REGISTER.LEAF})

    def test_missing_corrupt_and_applied_or_owned_history_refuse_before_native_reads(self):
        for data in (None, b'broken', encoded({'state': 'applied'}), encoded({'state': 'owned'})):
            if data is None:self.fixture.leaf.unlink()
            else:self.fixture.leaf.write_bytes(data);self.fixture.leaf.chmod(0o600)
            with self.subTest(data=data), self.assertRaises((OSError, ValueError)):
                self.fixture.audit(query=lambda end: self.fail('invalid history native read'))

    def test_recomputed_outer_hash_cannot_hide_wrong_transaction_or_intention(self):
        original = self.fixture.leaf.read_bytes()
        for change in ('transaction', 'intention'):
            plan = copy.deepcopy(self.fixture.plan)
            if change == 'transaction':plan['transaction'] = plan['transaction'].replace('policy drop;', 'policy accept;', 1)
            else:plan['intention']['policy']['rules']['input'][0]['expr'][-1] = {'accept': None}
            payload = encoded(plan);value = json.loads(original)
            value['payload'] = payload.decode();value['payload_sha256'] = hashlib.sha256(payload).hexdigest()
            self.fixture.leaf.write_bytes(encoded(value))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.fixture.audit(query=lambda end: self.fail('forged intention native read'))

    def test_another_historical_context_is_loadable_but_not_admitted_for_current_comparison(self):
        other = self.fixture.replace(self.fixture.namespace + 1)
        self.assertEqual(REGISTER.load(self.fixture.store), other)
        with self.assertRaisesRegex(ValueError, 'another caller context'):
            self.fixture.audit(query=lambda end: self.fail('foreign context read'))

    def test_initial_namespace_requires_true_positive_uint64_before_disk(self):
        with patch.object(REGISTER, 'load', side_effect=AssertionError('disk')):
            for value in (True, False, 0, -1, 1 << 64, '1', None):
                with self.subTest(value=value), self.assertRaises(ValueError):self.fixture.audit(scope=lambda: value)

    def test_invalid_deadlines_and_noncallable_readers_refuse_before_disk(self):
        with patch.object(REGISTER, 'load', side_effect=AssertionError('disk')):
            for end in (True, False, KERNEL.now() - 1, float('nan'), float('inf'), '10'):
                with self.subTest(end=end), self.assertRaises(ValueError):self.fixture.audit(deadline=end)
            for key in ('query', 'scope'):
                with self.subTest(key=key), self.assertRaises(ValueError):self.fixture.audit(**{key: None})

    def test_two_real_loads_and_queries_share_the_minimum_parent_and_own_window(self):
        clock = self.clock();original = REGISTER.load
        for parent, end in ((clock[0] + 2, clock[0] + 2), (clock[0] + 50, clock[0] + 10)):
            loads, queries = [], []
            def load(path, deadline):loads.append(deadline);return original(path, deadline=deadline)
            with patch.object(REGISTER, 'load', side_effect=load):
                self.fixture.audit(query=lambda deadline: queries.append(deadline) or self.fixture.query(deadline), deadline=parent)
            self.assertEqual(loads, [end, end]);self.assertEqual(queries, [end, end])

    def test_changed_valid_registration_after_real_comparison_withholds_receipt(self):
        original = MATCH.verify
        def verify(*args, **kwargs):
            result = original(*args, **kwargs);self.fixture.replace(self.fixture.namespace + 1);return result
        with patch.object(MATCH, 'verify', side_effect=verify), self.assertRaisesRegex(ValueError, 'bytes changed'):
            self.fixture.audit()

    def test_corruption_and_unsafe_mode_after_comparison_fail_the_final_real_load(self):
        original = MATCH.verify
        for damage in ('bytes', 'mode'):
            self.fixture.leaf.write_bytes(REGISTER.envelope(self.fixture.payload));self.fixture.leaf.chmod(0o600)
            def verify(*args, **kwargs):
                result = original(*args, **kwargs)
                if damage == 'bytes':self.fixture.leaf.write_bytes(b'damaged')
                else:self.fixture.leaf.chmod(0o660)
                return result
            with self.subTest(damage=damage), patch.object(MATCH, 'verify', side_effect=verify), self.assertRaises(ValueError):
                self.fixture.audit()

    def test_final_typed_context_is_checked_after_the_second_real_load(self):
        for last in (True, self.fixture.namespace + 1):
            calls = []
            def scope():calls.append(1);return last if len(calls) == 4 else self.fixture.namespace
            with self.subTest(last=last), patch.object(REGISTER, 'load', wraps=REGISTER.load) as load, self.assertRaises(ValueError):
                self.fixture.audit(scope=scope)
            self.assertEqual(len(calls), 4);self.assertEqual(load.call_count, 2)

    def test_inner_context_drift_refuses_even_if_a_later_scope_would_return(self):
        for turn in (2, 3):
            calls = []
            def scope():calls.append(1);return self.fixture.namespace + 1 if len(calls) == turn else self.fixture.namespace
            with self.subTest(turn=turn), self.assertRaises(ValueError):self.fixture.audit(scope=scope)
            self.assertEqual(len(calls), turn)

    def test_matching_public_marker_does_not_admit_accept_all_or_changed_full_policy(self):
        for change in ('verdict', 'order', 'selector', 'set'):
            value = copy.deepcopy(self.fixture.native);rules = native_fixture.objects(value, 'rule')
            if change == 'verdict':rules[0]['expr'][-1] = {'accept': None}
            elif change == 'order':rules[0]['expr'][0:2] = list(reversed(rules[0]['expr'][0:2]))
            elif change == 'selector':rules[0]['expr'][0]['match']['left'] = {'meta': {'key': 'oifname'}}
            else:native_fixture.objects(value, 'set')[0]['elem'] = ['203.0.113.250']
            with self.subTest(change=change), self.assertRaises(ValueError):self.fixture.audit(query=lambda end: value)

    def test_absent_foreign_extra_or_unmarked_objects_are_not_filtered_away(self):
        wrong = copy.deepcopy(self.fixture.native);del native_fixture.objects(wrong, 'table')[0]['comment']
        for value in ({'nftables': [self.fixture.native['nftables'][0]]}, {'nftables': []}, wrong,
                      {'nftables': self.fixture.native['nftables'] + [{'flowtable': {}}]}):
            with self.subTest(value=str(value)[:45]), self.assertRaises(ValueError):self.fixture.audit(query=lambda end: value)

    def test_second_handle_comment_and_metadata_drift_cannot_be_hidden_by_policy_hash(self):
        for change in ('handle', 'comment', 'metadata'):
            value = copy.deepcopy(self.fixture.native);table = native_fixture.objects(value, 'table')[0]
            if change == 'handle':table['handle'] += 100
            elif change == 'comment':table['comment'] = MATCH.PLAN.COMMENT_PREFIX + '0' * 64
            else:value['nftables'][0]['metainfo']['release_name'] = 'changed'
            deliveries = iter([self.fixture.native, value])
            with self.subTest(change=change), self.assertRaises(ValueError):self.fixture.audit(query=lambda end: next(deliveries))

    def test_only_anonymous_statistics_can_change_and_last_values_remain_in_receipt(self):
        first = copy.deepcopy(self.fixture.native);second = copy.deepcopy(first)
        for rule in native_fixture.objects(second, 'rule'):
            for statement in rule['expr']:
                if 'counter' in statement:statement['counter'] = {'packets': 0, 'bytes': 0}
        deliveries = iter([first, second]);result = json.loads(self.fixture.audit(query=lambda end: next(deliveries)))
        projected = MATCH.project(second, MATCH.PLAN.COMMENT_PREFIX + self.fixture.plan['correlation_id'])
        self.assertEqual(result['comparison']['observation']['statistics'], projected['statistics'])
        self.assertEqual(result['comparison']['observation']['identity'], projected['identity'])

    def test_mutating_a_prior_native_dictionary_cannot_rewrite_checked_comparison(self):
        first = copy.deepcopy(self.fixture.native);calls = []
        def query(end):
            calls.append(1)
            if len(calls) == 1:return first
            native_fixture.objects(first, 'rule')[0]['expr'][-1] = {'accept': None};return self.fixture.query(end)
        result = json.loads(self.fixture.audit(query=query))
        self.assertEqual(result['comparison']['intention'], self.fixture.plan['intention'])

    def test_comparator_identity_contract_is_checked_before_final_registration_load(self):
        original = MATCH.verify
        for key, bad in (('schema', 'owned'), ('state', 'applied'), ('profile', 'fresh'), ('namespace', True),
                         ('correlation_id', '0' * 64), ('proposal_sha256', '0' * 64), ('transaction_sha256', '0' * 64)):
            def verify(*args, **kwargs):return encoded(json.loads(original(*args, **kwargs)) | {key: bad})
            with self.subTest(key=key), patch.object(MATCH, 'verify', side_effect=verify), \
                    patch.object(REGISTER, 'load', wraps=REGISTER.load) as load, self.assertRaises(ValueError):self.fixture.audit()
            self.assertEqual(load.call_count, 1)

    def test_comparator_complete_fields_intention_and_canonical_bytes_are_checked(self):
        original = MATCH.verify
        for change in ('extra', 'missing', 'intention', 'canonical'):
            def verify(*args, **kwargs):
                raw = original(*args, **kwargs);value = json.loads(raw)
                if change == 'extra':value['owned'] = True
                elif change == 'missing':del value['observation']
                elif change == 'intention':value['intention']['policy']['rules']['input'][0]['expr'][-1] = {'accept': None}
                else:return b' ' + raw
                return encoded(value)
            with self.subTest(change=change), patch.object(MATCH, 'verify', side_effect=verify), self.assertRaises(ValueError):self.fixture.audit()

    def test_receipt_limit_and_serialization_expiry_precede_final_store_admission(self):
        with patch.object(AUDIT, 'MAX_OUTPUT', 1), patch.object(REGISTER, 'load', wraps=REGISTER.load) as load, self.assertRaises(ValueError):
            self.fixture.audit()
        self.assertEqual(load.call_count, 1)
        clock = self.clock();original = STATE.encoded
        def encode(value):
            result = original(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-registered-first-create-source-audit-1':clock[0] += 11
            return result
        with patch.object(STATE, 'encoded', side_effect=encode), patch.object(REGISTER, 'load', wraps=REGISTER.load) as load, self.assertRaises(ValueError):
            self.fixture.audit()
        self.assertEqual(load.call_count, 1)

    def test_expired_initial_and_final_real_loads_withhold_native_admission_or_receipt(self):
        clock = self.clock();original = REGISTER.load
        for turn in (1, 2):
            calls = []
            def load(*args, **kwargs):
                result = original(*args, **kwargs);calls.append(1)
                if len(calls) == turn:clock[0] += 11
                return result
            queries = []
            with self.subTest(turn=turn), patch.object(REGISTER, 'load', side_effect=load), self.assertRaises(ValueError):
                self.fixture.audit(query=lambda end: queries.append(1) or self.fixture.query(end))
            self.assertEqual(len(calls), turn);self.assertEqual(len(queries), 0 if turn == 1 else 2)

    def test_no_hash_compilation_or_encoding_occurs_after_final_typed_context_barrier(self):
        final = [];original_encode, original_hash, original_compile = STATE.encoded, hashlib.sha256, MATCH.PLAN.ASSEMBLY.POLICY.compile_policy
        calls = []
        def scope():
            calls.append(1)
            if len(calls) == 4:final.append(True)
            return self.fixture.namespace
        def encode(value):self.assertFalse(final);return original_encode(value)
        def digest(value):self.assertFalse(final);return original_hash(value)
        def compile_policy(raw):self.assertFalse(final);return original_compile(raw)
        with patch.object(STATE, 'encoded', side_effect=encode), patch.object(hashlib, 'sha256', side_effect=digest), \
                patch.object(MATCH.PLAN.ASSEMBLY.POLICY, 'compile_policy', side_effect=compile_policy):
            result = self.fixture.audit(scope=scope)
        self.assertIs(type(result), bytes);self.assertEqual(final, [True]);self.assertEqual(len(calls), 4)

    def test_read_only_audit_never_creates_syncs_links_unlinks_or_writes_registration(self):
        settings = [patch.object(BACKEND.os, name, side_effect=AssertionError(name)) for name in ('write', 'fsync', 'link', 'unlink', 'fchmod')]
        for setting in settings:setting.start()
        try:
            with patch.object(REGISTER, 'create', side_effect=AssertionError('registration create')):self.assertIs(type(self.fixture.audit()), bytes)
        finally:
            for setting in reversed(settings):setting.stop()

    def test_real_nonblocking_cooperating_lock_refuses_before_native_read(self):
        descriptor = os.open(self.fixture.store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.fixture.audit(query=lambda end: self.fail('locked query'))
        finally:os.close(descriptor)


class NativeAuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateAudit(self)
        self.binary, self.ledger = self.fixture.root / 'nft', self.fixture.root / 'ledger'
        for setting in (patch.object(NFT, 'BINARY', self.binary), patch.object(MATCH.KERNEL, 'TRUST_ROOT', self.fixture.root),
                        patch.object(MATCH.KERNEL, 'TRUSTED_UID', os.geteuid())):
            setting.start();self.addCleanup(setting.stop)

    def executable(self, value=None, body=None):
        prefix = f'import json,os,sys\nwith open({str(self.ledger)!r},"a") as stream:stream.write(json.dumps([sys.argv[1:],dict(os.environ)])+"\\n")\n'
        self.binary.write_text('#!/usr/bin/python3 -B\n' + prefix + (body if body is not None else f'print({json.dumps(self.fixture.native if value is None else value)!r})') + '\n')
        self.binary.chmod(0o700)

    def audit(self):
        return AUDIT.audit(self.fixture.store)

    def test_complete_private_registration_native_capture_parser_match_and_final_load_path(self):
        self.executable();before = self.fixture.leaf.read_bytes()
        with patch.dict(os.environ, {'TASK_SECRET': 'bad', 'NFT_CTX_FLAGS': 'bad'}), patch.object(REGISTER, 'load', wraps=REGISTER.load) as load:
            raw = self.audit()
        result = json.loads(raw);self.assertEqual(load.call_count, 2);self.assertEqual(result['namespace'], KERNEL.namespace())
        self.assertEqual(result['comparison']['intention'], self.fixture.plan['intention'])
        self.assertEqual(result['comparison']['observation']['source']['binary'], str(self.binary))
        self.assertEqual(self.fixture.leaf.read_bytes(), before)
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()];self.assertEqual(len(rows), 2)
        for argv, environment in rows:
            self.assertEqual(argv, list(NFT.COMMAND));self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})

    def test_actual_matching_marker_with_unsafe_policy_refuses(self):
        value = copy.deepcopy(self.fixture.native);native_fixture.objects(value, 'rule')[0]['expr'][-1] = {'accept': None}
        self.executable(value)
        with self.assertRaisesRegex(ValueError, 'intention'):self.audit()

    def test_actual_warning_exit_malformed_and_foreign_deliveries_cannot_return_receipt(self):
        foreign = copy.deepcopy(self.fixture.native);foreign['nftables'].append({'flowtable': {}})
        for body in ('raise SystemExit(1)', "print('{')", f'print({json.dumps(foreign)!r})',
                     f'import sys;print({json.dumps(self.fixture.native)!r});print("warning",file=sys.stderr)'):
            self.executable(body=body)
            with self.subTest(body=body[:45]), self.assertRaises((OSError, ValueError)):self.audit()

    def test_actual_second_child_handle_or_marker_drift_refuses(self):
        counter = self.fixture.root / 'turn'
        for change in ('handle', 'comment'):
            counter.unlink(missing_ok=True)
            statement = "v['nftables'][1]['table']['handle']+=n" if change == 'handle' else "v['nftables'][1]['table']['comment']='changed' if n==2 else v['nftables'][1]['table']['comment']"
            self.executable(body=f'from pathlib import Path\np=Path({str(counter)!r});n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))\nv=json.loads({json.dumps(self.fixture.native)!r})\n{statement}\nprint(json.dumps(v))')
            with self.subTest(change=change), self.assertRaises(ValueError):self.audit()
            self.assertEqual(counter.read_text(), '2')

    def test_actual_second_child_registration_damage_withholds_all_receipt_bytes(self):
        counter = self.fixture.root / 'turn'
        self.executable(body=f'from pathlib import Path\np=Path({str(counter)!r});n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))\nif n==2:Path({str(self.fixture.leaf)!r}).write_bytes(b"damaged")\nprint({json.dumps(self.fixture.native)!r})')
        with self.assertRaises(ValueError):self.audit()
        self.assertEqual(counter.read_text(), '2');self.assertEqual(self.fixture.leaf.read_bytes(), b'damaged')

    def test_actual_utf8_native_source_identity_preserves_exact_receipt_bytes(self):
        self.binary = self.fixture.root / 'nft-é';setting = patch.object(NFT, 'BINARY', self.binary)
        setting.start();self.addCleanup(setting.stop);self.executable()
        raw = self.audit();result = json.loads(raw)
        self.assertEqual(raw, encoded(result));self.assertIn('nft-é'.encode(), raw)
        self.assertEqual(result['comparison']['observation']['source']['binary'], str(self.binary))


if __name__ == '__main__':unittest.main()
