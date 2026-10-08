import copy
import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import test_auto_intent as automatic_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_create', ROOT / 'Firewall/first_create.py')
PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLAN)
ASSEMBLY, KERNEL, POLICY = automatic_fixture.ASSEMBLY, automatic_fixture.KERNEL, automatic_fixture.POLICY


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.helper = automatic_fixture.AutomaticTests();self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        alias = patch.object(PLAN, 'ASSEMBLY', ASSEMBLY);alias.start();self.addCleanup(alias.stop)
        self.namespace = self.helper.namespace

    def prepare(self, **settings):
        return PLAN.prepare(**(self.helper.readers() | settings))

    def test_real_automatic_plan_retains_complete_compiler_body_and_manifest(self):
        raw = self.prepare();value = json.loads(raw)
        topology = PLAN.MANIFEST.STATE.encoded(value['topology']);original = POLICY.compile_policy(topology)
        prefix = 'destroy table inet debian13s4\ntable inet debian13s4 {\n'
        expected = 'create table inet debian13s4 {\n    comment "' + PLAN.COMMENT_PREFIX + value['correlation_id'] + '"\n' + original[len(prefix):]
        self.assertEqual(value['transaction'], expected)
        self.assertEqual(value['schema'], 'debian13s4-automatic-nft-first-create-1')
        self.assertEqual(value['state'], 'prepared-first-create-intention')
        self.assertEqual(value['profile'], 'automatic-empty-source-first-create-intention-1')
        self.assertEqual(value['admission_profile'], PLAN.AUTO.ADMISSION)
        self.assertEqual(value['namespace'], self.namespace);self.assertRegex(value['correlation_id'], r'^[0-9a-f]{64}$')
        self.assertEqual(value['intention'], PLAN.MANIFEST.expected(topology))
        self.assertEqual(value['transaction_sha256'], hashlib.sha256(expected.encode('utf-8')).hexdigest())
        self.assertEqual(value['intention']['compiler_sha256'], hashlib.sha256(original.encode('utf-8')).hexdigest())
        self.assertNotEqual(value['transaction_sha256'], value['intention']['compiler_sha256'])
        self.assertEqual(len(value['intention']['policy']['sets']), 17)
        self.assertEqual(value['intention']['policy']['rules']['forward'], [])

    def test_identifier_is_generated_once_from_exact_32_byte_profile_and_not_an_owner_flag(self):
        with patch.object(PLAN.secrets, 'token_hex', return_value='ab' * 32) as generate:
            value = json.loads(self.prepare())
        generate.assert_called_once_with(32);self.assertEqual(value['correlation_id'], 'ab' * 32)
        self.assertEqual(value['transaction'].count(PLAN.COMMENT_PREFIX + 'ab' * 32), 1)
        self.assertFalse(re.search(r'^\s*(destroy|delete|flush|reset|include|add|replace)\b', value['transaction'], re.M))
        self.assertNotIn('flags owner', value['transaction']);self.assertNotIn('flags persist', value['transaction'])

    def test_distinct_identifiers_change_only_correlation_and_transaction_identity(self):
        with patch.object(PLAN.secrets, 'token_hex', side_effect=['1' * 64, '2' * 64]):
            first, second = json.loads(self.prepare()), json.loads(self.prepare())
        self.assertNotEqual(first['transaction_sha256'], second['transaction_sha256'])
        for key in set(first) - {'correlation_id', 'transaction', 'transaction_sha256'}:self.assertEqual(first[key], second[key])
        self.assertEqual(first['transaction'].replace('1' * 64, '2' * 64), second['transaction'])

    def test_malformed_or_injectable_generated_identifier_refuses_before_any_observer(self):
        class Text(str):pass
        for identifier in (None, True, 1, 'f' * 63, 'f' * 65, 'A' * 64, 'z' * 64, '";flush ruleset', 'a' * 63 + '\n', Text('f' * 64)):
            with self.subTest(identifier=identifier), patch.object(PLAN.secrets, 'token_hex', return_value=identifier), self.assertRaises(ValueError):
                self.prepare(nft=lambda **settings: self.fail('observer before identifier admission'))

    def test_identifier_generation_error_is_not_a_completed_intention(self):
        with patch.object(PLAN.secrets, 'token_hex', side_effect=OSError('entropy delivery')), self.assertRaises(OSError):
            self.prepare(nft=lambda **settings: self.fail('unexpected observer'))

    def test_identifier_preparation_expiry_refuses_before_native_admission(self):
        start = KERNEL.now();clock = [start]
        def generate(size):clock[0] += 61;return '0' * 64
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(PLAN.secrets, 'token_hex', side_effect=generate), self.assertRaises(ValueError):
            self.prepare(nft=lambda **settings: self.fail('expired observer'))

    def test_namespace_requires_true_positive_uint64_before_identifier_or_sources(self):
        for namespace in (True, False, 0, -1, 1 << 64, None, '1'):
            with self.subTest(namespace=namespace), patch.object(KERNEL, 'namespace', return_value=namespace), patch.object(PLAN.secrets, 'token_hex', side_effect=AssertionError('identifier')), self.assertRaises(ValueError):self.prepare()

    def test_invalid_deadlines_and_unknown_or_noncallable_readers_refuse_before_scope(self):
        for deadline in (True, float('nan'), float('inf'), 'future', KERNEL.now() - 1, 10 ** 10000):
            with self.subTest(kind=type(deadline).__name__), patch.object(KERNEL, 'namespace', side_effect=AssertionError('scope')), self.assertRaises(ValueError):self.prepare(deadline=deadline)
        for settings in ({'topology': {}}, {'compiler': POLICY.compile_policy}, {'scope': lambda: 1}, {'identifier': 'f' * 64}, {'nft': None}):
            with self.subTest(settings=settings), patch.object(KERNEL, 'namespace', side_effect=AssertionError('scope')), self.assertRaises(ValueError):self.prepare(**settings)

    def test_every_source_and_service_receives_one_capped_shared_deadline(self):
        start = KERNEL.now()
        for seconds in (10, 1000):
            calls = [];readers = self.helper.readers()
            for key, callback in tuple(readers.items()):
                readers[key] = lambda deadline, key=key, callback=callback: calls.append((key, deadline)) or callback(deadline)
            with patch.object(KERNEL, 'now', return_value=start):PLAN.prepare(deadline=start + seconds, **readers)
            self.assertEqual(len(calls), 21);self.assertEqual({end for _, end in calls}, {start + min(seconds, 60)})

    def test_manifest_transaction_hash_and_encoding_precede_all_final_receipt_reads(self):
        events = [];expected, encoded = PLAN.MANIFEST.expected, PLAN.MANIFEST.STATE.encoded
        def manifest(raw):events.append('manifest');return expected(raw)
        def encode(value):
            if type(value) is dict and value.get('schema') == 'debian13s4-automatic-nft-first-create-1':events.append('encoded')
            return encoded(value)
        def reader(name, callback):
            def call(deadline):events.append(name);return callback(deadline)
            return call
        settings = {name:reader(name, callback) for name, callback in self.helper.readers().items()}
        with patch.object(PLAN.MANIFEST, 'expected', side_effect=manifest), patch.object(PLAN.MANIFEST.STATE, 'encoded', side_effect=encode):PLAN.prepare(**settings)
        pivot = events.index('manifest')
        self.assertEqual(events[:pivot], ['nft', 'legacy', 'classifiers', 'bpf', 'bpf_links', 'dhcp', 'dns', 'ntp'] * 2)
        self.assertEqual(events[pivot + 1:], ['encoded', 'nft', 'legacy', 'classifiers', 'bpf', 'bpf_links'])

    def test_no_hash_compilation_copy_or_serialization_follows_the_real_final_barriers(self):
        finished = [False];observe, dumps, digest = ASSEMBLY.observe, json.dumps, hashlib.sha256
        def observed(**settings):result = observe(**settings);finished[0] = True;return result
        def encoded(*args, **kwargs):self.assertFalse(finished[0]);return dumps(*args, **kwargs)
        def hashed(*args, **kwargs):self.assertFalse(finished[0]);return digest(*args, **kwargs)
        with patch.object(ASSEMBLY, 'observe', side_effect=observed), patch.object(json, 'dumps', side_effect=encoded), patch.object(hashlib, 'sha256', side_effect=hashed):
            self.assertIs(type(self.prepare()), bytes)

    def test_different_compiler_text_cannot_be_associated_with_the_expected_intention(self):
        compile_policy = POLICY.compile_policy
        with patch.object(POLICY, 'compile_policy', side_effect=lambda raw: compile_policy(raw) + '\n'), self.assertRaisesRegex(ValueError, 'identity disagrees'):self.prepare()

    def test_added_frame_bytes_remain_inside_the_unchanged_compiler_output_bound(self):
        source = json.loads(self.helper.prepare());raw = PLAN.MANIFEST.STATE.encoded(source['topology'])
        original = POLICY.compile_policy(raw);calls = []
        def nft(deadline):calls.append(deadline);return automatic_fixture.nft_receipt(self.namespace)
        with patch.object(POLICY, 'MAX_OUTPUT', len(original.encode('utf-8'))), self.assertRaisesRegex(ValueError, 'transaction exceeds'):
            self.prepare(nft=nft)
        self.assertEqual(len(calls), 2)

    def test_complete_plan_byte_bound_withholds_final_native_admission(self):
        calls = []
        def nft(deadline):calls.append(deadline);return automatic_fixture.nft_receipt(self.namespace)
        with patch.object(PLAN, 'MAX_OUTPUT', 1), self.assertRaises(ValueError):self.prepare(nft=nft)
        self.assertEqual(len(calls), 2)

    def test_plan_encoding_expiry_withholds_final_native_admission(self):
        start = KERNEL.now();clock = [start];calls = [];encoded = PLAN.MANIFEST.STATE.encoded
        def encode(value):
            result = encoded(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-automatic-nft-first-create-1':clock[0] += 61
            return result
        def nft(deadline):calls.append(deadline);return automatic_fixture.nft_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(PLAN.MANIFEST.STATE, 'encoded', side_effect=encode), self.assertRaises(ValueError):self.prepare(nft=nft)
        self.assertEqual(len(calls), 2)

    def test_attribution_expiring_during_new_plan_encoding_is_checked_before_return(self):
        start = KERNEL.now();clock = [start];encoded = PLAN.MANIFEST.STATE.encoded;calls = []
        row = self.helper.records['dhcp4']['attributions'][0]
        row['preferred_until'] = row['valid_until'] = int((start + 1) * 1000000)
        def encode(value):
            result = encoded(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-automatic-nft-first-create-1':clock[0] += 2
            return result
        def nft(deadline):calls.append(deadline);return automatic_fixture.nft_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(PLAN.MANIFEST.STATE, 'encoded', side_effect=encode), self.assertRaises(ValueError):self.prepare(nft=nft)
        self.assertEqual(len(calls), 2)

    def test_final_nonempty_nft_receipt_cannot_certify_a_first_create_plan(self):
        calls = [0]
        def nft(deadline):
            calls[0] += 1;row = automatic_fixture.nft_receipt(self.namespace)
            if calls[0] == 3:row['empty'] = False
            return row
        with self.assertRaises(ValueError):self.prepare(nft=nft)
        self.assertEqual(calls[0], 3)

    def test_preparation_schema_profile_namespace_and_exact_transaction_object_remain_checked(self):
        observe = ASSEMBLY.observe
        for kind in ('schema', 'profile', 'namespace', 'policy'):
            def changed(**settings):
                result = observe(**settings)
                result[kind] = result['policy'].encode().decode() if kind == 'policy' else True if kind == 'namespace' else 'other'
                return result
            with self.subTest(kind=kind), patch.object(ASSEMBLY, 'observe', side_effect=changed), self.assertRaises(ValueError):self.prepare()

    def test_final_wrapper_scope_must_be_typed_and_equal_to_the_joined_context(self):
        for last in (True, self.namespace + 1, '1'):
            values = iter([self.namespace, self.namespace, last])
            with self.subTest(last=last), patch.object(KERNEL, 'namespace', side_effect=lambda: next(values)), self.assertRaises(ValueError):self.prepare()

    def test_full_receipt_is_exact_immutable_utf8_bytes_with_one_final_newline(self):
        raw = self.prepare();value = json.loads(raw)
        self.assertIs(type(raw), bytes);self.assertEqual(raw, PLAN.MANIFEST.STATE.encoded(value) + b'\n')
        self.assertFalse(raw.endswith(b'\n\n'));self.assertLessEqual(len(raw), PLAN.MAX_OUTPUT)

    def test_pure_delivery_path_has_no_store_or_native_policy_executor(self):
        with patch.object(PLAN.AUTO, 'prepare', side_effect=AssertionError('post-return wrapper')), patch.object(Path, 'open', side_effect=AssertionError('file publication')), patch.object(KERNEL.subprocess, 'Popen', side_effect=AssertionError('policy operation')):
            self.assertIs(type(self.prepare()), bytes)


class NativeTests(automatic_fixture.PrivateNative):
    def setUp(self):
        super().setUp();alias = patch.object(PLAN, 'ASSEMBLY', ASSEMBLY);alias.start();self.settings.append(alias)

    def test_complete_private_capture_all_admissions_and_new_transaction_intention(self):
        self.fixtures(tc_kind='fq_codel');value = json.loads(PLAN.prepare())
        self.assertEqual(value['namespace'], KERNEL.namespace())
        raw = PLAN.MANIFEST.STATE.encoded(value['topology']);text = POLICY.compile_policy(raw)
        self.assertEqual(value['transaction'].splitlines()[2:], text.splitlines()[2:])
        self.assertEqual(value['intention'], PLAN.MANIFEST.expected(raw))
        self.assertTrue(value['transaction'].startswith('create table inet debian13s4 {\n'))
        self.assertEqual(len(self.bpf_calls), 6);self.assertEqual(len(self.link_calls), 6)
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'ip' for kind, _, _ in rows), 258)
        self.assertEqual(sum(kind == 'bus' for kind, _, _ in rows), 100)
        self.assertEqual(sum(kind == 'tc' for kind, _, _ in rows), 12)
        self.assertEqual(sum(kind == 'nft' for kind, _, _ in rows), 6)
        self.assertEqual(sum('DescribeLink' in argv for _, argv, _ in rows), 4)
        self.assertEqual(sum(kind == 'ip' and 'get' in argv for kind, argv, _ in rows), 12)
        for kind, argv, environment in rows:
            self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})
            if kind == 'nft':self.assertEqual(argv, list(ASSEMBLY.NFT.COMMAND))

    def test_actual_existing_reserved_table_refuses_before_infrastructure_queries(self):
        self.fixtures();value = {'nftables': [{'metainfo': {'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}},
                                             {'table': {'family': 'inet', 'name': 'debian13s4', 'handle': 1}}]}
        self.executable(self.nft, 'print(' + repr(json.dumps(value)) + ')')
        with self.assertRaises(ValueError):PLAN.prepare()
        self.assertFalse(any(json.loads(line)[0] == 'bus' for line in self.ledger.read_text().splitlines()))

    def test_actual_postencoding_program_or_link_presence_withholds_all_plan_bytes(self):
        encode = PLAN.MANIFEST.STATE.encoded
        for kind in ('program', 'link'):
            self.fixtures();self.bpf_present = self.link_present = False;self.bpf_calls.clear();self.link_calls.clear()
            def encoded(value):
                result = encode(value)
                if type(value) is dict and value.get('schema') == 'debian13s4-automatic-nft-first-create-1':
                    if kind == 'program':self.bpf_present = True
                    else:self.link_present = True
                return result
            with self.subTest(kind=kind), patch.object(PLAN.MANIFEST.STATE, 'encoded', side_effect=encoded), self.assertRaises(ValueError):PLAN.prepare()
            self.assertEqual(len(self.bpf_calls), 5 if kind == 'program' else 6)
            self.assertEqual(len(self.link_calls), 4 if kind == 'program' else 5)

    def test_actual_permission_error_is_not_an_empty_admission_or_transaction_result(self):
        self.fixtures();self.link_error = errno.EPERM
        with self.assertRaises(ValueError):PLAN.prepare()
        self.assertEqual(len(self.link_calls), 1)
        self.assertFalse(any(json.loads(line)[0] == 'bus' for line in self.ledger.read_text().splitlines()))

    def test_bad_generated_identifier_refuses_before_actual_private_native_reads(self):
        self.fixtures()
        with patch.object(PLAN.secrets, 'token_hex', return_value='";flush ruleset'), self.assertRaises(ValueError):PLAN.prepare()
        self.assertEqual(self.ledger.read_text(), '');self.assertEqual(self.bpf_calls, []);self.assertEqual(self.link_calls, [])


if __name__ == '__main__':unittest.main()
