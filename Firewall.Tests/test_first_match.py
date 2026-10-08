import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_first_create as plan_fixture
import test_nft_manifest as native_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_match', ROOT / 'Firewall/first_match.py')
MATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATCH)
STATE, MANIFEST, KERNEL, NFT = MATCH.STATE, MATCH.MANIFEST, MATCH.KERNEL, MATCH.STATE.NFT


def encoded(value):
    return STATE.encoded(value) + b'\n'


def marked(plan):
    """Intention-derived delivery MODEL, not an independent nft formatter oracle."""
    value = native_fixture.native(plan['topology'])
    native_fixture.objects(value, 'table')[0]['comment'] = MATCH.PLAN.COMMENT_PREFIX + plan['correlation_id']
    return value


class Fixtures:
    def setUp(self):
        helper = plan_fixture.PlanTests();helper.setUp();self.addCleanup(helper.doCleanups)
        self.namespace = helper.namespace
        self.payload = helper.prepare();self.plan = json.loads(self.payload)
        self.value = marked(self.plan)

    def verify(self, value=None, payload=None, **settings):
        value = self.value if value is None else value
        return MATCH.verify(self.payload if payload is None else payload,
                            **({'query': lambda deadline: copy.deepcopy(value), 'scope': lambda: self.namespace} | settings))

    def clock(self):
        clock = [KERNEL.now()];setting = patch.object(KERNEL, 'now', side_effect=lambda: clock[0])
        setting.start();self.addCleanup(setting.stop);return clock


class MatchTests(Fixtures, unittest.TestCase):
    def test_complete_real_preparation_transaction_and_marked_policy_match(self):
        payload = self.verify();result = json.loads(payload)
        self.assertIs(type(payload), bytes);self.assertEqual(payload, encoded(result))
        self.assertLessEqual(len(payload), MATCH.MAX_OUTPUT)
        self.assertEqual(result['schema'], 'debian13s4-first-create-source-match-1')
        self.assertEqual(result['state'], 'source-correspondence-only')
        self.assertEqual(result['profile'], 'historical-first-create-intention-marked-source-1')
        self.assertEqual(result['namespace'], self.namespace)
        self.assertEqual(result['proposal_sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(result['transaction_sha256'], self.plan['transaction_sha256'])
        self.assertEqual(result['correlation_id'], self.plan['correlation_id'])
        self.assertEqual(result['intention'], self.plan['intention'])
        self.assertEqual(result['observation']['comment'], MATCH.PLAN.COMMENT_PREFIX + self.plan['correlation_id'])
        self.assertEqual(MANIFEST.canonical_policy(result['observation']['policy']), result['intention']['policy'])
        self.assertEqual(len(result['observation']['policy']['sets']), 17)
        self.assertEqual(set(result['observation']['policy']['chains']), {'input', 'output', 'forward'})
        self.assertTrue(result['observation']['identity']['table']);self.assertTrue(result['observation']['statistics'])

    def test_all_intention_fields_are_required_and_unknown_fields_refuse_before_query(self):
        for key in self.plan:
            value = copy.deepcopy(self.plan);del value[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(payload=encoded(value), query=lambda end: self.fail('read malformed plan'))
        value = self.plan | {'owned': True}
        with self.assertRaises(ValueError):self.verify(payload=encoded(value), query=lambda end: self.fail('read extra field'))

    def test_schema_state_profile_admission_and_namespace_cannot_be_relabelled(self):
        for key, bad in (('schema', 'debian13s4-automatic-nft-intent-1'), ('state', 'installed'),
                         ('profile', 'owned'), ('admission_profile', 'empty'),
                         *[('namespace', value) for value in (True, False, 0, -1, 1 << 64, '1', None)]):
            value = self.plan | {key: bad}
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                self.verify(payload=encoded(value), query=lambda end: self.fail('unadmitted plan read'))

    def test_correlation_is_exact_lower_hex_and_not_an_injectable_owner_credential(self):
        for identifier in (True, 32, None, 'A' * 64, 'g' * 64, '0' * 63, '0' * 65, 'a' * 63 + '\n', '";flush ruleset'):
            value = self.plan | {'correlation_id': identifier}
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):self.verify(payload=encoded(value))

    def test_transaction_body_header_comment_and_hash_are_recomputed_not_trusted(self):
        for text in (self.plan['transaction'].replace('create table', 'table', 1),
                     self.plan['transaction'].replace('create table', 'add table', 1),
                     self.plan['transaction'].replace('policy drop;', 'policy accept;', 1),
                     self.plan['transaction'].replace(self.plan['correlation_id'], 'a' * 64),
                     self.plan['transaction'] + 'flush ruleset\n', self.plan['transaction'][:-1]):
            value = self.plan | {'transaction': text, 'transaction_sha256': hashlib.sha256(text.encode()).hexdigest()}
            with self.subTest(text=text[:55]), self.assertRaises(ValueError):
                self.verify(payload=encoded(value), query=lambda end: self.fail('read altered transaction'))
        with self.assertRaises(ValueError):self.verify(payload=encoded(self.plan | {'transaction_sha256': '0' * 64}))

    def test_complete_intention_and_topology_are_recomputed_with_strict_types(self):
        for change in ('policy', 'compiler_sha256', 'topology_sha256', 'fingerprint', 'boolean_alias', 'topology'):
            value = copy.deepcopy(self.plan)
            if change == 'policy':value['intention']['policy']['rules']['input'][0]['expr'][-1] = {'accept': None}
            elif change == 'boolean_alias':value['intention']['policy']['rules']['input'][0]['expr'][0]['match']['right'] = True
            elif change == 'topology':value['topology']['schema'] = True
            else:value['intention'][change] = '0' * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(payload=encoded(value), query=lambda end: self.fail('read altered intention'))

    def test_canonical_encoding_duplicates_invalid_utf8_and_nonfinite_json_refuse(self):
        cases = (self.payload[:-1], self.payload + b'\n', b' ' + self.payload,
                 json.dumps(self.plan).encode() + b'\n', b'{"schema":1,"schema":2}',
                 b'{"schema":NaN}', b'{"schema":1.0}', b'\xff', b'{}', b'[]', b'null', b'')
        for data in cases:
            with self.subTest(data=data[:55]), self.assertRaises(ValueError):
                self.verify(payload=data, query=lambda end: self.fail('noncanonical native read'))

    def test_input_byte_structure_integer_and_string_bounds_refuse_before_query(self):
        class Bytes(bytes):pass
        data = self.payload
        for value in (Bytes(data), bytearray(data), data.decode(), None, data + b' ' * MATCH.PLAN.MAX_OUTPUT):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                MATCH.verify(value, query=lambda end: self.fail('invalid-byte read'), scope=lambda: self.namespace)
        for entry in ('\0', '\ud800', 1 << 65, [0] * (STATE.MAX_NODES + 1), [[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]):
            value = self.plan | {'extra': entry}
            raw = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
            with self.subTest(kind=type(entry).__name__), self.assertRaises(ValueError):self.verify(payload=raw)
        with patch.object(MATCH.PLAN, 'MAX_OUTPUT', len(self.payload) - 1), self.assertRaises(ValueError):self.verify()

    def test_compiler_frame_and_transaction_byte_bound_remain_positive_predicates(self):
        original = MATCH.PLAN.ASSEMBLY.POLICY.compile_policy
        for text in ('flush ruleset\n', original(STATE.encoded(self.plan['topology'])).rstrip('\n')):
            with patch.object(MATCH.PLAN.ASSEMBLY.POLICY, 'compile_policy', return_value=text), self.assertRaises(ValueError):self.verify()
        with patch.object(MATCH.PLAN.ASSEMBLY.POLICY, 'MAX_OUTPUT', 1), self.assertRaises(ValueError):self.verify()

    def test_current_context_must_match_checked_historical_plan_before_read(self):
        for namespace in (True, False, 0, -1, 1 << 64, '1', None, self.namespace + 1):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                self.verify(scope=lambda: namespace, query=lambda end: self.fail('foreign-context read'))

    def test_invalid_deadline_and_noncallable_readers_refuse_before_scope(self):
        for deadline in (True, False, float('nan'), float('inf'), '10', KERNEL.now() - 1, 10 ** 10000):
            with self.subTest(kind=type(deadline).__name__), self.assertRaises(ValueError):
                self.verify(deadline=deadline, scope=lambda: self.fail('invalid-deadline scope'))
        for key in ('scope', 'query'):
            with self.subTest(key=key), self.assertRaises(ValueError):self.verify(**{key: None})

    def test_compiler_preparation_expiry_prevents_native_admission(self):
        clock = self.clock();original = MANIFEST.expected
        def expected(raw):
            result = original(raw);clock[0] += 11;return result
        with patch.object(MANIFEST, 'expected', side_effect=expected), self.assertRaises(ValueError):
            self.verify(query=lambda end: self.fail('expired plan read'))

    def test_both_reads_use_same_minimum_parent_and_own_window(self):
        clock = self.clock()
        for parent, end in ((clock[0] + 2, clock[0] + 2), (clock[0] + 50, clock[0] + 10), (None, clock[0] + 10)):
            calls = []
            def query(deadline):calls.append(deadline);return copy.deepcopy(self.value)
            self.verify(query=query, deadline=parent);self.assertEqual(calls, [end, end])

    def test_missing_wrong_nonstring_and_wrong_prefix_comments_refuse(self):
        for comment in (None, True, 7, '', self.plan['correlation_id'], MATCH.PLAN.COMMENT_PREFIX + '0' * 64,
                        MATCH.PLAN.COMMENT_PREFIX + self.plan['correlation_id'] + '\n'):
            value = copy.deepcopy(self.value);native_fixture.objects(value, 'table')[0]['comment'] = comment
            with self.subTest(comment=comment), self.assertRaises(ValueError):self.verify(value)
        value = copy.deepcopy(self.value);del native_fixture.objects(value, 'table')[0]['comment']
        with self.assertRaises(ValueError):self.verify(value)

    def test_foreign_extra_duplicate_or_missing_tables_are_never_selected_away(self):
        for change in ('foreign', 'duplicate', 'missing', 'family', 'flags', 'owner'):
            value = copy.deepcopy(self.value);table = native_fixture.objects(value, 'table')[0]
            if change == 'foreign':value['nftables'].append({'table': table | {'name': 'foreign'}})
            elif change == 'duplicate':value['nftables'].append({'table': copy.deepcopy(table)})
            elif change == 'missing':value['nftables'] = [row for row in value['nftables'] if 'table' not in row]
            elif change == 'family':table['family'] = 'ip'
            elif change == 'flags':table['flags'] = ['owner', 'persist']
            else:table['owner'] = 123
            with self.subTest(change=change), self.assertRaises(ValueError):self.verify(value)

    def test_global_envelope_extra_objects_and_non_table_comments_refuse(self):
        for change in ('envelope', 'flowtable', 'rule_comment', 'chain_comment', 'command', 'mixed_object', 'nonobject'):
            value = copy.deepcopy(self.value)
            if change == 'envelope':value['owned'] = True
            elif change == 'flowtable':value['nftables'].append({'flowtable': {}})
            elif change == 'command':value['nftables'].append({'flush': {'ruleset': None}})
            elif change == 'mixed_object':value['nftables'][1]['owned'] = True
            elif change == 'nonobject':value['nftables'].append(1)
            else:native_fixture.objects(value, change.split('_')[0])[0]['comment'] = 'foreign'
            with self.subTest(change=change), self.assertRaises(ValueError):self.verify(value)

    def test_matching_public_comment_does_not_make_accept_all_an_intention_match(self):
        value = copy.deepcopy(self.value)
        for row in native_fixture.objects(value, 'rule'):
            row['expr'] = [{'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]
        self.assertTrue(MATCH.project(value, native_fixture.objects(value, 'table')[0]['comment']))
        with self.assertRaisesRegex(ValueError, 'intention'):self.verify(value)

    def test_selectors_verdicts_rule_order_set_entries_and_counter_positions_remain_bound(self):
        for change in ('selector', 'verdict', 'order', 'element', 'counter_position', 'boolean'):
            value = copy.deepcopy(self.value);rules = native_fixture.objects(value, 'rule')
            if change == 'selector':rules[0]['expr'][0]['match']['left'] = {'ct': {'key': 'direction'}}
            elif change == 'verdict':rules[0]['expr'][-1] = {'accept': None}
            elif change == 'order':rules[0]['expr'], rules[1]['expr'] = rules[1]['expr'], rules[0]['expr']
            elif change == 'element':native_fixture.objects(value, 'set')[0]['elem'] = ['203.0.113.1']
            elif change == 'boolean':rules[0]['expr'][0]['match']['right'] = True
            else:rules[0]['expr'].insert(0, rules[0]['expr'].pop(-2))
            with self.subTest(change=change), self.assertRaises(ValueError):self.verify(value)

    def test_complete_nonstatistical_source_metadata_handles_and_policy_drift_refuse(self):
        for change in ('table', 'chain', 'set', 'rule', 'metadata', 'comment', 'policy'):
            first, second = copy.deepcopy(self.value), copy.deepcopy(self.value)
            if change in ('table', 'chain', 'set', 'rule'):native_fixture.objects(second, change)[0]['handle'] += 1000
            elif change == 'metadata':second['nftables'][0]['metainfo']['release_name'] = 'other release'
            elif change == 'comment':native_fixture.objects(second, 'table')[0]['comment'] = MATCH.PLAN.COMMENT_PREFIX + '0' * 64
            else:native_fixture.objects(second, 'rule')[0]['expr'][-1] = {'accept': None}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(query=lambda end, rows=iter([first, second]): next(rows))

    def test_anonymous_statistics_can_decrease_reset_and_retain_final_values(self):
        first, second = copy.deepcopy(self.value), copy.deepcopy(self.value)
        for row in native_fixture.objects(first, 'rule'):row['expr'][-2]['counter'] = {'packets': 2 ** 64 - 1, 'bytes': 2 ** 64 - 1}
        for row in native_fixture.objects(second, 'rule'):row['expr'][-2]['counter'] = {'packets': 0, 'bytes': 0}
        result = json.loads(self.verify(query=lambda end, rows=iter([first, second]): next(rows)))
        self.assertTrue(all(row['packets'] == row['bytes'] == 0 for row in result['observation']['statistics']))
        for invalid in (True, -1, 2 ** 64, '0'):
            value = copy.deepcopy(self.value);native_fixture.objects(value, 'rule')[0]['expr'][-2]['counter']['packets'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):self.verify(value)

    def test_whole_native_copy_bounds_include_comment_before_projection(self):
        for entry in ('x' * NFT.MAX_BYTES, '\0', '\ud800'):
            value = copy.deepcopy(self.value);native_fixture.objects(value, 'table')[0]['comment'] = entry
            with self.subTest(size=len(entry)), self.assertRaises(ValueError):self.verify(value)
        with patch.object(NFT, 'MAX_BYTES', len(STATE.encoded(self.value)) - 1), self.assertRaises(ValueError):self.verify()

    def test_private_records_survive_later_callback_mutation_without_rewriting_first_facts(self):
        first = copy.deepcopy(self.value);calls = []
        def query(end):
            calls.append(end)
            if len(calls) == 1:return first
            native_fixture.objects(first, 'table')[0]['comment'] = 'changed'
            native_fixture.objects(first, 'rule')[0]['expr'][-1] = {'accept': None}
            return copy.deepcopy(self.value)
        result = json.loads(self.verify(query=query))
        self.assertEqual(result['observation']['comment'], native_fixture.objects(self.value, 'table')[0]['comment'])
        self.assertEqual(result['intention']['policy']['rules']['input'][0]['expr'][-1], {'drop': None})
        self.assertEqual(len(calls), 2)

    def test_original_caller_rows_and_closed_commentless_projection_are_unchanged(self):
        original = copy.deepcopy(self.value);self.verify()
        self.assertEqual(self.value, original)
        with self.assertRaises(ValueError):STATE.project(self.value)
        unmarked = copy.deepcopy(self.value);del native_fixture.objects(unmarked, 'table')[0]['comment']
        self.assertTrue(STATE.project(unmarked))
        with self.assertRaises(ValueError):self.verify(unmarked)

    def test_query_or_comparison_expiry_prevents_the_second_read(self):
        clock = self.clock();calls = []
        def query(end):calls.append(end);clock[0] = end;return copy.deepcopy(self.value)
        with self.assertRaises(ValueError):self.verify(query=query)
        self.assertEqual(len(calls), 1)
        clock[0] = KERNEL.now();calls.clear();original = MANIFEST.canonical_policy
        def canonical(value):
            result = original(value)
            if calls:clock[0] += 11
            return result
        with patch.object(MANIFEST, 'canonical_policy', side_effect=canonical), self.assertRaises(ValueError):
            self.verify(query=lambda end: calls.append(end) or copy.deepcopy(self.value))
        self.assertEqual(len(calls), 1)

    def test_encoding_expiry_and_final_typed_namespace_change_withhold_receipt(self):
        clock = self.clock();original = STATE.encoded
        def encode(value):
            data = original(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-source-match-1':clock[0] += 11
            return data
        with patch.object(STATE, 'encoded', side_effect=encode), self.assertRaises(ValueError):self.verify()
        for last in (True, self.namespace + 1):
            calls = []
            def scope():calls.append(1);return self.namespace if len(calls) == 1 else last
            with self.subTest(last=last), self.assertRaises(ValueError):self.verify(scope=scope)
            self.assertEqual(len(calls), 2)

    def test_complete_encoding_and_hashing_precede_final_context_barrier(self):
        events = [];original_encode, original_hash = STATE.encoded, MATCH.hashlib.sha256
        def encode(value):self.assertNotIn('final', events);return original_encode(value)
        def sha(value):self.assertNotIn('final', events);return original_hash(value)
        def scope():events.append('initial' if not events else 'final');return self.namespace
        with patch.object(STATE, 'encoded', side_effect=encode), patch.object(MATCH.hashlib, 'sha256', side_effect=sha):
            result = self.verify(scope=scope)
        self.assertIs(type(result), bytes);self.assertEqual(events, ['initial', 'final'])

    def test_receipt_limit_and_encoding_failure_cannot_return_success(self):
        original = STATE.encoded
        with patch.object(MATCH, 'MAX_OUTPUT', 1), self.assertRaises(ValueError):self.verify()
        def encode(value):
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-source-match-1':raise UnicodeError('sink encoding')
            return original(value)
        with patch.object(STATE, 'encoded', side_effect=encode), self.assertRaises(UnicodeError):self.verify()


class NativeTests(Fixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-match-', dir='/dev/shm');self.addCleanup(directory.cleanup)
        self.root = Path(directory.name);self.root.chmod(0o700)
        self.binary, self.ledger = self.root / 'nft', self.root / 'ledger'
        for setting in (patch.object(NFT, 'BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.root),
                        patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())):
            setting.start();self.addCleanup(setting.stop)
        self.plan['namespace'] = KERNEL.namespace();self.namespace = self.plan['namespace'];self.payload = encoded(self.plan)

    def executable(self, value=None, body=None):
        value = self.value if value is None else value
        self.binary.write_text('#!/usr/bin/python3 -B\n' + (body if body is not None else f'print({json.dumps(value)!r})') + '\n')
        self.binary.chmod(0o700)

    def actual(self):
        return MATCH.verify(self.payload)

    def test_real_fixed_native_capture_parser_context_and_complete_intention_match(self):
        self.executable(body=f"import json,os,sys\nwith open({str(self.ledger)!r},'a') as stream:stream.write(json.dumps([sys.argv[1:],dict(os.environ)])+'\\n')\nprint({json.dumps(self.value)!r})")
        with patch.dict(os.environ, {'TASK_SECRET': 'private', 'NFT_CTX_FLAGS': 'bad'}):result = json.loads(self.actual())
        self.assertEqual(result['namespace'], self.namespace);self.assertEqual(result['intention'], self.plan['intention'])
        self.assertEqual(result['observation']['source']['binary'], str(self.binary))
        deliveries = [json.loads(row) for row in self.ledger.read_text().splitlines()]
        self.assertEqual(len(deliveries), 2)
        for argv, environment in deliveries:
            self.assertEqual(argv, list(NFT.COMMAND));self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})

    def test_actual_missing_or_foreign_marker_cannot_return_match(self):
        for comment in (None, MATCH.PLAN.COMMENT_PREFIX + '0' * 64):
            value = copy.deepcopy(self.value);table = native_fixture.objects(value, 'table')[0]
            if comment is None:del table['comment']
            else:table['comment'] = comment
            self.executable(value)
            with self.subTest(comment=comment), self.assertRaises(ValueError):self.actual()

    def test_actual_matching_marker_with_unsafe_policy_remains_pending(self):
        value = copy.deepcopy(self.value)
        for row in native_fixture.objects(value, 'rule'):row['expr'][-1] = {'accept': None}
        self.executable(value)
        with self.assertRaisesRegex(ValueError, 'intention'):self.actual()

    def test_actual_warning_failed_truncated_and_foreign_dumps_refuse(self):
        foreign = copy.deepcopy(self.value);foreign['nftables'].append({'flowtable': {}})
        for body in ('raise SystemExit(1)', "print('{')", f"print({json.dumps(foreign)!r})",
                     f"import sys;print({json.dumps(self.value)!r});print('warning',file=sys.stderr)"):
            self.executable(body=body)
            with self.subTest(body=body[:50]), self.assertRaises(ValueError):self.actual()

    def test_actual_second_handle_and_comment_drift_are_not_hidden_by_policy_hash(self):
        counter = self.root / 'turn'
        for change in ('handle', 'comment'):
            counter.unlink(missing_ok=True)
            statement = "v['nftables'][1]['table']['handle']+=n" if change == 'handle' else "v['nftables'][1]['table']['comment']='changed' if n==2 else v['nftables'][1]['table']['comment']"
            self.executable(body=f"import json\nfrom pathlib import Path\np=Path({str(counter)!r});n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))\nv=json.loads({json.dumps(self.value)!r})\n{statement}\nprint(json.dumps(v))")
            with self.subTest(change=change), self.assertRaises(ValueError):self.actual()
            self.assertEqual(counter.read_text(), '2')

    def test_actual_unsafe_symbolic_and_wrong_owner_native_binary_refuse(self):
        self.executable()
        with patch.object(KERNEL, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(ValueError):self.actual()
        self.binary.chmod(0o720)
        with self.assertRaises(ValueError):self.actual()
        self.binary.chmod(0o700);original = self.root / 'original';self.binary.rename(original);self.binary.symlink_to(original)
        with self.assertRaises(ValueError):self.actual()

    def test_actual_utf8_source_path_retains_exact_receipt_bytes(self):
        self.binary = self.root / 'nft-é'
        setting = patch.object(NFT, 'BINARY', self.binary);setting.start();self.addCleanup(setting.stop)
        self.executable();raw = self.actual();result = json.loads(raw)
        self.assertIs(type(raw), bytes);self.assertEqual(raw, encoded(result))
        self.assertIn('nft-é'.encode('utf-8'), raw)
        self.assertEqual(result['observation']['source']['binary'], str(self.binary))


if __name__ == '__main__':unittest.main()
