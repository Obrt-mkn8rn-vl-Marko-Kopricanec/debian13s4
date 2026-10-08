import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_nft_state', ROOT / 'Firewall/nft_state.py')
STATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATE)
NFT, KERNEL = STATE.NFT, STATE.KERNEL


def message():
    objects = [{'metainfo': {'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}},
               {'table': {'family': 'inet', 'name': 'debian13s4', 'handle': 1}}]
    for index, name in enumerate(STATE.CHAINS, 2):
        objects.append({'chain': {'family': 'inet', 'table': 'debian13s4', 'name': name, 'handle': index,
                                 'type': 'filter', 'hook': name, 'prio': 0, 'policy': 'drop'}})
    for index, (name, datatype) in enumerate(STATE.SET_TYPES.items(), 10):
        flags = ['constant', 'interval'] if name in ('blocked4', 'blocked6', 'onlink6') else ['constant']
        objects.append({'set': {'family': 'inet', 'table': 'debian13s4', 'name': name, 'type': copy.deepcopy(datatype),
                               'handle': index, 'flags': flags, 'elem': []}})
    for index, name in enumerate(('input', 'output'), 100):
        objects.append({'rule': {'family': 'inet', 'table': 'debian13s4', 'chain': name, 'handle': index,
                                'expr': [{'match': {'op': '==', 'left': {'meta': {'key': 'iifname' if name == 'input' else 'oifname'}}, 'right': 'lo'}},
                                         {'counter': {'packets': 3, 'bytes': 180}}, {'accept': None}]}})
    return {'nftables': objects}


def object_row(value, kind, name=None):
    return next(item[kind] for item in value['nftables'] if kind in item and
                (name is None or item[kind].get('name', item[kind].get('chain')) == name))


class ProjectionTests(unittest.TestCase):
    def test_complete_source_projection_preserves_policy_identities_and_statistics(self):
        value = message();original = copy.deepcopy(value);result = STATE.project(value)
        self.assertEqual(value, original)
        self.assertEqual(set(result['policy']['sets']), set(STATE.SET_TYPES))
        self.assertEqual(len(result['policy']['sets']), 17)
        self.assertEqual(result['policy']['rules']['forward'], [])
        self.assertEqual(result['identity']['rules']['input'], [100])
        self.assertEqual(result['statistics'][0], {'chain': 'input', 'rule_handle': 100, 'position': 1, 'packets': 3, 'bytes': 180})
        self.assertEqual(result['policy']['rules']['input'][0]['expr'][1], {'counter': {}})
        self.assertEqual(result['fingerprint'], hashlib.sha256(STATE.encoded(result['policy'])).hexdigest())

    def test_fingerprint_changes_for_every_selector_verdict_and_set_content_change(self):
        initial = STATE.project(message())['fingerprint']
        for change in ('selector', 'verdict', 'set', 'counter-position'):
            value = message();row = object_row(value, 'rule', 'input')
            if change == 'selector':row['expr'][0]['match']['right'] = 'eth0'
            elif change == 'verdict':row['expr'][-1] = {'drop': None}
            elif change == 'set':object_row(value, 'set', 'dhcp4_links')['elem'] = ['eth0']
            else:row['expr'][0], row['expr'][1] = row['expr'][1], row['expr'][0]
            with self.subTest(change=change):self.assertNotEqual(STATE.project(value)['fingerprint'], initial)

    def test_handles_do_not_change_fingerprint_but_remain_complete_observed_identity(self):
        value = message();before = STATE.project(value)
        for item in value['nftables'][1:]:next(iter(item.values()))['handle'] += 1000
        after = STATE.project(value)
        self.assertEqual(before['fingerprint'], after['fingerprint']);self.assertNotEqual(before['identity'], after['identity'])

    def test_only_checked_counter_statistics_are_excluded_from_fingerprint(self):
        value = message();before = STATE.project(value)
        for item in value['nftables']:
            if 'rule' in item:item['rule']['expr'][1]['counter'] = {'packets': (1 << 64) - 1, 'bytes': 0}
        after = STATE.project(value)
        self.assertEqual(before['fingerprint'], after['fingerprint']);self.assertNotEqual(before['statistics'], after['statistics'])

    def test_rule_order_is_retained_and_not_sorted_by_handle(self):
        value = message();row = copy.deepcopy(object_row(value, 'rule', 'input'));row['handle'] = 99;row['expr'][-1] = {'drop': None}
        value['nftables'].append({'rule': row});first = STATE.project(value)
        value['nftables'][-3], value['nftables'][-1] = value['nftables'][-1], value['nftables'][-3]
        second = STATE.project(value)
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual(first['identity']['rules']['input'], [100, 99])

    def test_nonrule_declaration_order_and_flag_order_do_not_change_projection(self):
        value = message();first = STATE.project(value)
        value['nftables'][2:-2] = reversed(value['nftables'][2:-2])
        object_row(value, 'set', 'blocked4')['flags'].reverse()
        self.assertEqual(STATE.project(value), first)

    def test_empty_missing_duplicate_misordered_and_extra_metadata_refuse(self):
        for value in (None, {}, {'nftables': []}, {'nftables': message()['nftables'][:1]},
                      message() | {'extra': 1}, {'nftables': message()['nftables'][1:]},
                      {'nftables': message()['nftables'] + message()['nftables'][:1]}):
            with self.subTest(value=value), self.assertRaises(STATE.Pending):STATE.project(value)

    def test_foreign_table_family_name_flags_comment_and_second_table_refuse(self):
        for key, bad in (('family', 'ip'), ('name', 'other'), ('flags', ['owner']), ('flags', ['dormant']),
                         ('flags', False), ('comment', 'debian13s4 owned')):
            value = message();object_row(value, 'table')[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(STATE.Pending):STATE.project(value)
        value = message();value['nftables'].append(copy.deepcopy(value['nftables'][1]))
        with self.assertRaises(STATE.Pending):STATE.project(value)

    def test_missing_or_duplicate_base_chains_and_extra_fields_refuse(self):
        for name in STATE.CHAINS:
            value = message();value['nftables'] = [item for item in value['nftables'] if item.get('chain', {}).get('name') != name]
            with self.subTest(name=name), self.assertRaises(STATE.Pending):STATE.project(value)
        for key, bad in (('prio', True), ('prio', -1), ('prio', '0'), ('policy', 'accept'), ('type', 'nat'), ('hook', 'forward'), ('dev', 'eth0')):
            value = message();object_row(value, 'chain', 'input')[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(STATE.Pending):STATE.project(value)

    def test_all_seventeen_set_identities_are_mandatory_and_no_duplicate_is_admitted(self):
        for name in STATE.SET_TYPES:
            value = message();value['nftables'] = [item for item in value['nftables'] if item.get('set', {}).get('name') != name]
            with self.subTest(name=name), self.assertRaises(STATE.Pending):STATE.project(value)
        value = message();value['nftables'].append({'set': copy.deepcopy(object_row(value, 'set'))})
        with self.assertRaises(STATE.Pending):STATE.project(value)

    def test_wrong_set_types_flags_timeout_maps_and_unknown_objects_refuse(self):
        for key, bad in (('type', ['ifname', 'ipv4_addr']), ('flags', []), ('flags', ['constant', 'timeout']),
                         ('flags', ['constant', 'constant']), ('timeout', 60), ('gc-interval', 60), ('map', 'verdict')):
            value = message();object_row(value, 'set', 'blocked4')[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(STATE.Pending):STATE.project(value)
        for kind in ('map', 'element', 'flowtable', 'counter', 'quota', 'limit', 'ct helper', 'add', 'delete', 'flush', 'unknown'):
            value = message();value['nftables'].append({kind: {'family': 'inet', 'table': 'debian13s4'}})
            with self.subTest(kind=kind), self.assertRaises(STATE.Pending):STATE.project(value)

    def test_typed_static_set_options_and_scalar_or_array_elements_are_retained(self):
        for element in ('eth0', ['eth0', 'eth1'], {'concat': ['eth0', '8.8.8.8']}, 7, True):
            value = message();row = object_row(value, 'set', 'dhcp4_links');row.update(elem=element, policy='performance', size=0)
            self.assertEqual(STATE.project(value)['policy']['sets']['dhcp4_links']['elem'], element)
        for key, bad in (('size', True), ('size', -1), ('policy', {}), ('auto-merge', True), ('elem', None)):
            value = message();object_row(value, 'set', 'dhcp4_links')[key] = bad
            with self.subTest(key=key), self.assertRaises(STATE.Pending):STATE.project(value)

    def test_unknown_rule_chain_forward_rule_comment_duplicate_handle_and_no_rules_refuse(self):
        for key, bad in (('chain', 'forward'), ('chain', 'helper'), ('family', 'ip6'), ('table', 'other'), ('comment', 'owned'), ('index', 0)):
            value = message();object_row(value, 'rule', 'input')[key] = bad
            with self.subTest(key=key), self.assertRaises(STATE.Pending):STATE.project(value)
        value = message();value['nftables'].append({'rule': copy.deepcopy(object_row(value, 'rule', 'input'))})
        with self.assertRaises(STATE.Pending):STATE.project(value)
        value = message();value['nftables'] = [item for item in value['nftables'] if item.get('rule', {}).get('chain') != 'input']
        with self.assertRaises(STATE.Pending):STATE.project(value)

    def test_handles_namespace_and_counter_numbers_refuse_boolean_negative_and_overflow(self):
        for bad in (True, False, 0, -1, '1', 1 << 64):
            value = message();object_row(value, 'table')['handle'] = bad
            with self.subTest(bad=bad), self.assertRaises(STATE.Pending):STATE.project(value)
        for bad in (True, False, -1, '0', 1 << 64):
            value = message();object_row(value, 'rule', 'input')['expr'][1]['counter']['packets'] = bad
            with self.subTest(bad=bad), self.assertRaises(STATE.Pending):STATE.project(value)

    def test_rule_statement_unknowns_named_missing_duplicate_and_partial_counters_refuse(self):
        for expression in ([{'accept': None}], [{'counter': 'named'}, {'accept': None}],
                           [{'counter': {'packets': 0}}, {'accept': None}],
                           [{'counter': {'packets': 0, 'bytes': 0}}] * 2 + [{'drop': None}],
                           [{'jump': 'other'}, {'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}],
                           [{'accept': None}, {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}],
                           [{'counter': {'packets': 0, 'bytes': 0}}, {'accept': True}]):
            value = message();object_row(value, 'rule', 'input')['expr'] = expression
            with self.subTest(expression=expression), self.assertRaises(STATE.Pending):STATE.project(value)

    def test_match_operands_are_opaque_source_not_a_policy_health_or_ownership_certificate(self):
        value = message();row = object_row(value, 'rule', 'input')
        row['expr'] = [{'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]
        result = STATE.project(value)
        self.assertEqual(result['policy']['rules']['input'][0]['expr'][-1], {'accept': None})
        self.assertNotIn('healthy', result);self.assertNotIn('owned', result)
        value = message();object_row(value, 'rule', 'input')['expr'][0]['match']['left'] = {'opaque-native-expression': {'counter': {'packets': 7}}}
        result = STATE.project(value)
        self.assertEqual(result['policy']['rules']['input'][0]['expr'][0]['match']['left']['opaque-native-expression']['counter']['packets'], 7)

    def test_unsupported_match_fields_and_operators_refuse_without_evaluation(self):
        for change in ({'op': 'execute'}, {'op': []}, {'op': True}, {'extra': 'field'}):
            value = message();object_row(value, 'rule', 'input')['expr'][0]['match'].update(change)
            with self.subTest(change=change), self.assertRaises(STATE.Pending):STATE.project(value)

    def test_input_private_copy_structure_scalar_byte_and_encoding_bounds_fail_closed(self):
        value = message();result = STATE.project(value);object_row(value, 'rule', 'input')['expr'][0]['match']['right'] = 'changed'
        self.assertEqual(result['policy']['rules']['input'][0]['expr'][0]['match']['right'], 'lo')
        for bad in (1.1, float('nan'), '\0', '\ud800', 1 << 65, {'bad': {1: 'key'}}, tuple(), 'x' * (NFT.MAX_BYTES + 1)):
            value = message();object_row(value, 'rule', 'input')['expr'][0]['match']['right'] = bad
            with self.subTest(bad_type=type(bad).__name__), self.assertRaises(STATE.Pending):STATE.project(value)
        with patch.object(STATE, 'MAX_NODES', 5), self.assertRaises(STATE.Pending):STATE.project(message())
        with patch.object(STATE, 'MAX_OBJECTS', 2), self.assertRaises(STATE.Pending):STATE.project(message())
        value = message();nested = [];nested.append(nested);object_row(value, 'set')['elem'] = nested
        with self.assertRaises(STATE.Pending):STATE.project(value)


class ObservationTests(unittest.TestCase):
    def observe(self, **overrides):
        settings = {'query': lambda deadline: message()};settings.update(overrides);return STATE.observe(**settings)

    def test_two_complete_native_records_share_one_inherited_window(self):
        calls = [];deadline = KERNEL.now() + 5
        result = self.observe(query=lambda deadline: calls.append(deadline) or message(), deadline=deadline)
        self.assertEqual(calls, [deadline] * 2);self.assertEqual(result['namespace'], KERNEL.namespace())
        self.assertEqual(result['schema'], 'debian13s4-nft-candidate-1')
        self.assertEqual(result['profile'], 'reserved-inet-static-root-shape-source-1')

    def test_invalid_or_expired_deadline_refuses_before_scope_or_read(self):
        for deadline in (True, 'future', float('nan'), float('inf'), 10 ** 10000, KERNEL.now() - 1):
            with self.subTest(kind=type(deadline).__name__), self.assertRaises(STATE.Pending):
                self.observe(deadline=deadline, scope=lambda: self.fail('scope'), query=lambda deadline: self.fail('read'))

    def test_own_window_caps_an_inherited_budget_without_widening_it(self):
        start = KERNEL.now()
        for seconds in (1, 1000):
            seen = []
            with patch.object(KERNEL, 'now', return_value=start):self.observe(deadline=start + seconds, query=lambda deadline: seen.append(deadline) or message())
            self.assertEqual(seen, [start + min(seconds, STATE.ATTEMPT_SECONDS)] * 2)

    def test_current_namespace_is_true_nonzero_uint64_and_final_namespace_must_match(self):
        for bad in (True, 0, -1, '1', 1 << 64):
            with self.subTest(bad=bad), self.assertRaises(STATE.Pending):self.observe(scope=lambda: bad, query=lambda deadline: self.fail('read'))
        for last in (2, True, '1'):
            values = iter([1, last])
            with self.subTest(last=last), self.assertRaises(STATE.Pending):self.observe(scope=lambda: next(values))

    def test_valid_statistics_changes_are_observed_without_changing_static_facts(self):
        values = [message(), message()];object_row(values[1], 'rule', 'input')['expr'][1]['counter']['packets'] = 0
        result = self.observe(query=lambda deadline: values.pop(0))
        self.assertEqual(result['statistics'][0]['packets'], 0)

    def test_changed_table_chain_set_rule_handles_and_metadata_refuse_even_with_equal_fingerprint(self):
        for kind in ('table', 'chain', 'set', 'rule', 'metainfo'):
            values = [message(), message()];row = object_row(values[1], kind)
            if kind == 'metainfo':row['release_name'] = 'changed'
            else:row['handle'] += 1000
            with self.subTest(kind=kind), self.assertRaises(STATE.Pending):self.observe(query=lambda deadline: values.pop(0))

    def test_changed_full_rule_or_set_data_cannot_publish_a_stale_fingerprint(self):
        for kind in ('selector', 'set'):
            values = [message(), message()]
            if kind == 'selector':object_row(values[1], 'rule', 'input')['expr'][0]['match']['right'] = 'eth0'
            else:object_row(values[1], 'set', 'dhcp4_links')['elem'] = ['eth0']
            with self.subTest(kind=kind), self.assertRaises(STATE.Pending):self.observe(query=lambda deadline: values.pop(0))

    def test_later_callback_cannot_modify_the_first_admitted_private_record(self):
        first = message();calls = []
        def read(deadline):
            calls.append(deadline)
            if len(calls) == 1:return first
            object_row(first, 'rule', 'input')['expr'][0]['match']['right'] = 'tampered'
            return message()
        result = self.observe(query=read)
        self.assertEqual(result['policy']['rules']['input'][0]['expr'][0]['match']['right'], 'lo')

    def test_scope_and_first_delivery_expiration_prevent_later_reads(self):
        clock = [KERNEL.now()];start = clock[0]
        def scope():clock[0] = start + 11;return 1
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(STATE.Pending):self.observe(scope=scope, query=lambda deadline: self.fail('expired read'))
        clock[0] = start;calls = []
        def read(deadline):calls.append(deadline);clock[0] = deadline;return message()
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(STATE.Pending):self.observe(query=read)
        self.assertEqual(len(calls), 1)

    def test_final_scope_expiry_and_failed_native_delivery_withhold_receipt(self):
        clock = [KERNEL.now()];calls = []
        def scope():
            calls.append(1)
            if len(calls) == 2:clock[0] += 11
            return 1
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(STATE.Pending):self.observe(scope=scope)
        def missing(deadline):raise OSError('missing native state')
        with self.assertRaises(OSError):self.observe(query=missing)


class PrivateNative(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-nft-state-', dir='/dev/shm')
        self.root = Path(self.directory.name);self.binary = self.root / 'nft';self.ledger = self.root / 'ledger'
        self.settings = [patch.object(NFT, 'BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def executable(self, body=None):
        if body is None:body = 'print(' + repr(json.dumps(message())) + ')'
        self.binary.write_text('#!/usr/bin/python3 -B\n' + body + '\n');self.binary.chmod(0o700)

    def cli(self, encoding='utf-8'):
        sink = io.BytesIO();wrapper = io.TextIOWrapper(sink, encoding=encoding, errors='replace');err = io.StringIO()
        with patch.object(STATE.sys, 'argv', ['nft_state.py']), contextlib.redirect_stdout(wrapper), contextlib.redirect_stderr(err):status = STATE.main()
        wrapper.flush();data = sink.getvalue();wrapper.detach();return status, data, err.getvalue()


class NativeTests(PrivateNative):
    def test_complete_fixed_native_capture_and_projection_are_positive(self):
        self.executable(f"import json,os,sys\nwith open({str(self.ledger)!r},'a') as stream:stream.write(json.dumps([sys.argv[1:],dict(os.environ)])+'\\n')\nprint({json.dumps(message())!r})")
        with patch.dict(os.environ, {'TASK_SECRET': 'bad', 'NFT_CTX_FLAGS': 'bad'}):result = STATE.observe()
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        for arguments, environment in rows:
            self.assertEqual(arguments, list(NFT.COMMAND));self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})
        self.assertEqual(result['source']['binary'], str(self.binary))
        self.assertEqual(result['fingerprint'], STATE.project(message())['fingerprint'])

    def test_inherited_descriptor_is_closed_by_the_actual_native_reader(self):
        fd = os.open(self.root / 'fd', os.O_CREAT | os.O_WRONLY, 0o600);os.set_inheritable(fd, True)
        self.executable(f"import os\ntry:\n os.fstat({fd});raise SystemExit(2)\nexcept OSError:pass\nprint({json.dumps(message())!r})")
        try:self.assertEqual(STATE.observe()['namespace'], KERNEL.namespace())
        finally:os.close(fd)

    def test_failed_warned_truncated_duplicate_and_invalid_utf8_reads_remain_pending(self):
        for body in ('raise SystemExit(1)', "print('{')", "print('{\"nftables\":[],\"nftables\":[]}')", "import os;os.write(1,b'\\xff')",
                     f"import sys;print({json.dumps(message())!r});print('warning',file=sys.stderr)"):
            self.executable(body)
            with self.subTest(body=body), self.assertRaises(STATE.Pending):STATE.observe()

    def test_wrong_kind_symbolic_unsafe_owner_and_binary_replacement_refuse(self):
        self.executable()
        with patch.object(KERNEL, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(STATE.Pending):STATE.observe()
        self.binary.chmod(0o720)
        with self.assertRaises(STATE.Pending):STATE.observe()
        self.binary.chmod(0o700);original = self.root / 'original';self.binary.rename(original);self.binary.symlink_to(original)
        with self.assertRaises(STATE.Pending):STATE.observe()
        self.binary.unlink();os.mkfifo(self.binary)
        with self.assertRaises(STATE.Pending):STATE.observe()
        self.binary.unlink();self.executable(f"from pathlib import Path\nPath({str(self.binary)!r}).write_text('changed')\nprint({json.dumps(message())!r})")
        with self.assertRaises(STATE.Pending):STATE.observe()

    def test_each_actual_channel_bound_and_post_eof_completion_is_checked(self):
        for channel in (1, 2):
            self.executable(f'import os;os.write({channel},b"x"*{NFT.MAX_BYTES + 1})')
            with self.subTest(channel=channel), self.assertRaises(STATE.Pending):STATE.observe()
        self.executable('import os,time;os.close(1);os.close(2);time.sleep(60)')
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.1), self.assertRaises(STATE.Pending):STATE.observe()

    def test_foreign_or_incomplete_actual_state_cannot_publish_a_candidate(self):
        for extra in ({'table': {'family': 'bridge', 'name': 'filter', 'handle': 9}}, {'flowtable': {}}):
            value = message();value['nftables'].append(extra);self.executable('print(' + repr(json.dumps(value)) + ')')
            status, data, err = self.cli();self.assertEqual(status, 75);self.assertEqual(data, b'');self.assertIn('pending', err)

    def test_actual_cli_byte_sink_is_independent_of_utf32_and_ascii_handlers(self):
        value = message();object_row(value, 'set', 'dhcp4_links')['elem'] = ['ééé']
        self.executable('print(' + repr(json.dumps(value)) + ')')
        for encoding in ('utf-8', 'utf-32', 'ascii'):
            with self.subTest(encoding=encoding):
                status, data, err = self.cli(encoding);self.assertEqual(status, 0, err);self.assertEqual(err, '')
                self.assertEqual(json.loads(data)['policy']['sets']['dhcp4_links']['elem'], ['ééé'])
                self.assertIn('ééé'.encode(), data)

    def test_separate_interpreter_cli_pipe_bytes_preserve_utf8_despite_encoding_environment(self):
        value = message();object_row(value, 'set', 'dhcp4_links')['elem'] = ['ééé']
        self.executable('print(' + repr(json.dumps(value)) + ')')
        driver = f"""import importlib.util,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('private_state',{str(ROOT / 'Firewall/nft_state.py')!r})
state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
state.NFT.BINARY=Path({str(self.binary)!r})
state.KERNEL.TRUST_ROOT=Path({str(self.root)!r});state.KERNEL.TRUSTED_UID=os.geteuid()
sys.argv=['nft_state.py'];raise SystemExit(state.main())
"""
        for encoding in ('utf-8:strict', 'utf-32:strict', 'ascii:replace', 'ascii:ignore', 'ascii:backslashreplace'):
            child = subprocess.run(['python3', '-B', '-c', driver], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, close_fds=True,
                                   start_new_session=True, env=os.environ.copy() | {'PYTHONIOENCODING': encoding})
            with self.subTest(encoding=encoding):
                self.assertEqual(child.returncode, 0, child.stderr);self.assertEqual(child.stderr, b'')
                self.assertEqual(json.loads(child.stdout)['policy']['sets']['dhcp4_links']['elem'], ['ééé'])
                self.assertIn('ééé'.encode(), child.stdout)

    def test_actual_same_policy_with_replaced_handle_has_no_completed_cli_receipt(self):
        counter = self.root / 'turn'
        self.executable(f"""import json
from pathlib import Path
path=Path({str(counter)!r});turn=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(turn))
value=json.loads({json.dumps(message())!r})
value['nftables'][1]['table']['handle']+=turn
print(json.dumps(value))""")
        status, data, err = self.cli()
        self.assertEqual(status, 75);self.assertEqual(data, b'');self.assertIn('changed', err)
        self.assertEqual(counter.read_text(), '2')

    def test_usage_and_missing_binary_sink_refuse_before_any_native_read(self):
        self.executable(f"open({str(self.ledger)!r},'w').write('unexpected')")
        with patch.object(STATE.sys, 'argv', ['nft_state.py', 'flush']), contextlib.redirect_stdout(io.StringIO()):self.assertEqual(STATE.main(), 64)
        with patch.object(STATE.sys, 'argv', ['nft_state.py']), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):self.assertEqual(STATE.main(), 75)
        self.assertFalse(self.ledger.exists())

    def test_short_boolean_failed_write_and_flush_cannot_report_success(self):
        self.executable()
        class Sink:
            def __init__(self, mode):self.mode = mode;self.payload = None
            def write(self, payload):
                self.payload = payload
                if self.mode == 'write':raise OSError('write')
                return len(payload) - 1 if self.mode == 'short' else True if self.mode == 'bool' else None if self.mode == 'none' else len(payload)
            def flush(self):
                if self.mode == 'flush':raise OSError('flush')
        class Output:
            def __init__(self, sink):self.buffer = sink
        for mode in ('short', 'bool', 'none', 'write', 'flush'):
            sink = Sink(mode)
            with self.subTest(mode=mode), patch.object(STATE.sys, 'argv', ['nft_state.py']), patch.object(STATE.sys, 'stdout', Output(sink)), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(STATE.main(), 75)
            self.assertIs(type(sink.payload), bytes)

    def test_actual_publication_bound_includes_the_lf_and_prevents_any_successful_payload(self):
        self.executable()
        with patch.object(STATE, 'MAX_OUTPUT', 1):
            status, data, err = self.cli()
        self.assertEqual(status, 75);self.assertEqual(data, b'');self.assertIn('publication', err)


if __name__ == '__main__':unittest.main()
