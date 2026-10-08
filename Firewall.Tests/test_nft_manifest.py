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
SPEC = importlib.util.spec_from_file_location('firewall_nft_manifest', ROOT / 'Firewall/nft_manifest.py')
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)
STATE, POLICY, KERNEL = MANIFEST.STATE, MANIFEST.POLICY, MANIFEST.KERNEL
NFT = STATE.NFT


def topology():
    return {'schema': 1, 'interfaces': [{'name': 'enp1s0', 'kind': 'ether', 'dhcp4': True, 'dhcp6': True,
            'prefixes': ['192.168.50.0/24', 'fd50::/64', 'fe80::/64'],
            'gateways': [{'address': '192.168.50.1', 'mac': '02:00:00:00:00:01'}],
            'neighbors': [{'address': '192.168.50.20', 'mac': '02:00:00:00:00:20', 'state': 'REACHABLE'},
                          {'address': 'fd50::20', 'mac': '02:00:00:00:00:20', 'state': 'STALE'},
                          {'address': '192.168.50.1', 'mac': '02:00:00:00:00:01', 'state': 'REACHABLE'}]}],
            'dns': [{'interface': 'enp1s0', 'address': '192.168.50.1'}],
            'ntp': [{'interface': 'enp1s0', 'address': '192.168.50.3'}],
            'dhcp4': [{'interface': 'enp1s0', 'address': '192.168.50.1'}],
            'dhcp6': [{'interface': 'enp1s0', 'address': 'fe80::1'}]}


def raw(value=None):
    return json.dumps(topology() if value is None else value).encode('utf-8')


def native(value=None):
    """A private delivery model, NOT evidence of actual nft formatter output."""
    policy = MANIFEST.expected(raw(value))['policy']
    objects = [{'metainfo': {'version': '1.1.3', 'release_name': 'private numeric source', 'json_schema_version': 1}}]
    handle = 1
    for kind, rows in (('table', [policy['table']]), ('chain', policy['chains'].values()),
                       ('set', policy['sets'].values()), ('rule', [r for rules in policy['rules'].values() for r in rules])):
        for row in rows:
            row = copy.deepcopy(row);row['handle'] = handle;handle += 1
            if kind == 'rule':
                row['expr'][-2] = {'counter': {'packets': 3, 'bytes': 180}}
            objects.append({kind: row})
    return {'nftables': objects}


def objects(value, kind):
    return [item[kind] for item in value['nftables'] if kind in item]


def match(left, right, op='=='):
    return {'match': {'left': left, 'right': right, 'op': op}}


class ManifestTests(unittest.TestCase):
    def verify(self, value=None, data=None, **kwargs):
        value = native() if value is None else value
        return MANIFEST.verify(raw() if data is None else data, query=lambda deadline: copy.deepcopy(value), scope=lambda: 1, **kwargs)

    def test_full_compiler_intention_and_exact_numeric_representation_match(self):
        data = raw();text = POLICY.compile_policy(data);result = self.verify()
        self.assertEqual(result['compiler_sha256'], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(result['topology_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['fingerprint'], hashlib.sha256(STATE.encoded(result['policy'])).hexdigest())
        self.assertEqual(result['schema'], 'debian13s4-nft-compiler-match-1')
        self.assertEqual(set(result['policy']['sets']), set(STATE.SET_TYPES))
        self.assertEqual(len(result['policy']['sets']), 17)
        self.assertEqual(result['policy']['rules']['forward'], [])
        self.assertEqual(sum(map(len, result['policy']['rules'].values())), sum(' counter ' in line for line in text.splitlines()))

    def test_empty_topology_still_requires_the_entire_compiler_rule_inventory(self):
        value = {key: [] for key in ('interfaces', 'dns', 'ntp', 'dhcp4', 'dhcp6')} | {'schema': 1}
        result = self.verify(native(value), raw(value))
        self.assertEqual(result['policy']['sets']['ssh4']['elem'], [])
        self.assertTrue(result['policy']['rules']['input'])
        self.assertTrue(result['policy']['rules']['output'])
        self.assertTrue(result['policy']['sets']['blocked4']['elem'])

    def test_numeric_selector_and_constant_forms_are_explicit_independent_controls(self):
        cases = {
            'ct state invalid counter drop': [match({'ct': {'key': 'state'}}, 1, 'in')],
            'ct direction original counter accept': [match({'ct': {'key': 'direction'}}, 0)],
            'ct direction reply counter accept': [match({'ct': {'key': 'direction'}}, 1)],
            'meta nfproto ipv4 counter accept': [match({'meta': {'key': 'nfproto'}}, 2)],
            'meta nfproto ipv6 counter accept': [match({'meta': {'key': 'nfproto'}}, 10)],
            'tcp dport 22 counter accept': [match({'payload': {'protocol': 'tcp', 'field': 'dport'}}, 22)],
            'ct original proto-dst 22 counter accept': [match({'ct': {'key': 'proto-dst', 'dir': 'original'}}, 22)],
            'ip saddr 127.0.0.0/8 counter drop': [match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, {'prefix': {'addr': '127.0.0.0', 'len': 8}})],
            'icmp type time-exceeded counter accept': [match({'payload': {'protocol': 'icmp', 'field': 'type'}}, 11)],
            'icmpv6 type nd-neighbor-solicit counter accept': [match({'payload': {'protocol': 'icmpv6', 'field': 'type'}}, 135)],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):self.assertEqual(MANIFEST.expression(text)[:-2], expected)

    def test_state_sets_and_tcp_syn_mask_are_fully_retained(self):
        self.assertEqual(MANIFEST.expression('ct state { new, established } counter accept')[0],
                         match({'ct': {'key': 'state'}}, {'set': [8, 2]}, 'in'))
        expected = match({'&': [{'payload': {'protocol': 'tcp', 'field': 'flags'}}, 23]}, 2)
        self.assertEqual(MANIFEST.expression('tcp flags & (fin | syn | rst | ack) == syn counter accept')[0], expected)

    def test_concatenation_preserves_every_interface_ip_and_mac_operand(self):
        result = MANIFEST.expression('iifname . ip saddr . ether saddr @ssh4 counter accept')[0]
        self.assertEqual(result, match({'concat': [{'meta': {'key': 'iifname'}},
                                                  {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                                                  {'payload': {'protocol': 'ether', 'field': 'saddr'}}]}, '@ssh4'))

    def test_peer_router_and_infrastructure_entries_derive_from_the_real_compiler(self):
        sets = MANIFEST.expected(raw())['policy']['sets']
        self.assertEqual(sets['ssh4']['elem'], [{'concat': ['enp1s0', '192.168.50.20', '02:00:00:00:00:20']}])
        self.assertEqual(sets['dns_4']['elem'], [{'concat': ['enp1s0', '192.168.50.1']}])
        self.assertEqual(sets['dhcp4_links']['elem'], ['enp1s0'])
        self.assertEqual(sets['dhcp6_links']['elem'], ['enp1s0'])
        changed = topology();changed['interfaces'][0]['gateways'][0]['mac'] = None
        self.assertEqual(MANIFEST.expected(raw(changed))['policy']['sets']['ssh4']['elem'], [])

    def test_dotted_and_numeric_interface_names_do_not_change_token_identity(self):
        for name in ('eth0.10', '2', 'CONCAT', 'x-y_z'):
            value = topology();value['interfaces'][0]['name'] = name
            for service in ('dns', 'ntp', 'dhcp4', 'dhcp6'):
                for entry in value[service]:entry['interface'] = name
            with self.subTest(name=name):
                result = self.verify(native(value), raw(value))
                self.assertEqual(result['policy']['sets']['dhcp4_links']['elem'], [name])

    def test_topology_registration_and_malformed_input_cannot_supply_a_trusted_hash(self):
        for data in (b'{}', b'\xff', b'{"schema":1,"schema":1}', b'x' * (POLICY.MAX_INPUT + 1), None, bytearray(raw())):
            with self.subTest(data=type(data)), self.assertRaises(ValueError):MANIFEST.expected(data)
        value = topology();value['interfaces'][0]['name'] = 'eth0; accept'
        with self.assertRaises(ValueError):MANIFEST.expected(raw(value))

    def test_unknown_compiler_grammar_refuses_instead_of_guessing(self):
        for text in ('meta mark 1 counter accept', 'ct mark 1 counter accept', 'ip length 1 counter accept',
                     'iifname "lo" log counter accept', 'ct state broken counter accept', 'tcp dport 22 counter jump',
                     'tcp flags & (syn) != syn counter accept', 'ct state { new, } counter accept'):
            with self.subTest(text=text), self.assertRaises(ValueError):MANIFEST.expression(text)

    def test_structure_only_accept_all_counterexample_fails_intended_comparison(self):
        value = native()
        for row in objects(value, 'rule'):
            if row['chain'] == 'input':row['expr'] = [{'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]
        self.assertTrue(STATE.project(value))
        with self.assertRaisesRegex(STATE.Pending, 'intention'):self.verify(value)

    def test_every_rule_verdict_and_rule_presence_is_checked(self):
        baseline = native()
        for index, row in enumerate(objects(baseline, 'rule')):
            value = copy.deepcopy(baseline);changed = objects(value, 'rule')[index]
            changed['expr'][-1] = {'drop' if 'accept' in row['expr'][-1] else 'accept': None}
            with self.subTest(index=index), self.assertRaises(STATE.Pending):self.verify(value)
        value = native();value['nftables'].remove(next(entry for entry in value['nftables'] if 'rule' in entry))
        with self.assertRaises(STATE.Pending):self.verify(value)

    def test_rule_order_and_match_order_cannot_hide_early_acceptance(self):
        for kind in ('rules', 'matches', 'counter'):
            value = native();rules = objects(value, 'rule')
            if kind == 'rules':
                first, second = value['nftables'].index({'rule': rules[0]}), value['nftables'].index({'rule': rules[1]})
                value['nftables'][first], value['nftables'][second] = value['nftables'][second], value['nftables'][first]
            else:
                row = next(r for r in rules if len(r['expr']) > 3)
                a, b = (0, 1) if kind == 'matches' else (0, len(row['expr']) - 2)
                row['expr'][a], row['expr'][b] = row['expr'][b], row['expr'][a]
            with self.subTest(kind=kind), self.assertRaises(STATE.Pending):self.verify(value)

    def test_every_match_side_and_operator_is_checked(self):
        baseline = native();rules = objects(baseline, 'rule')
        for index, row in enumerate(rules):
            for position, statement in enumerate(row['expr'][:-2]):
                for part in ('left', 'right', 'op'):
                    value = copy.deepcopy(baseline);target = objects(value, 'rule')[index]['expr'][position]['match']
                    target[part] = '!=' if part == 'op' else 65535
                    with self.subTest(rule=index, position=position, part=part), self.assertRaises(STATE.Pending):self.verify(value)

    def test_every_named_set_entry_and_static_option_is_checked(self):
        baseline = native()
        for index in range(17):
            value = copy.deepcopy(baseline);objects(value, 'set')[index]['elem'].append('evil')
            with self.subTest(index=index), self.assertRaises(STATE.Pending):self.verify(value)
        for key, val in (('policy', 'memory'), ('size', 1), ('auto-merge', True)):
            value = native();row = next(r for r in objects(value, 'set') if r['name'] == 'blocked4');row[key] = val
            with self.subTest(key=key), self.assertRaises(STATE.Pending):self.verify(value)

    def test_declaration_flags_and_known_unordered_element_order_do_not_change_intention(self):
        value = native();nonrules = [r for r in value['nftables'][1:] if 'rule' not in r]
        value['nftables'][1:] = list(reversed(nonrules)) + [r for r in value['nftables'][1:] if 'rule' in r]
        for row in objects(value, 'set'):row['flags'].reverse();row['elem'].reverse()
        for row in objects(value, 'rule'):
            for statement in row['expr'][:-2]:
                right = statement['match']['right']
                if type(right) is dict and 'set' in right:right['set'].reverse()
        objects(value, 'table')[0]['flags'] = []
        self.assertEqual(self.verify(value)['policy'], MANIFEST.expected(raw())['policy'])

    def test_full_length_prefix_and_explicit_numeric_or_mask_are_checked_equivalents(self):
        value = native()
        for row in objects(value, 'rule'):
            for statement in row['expr'][:-2]:
                m = statement['match']
                if m['right'] == '::1':m['right'] = {'prefix': {'addr': '::1', 'len': 128}}
                if type(m['left']) is dict and '&' in m['left']:m['left']['&'][1] = {'|': [1, 2, 4, 16]}
        self.assertEqual(self.verify(value)['policy'], MANIFEST.expected(raw())['policy'])

    def test_interface_named_set_prefix_is_not_an_address_constant(self):
        value = topology();value['interfaces'][0]['name'] = '1.2.3.4'
        for service in ('dns', 'ntp', 'dhcp4', 'dhcp6'):
            for entry in value[service]:entry['interface'] = '1.2.3.4'
        delivered = native(value)
        row = next(r for r in objects(delivered, 'set') if r['name'] == 'dhcp4_links')
        row['elem'][0] = {'prefix': {'addr': '1.2.3.4', 'len': 32}}
        self.assertTrue(STATE.project(delivered))
        with self.assertRaises(STATE.Pending):self.verify(delivered, raw(value))

    def test_tuple_prefix_normalization_requires_the_correct_address_datatype(self):
        value = native();row = next(r for r in objects(value, 'set') if r['name'] == 'ssh4')
        row['elem'][0]['concat'][1] = {'prefix': {'addr': '192.168.50.20', 'len': 32}}
        self.assertEqual(self.verify(value)['policy'], MANIFEST.expected(raw())['policy'])
        for field, address, length in ((0, '192.168.50.20', 32), (1, '::1', 128), (2, '192.168.50.20', 32)):
            value = native();row = next(r for r in objects(value, 'set') if r['name'] == 'ssh4')
            row['elem'][0]['concat'][field] = {'prefix': {'addr': address, 'len': length}}
            with self.subTest(field=field), self.assertRaises(STATE.Pending):self.verify(value)

    def test_unknown_or_mistyped_operand_forms_are_never_silently_removed(self):
        for bad in (True, None, [], {'counter': {}}, {'prefix': {'addr': '::1', 'len': True}},
                    {'set': [1, 1]}, {'|': [1, True]}, {'&': [1, '27']}, {'meta': {'key': True}}):
            with self.subTest(bad=bad), self.assertRaises(STATE.Pending):MANIFEST.canonical_expression(bad)

    def test_unknown_selector_fields_and_ct_family_are_retained_then_rejected(self):
        for extra in ('family', 'unchecked'):
            value = native();objects(value, 'rule')[0]['expr'][0]['match']['left']['ct'][extra] = 'ip'
            with self.subTest(extra=extra), self.assertRaises(STATE.Pending):self.verify(value)

    def test_duplicate_named_elements_and_wrong_container_refuse(self):
        for duplicate in (True, False):
            value = native();row = next(r for r in objects(value, 'set') if r['name'] == 'dhcp4_links')
            row['elem'] = row['elem'] * 2 if duplicate else row['elem'][0]
            with self.subTest(duplicate=duplicate), self.assertRaises(STATE.Pending):self.verify(value)

    def test_counter_statistics_and_handle_values_are_not_expected_policy_inputs(self):
        value = native()
        for entry in value['nftables'][1:]:
            row = next(iter(entry.values()));row['handle'] += 1000
            if 'expr' in row:row['expr'][-2]['counter'] = {'packets': (1 << 64) - 1, 'bytes': 0}
        result = self.verify(value)
        self.assertEqual(result['identity']['table'], 1001)
        self.assertEqual(result['statistics'][0]['packets'], (1 << 64) - 1)
        self.assertEqual(result['fingerprint'], MANIFEST.expected(raw())['fingerprint'])

    def test_counters_can_change_between_reads_but_complete_handles_cannot(self):
        values = [native(), native()];objects(values[1], 'rule')[0]['expr'][-2]['counter']['packets'] = 0
        result = MANIFEST.verify(raw(), query=lambda deadline: values.pop(0), scope=lambda: 1)
        self.assertEqual(result['statistics'][0]['packets'], 0)
        values = [native(), native()];objects(values[1], 'table')[0]['handle'] += 100
        with self.assertRaisesRegex(STATE.Pending, 'changed'):MANIFEST.verify(raw(), query=lambda deadline: values.pop(0), scope=lambda: 1)

    def test_old_topology_and_new_peer_or_service_intention_cannot_match(self):
        for which in ('peer', 'dns', 'dhcp'):
            changed = topology()
            if which == 'peer':changed['interfaces'][0]['neighbors'][0]['mac'] = '02:00:00:00:00:21'
            elif which == 'dns':changed['dns'][0]['address'] = '192.168.50.2'
            else:changed['interfaces'][0]['dhcp4'] = False;changed['dhcp4'] = []
            with self.subTest(which=which), self.assertRaises(STATE.Pending):self.verify(native(changed))

    def test_expired_or_invalid_deadline_refuses_before_compiler_and_native_calls(self):
        for deadline in (True, float('nan'), float('inf'), '1', KERNEL.now() - 1):
            with (self.subTest(deadline=deadline), patch.object(POLICY, 'compile_policy', side_effect=AssertionError('compile')),
                  self.assertRaises(STATE.Pending)):MANIFEST.verify(raw(), deadline=deadline, query=lambda deadline: self.fail('read'))

    def test_own_window_caps_and_propagates_one_parent_deadline(self):
        start = KERNEL.now()
        for duration in (1, 1000):
            seen = []
            with patch.object(KERNEL, 'now', return_value=start):
                MANIFEST.verify(raw(), query=lambda deadline: seen.append(deadline) or native(), scope=lambda: 1, deadline=start + duration)
            self.assertEqual(seen, [start + min(duration, 10)] * 2)

    def test_final_namespace_or_expiry_cannot_publish_a_match(self):
        for last in (2, True, '1'):
            values = iter([1, 1, last])
            with self.subTest(last=last), self.assertRaises(STATE.Pending):
                MANIFEST.verify(raw(), query=lambda deadline: native(), scope=lambda: next(values))
        clock = [KERNEL.now()]
        def scope():
            scope.calls += 1
            if scope.calls == 3:clock[0] += 11
            return 1
        scope.calls = 0
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(STATE.Pending):
            MANIFEST.verify(raw(), query=lambda deadline: native(), scope=scope)

    def test_projection_copies_native_objects_before_later_callback_mutation(self):
        first = native();calls = [0]
        def query(deadline):
            calls[0] += 1
            if calls[0] == 2:objects(first, 'rule')[0]['expr'][-1] = {'accept': None};return native()
            return first
        result = MANIFEST.verify(raw(), query=query, scope=lambda: 1)
        self.assertEqual(result['policy']['rules']['input'][0]['expr'][-1], {'drop': None})


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-nft-manifest-', dir='/dev/shm')
        self.root = Path(self.directory.name);self.root.chmod(0o700)
        self.binary, self.ledger = self.root / 'nft', self.root / 'ledger'
        self.settings = [patch.object(NFT, 'BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.root),
                         patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def executable(self, value=None, body=None):
        self.binary.write_text('#!/usr/bin/python3 -B\n' + (body if body is not None else 'print(' + repr(json.dumps(native() if value is None else value)) + ')') + '\n')
        self.binary.chmod(0o700)

    def cli(self, encoding='utf-8', data=None):
        sink = io.BytesIO();wrapper = io.TextIOWrapper(sink, encoding=encoding, errors='replace');err = io.StringIO()
        input_stream = io.TextIOWrapper(io.BytesIO(raw() if data is None else data), encoding='utf-8')
        with (patch.object(MANIFEST.sys, 'argv', ['nft_manifest.py']), patch.object(MANIFEST.sys, 'stdin', input_stream),
              contextlib.redirect_stdout(wrapper), contextlib.redirect_stderr(err)):status = MANIFEST.main()
        wrapper.flush();payload = sink.getvalue();wrapper.detach();return status, payload, err.getvalue()

    def test_complete_private_native_capture_parser_compiler_comparison_and_cli(self):
        self.executable(body=f"import json,os,sys\nwith open({str(self.ledger)!r},'a') as stream:stream.write(json.dumps([sys.argv[1:],dict(os.environ)])+'\\n')\nprint({json.dumps(native())!r})")
        with patch.dict(os.environ, {'TASK_SECRET': 'bad', 'NFT_CTX_FLAGS': 'bad'}):status, payload, err = self.cli()
        self.assertEqual(status, 0, err);self.assertEqual(err, '')
        result = json.loads(payload);self.assertEqual(result['namespace'], KERNEL.namespace())
        self.assertEqual(result['policy'], MANIFEST.expected(raw())['policy'])
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        for argv, environment in rows:
            self.assertEqual(argv, list(NFT.COMMAND));self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})

    def test_real_structural_accept_all_delivery_has_no_completed_cli_match(self):
        value = native()
        for row in objects(value, 'rule'):
            if row['chain'] == 'input':row['expr'] = [{'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]
        self.executable(value);status, payload, err = self.cli()
        self.assertEqual(status, 75);self.assertEqual(payload, b'');self.assertIn('intention', err)

    def test_actual_ip_shaped_interface_tuple_prefix_does_not_publish_match(self):
        value = topology();value['interfaces'][0]['name'] = '1.2.3.4'
        for service in ('dns', 'ntp', 'dhcp4', 'dhcp6'):
            for entry in value[service]:entry['interface'] = '1.2.3.4'
        delivered = native(value)
        row = next(r for r in objects(delivered, 'set') if r['name'] == 'ssh4')
        row['elem'][0]['concat'][0] = {'prefix': {'addr': '1.2.3.4', 'len': 32}}
        self.assertTrue(STATE.project(delivered));self.executable(delivered)
        status, payload, err = self.cli(data=raw(value))
        self.assertEqual(status, 75);self.assertEqual(payload, b'');self.assertIn('pending', err)

    def test_foreign_partial_warned_and_failed_actual_reads_remain_pending(self):
        changed = native();changed['nftables'].append({'flowtable': {}})
        for body in ("raise SystemExit(1)", "print('{')", f"print({json.dumps(changed)!r})",
                     f"import sys;print({json.dumps(native())!r});print('warning',file=sys.stderr)"):
            self.executable(body=body);status, payload, err = self.cli()
            with self.subTest(body=body):self.assertEqual(status, 75);self.assertEqual(payload, b'');self.assertTrue(err)

    def test_actual_second_read_changed_handle_is_pending_without_match_output(self):
        counter = self.root / 'turn'
        self.executable(body=f"from pathlib import Path\nimport json\np=Path({str(counter)!r});n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))\nv=json.loads({json.dumps(native())!r});v['nftables'][1]['table']['handle']+=n\nprint(json.dumps(v))")
        status, payload, err = self.cli();self.assertEqual(status, 75);self.assertEqual(payload, b'');self.assertIn('changed', err)
        self.assertEqual(counter.read_text(), '2')

    def test_wrong_kind_symbolic_mode_and_owner_native_leaves_refuse(self):
        self.executable()
        with patch.object(KERNEL, 'TRUSTED_UID', os.geteuid() + 1):self.assertEqual(self.cli()[0:2], (75, b''))
        self.binary.chmod(0o720);self.assertEqual(self.cli()[0:2], (75, b''))
        self.binary.chmod(0o700);original = self.root / 'original';self.binary.rename(original);self.binary.symlink_to(original)
        self.assertEqual(self.cli()[0:2], (75, b''));self.binary.unlink();os.mkfifo(self.binary)
        self.assertEqual(self.cli()[0:2], (75, b''))

    def test_cli_uses_actual_byte_sink_despite_text_encoding_and_error_handler(self):
        self.binary = self.root / 'nft-é';setting = patch.object(NFT, 'BINARY', self.binary)
        self.settings.append(setting);setting.start();self.executable()
        for encoding in ('utf-8', 'utf-32', 'ascii'):
            status, payload, err = self.cli(encoding)
            with self.subTest(encoding=encoding):
                self.assertEqual(status, 0, err);self.assertIn('nft-é'.encode(), payload)
                self.assertEqual(json.loads(payload)['source']['binary'], str(self.binary))

    def test_separate_interpreter_pipe_bytes_ignore_pythonioencoding(self):
        self.binary = self.root / 'nft-é';setting = patch.object(NFT, 'BINARY', self.binary)
        self.settings.append(setting);setting.start();self.executable()
        driver = f"""import importlib.util,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('private_manifest',{str(ROOT / 'Firewall/nft_manifest.py')!r})
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.STATE.NFT.BINARY=Path({str(self.binary)!r});m.KERNEL.TRUST_ROOT=Path({str(self.root)!r});m.KERNEL.TRUSTED_UID=os.geteuid()
sys.argv=['nft_manifest.py'];raise SystemExit(m.main())
"""
        for encoding in ('utf-8:strict', 'utf-32:strict', 'ascii:replace', 'ascii:ignore', 'ascii:backslashreplace'):
            child = subprocess.run(['python3', '-B', '-c', driver], input=raw(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=30, close_fds=True, start_new_session=True,
                                   env=os.environ.copy() | {'PYTHONIOENCODING': encoding})
            with self.subTest(encoding=encoding):
                self.assertEqual(child.returncode, 0, child.stderr);self.assertEqual(child.stderr, b'')
                self.assertIn('nft-é'.encode(), child.stdout)
                self.assertEqual(json.loads(child.stdout)['source']['binary'], str(self.binary))

    def test_missing_binary_sink_and_usage_refuse_before_input_or_native_read(self):
        self.executable(body=f"open({str(self.ledger)!r},'w').write('bad')")
        class Input:
            @property
            def buffer(self):raise AssertionError('read')
        with patch.object(MANIFEST.sys, 'stdin', Input()), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with patch.object(MANIFEST.sys, 'argv', ['nft_manifest.py', 'check']):self.assertEqual(MANIFEST.main(), 64)
            with patch.object(MANIFEST.sys, 'argv', ['nft_manifest.py']):self.assertEqual(MANIFEST.main(), 75)
        self.assertFalse(self.ledger.exists())

    def test_bad_input_refuses_before_any_real_native_delivery(self):
        self.executable(body=f"open({str(self.ledger)!r},'w').write('bad')")
        for data in (b'{}', b'\xff', b'x' * (POLICY.MAX_INPUT + 1)):
            with self.subTest(data=data[:2]):self.assertEqual(self.cli(data=data)[0:2], (75, b''))
        self.assertFalse(self.ledger.exists())

    def test_publication_bound_short_boolean_write_and_flush_refuse_success(self):
        self.executable()
        with patch.object(STATE, 'MAX_OUTPUT', 1):self.assertEqual(self.cli()[0:2], (75, b''))
        class Sink:
            def __init__(self, mode):self.mode = mode;self.payload = None
            def write(self, payload):
                self.payload = payload
                if self.mode == 'write':raise OSError('write')
                return True if self.mode == 'bool' else None if self.mode == 'none' else len(payload) - 1 if self.mode == 'short' else len(payload)
            def flush(self):
                if self.mode == 'flush':raise OSError('flush')
        class Output:
            def __init__(self, sink):self.buffer = sink
        for mode in ('short', 'bool', 'none', 'write', 'flush'):
            sink = Sink(mode);input_stream = io.TextIOWrapper(io.BytesIO(raw()), encoding='utf-8')
            with (self.subTest(mode=mode), patch.object(MANIFEST.sys, 'argv', ['nft_manifest.py']), patch.object(MANIFEST.sys, 'stdin', input_stream),
                  patch.object(MANIFEST.sys, 'stdout', Output(sink)), contextlib.redirect_stderr(io.StringIO())):self.assertEqual(MANIFEST.main(), 75)
            self.assertIs(type(sink.payload), bytes)


if __name__ == '__main__':unittest.main()
