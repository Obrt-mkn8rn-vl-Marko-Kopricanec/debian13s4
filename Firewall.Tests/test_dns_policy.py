"""Pure compiler/SOURCE and serialized-packet models; no native host operation.

Reported namespace/address/conntrack facts and all site-like literals are TEST
DATA, not authenticated assignment, packet causation, locality or enforcement.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_kernel import snapshot, policy_input
from test_policy import PacketModel

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_dns_policy', ROOT / 'Firewall/dns_policy.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


def settings():
    return {'schema': 1, 'application_user': 'dns_app_demo', 'gateway_user': 'dns_gateway_demo',
        'ipc_group': 'dns_ipc_demo', 'application_binary': '/opt/fixture-dns/application/mk8.dns.Application',
        'gateway_binary': '/opt/fixture-dns/gateway/mk8.dns.Gateway', 'node': 'test-replica-1',
        'zones': ['1'*32], 'listeners': [{'address': '192.168.50.100', 'health_port': 9101},
            {'address': 'fd50::100', 'health_port': 9102}],
        'budgets': {key: minimum for key, (minimum, _) in M.DNS.BUDGETS.items()}}


def reported():
    data = snapshot()
    for row in data['addresses']:
        for entry in row['addr_info']:
            if entry['local'] in ('192.168.50.100', 'fd50::100'):
                entry.update(scope='global', valid_life_time='forever', preferred_life_time='forever')
    return {'schema': 1, 'namespace': 123456, 'snapshot': data}


def encoded(value):
    return M.DNS.BASE.canonical(value)


class DNSPolicyTests(unittest.TestCase):
    def setUp(self):
        self.settings = settings(); self.kernel = reported()
        self.raw = policy_input(M.KERNEL.normalize(self.kernel['snapshot']))
        self.topology = json.loads(self.raw)
        self.topology['dns'] = [{'interface': 'eth0', 'address': '192.168.50.1'}]
        self.topology['ntp'] = [{'interface': 'eth0', 'address': '192.168.50.3'}]
        self.raw = encoded(self.topology)

    def compile(self, raw=None, dns=None, kernel=None):
        return M.compile_intention(self.raw if raw is None else raw,
            encoded(self.settings) if dns is None else dns,
            encoded(self.kernel) if kernel is None else kernel)

    def record(self):
        return json.loads(self.compile())

    def model(self):
        return PacketModel(self.record()['policy'])

    def query(self, model, version=4, transport='udp', **changes):
        values = {'iifname': 'eth0', 'oifname': 'eth0', 'protocol': transport, 'direction': 'original',
            'state': 'new', 'sport': 40000, 'dport': 53, 'original_port': 53,
            'saddr': '15.16.17.18' if version == 4 else '2606:4700:20::1',
            'daddr': '192.168.50.100' if version == 4 else 'fd50::100'}
        values.update(changes)
        return model.verdict('input', **values)

    def reply(self, model, version=4, transport='udp', **changes):
        values = {'iifname': 'eth0', 'oifname': 'eth0', 'protocol': transport, 'direction': 'reply',
            'state': 'established', 'sport': 53, 'dport': 40000, 'original_port': 53,
            'saddr': '192.168.50.100' if version == 4 else 'fd50::100',
            'daddr': '15.16.17.18' if version == 4 else '2606:4700:20::1'}
        values.update(changes)
        return model.verdict('output', **values)

    def test_complete_canonical_intention_binds_all_three_raw_inputs_and_both_compilers(self):
        raw = self.compile(); record = json.loads(raw)
        self.assertEqual(raw, encoded(record))
        self.assertEqual(record['state'], 'dns-firewall-source-intention-only')
        self.assertEqual(record['namespace'], 123456)
        self.assertEqual(record['dns_configuration'], self.settings)
        for field, data in (('topology_sha256', self.raw), ('dns_configuration_sha256', encoded(self.settings)),
            ('kernel_snapshot_sha256', encoded(self.kernel))):
            self.assertEqual(record[field], hashlib.sha256(data).hexdigest())
        self.assertEqual(record['original_compiler_sha256'], hashlib.sha256(M.POLICY.compile_policy(self.raw).encode()).hexdigest())
        self.assertEqual(record['compiler_sha256'], hashlib.sha256(record['policy'].encode()).hexdigest())
        self.assertEqual([(row['interface'], row['address'], row['family']) for row in record['bindings']],
            [('eth0', '192.168.50.100', 4), ('eth0', 'fd50::100', 6)])

    def test_exact_original_body_order_sets_drop_chains_and_forwarding_are_preserved(self):
        original = M.POLICY.compile_policy(self.raw); text = self.record()['policy']
        inbound, replies = M.rules(self.record()['bindings'])
        reduced = '\n'.join(line for line in text.split('\n') if line not in (*inbound, *replies))
        self.assertEqual(reduced, original)
        self.assertEqual(len(inbound), 8); self.assertEqual(len(replies), 4)
        old = PacketModel(original); new = PacketModel(text)
        self.assertEqual(new.sets, old.sets); self.assertEqual(new.chains['forward'], [])
        self.assertEqual(text.count('policy drop;'), 3)
        self.assertEqual(text.count('set '), 17)
        self.assertTrue(text.startswith('destroy table inet debian13s4\ntable inet debian13s4 {\n'))
        self.assertNotIn('flush ruleset', text); self.assertNotIn('include ', text)

    def test_selected_external_dns_udp_and_tcp_queries_and_replies_are_admitted_in_model(self):
        model = self.model()
        for version in (4, 6):
            for transport in ('udp', 'tcp'):
                for state in ('new', 'established'):
                    self.assertEqual(self.query(model, version, transport, state=state), 'accept')
                self.assertEqual(self.reply(model, version, transport), 'accept')

    def test_default_compiler_still_refuses_all_added_server_dns_cases(self):
        original = PacketModel(M.POLICY.compile_policy(self.raw))
        for version in (4, 6):
            for transport in ('udp', 'tcp'):
                self.assertEqual(self.query(original, version, transport), 'drop')
                self.assertEqual(self.reply(original, version, transport), 'drop')

    def test_query_binding_requires_each_interface_destination_protocol_state_and_original_port(self):
        model = self.model()
        for version in (4, 6):
            host = '192.168.50.101' if version == 4 else 'fd50::101'
            for transport in ('udp', 'tcp'):
                for changes in ({'iifname':'eth1'}, {'daddr':host}, {'original_port':123},
                    {'direction':'reply'}, {'state':'invalid'}, {'state':'related'}, {'state':'untracked'},
                    {'dport':54}, {'dport':9101}):
                    with self.subTest(version=version, transport=transport, changes=changes):
                        self.assertEqual(self.query(model, version, transport, **changes), 'drop')

    def test_each_reply_requires_its_interface_source_protocol_state_port_and_original_port(self):
        model = self.model()
        for version in (4, 6):
            host = '192.168.50.101' if version == 4 else 'fd50::101'
            for transport in ('udp', 'tcp'):
                for changes in ({'oifname':'eth1'}, {'saddr':host}, {'direction':'original'}, {'state':'new'},
                    {'state':'invalid'}, {'state':'related'}, {'sport':54}, {'original_port':123}):
                    with self.subTest(version=version, transport=transport, changes=changes):
                        self.assertEqual(self.reply(model, version, transport, **changes), 'drop')

    def test_tcp_new_requires_initial_syn_udp_has_no_tcp_flag_requirement(self):
        model = self.model()
        for flags in (0, 0x10, 0x12, 0x03, 0x06, 0x17):
            for version in (4, 6):
                self.assertEqual(self.query(model, version, 'tcp', flags=flags), 'drop')
                self.assertEqual(self.query(model, version, 'udp', flags=flags), 'accept')
        self.assertEqual(self.query(model, transport='tcp', state='established', flags=0x10), 'accept')

    def test_scoped_dns_replies_precede_lan_isolation_but_original_lan_egress_remains_dropped(self):
        model = self.model(); text = self.record()['policy']
        for version in (4, 6):
            peer = '192.168.50.20' if version == 4 else 'fd50::20'
            for transport in ('udp', 'tcp'):
                self.assertEqual(self.reply(model, version, transport, daddr=peer), 'accept')
                self.assertEqual(self.reply(model, version, transport, daddr=peer, direction='original'), 'drop')
                self.assertEqual(self.query(model, version, transport, saddr=peer), 'accept')
        for line in M.rules(self.record()['bindings'])[1]:
            self.assertLess(text.index(line), text.index('        ip daddr @blocked4 counter drop'))
        for port in (25, 22, 445, 9101):
            self.assertEqual(model.verdict('output', oifname='eth0', daddr='192.168.50.20', dport=port), 'drop')

    def test_no_general_dns_resolver_mail_port_health_or_blanket_established_exception(self):
        model = self.model()
        for transport in ('tcp', 'udp'):
            for port in (25, 53, 110, 465, 587, 993, 995, 4190, 9101, 9102, 5432):
                self.assertEqual(model.verdict('output', protocol=transport, dport=port, oifname='eth0',
                    saddr='192.168.50.100', daddr='15.16.17.18', original_port=port), 'drop')
                if port != 53:
                    self.assertEqual(self.query(model, transport=transport, dport=port, original_port=port), 'drop')
        self.assertEqual(self.query(model, transport='gre'), 'drop')
        self.assertEqual(model.verdict('forward', iifname='eth0', dport=53, state='established'), 'drop')

    def test_existing_selected_resolver_ntp_web_and_neighbor_qualified_ssh_model_paths_remain(self):
        original = PacketModel(M.POLICY.compile_policy(self.raw)); current = self.model()
        cases = [('input', {'saddr':'192.168.50.20','dport':22,'original_port':22}),
            ('input', {'saddr':'192.168.50.20','dport':22,'original_port':22,'mac':'02:00:00:00:00:21'}),
            ('output', {'daddr':'192.168.50.1','dport':53,'original_port':53,'protocol':'udp'}),
            ('input', {'saddr':'192.168.50.1','sport':53,'original_port':53,'direction':'reply','state':'established','protocol':'udp'}),
            ('output', {'daddr':'192.168.50.3','dport':123,'original_port':123,'protocol':'udp'}),
            ('input', {'dport':443}), ('output', {'dport':80}), ('input', {'dport':443,'flags':0x10})]
        for chain, changes in cases:
            changes.update(iifname='eth0',oifname='eth0')
            with self.subTest(chain=chain, changes=changes):
                self.assertEqual(current.verdict(chain, **changes), original.verdict(chain, **changes))

    def test_one_configured_family_never_adds_the_other_server_family(self):
        value = copy.deepcopy(self.settings); value['listeners'] = value['listeners'][:1]
        record = json.loads(self.compile(dns=encoded(value))); model = PacketModel(record['policy'])
        self.assertEqual(len(record['bindings']), 1)
        self.assertEqual(self.query(model,4), 'accept'); self.assertEqual(self.query(model,6), 'drop')
        self.assertEqual(self.reply(model,6), 'drop')

    def test_every_complete_kernel_query_inventory_and_normalizer_refusal_is_required(self):
        for name in M.KERNEL.COMMANDS:
            value = copy.deepcopy(self.kernel); del value['snapshot'][name]
            with self.subTest(name=name), self.assertRaises(ValueError): self.compile(kernel=encoded(value))
        for change in ('proxy','route','rule','linkmac','loopback'):
            value = copy.deepcopy(self.kernel)
            if change=='proxy':value['snapshot']['proxy4']=[{'dst':'192.168.50.7'}]
            elif change=='route':value['snapshot']['routes4'][0]['gateway']='192.168.70.1'
            elif change=='rule':value['snapshot']['rules4'][1]['src']='192.168.50.0/24'
            elif change=='linkmac':value['snapshot']['addresses'][1]['address']='02:00:00:00:00:11'
            else:value['snapshot']['links']=value['snapshot']['links'][1:]
            with self.subTest(change=change), self.assertRaises(ValueError): self.compile(kernel=encoded(value))

    def test_complete_topology_kernel_agreement_cannot_be_replaced_by_matching_listen_prefix_only(self):
        for field in ('name','kind','prefixes','gateways','neighbors'):
            value = copy.deepcopy(self.topology)
            if field=='name':value['interfaces'][0][field]='eth1'
            elif field=='kind':value['interfaces'][0][field]='loopback'
            else:value['interfaces'][0][field]=[]
            with self.subTest(field=field), self.assertRaises(ValueError): self.compile(raw=encoded(value))
        value = copy.deepcopy(self.topology); value['interfaces'] = []
        with self.assertRaises(ValueError): self.compile(raw=encoded(value))

    def test_prefix_containment_neighbor_or_gateway_is_not_an_own_assignment(self):
        for address in ('192.168.50.20','192.168.50.1','192.168.50.101','fd50::20','fd50::101'):
            value = copy.deepcopy(self.settings);value['listeners']=[{'address':address,'health_port':9101}]
            with self.subTest(address=address), self.assertRaises(ValueError): self.compile(dns=encoded(value))

    def test_duplicate_same_or_other_interface_assignments_refuse_even_when_normalized_prefixes_match(self):
        value = copy.deepcopy(self.kernel); value['snapshot']['addresses'][1]['addr_info'].append(
            copy.deepcopy(value['snapshot']['addresses'][1]['addr_info'][0]))
        with self.assertRaises(ValueError): self.compile(kernel=encoded(value))
        value = copy.deepcopy(self.kernel); link=copy.deepcopy(value['snapshot']['links'][1]);link.update(ifindex=3,ifname='eth1')
        value['snapshot']['links'].append(link)
        row=copy.deepcopy(value['snapshot']['addresses'][1]);row.update(ifindex=3,ifname='eth1');value['snapshot']['addresses'].append(row)
        topology=json.loads(policy_input(M.KERNEL.normalize(value['snapshot'])))
        with self.assertRaises(ValueError): self.compile(raw=encoded(topology), kernel=encoded(value))

    def test_active_carrier_and_global_scope_required_before_rule_construction(self):
        for scope in (None,'link','host',0,True):
            value=copy.deepcopy(self.kernel);value['snapshot']['addresses'][1]['addr_info'][0]['scope']=scope
            with patch.object(M,'rules') as rules, self.subTest(scope=scope), self.assertRaises(ValueError):
                self.compile(kernel=encoded(value))
            rules.assert_not_called()
        value=copy.deepcopy(self.kernel)
        for row in (value['snapshot']['links'][1],value['snapshot']['addresses'][1]):row['flags'].remove('LOWER_UP')
        topology=json.loads(policy_input(M.KERNEL.normalize(value['snapshot'])))
        with self.assertRaises(ValueError): self.compile(raw=encoded(topology), kernel=encoded(value))

    def test_only_positively_infinite_static_preferred_and_valid_lifetimes_are_supported(self):
        for field in ('valid_life_time','preferred_life_time'):
            for bad in (None,0,3600,True,4294967295.0,'4294967295','infinite'):
                value=copy.deepcopy(self.kernel);value['snapshot']['addresses'][1]['addr_info'][0][field]=bad
                with self.subTest(field=field,bad=bad), self.assertRaises(ValueError): self.compile(kernel=encoded(value))
        value=copy.deepcopy(self.kernel)
        for row in value['snapshot']['addresses'][1]['addr_info']:
            if row['local'] in ('192.168.50.100','fd50::100'):row.update(valid_life_time=0xffffffff,preferred_life_time=0xffffffff)
        self.assertEqual(json.loads(self.compile(kernel=encoded(value)))['policy'], self.record()['policy'])

    def test_unusable_dynamic_flags_and_nonboolean_flags_refuse_before_original_compilation(self):
        for field in M.ADDRESS_FLAGS:
            for bad in ((True,1,'false',None) if field in M.UNSAFE_FLAGS else (1,'true',None)):
                value=copy.deepcopy(self.kernel);value['snapshot']['addresses'][1]['addr_info'][0][field]=bad
                with patch.object(M.POLICY,'compile_policy') as compiler, self.subTest(field=field,bad=bad), self.assertRaises(ValueError): self.compile(kernel=encoded(value))
                compiler.assert_not_called()
        value=copy.deepcopy(self.kernel);value['snapshot']['addresses'][1]['addr_info'][0]['noprefixroute']=True
        self.assertEqual(json.loads(self.compile(kernel=encoded(value)))['policy'],self.record()['policy'])

    def test_reported_network_broadcast_or_router_overlap_refuses(self):
        for address in ('192.168.50.0','192.168.50.255','192.168.50.1'):
            value=copy.deepcopy(self.kernel);value['snapshot']['addresses'][1]['addr_info'][0]['local']=address
            topology=json.loads(policy_input(M.KERNEL.normalize(value['snapshot'])))
            dns=copy.deepcopy(self.settings);dns['listeners'][0]['address']=address
            with self.subTest(address=address), self.assertRaises(ValueError): self.compile(raw=encoded(topology),dns=encoded(dns),kernel=encoded(value))

    def test_explicit_dns_settings_and_raw_canonical_bytes_use_real_provider_predicates(self):
        for field in self.settings:
            value=copy.deepcopy(self.settings);del value[field]
            with self.subTest(field=field), self.assertRaises(ValueError): self.compile(dns=encoded(value))
        for field,value in (('health_port',True),('address','0.0.0.0')):
            dns=copy.deepcopy(self.settings);dns['listeners'][0][field]=value
            with self.assertRaises(ValueError): self.compile(dns=encoded(dns))
        with self.assertRaises(ValueError): self.compile(dns=json.dumps(self.settings).encode())
        with self.assertRaises(ValueError): self.compile(dns=encoded(self.settings)+b'\n')

    def test_true_positive_kernel_context_closed_frame_and_schema_are_required(self):
        for context in (0,True,1.0,2**64,None):
            value=copy.deepcopy(self.kernel);value['namespace']=context
            with self.subTest(context=context), self.assertRaises(ValueError): self.compile(kernel=encoded(value))
        for schema in (True,2,'1'):
            value=copy.deepcopy(self.kernel);value['schema']=schema
            with self.assertRaises(ValueError): self.compile(kernel=encoded(value))
        value=copy.deepcopy(self.kernel);value['healthy']=True
        with self.assertRaises(ValueError): self.compile(kernel=encoded(value))

    def test_raw_type_size_depth_integer_duplicate_encoding_and_float_bounds_precede_work(self):
        for bad in (bytearray(b'{}'), '{}', b'\xff', b' '* (M.MAX_KERNEL+1),
            b'{"schema":1,"schema":1}', b'{"schema":NaN}', b'{"schema":1e999}',
            b'{"x":18446744073709551616}', b'{"x":"\\u0000"}', b'['*1500+b'0'+b']'*1500):
            with patch.object(M.KERNEL,'normalize') as normalize, self.subTest(bad=type(bad)), self.assertRaises(ValueError): self.compile(kernel=bad)
            normalize.assert_not_called()
        for field, bad in (('raw',b' '* (M.POLICY.MAX_INPUT+1)),('dns',b' '* (M.DNS.MAX_INPUT+1))):
            with self.assertRaises(ValueError): self.compile(**{field:bad})

    def test_no_native_observer_namespace_file_manager_transport_or_submission_entry(self):
        with patch.object(M.KERNEL,'native_query',side_effect=AssertionError('no native')), patch.object(M.KERNEL,'namespace',side_effect=AssertionError('no current scope')), patch.object(M.DNS.BASE,'read_protected',side_effect=AssertionError('no disk')), patch.object(M.KERNEL.subprocess,'Popen',side_effect=AssertionError('no entry')):
            result=json.loads(self.compile())
        self.assertEqual(result['state'],'dns-firewall-source-intention-only')
        self.assertFalse(hasattr(M,'main'))

    def test_original_compiler_frame_chains_isolation_anchor_and_output_bounds_fail_closed(self):
        original=M.POLICY.compile_policy(self.raw)
        for text in (original.replace('destroy table','flush table',1),original.replace('    chain forward {','    chain input {',1),
            original.replace('        ip daddr @blocked4 counter drop\n',''),original[:-1]):
            with patch.object(M.POLICY,'compile_policy',return_value=text), self.assertRaises(ValueError): self.compile()
        with patch.object(M,'MAX_OUTPUT',1), self.assertRaises(ValueError): self.compile()

    def test_received_inputs_are_not_rewritten_and_no_source_hash_shortcut_is_adopted(self):
        before=copy.deepcopy((self.topology,self.settings,self.kernel));self.compile()
        self.assertEqual(before,(self.topology,self.settings,self.kernel))
        value=copy.deepcopy(self.kernel);value['snapshot']['addresses'][1]['addr_info'][0]['scope']='host'
        with self.assertRaises(ValueError):self.compile(kernel=encoded(value))

    def test_old_complete_manifest_refuses_expanded_dns_source_without_any_native_query(self):
        spec=importlib.util.spec_from_file_location('private_old_dns_manifest',ROOT/'Firewall/nft_manifest.py')
        manifest=importlib.util.module_from_spec(spec);spec.loader.exec_module(manifest)
        original=manifest.expected(self.raw)['policy']
        with patch.object(manifest.POLICY,'compile_policy',return_value=self.record()['policy']):
            expanded=manifest.expected(self.raw)['policy']
        self.assertEqual(original['sets'],expanded['sets'])
        self.assertNotEqual(original,expanded)
        objects=[{'metainfo':{'version':'1.1.3','release_name':'private intention-derived MODEL','json_schema_version':1}}]
        handle=1
        for kind, rows in (('table',[expanded['table']]),('chain',expanded['chains'].values()),
            ('set',expanded['sets'].values()),('rule',[r for rules in expanded['rules'].values() for r in rules])):
            for row in rows:
                row=copy.deepcopy(row);row['handle']=handle;handle+=1
                if kind=='rule':row['expr'][-2]={'counter':{'packets':0,'bytes':0}}
                objects.append({kind:row})
        calls=[]
        def delivery(deadline): calls.append('source'); return copy.deepcopy({'nftables':objects})
        with patch.object(manifest.STATE.NFT,'native_query',side_effect=AssertionError('no native')):
            with self.assertRaisesRegex(manifest.Pending,'does not match compiler intention'):
                manifest.verify(self.raw,query=delivery,scope=lambda:123456)
        self.assertEqual(calls,['source','source'])


if __name__ == '__main__': unittest.main()
