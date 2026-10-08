import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_dhcp import xml
from test_dhcp_servers import document, inventory, kernel_data, encoded
from test_timesync import packet
from test_policy import PacketModel
from test_classifiers import options as fq_options

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_assemble', ROOT / 'Firewall/assemble.py')
ASSEMBLY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSEMBLY)
SERVERS, DHCP, TIME, DNS, KERNEL, POLICY = ASSEMBLY.SERVERS, ASSEMBLY.DHCP, ASSEMBLY.TIMESYNC, ASSEMBLY.RESOLVER, ASSEMBLY.KERNEL, ASSEMBLY.POLICY
NFT = ASSEMBLY.NFT
LEGACY = ASSEMBLY.LEGACY
CLASSIFIERS = ASSEMBLY.CLASSIFIERS


def nft_receipt(namespace):
    return {'schema': 'debian13s4-nft-empty-1', 'namespace': namespace, 'empty': True,
            'source': {'binary': str(NFT.BINARY), 'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}}


def legacy_receipt(namespace):
    return {'schema': 'debian13s4-legacy-ip-ip6-arp-empty-1', 'namespace': namespace, 'empty': True,
            'source': {'path': str(LEGACY.PROC / str(os.getpid()) / 'net'),
                       'identity': [1, 1, 0o40555, LEGACY.TRUSTED_UID, 0, 0, 0, 0],
                       'files': {name: {'identity': [1, index + 2, 0o100440, LEGACY.TRUSTED_UID, 0, 0, 0, 0],
                                        'bytes': 0, 'sha256': LEGACY.EMPTY_HASH}
                                 for index, name in enumerate(LEGACY.FILES)}}}


def classifier_receipt(kernel, kind='noqueue'):
    rows = [dict(kernel_data()['links'][0], qdisc='noqueue')]
    for link in kernel['interfaces']:
        row = {'ifname': link['name'], 'ifindex': link['index'], 'address': link['mac'],
               'flags': list(link['flags']), 'link_type': '[1]', 'qdisc': kind}
        if link['vlan'] is not None:
            row.update(link_index=link['parent'], linkinfo={'info_kind': 'vlan', 'info_data': copy.deepcopy(link['vlan'])})
        rows.append(row)
    qdiscs = [{'kind': row['qdisc'], 'handle': '0:', 'dev': row['ifname'], 'root': True,
               'options': fq_options() if row['qdisc']=='fq_codel' else {}} for row in rows]
    return {'schema': 'debian13s4-tc-fq-codel-classifiers-1', 'profile': 'all-links-noqueue-or-fq-codel-roots-empty-filters-1',
            'namespace': kernel['namespace'], 'source': {'tc': str(CLASSIFIERS.BINARY), 'ip': str(CLASSIFIERS.KERNEL.IP_BINARY)},
            'links': rows, 'qdiscs': qdiscs, 'fq_codel_filters': {row['dev']: [] for row in qdiscs if row['kind']=='fq_codel'}}


def records():
    kernel = SERVERS.assigned_topology(KERNEL.now() + 30, query=lambda name, deadline: copy.deepcopy(kernel_data()[name]))
    clients = inventory(families=(4,))['interfaces']
    attribution = SERVERS.descriptions(encoded(document(infinite=True)), clients[0], kernel)
    common = {key: kernel[key] for key in ('schema', 'namespace', 'interfaces')}
    return {'dhcp4': {'schema': 'debian13s4-networkd-dhcp4-servers-1', 'kernel': kernel,
                     'source': {'service': DHCP.SERVICE, 'owner': ':1.88', 'pid': os.getpid()},
                     'interfaces': clients, 'attributions': attribution, 'dhcp4': [{'interface': 'eth0', 'address': '192.168.50.1'}]},
            'dns': {'schema': 'debian13s4-resolver-1', 'kernel': common | {'scope_names': {'lo': 1, 'eth0': 2}},
                    'source': {'path': '/etc/resolv.conf', 'sha256': hashlib.sha256(b'nameserver 192.168.50.1\n').hexdigest()},
                    'dns': [{'interface': 'eth0', 'address': '192.168.50.1'}]},
            'ntp': {'schema': 'debian13s4-timesync-1', 'kernel': common,
                    'source': {'service': TIME.SERVICE, 'owner': ':1.77', 'pid': os.getpid(), 'name': 'time.example.test'},
                    'ntp': [{'interface': 'eth0', 'address': '192.168.50.3'}]}}


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.records = records()
        self.namespace = self.records['dhcp4']['kernel']['namespace']

    def observe(self, **overrides):
        settings = {name: (lambda deadline, key=key: copy.deepcopy(self.records[key])) for name, key in (('dhcp', 'dhcp4'), ('dns', 'dns'), ('ntp', 'ntp'))}
        settings['nft'] = lambda deadline: nft_receipt(self.namespace)
        settings['legacy'] = lambda deadline: legacy_receipt(self.namespace)
        settings['classifiers'] = lambda deadline: classifier_receipt(self.records['dhcp4'].get('kernel') or records()['dhcp4']['kernel'])
        settings.update(overrides)
        return ASSEMBLY.observe(**settings)

    def test_two_complete_rounds_share_one_deadline_and_feed_the_real_compiler(self):
        calls = []
        def reader(name):
            def read(deadline):
                calls.append((name, deadline))
                return self.records[name]
            return read
        result = self.observe(dhcp=reader('dhcp4'), dns=reader('dns'), ntp=reader('ntp'))
        self.assertEqual([name for name, _ in calls], ['dhcp4', 'dns', 'ntp'] * 2)
        self.assertEqual(len({deadline for _, deadline in calls}), 1)
        self.assertEqual(result['schema'], 'debian13s4-assembled-policy-1')
        self.assertEqual(result['topology']['dhcp6'], [])
        self.assertEqual(result['policy'], POLICY.compile_policy(json.dumps(result['topology']).encode()))
        self.assertIn('"eth0" . 192.168.50.20 . 02:00:00:00:00:20', result['policy'])
        self.assertNotIn('"eth0" . 192.168.50.1 . 02:00:00:00:00:01', result['policy'])

    def test_invalid_inherited_deadline_refuses_before_any_observer(self):
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(ASSEMBLY.Pending):
                self.observe(deadline=deadline, dhcp=lambda **kw: self.fail('unexpected reader'))

    def test_inherited_window_never_widens_and_expiration_prevents_later_admission(self):
        start = KERNEL.now()
        for budget in (10, 1000):
            seen = []
            with self.subTest(budget=budget), patch.object(KERNEL, 'now', return_value=start):
                self.observe(deadline=start + budget, dhcp=lambda deadline: seen.append(deadline) or self.records['dhcp4'])
            self.assertEqual(seen, [start + min(budget, ASSEMBLY.ATTEMPT_SECONDS)] * 2)
        with patch.object(ASSEMBLY, 'ATTEMPT_SECONDS', 0), self.assertRaises(ASSEMBLY.Pending):
            self.observe(dhcp=lambda **kw: self.fail('unexpected expired admission'))

    def test_all_instantiated_dhcp6_states_refuse_before_dns_or_compile(self):
        for state in DHCP.STATES[6]:
            self.records['dhcp4']['interfaces'][0].update(dhcp6=True, state6=state)
            with self.subTest(state=state), self.assertRaisesRegex(ASSEMBLY.Pending, 'DHCPv6 reply'):
                self.observe(dns=lambda **kw: self.fail('unsupported profile advanced'), compiler=lambda raw: self.fail('unexpected compile'))

    def test_independently_valid_different_namespace_interface_index_mac_or_prefix_cannot_combine(self):
        for field, changed in (('index', 3), ('mac', '02:00:00:00:00:11'), ('prefixes', ['192.168.60.0/24'])):
            self.records = records()
            self.records['dns']['kernel']['interfaces'] = copy.deepcopy(self.records['dns']['kernel']['interfaces'])
            self.records['dns']['kernel']['interfaces'][0][field] = changed
            with self.subTest(field=field), self.assertRaises(ASSEMBLY.Pending):
                self.observe()
        self.records = records()
        self.records['ntp']['kernel']['namespace'] += 1
        with self.assertRaises(ASSEMBLY.Pending):
            self.observe()

    def test_second_complete_round_source_owner_peer_state_or_endpoint_change_is_pending(self):
        for service, field, changed in (('dns', 'sha256', 'a' * 64), ('ntp', 'owner', ':1.78'), ('ntp', 'name', 'other.test'), ('dhcp4', 'owner', ':1.89')):
            count = 0
            def read(deadline):
                nonlocal count
                count += 1
                value = copy.deepcopy(self.records[service])
                if count == 2:
                    value['source'][field] = changed
                return value
            name = 'dhcp' if service == 'dhcp4' else service
            with self.subTest(service=service, field=field), self.assertRaises(ASSEMBLY.Pending):
                self.observe(**{name: read})
        count = 0
        def dns(deadline):
            nonlocal count
            count += 1
            value = copy.deepcopy(self.records['dns'])
            if count == 2:value['dns'][0]['address'] = '192.168.50.2'
            return value
        with self.assertRaises(ASSEMBLY.Pending):self.observe(dns=dns)

    def test_reader_reusing_and_mutating_an_object_cannot_rewrite_the_first_round(self):
        value = copy.deepcopy(self.records['dns']);count = 0
        def dns(deadline):
            nonlocal count
            count += 1
            if count == 2:value['source']['sha256'] = 'a' * 64
            return value
        with self.assertRaises(ASSEMBLY.Pending):self.observe(dns=dns)

    def test_missing_unknown_schema_malformed_client_or_empty_infrastructure_refuse(self):
        for service in self.records:
            original = records()
            for mutation in ('schema', 'extra', 'missing'):
                self.records = copy.deepcopy(original)
                record = self.records[service]
                if mutation == 'schema':record['schema'] = 'unknown'
                elif mutation == 'extra':record['extra'] = True
                else:del record['kernel']
                with self.subTest(service=service, mutation=mutation), self.assertRaises(ASSEMBLY.Pending):self.observe()
        for service in ('dns', 'ntp'):
            self.records = records();self.records[service][service] = []
            with self.subTest(service=service), self.assertRaises(ASSEMBLY.Pending):self.observe()
        for field, bad in (('dhcp4', 1), ('dhcp6', None), ('state4', []), ('state6', 'bound'), ('path', '/wrong'), ('administrative', 'unmanaged')):
            self.records = records();self.records['dhcp4']['interfaces'][0][field] = bad
            with self.subTest(field=field), self.assertRaises(ASSEMBLY.Pending):self.observe()

    def test_live_client_endpoint_attribution_and_exact_assignment_are_required(self):
        for mutation in ('missing-attribution', 'missing-endpoint', 'missing-assignment', 'wrong-mask', 'unusable', 'duplicate-assignment', 'non-live'):
            self.records = records();dhcp = self.records['dhcp4']
            if mutation == 'missing-attribution':dhcp['attributions'] = []
            elif mutation == 'missing-endpoint':dhcp['dhcp4'] = []
            elif mutation == 'missing-assignment':dhcp['kernel']['assigned4'] = []
            elif mutation == 'wrong-mask':dhcp['kernel']['assigned4'][0]['prefixlen'] = 25
            elif mutation == 'unusable':dhcp['kernel']['assigned4'][0]['usable'] = False
            elif mutation == 'duplicate-assignment':dhcp['kernel']['assigned4'].append(copy.deepcopy(dhcp['kernel']['assigned4'][0]))
            else:dhcp['interfaces'][0]['state4'] = 'selecting'
            with self.subTest(mutation=mutation), self.assertRaises(ASSEMBLY.Pending):self.observe()
        self.records = records();self.records['dhcp4']['attributions'] = [];self.records['dhcp4']['dhcp4'] = []
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'complete server'):self.observe()

    def test_static_and_bootstrap_dhcp4_state_need_no_unicast_server_guess(self):
        for state in (None, 'stopped', 'selecting', 'requesting'):
            self.records = records();client = self.records['dhcp4']['interfaces'][0]
            client.update(dhcp4=state is not None, state4=state)
            self.records['dhcp4']['dhcp4'] = [];self.records['dhcp4']['attributions'] = []
            with self.subTest(state=state):
                result = self.observe()
                self.assertEqual(result['topology']['dhcp4'], [])
                self.assertEqual(result['topology']['interfaces'][0]['dhcp4'], state is not None)

    def test_expiry_during_other_observers_or_compiler_cannot_publish(self):
        start = KERNEL.now();until = int((start + 5) * 1000000)
        for name in ('preferred_until', 'valid_until'):self.records['dhcp4']['attributions'][0][name] = until
        clock = [start]
        def compiler(raw):
            text = POLICY.compile_policy(raw);clock[0] = start + 6;return text
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaisesRegex(ASSEMBLY.Pending, 'attribution expired'):
            self.observe(compiler=compiler)
        self.records = records()
        def compiler(raw):
            text = POLICY.compile_policy(raw);clock[0] = start + 61;return text
        clock[0] = start
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaisesRegex(ASSEMBLY.Pending, 'expired before publication'):
            self.observe(compiler=compiler)

    def test_final_namespace_change_or_native_observer_failure_cannot_publish(self):
        with patch.object(KERNEL, 'namespace', return_value=KERNEL.namespace() + 1), self.assertRaises(ASSEMBLY.Pending):self.observe()
        for name in ('dhcp', 'dns', 'ntp'):
            def failure(**kw):raise OSError('fixture failed delivery')
            with self.subTest(name=name), self.assertRaises(OSError):self.observe(**{name: failure}, compiler=lambda raw: self.fail('compiled failed observation'))

    def test_down_static_interfaces_keep_blocked_prefixes_without_cached_ssh_admission(self):
        extra = copy.deepcopy(self.records['dhcp4']['kernel']['interfaces'][0])
        extra.update(name='eth1', index=3, up=False, flags=['BROADCAST', 'MULTICAST'])
        for service in self.records:
            self.records[service]['kernel']['interfaces'] = copy.deepcopy(self.records[service]['kernel']['interfaces']) + [copy.deepcopy(extra)]
        client = copy.deepcopy(self.records['dhcp4']['interfaces'][0])
        client.update(name='eth1', index=3, path=DHCP.link_path(3), dhcp4=False, state4=None)
        self.records['dhcp4']['interfaces'].append(client)
        result = self.observe()
        self.assertEqual(result['topology']['interfaces'][1]['neighbors'], [])
        self.assertEqual(result['topology']['interfaces'][1]['prefixes'], extra['prefixes'])
        self.assertNotIn('"eth1" . 192.168.50.20 .', result['policy'])
        self.records['dns']['dns'][0]['interface'] = 'eth1'
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'active common'):self.observe()

    def test_real_compiler_rejects_invalid_endpoints_masks_and_aggregate_limits(self):
        for service in ('dns', 'ntp'):
            self.records = records();self.records[service][service][0]['address'] = '::ffff:192.168.50.1'
            with self.subTest(service=service), self.assertRaises(POLICY.InvalidTopology):self.observe()
        self.records = records()
        with patch.object(POLICY, 'MAX_INPUT', 1), self.assertRaises(POLICY.InvalidTopology):self.observe()

    def test_snapshot_encoding_structure_bounds_and_private_copy_are_positive(self):
        for value in ({'bad': 1.0}, {'bad': float('nan')}, {'bad': '\ud800'}, {'bad': b'bytes'}, {1: 'nonstring'}, {'bad': '\x00'}):
            with self.subTest(value=repr(value)), self.assertRaises(ASSEMBLY.Pending):ASSEMBLY.snapshot(value)
        with patch.object(ASSEMBLY, 'MAX_NODES', 1), self.assertRaises(ASSEMBLY.Pending):ASSEMBLY.snapshot({'a': ['b']})
        value = {};current = value
        for _ in range(18):current['next'] = {};current = current['next']
        with self.assertRaises(ASSEMBLY.Pending):ASSEMBLY.snapshot(value)
        value = {'a': ['b']};copied = ASSEMBLY.snapshot(value);value['a'].append('c')
        self.assertEqual(copied, {'a': ['b']})

    def test_final_compiler_output_type_and_byte_bound_are_checked(self):
        for text in (None, '', b'nft', 'x' * (POLICY.MAX_OUTPUT + 1)):
            with self.subTest(type=type(text).__name__), self.assertRaises(ASSEMBLY.Pending):self.observe(compiler=lambda raw: text)

    def test_nft_refusal_or_invalid_receipt_prevents_infrastructure_and_compiler_admission(self):
        def failure(deadline):raise NFT.Pending('existing nft objects')
        with self.assertRaises(NFT.Pending):
            self.observe(nft=failure, dhcp=lambda **kw: self.fail('unadmitted infrastructure'), compiler=lambda raw: self.fail('unadmitted compiler'))
        for empty in (False, 1, None, 'true'):
            receipt = nft_receipt(self.records['dhcp4']['kernel']['namespace']);receipt['empty'] = empty
            with self.subTest(empty=empty), self.assertRaises(ValueError):self.observe(nft=lambda deadline: receipt, dhcp=lambda **kw: self.fail('unverified receipt admitted'))

    def test_nft_and_infrastructure_namespace_mismatch_refuses_before_dns(self):
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'nft and infrastructure'):
            self.observe(nft=lambda deadline: nft_receipt(self.records['dhcp4']['kernel']['namespace'] + 1), dns=lambda **kw: self.fail('foreign namespace advanced'))

    def test_nft_source_changes_in_second_round_or_after_compile_cannot_publish(self):
        for turn in (2, 3):
            calls = []
            def read(deadline):
                calls.append(deadline);result = nft_receipt(self.records['dhcp4']['kernel']['namespace'])
                if len(calls)==turn:result['source']['version'] = '1.1.4'
                return result
            with self.subTest(turn=turn), self.assertRaises(ASSEMBLY.Pending):self.observe(nft=read)

    def test_nft_rounds_and_final_barrier_share_the_existing_inherited_window(self):
        seen = [];deadline = KERNEL.now() + 20
        def read(deadline):seen.append(deadline);return nft_receipt(self.namespace)
        result = self.observe(nft=read, deadline=deadline)
        self.assertEqual(seen, [deadline] * 3)
        self.assertEqual(result['sources']['nft']['binary'], str(NFT.BINARY))

    def test_legacy_refusal_or_unverifiable_receipt_prevents_infrastructure_and_compiler(self):
        def failure(deadline):raise FileNotFoundError('missing legacy reporting')
        with self.assertRaises(FileNotFoundError):
            self.observe(legacy=failure, dhcp=lambda **kw:self.fail('unadmitted infrastructure'),
                         compiler=lambda raw:self.fail('unadmitted compile'))
        for empty in (False, 1, None):
            value = legacy_receipt(self.namespace);value['empty'] = empty
            with self.subTest(empty=empty), self.assertRaises(LEGACY.Pending):
                self.observe(legacy=lambda deadline:value, dhcp=lambda **kw:self.fail('unverified receipt admitted'))

    def test_legacy_namespace_mismatch_refuses_before_infrastructure(self):
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'namespaces disagree'):
            self.observe(legacy=lambda deadline:legacy_receipt(self.namespace + 1),
                         dhcp=lambda **kw:self.fail('foreign legacy admission'),
                         compiler=lambda raw:self.fail('foreign legacy compile'))

    def test_legacy_identity_change_in_second_round_or_after_compile_cannot_publish(self):
        for turn in (2, 3):
            calls = []
            def changed(deadline):
                calls.append(deadline);value = legacy_receipt(self.namespace)
                if len(calls) == turn:value['source']['files'][LEGACY.FILES[0]]['identity'][1] += 1
                return value
            with self.subTest(turn=turn), self.assertRaises(ASSEMBLY.Pending):self.observe(legacy=changed)
            self.assertEqual(len(calls), turn)

    def test_legacy_rounds_and_final_barrier_share_one_deadline_and_retain_full_source(self):
        calls = [];deadline = KERNEL.now() + 20
        def read(deadline):calls.append(deadline);return legacy_receipt(self.namespace)
        result = self.observe(legacy=read, deadline=deadline)
        self.assertEqual(calls, [deadline] * 3)
        self.assertEqual(result['sources']['legacy'], legacy_receipt(self.namespace)['source'])
        self.assertEqual(result['profile'], 'nft-legacy-proc-tc-fq-empty-networkd-classic-timesyncd-no-dhcp6-1')

    def test_legacy_snapshot_cannot_be_mutated_by_a_later_infrastructure_callback(self):
        value = legacy_receipt(self.namespace)
        def changed(deadline):
            value['source']['files'][LEGACY.FILES[0]]['identity'][1] += 1
            return self.records['dhcp4']
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'complete infrastructure observations changed'):
            self.observe(legacy=lambda deadline:value, dhcp=changed)

    def test_legacy_deadline_expiry_cannot_admit_infrastructure_or_late_publication(self):
        start = KERNEL.now();clock = [start]
        def expire(deadline):clock[0] = deadline;return legacy_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(ASSEMBLY.Pending):
            self.observe(legacy=expire, dhcp=lambda **kw:self.fail('expired legacy admission'))
        clock[0] = start;calls = []
        def late(deadline):
            calls.append(deadline)
            if len(calls) == 3:clock[0] = deadline
            return legacy_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(ASSEMBLY.Pending):
            self.observe(legacy=late)
        self.assertEqual(len(calls), 3)

    def test_nft_expiry_after_compile_prevents_final_legacy_read(self):
        start = KERNEL.now();clock = [start];nft_calls = [];legacy_calls = []
        def nft(deadline):
            nft_calls.append(deadline)
            if len(nft_calls) == 3:clock[0] = deadline
            return nft_receipt(self.namespace)
        def legacy(deadline):legacy_calls.append(deadline);return legacy_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(ASSEMBLY.Pending):
            self.observe(nft=nft, legacy=legacy)
        self.assertEqual(len(nft_calls), 3);self.assertEqual(len(legacy_calls), 2)


class ClassifierAdmissionTests(unittest.TestCase):
    def setUp(self):AssemblyTests.setUp(self)
    def observe(self, **kwargs):return AssemblyTests.observe(self, **kwargs)

    def test_positive_fq_receipts_share_three_deadlines_and_retain_complete_facts(self):
        calls=[];deadline=KERNEL.now()+20
        def read(deadline):calls.append(deadline);return classifier_receipt(self.records['dhcp4']['kernel'],'fq_codel')
        result=self.observe(classifiers=read,deadline=deadline)
        self.assertEqual(calls,[deadline]*3);self.assertEqual(result['classifiers'],classifier_receipt(self.records['dhcp4']['kernel'],'fq_codel'))
        self.assertEqual(result['profile'],'nft-legacy-proc-tc-fq-empty-networkd-classic-timesyncd-no-dhcp6-1')

    def test_missing_failed_nonempty_and_foreign_receipts_prevent_infrastructure(self):
        def fail(deadline):raise OSError('private tc read failed')
        with self.assertRaises(OSError):self.observe(classifiers=fail,dhcp=lambda **kw:self.fail('unadmitted infrastructure'))
        for mutation in ('missing','filters','source','namespace'):
            value=classifier_receipt(self.records['dhcp4']['kernel'],'fq_codel')
            if mutation=='missing':value['qdiscs'].pop()
            elif mutation=='filters':value['fq_codel_filters']['eth0']=[{'kind':'bpf'}]
            elif mutation=='source':value['source']['tc']='/foreign'
            else:value['namespace']+=1
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.observe(classifiers=lambda deadline:value,dhcp=lambda **kw:self.fail('unverified tc admitted'))

    def test_complete_nonloopback_identity_disagreement_cannot_bind(self):
        for key,bad in (('ifindex',9),('address','02:00:00:00:00:11'),('flags',['BROADCAST']),('ifname','other')):
            value=classifier_receipt(self.records['dhcp4']['kernel']);value['links'][1][key]=bad
            if key=='ifname':value['qdiscs'][1]['dev']=bad
            with self.subTest(key=key),self.assertRaisesRegex(ASSEMBLY.Pending,'interface identities'):
                self.observe(classifiers=lambda deadline:value,compiler=lambda raw:self.fail('foreign link compiled'))

    def test_second_round_or_final_receipt_changes_prevent_publication(self):
        for turn in (2,3):
            calls=[]
            def read(deadline):
                calls.append(deadline);value=classifier_receipt(self.records['dhcp4']['kernel'])
                if len(calls)==turn:value['links'][1]['mtu']=1400
                return value
            with self.subTest(turn=turn),self.assertRaises(ASSEMBLY.Pending):self.observe(classifiers=read)
            self.assertEqual(len(calls),turn)

    def test_later_callback_cannot_mutate_a_copied_classifier_receipt(self):
        value=classifier_receipt(self.records['dhcp4']['kernel'])
        def dhcp(deadline):value['links'][1]['mtu']=1400;return self.records['dhcp4']
        with self.assertRaisesRegex(ASSEMBLY.Pending,'observations changed'):self.observe(classifiers=lambda deadline:value,dhcp=dhcp)

    def test_expired_classifier_delivery_does_not_admit_infrastructure(self):
        start=KERNEL.now();clock=[start]
        def read(deadline):clock[0]=deadline;return classifier_receipt(self.records['dhcp4']['kernel'])
        with patch.object(KERNEL,'now',side_effect=lambda:clock[0]),self.assertRaises(ASSEMBLY.Pending):
            self.observe(classifiers=read,dhcp=lambda **kw:self.fail('expired tc admitted'))

    def test_final_legacy_expiry_prevents_another_classifier_read(self):
        start=KERNEL.now();clock=[start];tc_calls=[];legacy_calls=[]
        def tc(deadline):tc_calls.append(deadline);return classifier_receipt(self.records['dhcp4']['kernel'])
        def legacy(deadline):
            legacy_calls.append(deadline)
            if len(legacy_calls)==3:clock[0]=deadline
            return legacy_receipt(self.namespace)
        with patch.object(KERNEL,'now',side_effect=lambda:clock[0]),self.assertRaises(ASSEMBLY.Pending):self.observe(classifiers=tc,legacy=legacy)
        self.assertEqual(len(tc_calls),2);self.assertEqual(len(legacy_calls),3)

    def test_final_classifier_expiry_or_postcompile_damage_withholds_cli_text(self):
        real=ASSEMBLY.observe;start=KERNEL.now();clock=[start];calls=[]
        def tc(deadline):
            calls.append(deadline);value=classifier_receipt(self.records['dhcp4']['kernel'])
            if len(calls)==3:clock[0]=deadline
            return value
        with patch.object(KERNEL,'now',side_effect=lambda:clock[0]),self.assertRaises(ASSEMBLY.Pending):self.observe(classifiers=tc)
        out,err=io.StringIO(),io.StringIO();value=classifier_receipt(self.records['dhcp4']['kernel'],'fq_codel')
        def compile(raw):
            text=POLICY.compile_policy(raw);value['fq_codel_filters']['eth0']=[{'kind':'bpf'}];return text
        settings={'dhcp':lambda deadline:self.records['dhcp4'],'dns':lambda deadline:self.records['dns'],
                  'ntp':lambda deadline:self.records['ntp'],'nft':lambda deadline:nft_receipt(self.namespace),
                  'legacy':lambda deadline:legacy_receipt(self.namespace),'classifiers':lambda deadline:value,'compiler':compile}
        with patch.object(ASSEMBLY,'observe',side_effect=lambda:real(**settings)),patch.object(ASSEMBLY.sys,'argv',['assemble.py']),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):status=ASSEMBLY.main()
        self.assertEqual(status,75);self.assertEqual(out.getvalue(),'');self.assertIn('pending',err.getvalue())


class CLITests(unittest.TestCase):
    def test_arguments_and_refusal_do_not_emit_a_partial_policy(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py', 'extra']), contextlib.redirect_stdout(out):self.assertEqual(ASSEMBLY.main(), 64)
        self.assertEqual(out.getvalue(), '')
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), patch.object(ASSEMBLY, 'observe', side_effect=ASSEMBLY.Pending('fixture')), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(ASSEMBLY.main(), 75)
        self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())

    def test_success_emits_only_checked_compiler_text_and_write_errors_fail(self):
        out = io.StringIO()
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), patch.object(ASSEMBLY, 'observe', return_value={'policy': 'fixture\n'}), contextlib.redirect_stdout(out):self.assertEqual(ASSEMBLY.main(), 0)
        self.assertEqual(out.getvalue(), 'fixture\n')
        class FailedOutput:
            def write(self, value):raise OSError('fixture write')
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), patch.object(ASSEMBLY, 'observe', return_value={'policy': 'fixture\n'}), patch.object(ASSEMBLY.sys, 'stdout', FailedOutput()), contextlib.redirect_stderr(io.StringIO()):self.assertEqual(ASSEMBLY.main(), 75)


class PrivateNative(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-assembly-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.bus, self.ip, self.ledger = self.root / 'busctl', self.root / 'ip', self.root / 'ledger'
        self.nft = self.root / 'nft'
        self.tc = self.root / 'tc'
        self.proc = self.root / 'proc'
        self.legacy_net = self.proc / str(os.getpid()) / 'net'
        self.legacy_net.mkdir(parents=True)
        for path in (self.proc, self.legacy_net.parent, self.legacy_net):path.chmod(0o700)
        for name in LEGACY.FILES:
            path = self.legacy_net / name;path.write_bytes(b'');path.chmod(0o440)
        self.source = self.root / 'resolv.conf'
        self.settings = [patch.object(DHCP, 'BUS_BINARY', self.bus), patch.object(TIME, 'BUS_BINARY', self.bus),
                         patch.object(KERNEL, 'IP_BINARY', self.ip), patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid()),
                         patch.object(DNS, 'RESOLV_CONF', self.source), patch.object(DNS, 'TRUST_ROOT', self.root), patch.object(DNS, 'TRUSTED_UID', os.geteuid())]
        self.settings += [patch.object(NFT, 'BINARY', self.nft), patch.object(NFT.KERNEL, 'TRUST_ROOT', self.root), patch.object(NFT.KERNEL, 'TRUSTED_UID', os.geteuid())]
        self.settings += [patch.object(LEGACY, 'PROC', self.proc), patch.object(LEGACY, 'TRUST_ROOT', self.root),
                          patch.object(LEGACY, 'TRUSTED_UID', os.geteuid()), patch.object(LEGACY, 'filesystem')]
        self.settings += [patch.object(CLASSIFIERS, 'BINARY', self.tc), patch.object(CLASSIFIERS.KERNEL, 'IP_BINARY', self.ip),
                          patch.object(CLASSIFIERS.KERNEL, 'TRUST_ROOT', self.root), patch.object(CLASSIFIERS.KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def executable(self, path, body):
        path.write_text('#!/usr/bin/python3 -B\n' + body + '\n');path.chmod(0o700)

    def fixtures(self, state='bound', families=(4,), change_provider=False, change_time=False, change_dns=False, warning=False, corrupt=False, dns='8.8.8.8', tc_kind='noqueue', tc_filters=None):
        self.source.write_text('nameserver ' + dns + '\n')
        self.source.chmod(0o600)
        node_path, peer_path = self.root / 'description.json', self.root / 'peer.json'
        node = document(infinite=True)
        if corrupt:node['Addresses'][0]['ConfigProvider'] = [0, 0, 0, 0]
        node_path.write_text(json.dumps(node));peer_path.write_text(json.dumps(packet('192.168.50.3')))
        desc_count, peer_count = self.root / 'descriptions', self.root / 'peers'
        for path in (desc_count, peer_count):
            if path.exists():path.unlink()
        self.ledger.write_text('')
        self.executable(self.nft, f"import json,os,sys\nargs=sys.argv[1:]\nwith open({str(self.ledger)!r},'a') as log:log.write(json.dumps(['nft',args,dict(os.environ)])+'\\n')\nif args!={list(NFT.COMMAND)!r}:raise SystemExit(1)\nprint({json.dumps({'nftables': [{'metainfo': {'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}}]})!r})")
        self.executable(self.bus, f"""import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['bus',args,dict(os.environ)])+'\\n')
if args[:8]!=['--system','--no-pager','--json=short','--auto-start=no','--allow-interactive-authorization=no','--expect-reply=yes','--timeout=3s','call']: raise SystemExit(1)
a=args[8:]
namespace=int(os.readlink('/proc/self/ns/net')[5:-1])
if a=={[*DHCP.BUS,'GetNameOwner','s',DHCP.SERVICE]!r}: result={{'type':'s','data':[':1.88']}}
elif a=={[*TIME.BUS,'GetNameOwner','s',TIME.SERVICE]!r}: result={{'type':'s','data':[':1.77']}}
elif len(a)==6 and a[:4]=={[*DHCP.BUS,'GetConnectionUnixProcessID']!r} and a[4]=='s' and a[5] in (':1.88',':1.77'): result={{'type':'u','data':[os.getppid()]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.MANAGER,'ListLinks']!r}: result={{'type':'a(iso)','data':[[[1,'lo',{DHCP.link_path(1)!r}],[2,'eth0',{DHCP.link_path(2)!r}]]]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.PROPERTIES,'Get','ss',DHCP.MANAGER,'NamespaceId']!r}: result={{'type':'v','data':[{{'type':'t','data':namespace}}]}}
elif a=={[':1.88',DHCP.link_path(2),DHCP.INTROSPECT,'Introspect']!r}: result={{'type':'s','data':[{xml(families)!r}]}}
elif a=={[':1.88',DHCP.link_path(2),DHCP.PROPERTIES,'Get','ss',DHCP.LINK,'AdministrativeState']!r}: result={{'type':'v','data':[{{'type':'s','data':'configured'}}]}}
elif len(a)==7 and a[:4]=={[':1.88',DHCP.link_path(2),DHCP.PROPERTIES,'Get']!r} and a[4]=='ss' and a[6]=='State':
 family=4 if a[5]=={DHCP.CLIENTS[4]!r} else 6 if a[5]=={DHCP.CLIENTS[6]!r} else 0
 if family not in {families!r}: raise SystemExit(1)
 result={{'type':'v','data':[{{'type':'s','data':{state!r} if family==4 else 'bound'}}]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.MANAGER,'DescribeLink','i','2']!r}:
 path=Path({str(desc_count)!r});turn=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(turn))
 node=json.loads(Path({str(node_path)!r}).read_text())
 if {change_provider!r} and turn>=3: node['Addresses'][0]['ConfigProvider']=[192,168,50,2]
 if {change_dns!r} and turn>=3: Path({str(self.source)!r}).write_text('nameserver 9.9.9.9\\n')
 result={{'type':'s','data':[json.dumps(node)]}}
elif a=={[':1.77',TIME.OBJECT,'org.freedesktop.DBus.Properties','GetAll','s',TIME.INTERFACE]!r}:
 path=Path({str(peer_count)!r});turn=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(turn))
 result=json.loads(Path({str(peer_path)!r}).read_text())
 if {change_time!r} and turn>=4: result['data'][0]['ServerName']['data']='changed.test'
 if {warning!r}: print('fixture warning',file=sys.stderr)
else: raise SystemExit(1)
print(json.dumps(result))""")
        data = kernel_data()
        for row in data['links']:row['qdisc'] = tc_kind if row['ifname']!='lo' else 'noqueue'
        qdiscs = [{'kind': row['qdisc'], 'handle': '0:', 'dev': row['ifname'], 'root': True,
                   'options': fq_options() if row['qdisc']=='fq_codel' else {}} for row in data['links']]
        self.executable(self.tc, f"import json,os,sys\nargs=sys.argv[1:]\nwith open({str(self.ledger)!r},'a') as log:log.write(json.dumps(['tc',args,dict(os.environ)])+'\\n')\nif args=={list(CLASSIFIERS.QDISCS)!r}:print({json.dumps(qdiscs)!r})\nelif args==['-json','filter','show','dev','eth0']:print({json.dumps([] if tc_filters is None else tc_filters)!r})\nelse:raise SystemExit(1)")
        self.executable(self.ip, f"""import json,sys
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['ip',args,{{}}])+'\\n')
if args[:2]!=['-j','-N']: raise SystemExit(1)
a=args[2:]
commands={KERNEL.COMMANDS!r}
data={data!r}
if len(a)==4 and a[0]=='-4' and a[1:3]==['route','get'] and a[3] in ('8.8.8.8','9.9.9.9','192.168.50.1','192.168.50.2','192.168.50.3'):
 row={{'dst':a[3],'dev':'eth0'}}
 if a[3] in ('8.8.8.8','9.9.9.9'): row['gateway']='192.168.50.1'
 result=[row]
else:
 keys=[key for key,value in commands.items() if list(value)==a]
 if len(keys)!=1: raise SystemExit(1)
 result=data[keys[0]]
print(json.dumps(result))""")


class ClassifierNativeIntegrationTests(PrivateNative):
    def test_full_private_fq_capture_join_compiler_path_repeats_every_root_query(self):
        self.fixtures(tc_kind='fq_codel');result=ASSEMBLY.observe()
        self.assertEqual(result['classifiers']['fq_codel_filters'],{'eth0':[]})
        rows=[json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind=='tc' for kind,_,_ in rows),12)
        self.assertEqual(sum(kind=='ip' for kind,_,_ in rows),258)
        self.assertEqual(sum(kind=='bus' for kind,_,_ in rows),100)
        self.assertEqual(sum(kind=='tc' and 'filter' in args for kind,args,_ in rows),6)
        self.assertEqual(result['policy'],POLICY.compile_policy(json.dumps(result['topology']).encode()))

    def test_real_private_nonempty_classifier_prevents_infrastructure_and_cli_output(self):
        self.fixtures(tc_kind='fq_codel',tc_filters=[{'kind':'bpf','chain':77}]);out,err=io.StringIO(),io.StringIO()
        with patch.object(ASSEMBLY.sys,'argv',['assemble.py']),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):status=ASSEMBLY.main()
        self.assertEqual(status,75);self.assertEqual(out.getvalue(),'');self.assertIn('positively empty',err.getvalue())
        rows=[json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertFalse(any(kind=='bus' for kind,_,_ in rows))
        self.assertEqual(sum(kind=='tc' for kind,_,_ in rows),2)


class NativeAssemblyTests(PrivateNative):
    def test_full_private_capture_observation_join_and_compiler_path_is_positive(self):
        self.fixtures()
        with patch.dict(os.environ, {'DBUS_SYSTEM_BUS_ADDRESS': 'bad', 'ASSEMBLY_SECRET': 'bad'}):result = ASSEMBLY.observe()
        self.assertEqual(result['topology']['dns'], [{'interface': 'eth0', 'address': '8.8.8.8'}])
        self.assertEqual(result['topology']['ntp'], [{'interface': 'eth0', 'address': '192.168.50.3'}])
        self.assertEqual(result['topology']['dhcp4'], [{'interface': 'eth0', 'address': '192.168.50.1'}])
        self.assertEqual(result['sources']['dhcp4']['pid'], os.getpid())
        self.assertEqual(result['sources']['ntp']['pid'], os.getpid())
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind=='bus' for kind, _, _ in rows), 100)
        self.assertEqual(sum(kind=='ip' for kind, _, _ in rows), 258)
        self.assertEqual(sum('DescribeLink' in args for _, args, _ in rows), 4)
        self.assertEqual(sum('get' in args for kind, args, _ in rows if kind=='ip'), 12)
        for _, _, environment in rows:self.assertFalse(set(environment) & {'DBUS_SYSTEM_BUS_ADDRESS', 'ASSEMBLY_SECRET'})
        model = PacketModel(result['policy'])
        self.assertEqual(model.verdict('input', iifname='eth0', saddr='192.168.50.20', mac='02:00:00:00:00:20', dport=22), 'accept')
        self.assertEqual(model.verdict('input', iifname='eth0', saddr='192.168.50.1', mac='02:00:00:00:00:01', dport=22), 'drop')
        self.assertEqual(model.verdict('output', oifname='eth0', daddr='192.168.50.20', dport=445), 'drop')

    def test_private_static_and_bootstrap_clients_need_no_invented_server(self):
        for families, state in (((), 'bound'), ((4,), 'selecting')):
            self.fixtures(families=families, state=state)
            with self.subTest(families=families, state=state):
                result = ASSEMBLY.observe()
                self.assertEqual(result['topology']['dhcp4'], [])
                self.assertEqual(result['topology']['interfaces'][0]['dhcp4'], bool(families))
                self.assertFalse(any('DescribeLink' in json.loads(line)[1] for line in self.ledger.read_text().splitlines()))

    def test_private_instantiated_dhcp6_remains_pending_without_compiling(self):
        self.fixtures(families=(4, 6))
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'DHCPv6 reply'):
            ASSEMBLY.observe(compiler=lambda raw: self.fail('unsupported profile compiled'))
        self.assertFalse(any(TIME.SERVICE in json.loads(line)[1] for line in self.ledger.read_text().splitlines()))

    def test_independently_healthy_native_second_round_changes_cannot_publish(self):
        for options in ({'change_provider': True}, {'change_time': True}, {'change_dns': True}):
            self.fixtures(**options)
            with self.subTest(options=options), self.assertRaisesRegex(ASSEMBLY.Pending, 'complete infrastructure observations changed'):
                ASSEMBLY.observe(compiler=lambda raw: self.fail('changed complete round compiled'))

    def test_private_native_warning_bad_provider_and_local_dns_stub_refuse(self):
        for options, message in (({'warning': True}, 'time query failed or warned'), ({'corrupt': True}, 'non-unicast'), ({'dns': '127.0.0.53'}, 'local resolver stub')):
            self.fixtures(**options)
            with self.subTest(options=options), self.assertRaisesRegex(ASSEMBLY.Pending, message):
                ASSEMBLY.observe(compiler=lambda raw: self.fail('failed native predicate compiled'))

    def test_private_cli_prepares_text_only_after_real_observer_and_compiler_predicates(self):
        self.fixtures();out, err = io.StringIO(), io.StringIO()
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(ASSEMBLY.main(), 0)
        self.assertTrue(out.getvalue().startswith('destroy table inet debian13s4\n'))
        self.assertEqual(err.getvalue(), '')
        self.fixtures(warning=True);out = io.StringIO()
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(ASSEMBLY.main(), 75)
        self.assertEqual(out.getvalue(), '')

    def test_complete_native_legacy_predicate_repeats_six_times_before_prepared_text(self):
        self.fixtures();LEGACY.filesystem.reset_mock()
        result = ASSEMBLY.observe()
        self.assertEqual(LEGACY.filesystem.call_count, 48)
        self.assertEqual(result['sources']['legacy']['path'], str(self.legacy_net))
        self.assertEqual(set(result['sources']['legacy']['files']), set(LEGACY.FILES))
        self.assertTrue(result['policy'].startswith('destroy table inet debian13s4\n'))

    def test_each_real_missing_legacy_view_refuses_cli_before_native_infrastructure(self):
        for name in LEGACY.FILES:
            self.fixtures();leaf = self.legacy_net / name;leaf.unlink();out,err = io.StringIO(),io.StringIO()
            try:
                with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(ASSEMBLY.main(), 75)
                self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())
                self.assertFalse(any(json.loads(line)[0] in ('bus','ip') for line in self.ledger.read_text().splitlines()))
            finally:leaf.write_bytes(b'');leaf.chmod(0o440)

    def test_real_nonempty_legacy_view_and_protected_leaf_drift_refuse_before_compile(self):
        self.fixtures()
        for name in LEGACY.FILES:
            leaf = self.legacy_net / name;leaf.chmod(0o640);leaf.write_bytes(b'nat\n');leaf.chmod(0o440)
            try:
                with self.subTest(name=name), self.assertRaisesRegex(LEGACY.Pending, 'legacy table state'):
                    ASSEMBLY.observe(compiler=lambda raw:self.fail('nonempty legacy compile'))
            finally:leaf.chmod(0o640);leaf.write_bytes(b'');leaf.chmod(0o440)
        leaf = self.legacy_net / LEGACY.FILES[0];leaf.chmod(0o460)
        with self.assertRaises(LEGACY.Pending):ASSEMBLY.observe(compiler=lambda raw:self.fail('unsafe legacy compile'))

    def test_real_final_legacy_damage_after_compile_cannot_emit_prepared_text(self):
        self.fixtures();out,err = io.StringIO(),io.StringIO();original = ASSEMBLY.observe
        def compile_and_damage(raw):
            text = POLICY.compile_policy(raw);leaf = self.legacy_net / LEGACY.FILES[1]
            leaf.chmod(0o640);leaf.write_bytes(b'filter\n');leaf.chmod(0o440)
            return text
        with patch.object(ASSEMBLY, 'observe', side_effect=lambda:original(compiler=compile_and_damage)), \
                patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(ASSEMBLY.main(), 75)
        self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())


if __name__ == '__main__':
    unittest.main()
