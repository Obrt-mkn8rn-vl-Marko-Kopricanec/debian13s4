import contextlib
import copy
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_kernel import snapshot
from test_dhcp import replies, value, xml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_dhcp6', ROOT / 'Firewall/dhcp6.py')
DHCP6 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DHCP6)
DHCP, KERNEL = DHCP6.DHCP, DHCP6.KERNEL


def kernel_data():
    data = snapshot()
    for link in data['addresses']:
        for row in link['addr_info']:
            if row['family'] == 'inet6':
                row['scope'] = 'host' if link['ifname'] == 'lo' else 'link' if row['local'].startswith('fe80:') else 'global'
                row['valid_life_time'] = 4294967295
                row['preferred_life_time'] = 4294967295
    return data


def topology():
    return DHCP6.extended_topology(KERNEL.now() + 30, query=lambda name, deadline: copy.deepcopy(kernel_data()[name]))


def inventory(state='bound', families=(4, 6)):
    def query(operation, deadline, **kwargs):
        if operation == 'state6':
            return {'type': 'v', 'data': [{'type': 's', 'data': state}]}
        return replies(operation, deadline, **kwargs, families=families)
    return DHCP.read_inventory(KERNEL.now() + 30, query=query)


def document(local='fe80::100'):
    return {'Index': 2, 'Name': 'eth0', 'Type': 'ether', 'HardwareAddress': [2, 0, 0, 0, 0, 16],
            'Flags': 65539, 'AdministrativeState': 'configured',
            'IPv6LinkLocalAddress': list(ipaddress.ip_address(local).packed),
            'DHCPv6Client': {'DUID': [0, 2, 0, 0, 171, 17, 1, 2, 3, 4, 5, 6, 7, 8]}}


def encoded(node):
    return value('s', json.dumps(node))


class TopologyTests(unittest.TestCase):
    def test_reuses_exact_existing_two_address_and_route_deliveries_without_extra_queries(self):
        calls = []
        def query(name, deadline):
            calls.append((name, deadline))
            return copy.deepcopy(kernel_data()[name])
        result = DHCP6.extended_topology(KERNEL.now() + 30, query=query)
        self.assertEqual(len(calls), 20)
        self.assertEqual(sum(name == 'addresses' for name, _ in calls), 2)
        self.assertEqual(sum(name == 'routes6' for name, _ in calls), 2)
        self.assertEqual(len({deadline for _, deadline in calls}), 1)
        self.assertEqual(result['assigned6'][0], {'interface': 'eth0', 'address': 'fd50::100', 'prefixlen': 64, 'scope': 'global', 'usable': True})
        self.assertEqual(result['assigned6'][1]['address'], 'fe80::100')
        self.assertEqual(result['multicast6'], [{'type': 'multicast', 'dst': 'ff00::/8', 'dev': 'eth0', 'table': '255', 'flags': []}])

    def test_wrong_kind_missing_unknown_scope_and_nonnative_flags_are_pending(self):
        for key, bad in (('scope', []), ('scope', {}), ('scope', True), ('scope', None), ('scope', 'other'),
                         ('tentative', 1), ('dadfailed', None), ('deprecated', 'false'), ('valid_life_time', True)):
            data = kernel_data()
            data['addresses'][1]['addr_info'][1][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(DHCP6.Pending):
                DHCP6.extended_topology(KERNEL.now() + 30, query=lambda name, deadline: data[name])

    def test_zero_missing_expired_or_tentative_local_address_is_recorded_unusable(self):
        for key, bad in (('valid_life_time', 0), ('preferred_life_time', 0), ('preferred_life_time', None),
                         ('tentative', True), ('dadfailed', True), ('deprecated', True)):
            data = kernel_data()
            row = data['addresses'][1]['addr_info'][1]
            if bad is None:
                del row[key]
            else:
                row[key] = bad
            with self.subTest(key=key):
                result = DHCP6.extended_topology(KERNEL.now() + 30, query=lambda name, deadline: data[name])
                self.assertFalse(next(row for row in result['assigned6'] if row['address'] == 'fe80::100')['usable'])

    def test_local_mask_scope_usability_and_route_changes_require_a_retry(self):
        for key, bad in (('prefixlen', 128), ('scope', 'global'), ('tentative', True)):
            count = 0
            def query(name, deadline):
                nonlocal count
                data = kernel_data()
                if name == 'addresses':
                    count += 1
                    if count == 2:
                        data[name][1]['addr_info'][1][key] = bad
                return data[name]
            with self.subTest(key=key), self.assertRaises(DHCP6.Pending):
                DHCP6.extended_topology(KERNEL.now() + 30, query=query)
        count = 0
        def query(name, deadline):
            nonlocal count
            data = kernel_data()
            if name == 'routes6':
                count += 1
                if count == 2:
                    data[name][-1]['metric'] = 2
            return data[name]
        with self.assertRaises(DHCP6.Pending):
            DHCP6.extended_topology(KERNEL.now() + 30, query=query)

    def test_normal_declining_positive_relative_lifetimes_do_not_create_false_drift(self):
        count = 0
        def query(name, deadline):
            nonlocal count
            data = kernel_data()
            if name == 'addresses':
                count += 1
                data[name][1]['addr_info'][1]['valid_life_time'] = 100 - count
                data[name][1]['addr_info'][1]['preferred_life_time'] = 50 - count
            return data[name]
        self.assertTrue(next(row for row in DHCP6.extended_topology(KERNEL.now() + 30, query=query)['assigned6'] if row['address'] == 'fe80::100')['usable'])


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.inventory = inventory()
        self.kernel = topology()
        self.node = document()

    def parse(self):
        return DHCP6.local_client(encoded(self.node), self.inventory['interfaces'][0], self.kernel)

    def test_positive_native_link_local_duid_and_multicast_substrate(self):
        result = self.parse()
        self.assertEqual(result['local'], 'fe80::100')
        self.assertEqual(result['prefixlen'], 64)
        self.assertEqual(result['interface'], 'eth0')
        self.assertEqual(len(result['duid_sha256']), 64)
        self.assertEqual(result['route']['dst'], 'ff00::/8')

    def test_all_native_client_states_including_information_request_and_stopped_are_instances(self):
        for state in DHCP.STATES[6]:
            self.inventory = inventory(state)
            with self.subTest(state=state):
                self.assertEqual(self.parse()['state'], state)
        self.inventory = inventory('stopped')
        self.node['DHCPv6Client']['Lease'] = {}
        self.assertEqual(self.parse()['state'], 'stopped')

    def test_missing_bad_family_mapped_global_unspecified_or_corrupt_local_address_refuse(self):
        for raw in (None, [], [1] * 15, [1] * 17, [False] * 16, [256] * 16,
                    list(ipaddress.ip_address('::').packed), list(ipaddress.ip_address('::1').packed),
                    list(ipaddress.ip_address('ff02::1').packed), list(ipaddress.ip_address('fd50::100').packed),
                    list(ipaddress.ip_address('::ffff:192.168.50.100').packed)):
            self.node = document()
            self.node['IPv6LinkLocalAddress'] = raw
            with self.subTest(raw=raw), self.assertRaises(DHCP6.Pending):
                self.parse()

    def test_description_identity_mac_admin_kind_master_server_and_link_flags_refuse(self):
        for key, bad in (('Name', 'eth1'), ('Index', 3), ('Index', True), ('HardwareAddress', [2, 0, 0, 0, 0, 17]),
                         ('Type', 'wlan'), ('AdministrativeState', 'unmanaged'), ('Flags', 1), ('Flags', True),
                         ('MasterInterfaceIndex', 3), ('DHCPServer', {}), ('Kind', 'bridge'), ('Unexpected', 1)):
            self.node = document()
            self.node[key] = bad
            with self.subTest(key=key), self.assertRaises(DHCP6.Pending):
                self.parse()
        for key in ('Index', 'Name', 'HardwareAddress', 'Type', 'AdministrativeState', 'Flags', 'IPv6LinkLocalAddress', 'DHCPv6Client'):
            self.node = document()
            del self.node[key]
            with self.subTest(missing=key), self.assertRaises(DHCP6.Pending):
                self.parse()

    def test_duid_requires_native_raw_length_and_bytes_without_mac_authentication_claims(self):
        for duid in (None, [], [1], [1, 2], [True, 0, 1], [0, 1, 256], [0] * 131, 'duid'):
            self.node = document()
            self.node['DHCPv6Client']['DUID'] = duid
            with self.subTest(duid=duid), self.assertRaises(DHCP6.Pending):
                self.parse()
        for length in (3, 130):
            self.node = document()
            self.node['DHCPv6Client']['DUID'] = [0, 2] + [1] * (length - 2)
            self.assertEqual(len(self.parse()['duid_sha256']), 64)

    def test_delegated_prefix_unknown_client_payload_and_missing_duid_refuse(self):
        for payload in (None, {}, {'DUID': [0, 2, 1], 'Prefixes': []}, {'DUID': [0, 2, 1], 'Unknown': 1}):
            self.node['DHCPv6Client'] = payload
            with self.subTest(payload=payload), self.assertRaises(DHCP6.Pending):
                self.parse()

    def test_exact_kernel_assignment_and_link_scope_usability_are_required(self):
        for mutation in ('missing', 'duplicate', 'scope', 'unusable', 'inactive', 'index'):
            self.kernel = topology()
            if mutation == 'missing':
                self.kernel['assigned6'] = []
            elif mutation == 'duplicate':
                self.kernel['assigned6'].append(copy.deepcopy(self.kernel['assigned6'][1]))
            elif mutation in ('scope', 'unusable'):
                self.kernel['assigned6'][1].update({'scope': 'global'} if mutation == 'scope' else {'usable': False})
            else:
                self.kernel['interfaces'][0].update({'up': False} if mutation == 'inactive' else {'index': 3})
            with self.subTest(mutation=mutation), self.assertRaises(DHCP6.Pending):
                self.parse()

    def test_missing_ambiguous_inactive_gateway_and_bad_metric_multicast_routes_refuse(self):
        original = topology()['multicast6'][0]
        for routes in ([], [original, original], [original | {'flags': ['linkdown']}],
                       [original | {'gateway': 'fe80::1'}], [original | {'table': '254'}],
                       [original | {'metric': True}], [original | {'scope': []}], [original | {'prefsrc': 'fe80::101'}],
                       [original | {'type': 'unicast'}], [original | {'dst': 'ff05::/16'}], [original | {'dst': 'fe80::/64'}]):
            self.kernel = topology()
            self.kernel['multicast6'] = routes
            with self.subTest(routes=routes), self.assertRaises(DHCP6.Pending):
                self.parse()

    def test_longest_prefix_and_lowest_metric_selection_is_unique_and_checked(self):
        self.kernel['multicast6'] = [self.kernel['multicast6'][0] | {'metric': 0},
                                    self.kernel['multicast6'][0] | {'dst': 'ff02::/16', 'metric': 10},
                                    self.kernel['multicast6'][0] | {'dst': 'ff02::/16', 'metric': 5}]
        self.assertEqual(self.parse()['route']['metric'], 5)
        self.kernel['multicast6'].append(self.kernel['multicast6'][-1] | {'protocol': 'kernel'})
        with self.assertRaises(DHCP6.Pending):
            self.parse()


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.inventory = inventory()
        self.kernel = topology()
        self.node = document()

    def observe(self, **overrides):
        options = {'read': lambda deadline: copy.deepcopy(self.inventory), 'topology': lambda deadline: copy.deepcopy(self.kernel),
                   'query': lambda *args, **kwargs: encoded(self.node)}
        options.update(overrides)
        return DHCP6.observe(**options)

    def test_complete_three_client_reads_two_topologies_and_descriptions_share_one_window(self):
        calls = []
        def read(deadline):
            calls.append(('read', deadline))
            return copy.deepcopy(self.inventory)
        def topology(deadline):
            calls.append(('kernel', deadline))
            return copy.deepcopy(self.kernel)
        def query(operation, deadline, **kwargs):
            calls.append((operation, deadline))
            self.assertEqual(kwargs, {'owner': ':1.88', 'index': 2})
            return encoded(self.node)
        result = self.observe(read=read, topology=topology, query=query)
        self.assertEqual([name for name, _ in calls], ['read', 'kernel', 'describe', 'read', 'kernel', 'describe', 'read'])
        self.assertEqual(len({deadline for _, deadline in calls}), 1)
        self.assertEqual(result['schema'], 'debian13s4-networkd-dhcp6-multicast-1')
        self.assertEqual(result['transport'], {'basis': 'pinned-networkd-v257-send-path', 'destination': 'ff02::1:2', 'client_port': 546, 'server_port': 547, 'unicast_servers': []})
        self.assertNotIn('dhcp6', result)

    def test_static_absent_client_does_not_query_or_infer_transport_health(self):
        self.inventory = inventory(families=(4,))
        result = self.observe(query=lambda *a, **kw: self.fail('unexpected DHCPv6 description'))
        self.assertEqual(result['clients'], [])
        self.assertEqual(result['transport']['unicast_servers'], [])

    def test_invalid_and_inherited_deadline_is_checked_without_widening(self):
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(DHCP6.Pending):
                self.observe(deadline=deadline, read=lambda *a: self.fail('unexpected read'))
        deadline = KERNEL.now() + 10
        seen = []
        result = self.observe(deadline=deadline, read=lambda window: seen.append(window) or self.inventory)
        self.assertEqual(seen, [deadline] * 3)
        self.assertEqual(result['clients'][0]['local'], 'fe80::100')

    def test_changed_local_address_duid_and_final_state_cannot_publish(self):
        for turn in (2, 3):
            count = 0
            def read(deadline):
                nonlocal count
                count += 1
                record = copy.deepcopy(self.inventory)
                if count == turn:
                    record['interfaces'][0]['state6'] = 'renew'
                return record
            with self.subTest(turn=turn), self.assertRaises(DHCP6.Pending):
                self.observe(read=read)
        for key in ('local', 'duid'):
            count = 0
            def query(*a, **kw):
                nonlocal count
                count += 1
                node = document()
                if count == 2:
                    if key == 'local':
                        node['IPv6LinkLocalAddress'][-1] += 1
                    else:
                        node['DHCPv6Client']['DUID'][-1] += 1
                return encoded(node)
            with self.subTest(key=key), self.assertRaises(DHCP6.Pending):
                self.observe(query=query)

    def test_changed_topology_namespace_and_attempt_expiry_are_pending(self):
        values = iter([self.kernel, self.kernel | {'assigned6': []}])
        with self.assertRaises(DHCP6.Pending):
            self.observe(topology=lambda deadline: next(values))
        with patch.object(KERNEL, 'namespace', return_value=self.kernel['namespace'] + 1), self.assertRaises(DHCP6.Pending):
            self.observe()
        with patch.object(DHCP6, 'ATTEMPT_SECONDS', 0), self.assertRaises(DHCP6.Pending):
            self.observe()

    def test_client_and_kernel_inventory_mismatch_is_not_a_permission_source(self):
        self.inventory['interfaces'][0]['index'] = 3
        with self.assertRaises(DHCP6.Pending):
            self.observe()

    def test_cli_usage_pending_and_success_have_checked_no_partial_output(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(DHCP6.sys, 'argv', ['dhcp6.py', 'extra']), contextlib.redirect_stdout(out):
            self.assertEqual(DHCP6.main(), 64)
        self.assertEqual(out.getvalue(), '')
        with patch.object(DHCP6.sys, 'argv', ['dhcp6.py']), patch.object(DHCP6, 'observe', side_effect=DHCP6.Pending('fixture')), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(DHCP6.main(), 75)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('pending', err.getvalue())
        with patch.object(DHCP6.sys, 'argv', ['dhcp6.py']), patch.object(DHCP6, 'observe', return_value=self.observe()), contextlib.redirect_stdout(out):
            self.assertEqual(DHCP6.main(), 0)
        self.assertEqual(json.loads(out.getvalue())['clients'][0]['local'], 'fe80::100')


class PrivateNative(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-dhcp6-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.bus = self.root / 'busctl'
        self.ip = self.root / 'ip'
        self.ledger = self.root / 'ledger'
        self.settings = [patch.object(DHCP, 'BUS_BINARY', self.bus), patch.object(KERNEL, 'IP_BINARY', self.ip),
                         patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:
            setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):
            setting.stop()
        self.directory.cleanup()

    def executable(self, path, body):
        path.write_text('#!/usr/bin/python3 -B\n' + body + '\n')
        path.chmod(0o700)

    def fixtures(self, state='bound', families=(4, 6), change_turn=0, warning=False, node_edit=None, data_edit=None, address_turn=0):
        node = document()
        if node_edit:
            node_edit(node)
        node_path = self.root / 'description.json'
        node_path.write_text(json.dumps(node))
        count, address_count = self.root / 'count', self.root / 'address-count'
        for path in (count, address_count):
            if path.exists():
                path.unlink()
        self.ledger.write_text('')
        self.executable(self.bus, f"""import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['bus',args])+'\\n')
if args[:8]!=['--system','--no-pager','--json=short','--auto-start=no','--allow-interactive-authorization=no','--expect-reply=yes','--timeout=3s','call']: raise SystemExit(1)
a=args[8:]
namespace=int(os.readlink('/proc/self/ns/net')[5:-1])
if a=={[*DHCP.BUS,'GetNameOwner','s',DHCP.SERVICE]!r}: result={{'type':'s','data':[':1.88']}}
elif a=={[*DHCP.BUS,'GetConnectionUnixProcessID','s',':1.88']!r}: result={{'type':'u','data':[os.getppid()]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.MANAGER,'ListLinks']!r}: result={{'type':'a(iso)','data':[[[1,'lo',{DHCP.link_path(1)!r}],[2,'eth0',{DHCP.link_path(2)!r}]]]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.PROPERTIES,'Get','ss',DHCP.MANAGER,'NamespaceId']!r}: result={{'type':'v','data':[{{'type':'t','data':namespace}}]}}
elif a=={[':1.88',DHCP.link_path(2),DHCP.INTROSPECT,'Introspect']!r}: result={{'type':'s','data':[{xml(families)!r}]}}
elif a=={[':1.88',DHCP.link_path(2),DHCP.PROPERTIES,'Get','ss',DHCP.LINK,'AdministrativeState']!r}: result={{'type':'v','data':[{{'type':'s','data':'configured'}}]}}
elif len(a)==7 and a[:4]=={[':1.88',DHCP.link_path(2),DHCP.PROPERTIES,'Get']!r} and a[4]=='ss' and a[6]=='State':
 family=4 if a[5]=={DHCP.CLIENTS[4]!r} else 6 if a[5]=={DHCP.CLIENTS[6]!r} else 0
 if family not in {families!r}: raise SystemExit(1)
 result={{'type':'v','data':[{{'type':'s','data':{state!r} if family==6 else 'bound'}}]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.MANAGER,'DescribeLink','i','2']!r}:
 path=Path({str(count)!r});turn=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(turn))
 node=json.loads(Path({str(node_path)!r}).read_text())
 if turn=={change_turn}: node['DHCPv6Client']['DUID'][-1]+=1
 if {warning!r}: print('fixture warning',file=sys.stderr)
 result={{'type':'s','data':[json.dumps(node)]}}
else: raise SystemExit(1)
print(json.dumps(result))""")
        data = kernel_data()
        if data_edit:
            data_edit(data)
        self.executable(self.ip, f"""import json,sys
from pathlib import Path
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['ip',args])+'\\n')
if args[:2]!=['-j','-N']: raise SystemExit(1)
a=args[2:]
commands={KERNEL.COMMANDS!r}
data={data!r}
keys=[key for key,value in commands.items() if list(value)==a]
if len(keys)!=1: raise SystemExit(1)
key=keys[0]
if key=='addresses':
 path=Path({str(address_count)!r});turn=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(turn))
 if turn=={address_turn}: data[key][1]['addr_info'][1]['preferred_life_time']=0
print(json.dumps(data[key]))""")


class NativeObservationTests(PrivateNative):
    def test_complete_private_native_delivery_has_no_extra_route_get_or_server_guess(self):
        self.fixtures()
        result = DHCP6.observe()
        self.assertEqual(result['clients'][0]['local'], 'fe80::100')
        self.assertEqual(result['source']['pid'], os.getpid())
        self.assertEqual(result['transport']['unicast_servers'], [])
        commands = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'bus' for kind, _ in commands), 41)
        self.assertEqual(sum(kind == 'ip' for kind, _ in commands), 40)
        self.assertEqual(sum('DescribeLink' in args for _, args in commands), 2)
        self.assertFalse(any('get' in args for kind, args in commands if kind == 'ip'))

    def test_private_information_request_and_stopped_client_keep_multicast_substrate_without_lease_health(self):
        for state in ('information-request', 'stopped'):
            self.fixtures(state=state, families=(6,), node_edit=lambda node: node['DHCPv6Client'].update(Lease={}))
            with self.subTest(state=state):
                result = DHCP6.observe()
                self.assertEqual(result['clients'][0]['state'], state)
                self.assertEqual(result['clients'][0]['route']['dst'], 'ff00::/8')
                self.assertNotIn('Lease', result['clients'][0])

    def test_private_absent_client_is_not_described_and_does_not_certify_other_clients_absent(self):
        self.fixtures(families=())
        result = DHCP6.observe()
        self.assertEqual(result['clients'], [])
        commands = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertFalse(any('DescribeLink' in args for _, args in commands))
        self.assertEqual(result['interfaces'][0]['dhcp6'], False)

    def test_zero_exit_private_corrupt_description_scope_assignment_or_route_refuses(self):
        for node_edit, data_edit in (
                (lambda node: node.update(IPv6LinkLocalAddress=[0] * 16), None),
                (None, lambda data: data['addresses'][1]['addr_info'][1].update(scope=[])),
                (None, lambda data: data['addresses'][1]['addr_info'][1].update(preferred_life_time=0)),
                (None, lambda data: data['routes6'][-1].update(table='254'))):
            self.fixtures(node_edit=node_edit, data_edit=data_edit)
            with self.subTest(node=bool(node_edit), data=bool(data_edit)), self.assertRaises(DHCP6.Pending):
                DHCP6.observe()

    def test_second_private_description_or_native_assignment_change_cannot_publish(self):
        for change_turn, address_turn in ((2, 0), (0, 3)):
            self.fixtures(change_turn=change_turn, address_turn=address_turn)
            with self.subTest(description=change_turn, address=address_turn), self.assertRaises(DHCP6.Pending):
                DHCP6.observe()

    def test_private_zero_exit_warning_cli_remains_pending_with_no_partial_stdout(self):
        self.fixtures(warning=True)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(DHCP6.sys, 'argv', ['dhcp6.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(DHCP6.main(), 75)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('pending', err.getvalue())


if __name__ == '__main__':
    unittest.main()
