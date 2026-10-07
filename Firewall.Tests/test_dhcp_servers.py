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
SPEC = importlib.util.spec_from_file_location('firewall_dhcp_servers', ROOT / 'Firewall/dhcp_servers.py')
SERVERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVERS)
DHCP, KERNEL = SERVERS.DHCP, SERVERS.KERNEL


def kernel_data():
    result = snapshot()
    for link in result['addresses']:
        for row in link['addr_info']:
            if row['family'] == 'inet':
                row['scope'] = 'host' if link['ifname'] == 'lo' else 'global'
                row['valid_life_time'] = 3600
    return result


def topology():
    return SERVERS.assigned_topology(KERNEL.now() + 30, query=lambda name, deadline: copy.deepcopy(kernel_data()[name]))


def inventory(families=(4, 6), state='bound'):
    def query(op, deadline, **kwargs):
        if op == 'state4':
            return {'type': 'v', 'data': [{'type': 's', 'data': state}]}
        return replies(op, deadline, **kwargs, families=families)
    return DHCP.read_inventory(KERNEL.now() + 30, query=query)


def document(provider='192.168.50.1', infinite=False):
    instant = int(KERNEL.now() * 1000000)
    row = {'Family': 2, 'Address': [192, 168, 50, 100], 'PrefixLength': 24, 'ConfigSource': 'DHCPv4',
           'ConfigProvider': list(ipaddress.ip_address(provider).packed), 'Scope': 0, 'ScopeString': 'global',
           'Flags': 0, 'FlagsString': '', 'ConfigState': 'configured'}
    if not infinite:
        for stem in ('PreferredLifetime', 'ValidLifetime'):
            row[stem + 'USec'] = row[stem + 'Usec'] = instant + 3600000000
    return {'Index': 2, 'Name': 'eth0', 'Type': 'ether', 'HardwareAddress': [2, 0, 0, 0, 0, 16],
            'Flags': 65539, 'AdministrativeState': 'configured', 'Addresses': [row],
            'DHCPv4Client': {'ClientIdentifier': [1, 2, 0, 0, 0, 0, 16],
                             'Lease': {'LeaseTimestampUSec': instant - 1000000, 'Timeout1USec': instant + 1800000000, 'Timeout2USec': instant + 2700000000}}}


def encoded(node):
    return value('s', json.dumps(node))


class DescriptionTests(unittest.TestCase):
    def setUp(self):
        self.client = inventory()['interfaces'][0]
        self.kernel = topology()
        self.node = document()

    def parse(self, node=None):
        return SERVERS.descriptions(encoded(node or self.node), self.client, self.kernel)

    def test_positive_native_byte_array_attribution_matches_exact_assigned_address(self):
        result = self.parse()
        self.assertEqual(result[0]['address'], '192.168.50.1')
        self.assertEqual(result[0]['assigned'], '192.168.50.100')
        self.assertEqual(result[0]['prefixlen'], 24)
        self.assertEqual(result[0]['interface'], 'eth0')

    def test_native_infinite_address_lifetimes_are_explicit_omissions_not_zero_defaults(self):
        result = self.parse(document(infinite=True))
        self.assertIsNone(result[0]['preferred_until'])
        self.assertIsNone(result[0]['valid_until'])
        for name in ('PreferredLifetimeUSec', 'PreferredLifetimeUsec', 'ValidLifetimeUSec', 'ValidLifetimeUsec'):
            node = document(infinite=True)
            node['Addresses'][0][name] = 0
            with self.subTest(name=name), self.assertRaises(SERVERS.Pending):
                self.parse(node)

    def test_description_name_index_mac_kind_type_admin_master_and_server_role_refuse(self):
        for key, bad in (('Index', 3), ('Index', True), ('Name', 'eth1'), ('HardwareAddress', [2, 0, 0, 0, 0, 17]),
                         ('HardwareAddress', [2]), ('Type', 'wlan'), ('Kind', 'bridge'), ('AdministrativeState', 'unmanaged'),
                         ('Flags', 1), ('MasterInterfaceIndex', 5), ('DHCPServer', {}), ('UnknownProperty', 1)):
            node = copy.deepcopy(self.node)
            node[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(SERVERS.Pending):
                self.parse(node)
        for key in ('Index', 'Name', 'HardwareAddress', 'Type', 'AdministrativeState', 'Flags'):
            node = copy.deepcopy(self.node)
            del node[key]
            with self.subTest(missing=key), self.assertRaises(SERVERS.Pending):
                self.parse(node)

    def test_client_identifier_missing_lease_future_timestamp_and_bad_timeouts_refuse(self):
        for payload in (None, {}, {'Lease': {}}, {'ClientIdentifier': []},
                        {'ClientIdentifier': [1, True], 'Lease': {'LeaseTimestampUSec': 0}},
                        self.node['DHCPv4Client'] | {'6rdPrefix': {}}, self.node['DHCPv4Client'] | {'Other': 1}):
            node = copy.deepcopy(self.node)
            node['DHCPv4Client'] = payload
            with self.subTest(payload=payload), self.assertRaises(SERVERS.Pending):
                self.parse(node)
        for key, bad in (('LeaseTimestampUSec', int(KERNEL.now() * 1000000) + 10000000000),
                         ('LeaseTimestampUSec', True), ('Timeout1USec', 0), ('Timeout2USec', 0),
                         ('LeaseTimestampUSec', (1 << 64) - 1)):
            node = copy.deepcopy(self.node)
            node['DHCPv4Client']['Lease'][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(SERVERS.Pending):
                self.parse(node)

    def test_missing_corrupt_or_non_unicast_provider_and_local_subnet_endpoints_refuse(self):
        for provider in (None, [], [192, 168, 50], [192, 168, 50, True], [192, 168, 50, 256], '192.168.50.1',
                         [0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255, 255, 255, 255],
                         [192, 168, 50, 0], [192, 168, 50, 255], [192, 168, 50, 100]):
            node = copy.deepcopy(self.node)
            node['Addresses'][0]['ConfigProvider'] = provider
            with self.subTest(provider=provider), self.assertRaises(SERVERS.Pending):
                self.parse(node)

    def test_marked_removing_tentative_failed_deprecated_wrong_scope_and_peer_refuse(self):
        for key, bad in (('ConfigState', 'configured,marked'), ('ConfigState', 'configuring'), ('ConfigState', None),
                         ('Flags', 8), ('Flags', 32), ('Flags', 64), ('Flags', True), ('Scope', 253),
                         ('Peer', [192, 168, 50, 101]), ('Family', 10), ('PrefixLength', 0), ('PrefixLength', True)):
            node = copy.deepcopy(self.node)
            node['Addresses'][0][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(SERVERS.Pending):
                self.parse(node)

    def test_expiry_alias_disagreement_negative_types_and_preferred_after_valid_refuse(self):
        for key, bad in (('ValidLifetimeUSec', 0), ('ValidLifetimeUSec', True), ('ValidLifetimeUSec', -1),
                         ('ValidLifetimeUSec', (1 << 64) - 1), ('ValidLifetimeUSec', 'future'),
                         ('PreferredLifetimeUSec', (1 << 64) - 2)):
            node = copy.deepcopy(self.node)
            node['Addresses'][0][key] = bad
            with self.subTest(key=key), self.assertRaises(SERVERS.Pending):
                self.parse(node)
        for name in ('PreferredLifetimeUSec', 'PreferredLifetimeUsec', 'ValidLifetimeUSec', 'ValidLifetimeUsec'):
            node = copy.deepcopy(self.node)
            del node['Addresses'][0][name]
            with self.subTest(missing=name), self.assertRaises(SERVERS.Pending):
                self.parse(node)
        node = copy.deepcopy(self.node)
        for stem in ('PreferredLifetime', 'ValidLifetime'):
            node['Addresses'][0][stem + 'USec'] = node['Addresses'][0][stem + 'Usec'] = int(KERNEL.now() * 1000000) - 1
        with self.assertRaises(SERVERS.Pending):
            self.parse(node)

    def test_actual_assignment_prefix_usability_scope_and_active_interface_are_required(self):
        for key, bad in (('address', '192.168.50.101'), ('prefixlen', 25), ('usable', False), ('scope', 'link')):
            old = copy.deepcopy(self.kernel)
            self.kernel['assigned4'][0][key] = bad
            with self.subTest(key=key), self.assertRaises(SERVERS.Pending):
                self.parse()
            self.kernel = old
        self.kernel['interfaces'][0]['up'] = False
        with self.assertRaises(SERVERS.Pending):
            self.parse()

    def test_missing_duplicate_conflicting_and_malformed_address_attributions_refuse(self):
        for rows in ([], None, 'addresses', [None], [self.node['Addresses'][0]] * 2):
            node = copy.deepcopy(self.node)
            node['Addresses'] = rows
            with self.subTest(rows=type(rows).__name__), self.assertRaises(SERVERS.Pending):
                self.parse(node)
        node = copy.deepcopy(self.node)
        row = copy.deepcopy(node['Addresses'][0])
        row['Address'] = [192, 168, 50, 101]
        row['ConfigProvider'] = [192, 168, 50, 2]
        node['Addresses'].append(row)
        self.kernel['assigned4'].append(self.kernel['assigned4'][0] | {'address': '192.168.50.101'})
        with self.assertRaises(SERVERS.Pending):
            self.parse(node)

    def test_foreign_static_ndisc_and_ipv6_provider_never_become_dhcp4_server_permission(self):
        node = copy.deepcopy(self.node)
        for source in ('foreign', 'static', 'NDisc', 'DHCPv6', 'DHCP-PD', 'runtime', 'IPv4LL'):
            row = copy.deepcopy(self.node['Addresses'][0])
            row['ConfigSource'] = source
            row['ConfigProvider'] = [192, 168, 50, 2]
            node['Addresses'].append(row)
        self.assertEqual({row['address'] for row in self.parse(node)}, {'192.168.50.1'})
        node = copy.deepcopy(self.node)
        node['Addresses'][0]['ConfigSource'] = 'other'
        with self.assertRaises(SERVERS.Pending):
            self.parse(node)

    def test_json_duplicate_keys_nonfinite_float_nesting_sizes_invalid_encoding_and_signature_refuse(self):
        for text in ('{"Index":2,"Index":3}', '{"extra":NaN}', '{"extra":1.0}', 'bad', '\ud800',
                     'x' * (DHCP.MAX_BYTES + 1), '[' * 50 + '0' + ']' * 50):
            with self.subTest(kind=type(text).__name__), self.assertRaises((SERVERS.Pending, UnicodeError)):
                SERVERS.bounded_json(value('s', text))
        with patch.object(SERVERS, 'MAX_ITEMS', 2), self.assertRaises(SERVERS.Pending):
            SERVERS.bounded_json(encoded(self.node))
        for message in (value('u', 2), value('s', None), {'type': 's', 'data': []}):
            with self.subTest(message=message), self.assertRaises(SERVERS.Pending):
                SERVERS.bounded_json(message)


class AssignmentTests(unittest.TestCase):
    def test_reuses_two_existing_native_address_deliveries_without_extra_commands(self):
        calls = []
        def query(name, deadline):
            calls.append((name, deadline))
            return copy.deepcopy(kernel_data()[name])
        result = SERVERS.assigned_topology(KERNEL.now() + 30, query=query)
        self.assertEqual(len(calls), 20)
        self.assertEqual(len({deadline for _, deadline in calls}), 1)
        self.assertEqual(result['assigned4'], [{'interface': 'eth0', 'address': '192.168.50.100', 'prefixlen': 24, 'scope': 'global', 'usable': True}])

    def test_changed_assignment_mask_invisibility_or_usability_between_rounds_refuse(self):
        for key, bad in (('prefixlen', 25), ('tentative', True), ('scope', 'link'), ('valid_life_time', 0)):
            count = 0
            def query(name, deadline):
                nonlocal count
                data = kernel_data()
                if name == 'addresses':
                    count += 1
                    if count == 2:
                        data[name][1]['addr_info'][0][key] = bad
                return data[name]
            with self.subTest(key=key), self.assertRaises(SERVERS.Pending):
                SERVERS.assigned_topology(KERNEL.now() + 30, query=query)

    def test_unknown_scope_and_nonnative_usability_flags_refuse(self):
        for key, bad in (('scope', None), ('scope', 'other'), ('tentative', 1), ('dadfailed', 'false'), ('deprecated', None), ('valid_life_time', True)):
            data = kernel_data()
            data['addresses'][1]['addr_info'][0][key] = bad
            with self.subTest(key=key), self.assertRaises(SERVERS.Pending):
                SERVERS.assigned_topology(KERNEL.now() + 30, query=lambda name, deadline: data[name])

    def test_missing_zero_lifetime_and_tentative_address_are_explicitly_unusable(self):
        for key, bad in (('valid_life_time', 0), ('valid_life_time', None), ('tentative', True), ('dadfailed', True), ('deprecated', True)):
            data = kernel_data()
            row = data['addresses'][1]['addr_info'][0]
            if bad is None:
                del row[key]
            else:
                row[key] = bad
            with self.subTest(key=key):
                result = SERVERS.assigned_topology(KERNEL.now() + 30, query=lambda name, deadline: data[name])
                self.assertFalse(result['assigned4'][0]['usable'])

    def test_wrong_kind_scope_is_pending_without_an_unhashable_lookup_exception(self):
        for scope in ([], {}, ['global'], 0, True):
            data = kernel_data()
            data['addresses'][1]['addr_info'][0]['scope'] = scope
            with self.subTest(scope=scope), self.assertRaises(SERVERS.Pending):
                SERVERS.assigned_topology(KERNEL.now() + 30, query=lambda name, deadline: data[name])


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.inventory = inventory()
        self.kernel = topology()
        self.node = document()
        self.calls = []

    def query(self, operation, deadline, owner=None, index=None):
        self.calls.append((operation, deadline, owner, index))
        self.assertEqual((operation, owner, index), ('describe', ':1.88', 2))
        return encoded(self.node)

    def route(self, address, interface, deadline):
        self.assertIsNone(interface, 'IPv4 server route must not force a guessed egress')
        return [{'dst': address, 'dev': 'eth0'}]

    def observe(self, **overrides):
        options = {'read': lambda deadline: copy.deepcopy(self.inventory), 'topology': lambda deadline: copy.deepcopy(self.kernel), 'query': self.query, 'route': self.route}
        options.update(overrides)
        return SERVERS.observe(**options)

    def test_complete_attributions_bind_server_to_own_client_without_forcing_interface(self):
        result = self.observe()
        self.assertEqual(result['dhcp4'], [{'interface': 'eth0', 'address': '192.168.50.1'}])
        self.assertEqual(result['schema'], 'debian13s4-networkd-dhcp4-servers-1')
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn('dhcp6', result)

    def test_static_stopped_and_bootstrap_clients_have_no_current_unicast_server_claim(self):
        for families, state in (((), 'bound'), ((6,), 'bound'), ((4,), 'stopped'), ((4,), 'selecting'), ((4,), 'initialization')):
            self.inventory = inventory(families, state)
            with self.subTest(families=families, state=state):
                self.assertEqual(self.observe(query=lambda *a, **kw: self.fail('unexpected description'))['dhcp4'], [])

    def test_all_live_state_variants_require_actual_positive_attribution(self):
        for state in SERVERS.LIVE_STATES:
            self.inventory = inventory(state=state)
            with self.subTest(state=state):
                self.assertEqual(self.observe()['dhcp4'][0]['address'], '192.168.50.1')
                with self.assertRaises(SERVERS.Pending):
                    self.observe(query=lambda *a, **kw: encoded(self.node | {'Addresses': []}))

    def test_route_wrong_client_interface_negative_local_unobserved_gateway_and_missing_refuse(self):
        second = copy.deepcopy(self.kernel['interfaces'][0]) | {'name': 'eth1', 'index': 3}
        self.kernel['interfaces'].append(second)
        extra_client = copy.deepcopy(self.inventory['interfaces'][0]) | {'name': 'eth1', 'index': 3, 'path': DHCP.link_path(3), 'dhcp4': False, 'dhcp6': False, 'state4': None, 'state6': None}
        self.inventory['interfaces'].append(extra_client)
        for rows in ([], [{'dst': '192.168.50.1', 'dev': 'eth1'}], [{'dst': '192.168.50.1', 'dev': 'eth0', 'type': 'local'}],
                     [{'dst': '192.168.50.1', 'dev': 'eth0', 'type': 'blackhole'}], [{'dst': '192.168.50.1', 'dev': 'eth0', 'gateway': '192.168.50.2'}]):
            with self.subTest(rows=rows), self.assertRaises(SERVERS.Pending):
                self.observe(route=lambda *args: rows)

    def test_relayed_server_requires_actual_observed_gateway_on_its_client_interface(self):
        self.node = document('10.0.0.1')
        rows = [{'dst': '10.0.0.1', 'dev': 'eth0', 'gateway': '192.168.50.1'}]
        self.assertEqual(self.observe(route=lambda *args: rows)['dhcp4'][0]['address'], '10.0.0.1')
        with self.assertRaises(SERVERS.Pending):
            self.observe()

    def test_changed_server_assignment_lifetime_and_final_client_read_refuse(self):
        for turn in (2, 3):
            count = 0
            def read(deadline):
                nonlocal count
                count += 1
                record = copy.deepcopy(self.inventory)
                if count == turn:
                    record['interfaces'][0]['state4'] = 'renewing'
                return record
            with self.subTest(turn=turn), self.assertRaises(SERVERS.Pending):
                self.observe(read=read)
        for key, bad in (('ConfigProvider', [192, 168, 50, 2]), ('Address', [192, 168, 50, 101]), ('ValidLifetimeUSec', 0)):
            count = 0
            def query(*args, **kwargs):
                nonlocal count
                count += 1
                node = copy.deepcopy(self.node)
                if count == 2:
                    node['Addresses'][0][key] = bad
                return encoded(node)
            with self.subTest(key=key), self.assertRaises(SERVERS.Pending):
                self.observe(query=query)

    def test_route_row_changes_and_kernel_assignment_changes_are_not_hidden_by_same_endpoint(self):
        count = 0
        def route(address, interface, deadline):
            nonlocal count
            count += 1
            return [{'dst': address, 'dev': 'eth0', 'metric': count}]
        with self.assertRaises(SERVERS.Pending):
            self.observe(route=route)
        values = iter([self.kernel, self.kernel | {'assigned4': []}])
        with self.assertRaises(SERVERS.Pending):
            self.observe(topology=lambda deadline: next(values))

    def test_invalid_inherited_budget_final_expiry_and_namespace_changes_refuse(self):
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(SERVERS.Pending):
                self.observe(deadline=deadline, read=lambda *a: self.fail('unexpected read'))
        with patch.object(SERVERS, 'ATTEMPT_SECONDS', 0), self.assertRaises(SERVERS.Pending):
            self.observe()
        with patch.object(KERNEL, 'namespace', return_value=self.kernel['namespace'] + 1), self.assertRaises(SERVERS.Pending):
            self.observe()

    def test_expiration_during_final_read_never_publishes_previously_fresh_attribution(self):
        until = int((KERNEL.now() + 5) * 1000000)
        for stem in ('PreferredLifetime', 'ValidLifetime'):
            self.node['Addresses'][0][stem + 'USec'] = self.node['Addresses'][0][stem + 'Usec'] = until
        calls = 0
        actual_now = KERNEL.now()
        def read(deadline):
            nonlocal calls
            calls += 1
            return self.inventory
        def clock():
            return until / 1000000 + 1 if calls == 3 else actual_now
        with patch.object(KERNEL, 'now', side_effect=clock), self.assertRaisesRegex(SERVERS.Pending, 'attribution expired'):
            self.observe(read=read)

    def test_cli_usage_pending_and_success_keep_the_checked_output_contract(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(SERVERS.sys, 'argv', ['dhcp_servers.py', 'extra']), contextlib.redirect_stdout(out):
            self.assertEqual(SERVERS.main(), 64)
        self.assertEqual(out.getvalue(), '')
        with patch.object(SERVERS.sys, 'argv', ['dhcp_servers.py']), patch.object(SERVERS, 'observe', side_effect=SERVERS.Pending('fixture refusal')), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(SERVERS.main(), 75)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('pending', err.getvalue())
        with patch.object(SERVERS.sys, 'argv', ['dhcp_servers.py']), patch.object(SERVERS, 'observe', return_value=self.observe()), contextlib.redirect_stdout(out):
            self.assertEqual(SERVERS.main(), 0)
        self.assertEqual(json.loads(out.getvalue())['dhcp4'], [{'interface': 'eth0', 'address': '192.168.50.1'}])


class PrivateNative(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-dhcp-server-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.bus = self.root / 'busctl'
        self.ip = self.root / 'ip'
        self.ledger = self.root / 'ledger'
        self.patches = [patch.object(DHCP, 'BUS_BINARY', self.bus), patch.object(KERNEL, 'IP_BINARY', self.ip),
                        patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.patches:
            setting.start()

    def tearDown(self):
        for setting in reversed(self.patches):
            setting.stop()
        self.directory.cleanup()

    def executable(self, path, body):
        path.write_text('#!/usr/bin/python3 -B\n' + body + '\n')
        path.chmod(0o700)


class NativeExtensionTests(PrivateNative):
    def test_description_uses_only_checked_unique_owner_manager_signed_index_and_fixed_method(self):
        self.executable(self.bus, f"import json,os,sys\nopen({str(self.ledger)!r},'w').write(json.dumps([sys.argv[1:],dict(os.environ)]))\nprint('{{\"type\":\"s\",\"data\":[\"{{}}\"]}}')")
        with patch.dict(os.environ, {'DBUS_SYSTEM_BUS_ADDRESS': 'bad', 'TASK_SECRET': 'secret'}):
            self.assertEqual(DHCP.native_query('describe', KERNEL.now() + 10, owner=':1.88', index=2), value('s', '{}'))
        arguments, environment = json.loads(self.ledger.read_text())
        self.assertEqual(arguments, ['--system', '--no-pager', '--json=short', '--auto-start=no', '--allow-interactive-authorization=no', '--expect-reply=yes', '--timeout=3s',
                                     'call', ':1.88', DHCP.OBJECT, DHCP.MANAGER, 'DescribeLink', 'i', '2'])
        self.assertNotIn('DBUS_SYSTEM_BUS_ADDRESS', environment)
        self.assertNotIn('TASK_SECRET', environment)

    def test_missing_bad_bool_overflow_and_injectable_owner_or_index_never_execute(self):
        marker = self.root / 'executed'
        self.executable(self.bus, f"open({str(marker)!r},'w').write('unexpected')")
        for owner, index in ((None, 2), (DHCP.SERVICE, 2), ('--system', 2), (':1.88', None), (':1.88', True),
                             (':1.88', '2'), (':1.88', 0), (':1.88', -1), (':1.88', 1 << 31)):
            with self.subTest(owner=owner, index=index), self.assertRaises(SERVERS.Pending):
                DHCP.native_query('describe', KERNEL.now() + 10, owner=owner, index=index)
        self.assertFalse(marker.exists())

    def test_description_nonzero_warning_oversized_or_invalid_bytes_remain_capture_failures(self):
        for body in ('raise SystemExit(1)', "import sys; print('{}'); print('warning',file=sys.stderr)",
                     "import os; os.write(1,b'\\xff')", f"print('x'*{DHCP.MAX_BYTES + 1})"):
            self.executable(self.bus, body)
            with self.subTest(body=body), self.assertRaises(SERVERS.Pending):
                DHCP.native_query('describe', KERNEL.now() + 10, owner=':1.88', index=2)

    def test_query_completion_is_still_required_after_description_capture_eof(self):
        self.executable(self.bus, 'import os,time\nos.close(1);os.close(2);time.sleep(60)')
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.1), self.assertRaises(SERVERS.Pending):
            DHCP.native_query('describe', KERNEL.now() + 10, owner=':1.88', index=2)


class NativeObservationTests(PrivateNative):
    def fixtures(self, provider='192.168.50.1', state='bound', families=(4, 6), change_turn=0, wrong_route=False, node_edit=None, data_edit=None):
        node = document(provider)
        if node_edit:
            node_edit(node)
        node_path = self.root / 'description.json'
        node_path.write_text(json.dumps(node))
        count = self.root / 'count'
        if count.exists():
            count.unlink()
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
 result={{'type':'v','data':[{{'type':'s','data':{state!r} if family==4 else 'bound'}}]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.MANAGER,'DescribeLink','i','2']!r}:
 path=Path({str(count)!r});turn=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(turn))
 node=json.loads(Path({str(node_path)!r}).read_text())
 if turn=={change_turn}: node['Addresses'][0]['ConfigProvider']=[192,168,50,2]
 result={{'type':'s','data':[json.dumps(node)]}}
else: raise SystemExit(1)
print(json.dumps(result))""")
        data = kernel_data()
        if data_edit:
            data_edit(data)
        self.executable(self.ip, f"""import json,sys
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['ip',args])+'\\n')
if args[:2]!=['-j','-N']: raise SystemExit(1)
a=args[2:]
commands={KERNEL.COMMANDS!r}
data={data!r}
if a==['-4','route','get',{provider!r}]:
 row={{'dst':{provider!r},'dev':'eth1' if {wrong_route!r} else 'eth0'}}
 if {provider!r}=='10.0.0.1': row['gateway']='192.168.50.1'
 result=[row]
else:
 keys=[key for key,value in commands.items() if list(value)==a]
 if len(keys)!=1: raise SystemExit(1)
 result=data[keys[0]]
print(json.dumps(result))""")

    def test_full_private_delivery_runs_native_client_assignment_description_and_routes(self):
        self.fixtures()
        result = SERVERS.observe()
        self.assertEqual(result['dhcp4'], [{'interface': 'eth0', 'address': '192.168.50.1'}])
        self.assertEqual(result['source']['pid'], os.getpid())
        commands = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'bus' for kind, _ in commands), 41)
        self.assertEqual(sum(kind == 'ip' for kind, _ in commands), 42)
        self.assertEqual(sum('get' in args for kind, args in commands if kind == 'ip'), 2)
        self.assertEqual(sum('DescribeLink' in args for kind, args in commands if kind == 'bus'), 2)

    def test_full_private_relayed_identifier_requires_observed_gateway_binding(self):
        self.fixtures(provider='10.0.0.1')
        self.assertEqual(SERVERS.observe()['dhcp4'][0]['address'], '10.0.0.1')

    def test_zero_exit_native_wrong_route_missing_assignment_or_corrupt_provider_cannot_publish(self):
        for wrong_route, edit in ((True, None), (False, lambda node: node['Addresses'][0].update(Address=[192, 168, 50, 101])),
                                  (False, lambda node: node['Addresses'][0].update(ConfigProvider=[0, 0, 0, 0]))):
            self.fixtures(wrong_route=wrong_route, node_edit=edit)
            with self.subTest(wrong_route=wrong_route), self.assertRaises(SERVERS.Pending):
                SERVERS.observe()

    def test_second_native_provider_change_never_certifies_a_stale_endpoint(self):
        self.fixtures(change_turn=2)
        with self.assertRaises(SERVERS.Pending):
            SERVERS.observe()

    def test_static_and_bootstrap_private_delivery_do_not_guess_unicast_endpoints(self):
        for state, families in (('bound', ()), ('selecting', (4,))):
            self.fixtures(state=state, families=families)
            self.ledger.write_text('')
            with self.subTest(state=state, families=families):
                result = SERVERS.observe()
                self.assertEqual(result['dhcp4'], [])
                commands = [json.loads(line) for line in self.ledger.read_text().splitlines()]
                self.assertFalse(any('DescribeLink' in args or 'get' in args for _, args in commands))

    def test_real_private_wrong_kind_scope_cli_returns_pending_with_no_partial_stdout(self):
        self.fixtures(data_edit=lambda data: data['addresses'][1]['addr_info'][0].update(scope=[]))
        out, err = io.StringIO(), io.StringIO()
        with patch.object(SERVERS.sys, 'argv', ['dhcp_servers.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(SERVERS.main(), 75)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('pending', err.getvalue())


if __name__ == '__main__':
    unittest.main()
