import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from test_kernel import snapshot
from test_policy import POLICY

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_resolver', ROOT / 'Firewall/resolver.py')
RESOLVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESOLVER)
KERNEL = RESOLVER.KERNEL


def scope_snapshot(name='2', index=7):
    data = snapshot()
    interface = copy.deepcopy(data['links'][1])
    interface.update(ifindex=index, ifname=name, address='02:00:00:00:00:70')
    data['links'].append(interface)
    data['addresses'].append(copy.deepcopy(interface) | {'addr_info': [
        {'family': 'inet', 'local': '192.168.70.100', 'prefixlen': 24},
        {'family': 'inet6', 'local': 'fe80::700', 'prefixlen': 64}]})
    data['routes4'].append({'dst': '192.168.70.0/24', 'dev': name, 'table': '254', 'flags': []})
    data['routes6'].append({'dst': 'fe80::/64', 'dev': name, 'table': '254', 'flags': []})
    return data


class ConfigurationTests(unittest.TestCase):
    def parse(self, raw):
        return RESOLVER.parse_configuration(raw)

    def reject(self, raw):
        with self.assertRaises(RESOLVER.Pending):
            self.parse(raw)

    def test_explicit_ipv4_ipv6_scopes_options_and_inline_comments(self):
        raw = (b'# trusted source\n; another comment\n\n'
               b'nameserver 192.168.50.1 # IPv4\n'
               b'nameserver 2606:4700:4700::1111 ; IPv6\n'
               b'nameserver fe80::1%enp1.7\n'
               b'search example.test\ndomain example.test\nsortlist 192.168.50.0/24\n'
               b'options rotate use-vc ndots:15 timeout:30 attempts:5 # options\n')
        self.assertEqual(self.parse(raw), [('192.168.50.1', None),
                        ('2606:4700:4700::1111', None), ('fe80::1', 'enp1.7')])
        self.assertEqual(self.parse(b'nameserver fe80::1%2\n'), [('fe80::1', '2')])
        self.assertEqual(self.parse(b'options\nnameserver\t8.8.8.8\n'), [('8.8.8.8', None)])

    def test_glibc_column_zero_match_is_not_replaced_by_stripping(self):
        for raw in (b' nameserver 8.8.8.8\n', b'\tnameserver 8.8.8.8\n',
                    b'nameservers 8.8.8.8\n', b'nameserver8.8.8.8\n', b' # nameserver 8.8.8.8\n'):
            with self.subTest(raw=raw):
                self.reject(raw)
        self.assertEqual(self.parse(b' \t\nnameserver 8.8.8.8\n'), [('8.8.8.8', None)])

    def test_local_stub_implicit_defaults_and_empty_sources_remain_pending(self):
        for raw in (b'', b'# only a comment\n', b'search example.test\n',
                    b'nameserver 127.0.0.53\n', b'nameserver 127.0.0.1\n',
                    b'nameserver ::1\n', b'nameserver 0.0.0.0\n', b'nameserver ::\n',
                    b'nameserver 8.8.8.8\nnameserver 127.0.0.53\n'):
            with self.subTest(raw=raw):
                self.reject(raw)

    def test_nonunicast_noncanonical_and_encrypted_endpoints_are_refused(self):
        for token in ('224.0.0.1', '255.255.255.255', 'ff02::1', '::ffff:192.0.2.1',
                      '2606:4700:4700:0:0:0:0:1111', '192.168.050.1', '0x08080808',
                      'dns.example.test', '8.8.8.8:853', 'https://dns.example.test/dns-query'):
            with self.subTest(token=token):
                self.reject(('nameserver ' + token + '\n').encode())

    def test_scope_is_only_explicit_ipv6_link_local_and_bounded(self):
        for token in ('fe80::1', 'fe80::1%', 'fe80::1%eth0%eth1', 'fe80::1%-bad',
                      'fe80::1%eth0/path', 'fe80::1%' + 'x' * 16, '8.8.8.8%eth0',
                      '2606:4700:4700::1111%eth0'):
            with self.subTest(token=token):
                self.reject(('nameserver ' + token + '\n').encode())

    def test_invalid_unknown_no_reload_and_out_of_range_options_refuse(self):
        for option in ('no-reload', 'tls', 'timeout:0', 'timeout:31', 'attempts:0',
                       'attempts:6', 'ndots:16', 'ndots:-1', 'ndots:01', 'ndots:1:2',
                       'timeout:999999', 'timeout:', 'unknown'):
            with self.subTest(option=option):
                self.reject(('nameserver 8.8.8.8\noptions ' + option + '\n').encode())
        for option in RESOLVER.OPTIONS:
            self.assertEqual(self.parse(('nameserver 8.8.8.8\noptions ' + option + '\n').encode()), [('8.8.8.8', None)])

    def test_server_count_suffix_and_incomplete_directive_refusals(self):
        for raw in (b'nameserver\n', b'nameserver 8.8.8.8 extra\n', b'domain\nnameserver 8.8.8.8\n',
                    b'search\nnameserver 8.8.8.8\n', b'unknown value\nnameserver 8.8.8.8\n',
                    b'nameserver 8.8.8.8\n' * 4):
            with self.subTest(raw=raw):
                self.reject(raw)
        self.assertEqual(len(self.parse(b'nameserver 8.8.8.8\n' * 3)), 3)

    def test_bytes_ascii_line_and_total_limits_are_checked(self):
        for raw in ('nameserver 8.8.8.8\n', bytearray(b'nameserver 8.8.8.8\n'),
                    b'nameserver 8.8.8.8\r\n', b'nameserver 8.8.8.8\x00',
                    b'nameserver 8.8.8.8\x7f', b'nameserver 8.8.8.8\xff',
                    'search ignored\u2028nameserver 8.8.8.8\n'.encode(),
                    b'#' * (RESOLVER.MAX_LINE + 1), b'\n' * (RESOLVER.MAX_LINES + 1),
                    b'x' * (RESOLVER.MAX_FILE + 1)):
            with self.subTest(kind=type(raw).__name__, length=len(raw)):
                self.reject(raw)


class FileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-resolver-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.source = self.root / 'etc/resolv.conf'
        self.source.parent.mkdir(mode=0o700)
        self.target = self.root / 'run/NetworkManager/resolv.conf'
        self.target.parent.mkdir(parents=True, mode=0o700)
        (self.root / 'run').chmod(0o700)
        self.other = self.root / 'run/resolvconf/resolv.conf'
        self.other.parent.mkdir(mode=0o700)
        self.settings = [patch.object(RESOLVER, 'TRUST_ROOT', self.root),
                         patch.object(RESOLVER, 'TRUSTED_UID', os.geteuid()),
                         patch.object(RESOLVER, 'RESOLV_CONF', self.source),
                         patch.object(RESOLVER, 'TARGETS', {self.target, self.other})]
        for setting in self.settings:
            setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):
            setting.stop()
        self.directory.cleanup()

    def write(self, path=None, raw=b'nameserver 8.8.8.8\n'):
        path = self.source if path is None else path
        path.write_bytes(raw)
        path.chmod(0o600)

    def test_regular_file_is_read_with_native_metadata_and_digest(self):
        self.write()
        before = KERNEL.signature(self.source.lstat())
        metadata, raw = RESOLVER.read_configuration()
        self.assertEqual(raw, b'nameserver 8.8.8.8\n')
        self.assertEqual(metadata, {'path': str(self.source), 'signature': before, 'link': None,
                                   'sha256': hashlib.sha256(raw).hexdigest()})
        self.assertEqual(KERNEL.signature(self.source.lstat()), before)

    def test_exact_known_root_owned_single_links_accept_absolute_and_relative_targets(self):
        for target, spelling in ((self.target, str(self.target)), (self.other, '../run/resolvconf/resolv.conf')):
            with self.subTest(target=target):
                self.write(target)
                self.source.symlink_to(spelling)
                metadata, raw = RESOLVER.read_configuration()
                self.assertEqual(metadata['path'], str(target))
                self.assertEqual(metadata['link'], KERNEL.signature(self.source.lstat()))
                self.assertEqual(RESOLVER.parse_configuration(raw), [('8.8.8.8', None)])
                self.source.unlink()

    def test_unknown_symlink_target_and_symlink_chain_leave_victim_untouched(self):
        victim = self.root / 'victim'
        self.write(victim, b'unchanged victim\r\n')
        before = KERNEL.signature(victim.lstat())
        for destination in (victim, self.target):
            self.source.symlink_to(destination)
            if destination == self.target:
                self.target.symlink_to(victim)
            with self.assertRaises(RESOLVER.Pending):
                RESOLVER.read_configuration()
            self.assertEqual(victim.read_bytes(), b'unchanged victim\r\n')
            self.assertEqual(KERNEL.signature(victim.lstat()), before)
            self.source.unlink()

    def test_lexical_dotdot_cannot_substitute_a_different_native_symlink_target(self):
        self.write(self.target)
        alternate = self.root / 'elsewhere/run/NetworkManager/resolv.conf'
        alternate.parent.mkdir(parents=True)
        self.write(alternate, b'nameserver 9.9.9.9\n')
        intermediate = self.root / 'elsewhere/inner'
        intermediate.mkdir()
        (self.root / 'alias').symlink_to(intermediate, target_is_directory=True)
        spelling = str(self.root / 'alias/../run/NetworkManager/resolv.conf')
        self.source.symlink_to(spelling)
        before = KERNEL.signature(alternate.lstat())
        self.assertEqual(self.source.read_bytes(), b'nameserver 9.9.9.9\n')
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.read_configuration()
        self.assertEqual(alternate.read_bytes(), b'nameserver 9.9.9.9\n')
        self.assertEqual(KERNEL.signature(alternate.lstat()), before)

    def test_fifo_directory_socket_and_missing_file_are_finite_refusals(self):
        started = time.monotonic()
        with self.assertRaises(FileNotFoundError):
            RESOLVER.read_configuration()
        os.mkfifo(self.source, 0o600)
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.read_configuration()
        self.assertTrue(self.source.is_fifo())
        self.source.unlink()
        self.source.mkdir()
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.read_configuration()
        self.source.rmdir()
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(self.source))
            with self.assertRaises(RESOLVER.Pending):
                RESOLVER.read_configuration()
            self.source.unlink()
        self.assertLess(time.monotonic() - started, 2)

    def test_wrong_owner_leaf_and_writable_or_symbolic_ancestry_are_refused(self):
        self.write()
        with patch.object(RESOLVER, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(RESOLVER.Pending):
            RESOLVER.read_configuration()
        for path in (self.source, self.source.parent, self.root):
            previous = path.stat().st_mode & 0o777
            path.chmod(previous | 0o020)
            try:
                with self.subTest(path=path), self.assertRaises(RESOLVER.Pending):
                    RESOLVER.read_configuration()
            finally:
                path.chmod(previous)
        original = self.root / 'original-etc'
        self.source.parent.rename(original)
        self.source.parent.symlink_to(original, target_is_directory=True)
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.read_configuration()

    def test_noncanonical_and_outside_anchor_paths_are_refused(self):
        self.write()
        for path in (Path('relative/resolv.conf'), self.root.parent / 'outside', self.root / 'etc/../etc/resolv.conf'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                RESOLVER.trusted(path)

    def test_bounded_file_read_refuses_oversized_regular_payload(self):
        self.write(raw=b'#' * (RESOLVER.MAX_FILE + 1))
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.read_configuration()
        self.assertEqual(self.source.stat().st_size, RESOLVER.MAX_FILE + 1)

    def test_descriptor_path_and_source_link_changes_are_not_certified(self):
        self.write(self.target)
        self.source.symlink_to(self.target)
        native_read = os.read
        changed = False
        def replace_source(fd, count):
            nonlocal changed
            data = native_read(fd, count)
            if not changed:
                changed = True
                self.source.unlink()
                self.source.symlink_to(self.other)
            return data
        with patch.object(RESOLVER.os, 'read', side_effect=replace_source), self.assertRaises(RESOLVER.Pending):
            RESOLVER.read_configuration()
        self.source.unlink()
        self.write()
        changed = False
        def replace_payload(fd, count):
            nonlocal changed
            data = native_read(fd, count)
            if not changed:
                changed = True
                replacement = self.root / 'replacement'
                self.write(replacement)
                replacement.replace(self.source)
            return data
        with patch.object(RESOLVER.os, 'read', side_effect=replace_payload), self.assertRaises(RESOLVER.Pending):
            RESOLVER.read_configuration()

    def test_read_and_close_errors_propagate_without_certifying_payload(self):
        self.write()
        with patch.object(RESOLVER.os, 'read', side_effect=OSError('read failed')), self.assertRaises(OSError):
            RESOLVER.read_configuration()
        native_close = os.close
        def failed_close(fd):
            native_close(fd)
            raise OSError('close failed')
        with patch.object(RESOLVER.os, 'close', side_effect=failed_close), self.assertRaises(OSError):
            RESOLVER.read_configuration()


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.interfaces = KERNEL.normalize(snapshot())
        self.row = {'dst': '8.8.8.8', 'dev': 'eth0', 'gateway': '192.168.50.1',
                    'prefsrc': '192.168.50.100', 'flags': [], 'uid': os.geteuid(), 'cache': []}

    def bind(self, row=None, destination='8.8.8.8', scope=None):
        return RESOLVER.bind_route(destination, scope, [self.row if row is None else row], self.interfaces)

    def test_positive_gateway_direct_ipv6_and_scoped_link_local_bindings(self):
        self.assertEqual(self.bind(), {'interface': 'eth0', 'address': '8.8.8.8'})
        for destination, extra, scope in (
                ('192.168.50.1', {}, None), ('fd50::20', {}, None),
                ('2606:4700:4700::1111', {'gateway': 'fe80::1', 'from': '::'}, None),
                ('fe80::1', {}, 'eth0')):
            row = {'dst': destination, 'dev': 'eth0', 'flags': [], **extra}
            self.assertEqual(self.bind(row, destination, scope), {'interface': 'eth0', 'address': destination})
        for route_type in ('1', 'unicast'):
            for table in (254, '254', 'main', 253, '253', 'default'):
                self.assertEqual(self.bind(self.row | {'type': route_type, 'table': table})['interface'], 'eth0')

    def test_missing_multiple_nonlist_and_unknown_route_fields_refuse(self):
        for rows in ([], [self.row, self.row], {}, None, [self.row | {'nexthops': []}], [self.row | {'encap': {}}], [{}]):
            with self.subTest(rows=rows), self.assertRaises(RESOLVER.Pending):
                RESOLVER.bind_route('8.8.8.8', None, rows, self.interfaces)

    def test_negative_local_wrong_destination_and_unsupported_tables_refuse(self):
        for extra in ({'type': 'local'}, {'type': '2'}, {'type': 'blackhole'}, {'type': 'throw'},
                      {'dst': '9.9.9.9'}, {'dst': '8.8.8.8/32'}, {'table': 'local'}, {'table': 100}):
            with self.subTest(extra=extra), self.assertRaises(RESOLVER.Pending):
                self.bind(self.row | extra)

    def test_route_flags_cache_source_and_uid_ambiguity_refuse(self):
        for extra in ({'flags': ['linkdown']}, {'flags': 'onlink'}, {'cache': [{'expires': 1}]},
                      {'cache': {}}, {'from': '192.168.50.100'}, {'uid': os.geteuid() + 1},
                      {'uid': True}, {'src': '192.168.50.200'}, {'prefsrc': '::1'}):
            with self.subTest(extra=extra), self.assertRaises(RESOLVER.Pending):
                self.bind(self.row | extra)
        self.assertEqual(self.bind(self.row | {'src': '192.168.50.100', 'from': '0.0.0.0'})['interface'], 'eth0')

    def test_unknown_inactive_and_wrong_scoped_interfaces_refuse(self):
        for dev in ('lo', 'eth9', True, []):
            with self.subTest(dev=dev), self.assertRaises(RESOLVER.Pending):
                self.bind(self.row | {'dev': dev})
        with self.assertRaises(RESOLVER.Pending):
            self.bind(scope='eth1')
        self.interfaces[0]['up'] = False
        with self.assertRaises(RESOLVER.Pending):
            self.bind()

    def test_unobserved_gateway_and_nonlink_direct_route_do_not_infer_permission(self):
        for extra in ({'gateway': '192.168.50.99'}, {'gateway': '::1'}, {'gateway': '8.8.4.4'}):
            with self.subTest(extra=extra), self.assertRaises(RESOLVER.Pending):
                self.bind(self.row | extra)
        row = copy.deepcopy(self.row)
        row.pop('gateway')
        with self.assertRaises(RESOLVER.Pending):
            self.bind(row)

    def test_scope_name_and_index_match_exact_inventory_and_unknown_scopes_refuse(self):
        for scope in ('eth0', '2'):
            self.assertEqual(RESOLVER.scoped_interface(scope, self.interfaces), 'eth0')
        self.assertIsNone(RESOLVER.scoped_interface(None, self.interfaces))
        for scope in ('0', '02', '3', 'eth1'):
            with self.subTest(scope=scope), self.assertRaises(RESOLVER.Pending):
                RESOLVER.scoped_interface(scope, self.interfaces)

    def test_decimal_interface_name_takes_precedence_over_another_interface_index(self):
        interfaces = KERNEL.normalize(scope_snapshot())
        self.assertEqual({entry['name']: entry['index'] for entry in interfaces}, {'eth0': 2, '2': 7})
        self.assertEqual(RESOLVER.scoped_interface('2', interfaces), '2')
        self.assertEqual(RESOLVER.scoped_interface('7', interfaces), '2')
        self.assertEqual(RESOLVER.scoped_interface('eth0', interfaces), 'eth0')

    def test_zero_and_noncanonical_decimal_spellings_are_valid_exact_interface_names(self):
        for name in ('0', '02'):
            with self.subTest(name=name):
                interfaces = KERNEL.normalize(scope_snapshot(name))
                self.assertEqual(RESOLVER.scoped_interface(name, interfaces), name)
        for scope in ('0', '02', '7', 'unknown'):
            with self.subTest(scope=scope), self.assertRaises(RESOLVER.Pending):
                RESOLVER.scoped_interface(scope, self.interfaces)

    def test_duplicate_exact_names_cannot_fall_back_to_a_numeric_index(self):
        interfaces = KERNEL.normalize(scope_snapshot())
        interfaces.append(copy.deepcopy(interfaces[0]))
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.scoped_interface('2', interfaces)

    def test_alternative_decimal_name_uses_observed_name_index_before_fallback(self):
        interfaces = KERNEL.normalize(scope_snapshot('eth1'))
        names = {'lo': 1, 'eth0': 2, 'eth1': 7, '2': 7}
        self.assertEqual(RESOLVER.scoped_interface('2', interfaces, names), 'eth1')
        self.assertEqual(RESOLVER.scoped_interface('7', interfaces, names), 'eth1')
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.scoped_interface('eth0', interfaces, names | {'eth0': 7})

    def test_loopback_decimal_alias_cannot_fall_back_to_an_admitted_index(self):
        names = {'lo': 1, 'eth0': 2, '2': 1}
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.scoped_interface('2', self.interfaces, names)


class TopologyTests(unittest.TestCase):
    def test_complete_name_inventory_preserves_aliases_and_both_rounds(self):
        data = scope_snapshot('eth1')
        data['links'][2]['altnames'] = ['2', '02', 'an-alias-longer-than-fifteen']
        calls = []
        def query(name, deadline):
            calls.append((name, deadline))
            return copy.deepcopy(data[name])
        result = RESOLVER.resolver_topology(KERNEL.now() + 30, query=query)
        self.assertEqual(result['scope_names'], {'lo': 1, 'eth0': 2, 'eth1': 7, '2': 7, '02': 7})
        self.assertEqual(result['interfaces'], KERNEL.normalize(data))
        self.assertEqual([name for name, _ in calls], list(KERNEL.COMMANDS) * 2)
        self.assertEqual(len({deadline for _, deadline in calls}), 1)

    def test_changed_alias_mapping_requires_retry_when_kernel_facts_are_unchanged(self):
        first = scope_snapshot('eth1')
        first['links'][2]['altnames'] = ['2']
        second = copy.deepcopy(first)
        second['links'][2]['altnames'] = []
        second['links'][1]['altnames'] = ['2']
        self.assertEqual(KERNEL.normalize(first), KERNEL.normalize(second))
        calls = 0
        def query(name, deadline):
            nonlocal calls
            data = first if calls < len(KERNEL.COMMANDS) else second
            calls += 1
            return copy.deepcopy(data[name])
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.resolver_topology(KERNEL.now() + 30, query=query)

    def test_duplicate_wrong_kind_and_oversized_name_inventories_refuse(self):
        for aliases in (None, '2', [True], [''], ['x' * 128], ['eth0'], ['2', '2'], ['2'] * KERNEL.MAX_ITEMS):
            data = scope_snapshot('eth1')
            data['links'][2]['altnames'] = aliases
            with self.subTest(aliases=repr(aliases)[:60]), self.assertRaises(RESOLVER.Pending):
                RESOLVER.scope_names(data['links'])
        data = snapshot()
        data['links'][0]['altnames'] = ['2']
        self.assertEqual(RESOLVER.scope_names(data['links'])['2'], 1)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.raw = b'nameserver 8.8.8.8\nnameserver fe80::1%2\n'
        self.source = {'path': '/etc/resolv.conf', 'sha256': hashlib.sha256(self.raw).hexdigest(),
                       'signature': (1, 2), 'link': None}
        self.calls = []
        self.data = snapshot()
        self.reads = 0
        self.topologies = 0
        self.routes = 0

    def read(self):
        self.reads += 1
        self.calls.append(('read',))
        return copy.deepcopy(self.source), self.raw

    def topology(self, deadline):
        self.topologies += 1
        self.calls.append(('topology', deadline))
        def query(name, inherited):
            self.calls.append(('ip-show', name, inherited))
            return copy.deepcopy(self.data[name])
        return KERNEL.observe(query=query, scope=KERNEL.namespace, deadline=deadline)

    def route(self, destination, interface, deadline):
        self.routes += 1
        self.calls.append(('route', destination, interface, deadline))
        return [{'dst': destination, 'dev': 'eth0', 'flags': [], 'cache': [],
                 **({'gateway': '192.168.50.1'} if destination == '8.8.8.8' else {})}]

    def observe(self, **replacements):
        return RESOLVER.observe(read=replacements.get('read', self.read),
                                topology=replacements.get('topology', self.topology),
                                route=replacements.get('route', self.route))

    def test_complete_observation_uses_decimal_name_instead_of_the_colliding_index(self):
        self.data = scope_snapshot()
        self.raw = b'nameserver fe80::1%2\n'
        self.source['sha256'] = hashlib.sha256(self.raw).hexdigest()
        def route(destination, interface, deadline):
            self.routes += 1
            self.calls.append(('route', destination, interface, deadline))
            # Both interfaces have a valid direct fe80::/64 link, so a
            # wrongly forced eth0 route would still pass native postconditions.
            return [{'dst': destination, 'dev': interface, 'flags': [], 'cache': []}]
        result = self.observe(route=route)
        self.assertEqual(result['dns'], [{'interface': '2', 'address': 'fe80::1'}])
        self.assertEqual([entry[2] for entry in self.calls if entry[0] == 'route'], ['2', '2'])
        self.assertEqual((self.reads, self.topologies, self.routes), (3, 2, 2))
        self.assertEqual(len([entry for entry in self.calls if entry[0] == 'ip-show']), 40)

    def test_inactive_decimal_name_cannot_fall_back_to_a_healthy_index_target(self):
        self.data = scope_snapshot()
        for collection in ('links', 'addresses'):
            self.data[collection][-1]['flags'].remove('LOWER_UP')
        self.raw = b'nameserver fe80::1%2\n'
        def route(destination, interface, deadline):
            return [{'dst': destination, 'dev': interface, 'flags': []}]
        with self.assertRaises(RESOLVER.Pending):
            self.observe(route=route)

    def test_unknown_numeric_scope_refuses_before_any_lookup(self):
        self.data = scope_snapshot()
        self.raw = b'nameserver fe80::1%9\n'
        with self.assertRaises(RESOLVER.Pending):
            self.observe()
        self.assertEqual(self.routes, 0)

    def test_complete_configuration_kernel_and_bound_route_rounds_share_one_deadline(self):
        result = self.observe()
        self.assertEqual(result['schema'], 'debian13s4-resolver-1')
        self.assertEqual(result['dns'], [{'interface': 'eth0', 'address': '8.8.8.8'},
                                        {'interface': 'eth0', 'address': 'fe80::1'}])
        self.assertEqual((self.reads, self.topologies, self.routes), (3, 2, 4))
        self.assertEqual(len([entry for entry in self.calls if entry[0] == 'ip-show']), 40)
        deadlines = [entry[-1] for entry in self.calls if entry[0] in ('topology', 'route')]
        self.assertEqual(len(set(deadlines)), 1)
        self.assertEqual([entry[2] for entry in self.calls if entry[0] == 'route'], [None, 'eth0', None, 'eth0'])
        with self.assertRaises(POLICY.InvalidTopology):
            POLICY.compile_policy(json.dumps(result).encode())

    def test_duplicate_servers_are_checked_then_deduplicated_and_sorted(self):
        self.raw = b'nameserver 8.8.8.8\n' * 3
        self.source['sha256'] = hashlib.sha256(self.raw).hexdigest()
        self.assertEqual(self.observe()['dns'], [{'interface': 'eth0', 'address': '8.8.8.8'}])
        self.assertEqual(self.routes, 6)

    def test_changed_configuration_bytes_metadata_or_link_never_publishes(self):
        for change in ('bytes', 'signature', 'link', 'path', 'sha256'):
            calls = 0
            def changed():
                nonlocal calls
                calls += 1
                metadata, raw = self.read()
                if calls == 2:
                    if change == 'bytes':
                        raw = b'nameserver 9.9.9.9\n'
                    else:
                        metadata[change] = 'changed'
                return metadata, raw
            with self.subTest(change=change), self.assertRaises(RESOLVER.Pending):
                self.observe(read=changed)

    def test_last_configuration_change_after_route_comparison_is_pending(self):
        calls = 0
        def changed():
            nonlocal calls
            calls += 1
            metadata, raw = self.read()
            return (metadata, raw) if calls < 3 else (metadata, b'nameserver 9.9.9.9\n')
        with self.assertRaises(RESOLVER.Pending):
            self.observe(read=changed)

    def test_kernel_change_and_native_topology_failure_remain_pending(self):
        def changed(deadline):
            result = self.topology(deadline)
            if self.topologies == 2:
                result['interfaces'][0]['mac'] = '02:00:00:00:00:99'
            return result
        with self.assertRaises(RESOLVER.Pending):
            self.observe(topology=changed)
        def failed(deadline):
            raise RESOLVER.Pending('native topology failure')
        with self.assertRaises(RESOLVER.Pending):
            self.observe(topology=failed)

    def test_changed_route_interface_gateway_and_nonsecurity_metadata_are_pending(self):
        for change in ({'dev': 'eth1'}, {'gateway': '192.168.50.99'}, {'metric': 100}, {'uid': os.geteuid()}):
            calls = 0
            def changed(destination, interface, deadline):
                nonlocal calls
                calls += 1
                result = self.route(destination, interface, deadline)
                if calls == 3:
                    result[0].update(change)
                return result
            with self.subTest(change=change), self.assertRaises(RESOLVER.Pending):
                self.observe(route=changed)

    def test_scoped_unknown_interface_and_failed_route_have_no_default_binding(self):
        self.raw = b'nameserver fe80::1%eth9\n'
        with self.assertRaises(RESOLVER.Pending):
            self.observe()
        self.assertEqual(self.routes, 0)
        self.raw = b'nameserver 8.8.8.8\n'
        def failed(destination, interface, deadline):
            raise RESOLVER.Pending('native route failure')
        with self.assertRaises(RESOLVER.Pending):
            self.observe(route=failed)

    def test_stub_configuration_is_refused_before_any_kernel_queries(self):
        self.raw = b'nameserver 127.0.0.53\n'
        with self.assertRaises(RESOLVER.Pending):
            self.observe()
        self.assertEqual((self.topologies, self.routes), (0, 0))

    def test_namespace_change_and_total_window_expiry_are_pending(self):
        identity = KERNEL.namespace()
        with patch.object(KERNEL, 'namespace', side_effect=[identity] * 4 + [identity + 1]), self.assertRaises(RESOLVER.Pending):
            self.observe()
        calls = 0
        def clock():
            nonlocal calls
            calls += 1
            return 1000 if calls > 5 else 10
        with patch.object(KERNEL, 'now', side_effect=clock), self.assertRaises(RESOLVER.Pending):
            self.observe()

    def test_cli_returns_usage_or_pending_without_partial_stdout(self):
        import io
        with patch.object(RESOLVER.sys, 'argv', ['resolver.py', 'unsafe']), patch.object(RESOLVER, 'observe') as observe:
            self.assertEqual(RESOLVER.main(), 64)
            observe.assert_not_called()
        for error in (RESOLVER.Pending('not ready'), OSError('read failed')):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(RESOLVER.sys, 'argv', ['resolver.py']), patch.object(RESOLVER, 'observe', side_effect=error), patch.object(RESOLVER.sys, 'stdout', stdout), patch.object(RESOLVER.sys, 'stderr', stderr):
                self.assertEqual(RESOLVER.main(), 75)
            self.assertEqual(stdout.getvalue(), '')
            self.assertIn('pending', stderr.getvalue())

    def test_cli_serializes_the_same_partial_record_after_real_predicates(self):
        import io
        result = self.observe()
        stdout = io.StringIO()
        with patch.object(RESOLVER.sys, 'argv', ['resolver.py']), patch.object(RESOLVER, 'observe', return_value=result), patch.object(RESOLVER.sys, 'stdout', stdout):
            self.assertEqual(RESOLVER.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue()), result)


class NativeObservationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-dns-native-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.source = self.root / 'resolv.conf'
        self.source.write_bytes(b'nameserver 8.8.8.8\nnameserver fe80::1%eth0\n')
        self.source.chmod(0o600)
        self.binary = self.root / 'ip'
        self.ledger = self.root / 'calls.jsonl'
        self.settings = [patch.object(RESOLVER, 'TRUST_ROOT', self.root),
                         patch.object(RESOLVER, 'TRUSTED_UID', os.geteuid()),
                         patch.object(RESOLVER, 'RESOLV_CONF', self.source),
                         patch.object(KERNEL, 'TRUST_ROOT', self.root),
                         patch.object(KERNEL, 'TRUSTED_UID', os.geteuid()),
                         patch.object(KERNEL, 'IP_BINARY', self.binary)]
        for setting in self.settings:
            setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):
            setting.stop()
        self.directory.cleanup()

    def executable(self, route_suffix='', data=None):
        data = snapshot() if data is None else data
        script = ("#!/usr/bin/python3\nimport json,os,sys\n"
                  f"data={data!r}\ncommands={KERNEL.COMMANDS!r}\n"
                  f"with open({str(self.ledger)!r},'a') as stream: stream.write(json.dumps({{'argv':sys.argv[1:],'env':dict(os.environ),'pid':os.getpid(),'sid':os.getsid(0)}})+'\\n')\n"
                  "argv=tuple(sys.argv[3:])\n"
                  "if len(argv)>=4 and argv[1:3]==('route','get'):\n"
                  " destination=argv[3]\n"
                  " if destination=='fe80::1' and (len(argv)!=6 or argv[:5]!=('-6','route','get','fe80::1','oif') or argv[5] not in [row['ifname'] for row in data['links'] if row['ifname']!='lo']): sys.exit(20)\n"
                  " if destination=='8.8.8.8' and argv!=('-4','route','get','8.8.8.8'): sys.exit(21)\n"
                  " result=[{'dst':destination,'dev':argv[5] if destination=='fe80::1' else 'eth0','flags':[],'cache':[],'uid':os.geteuid()}]\n"
                  " if destination=='8.8.8.8': result[0]['gateway']='192.168.50.1'\n"
                  + ''.join(' '+line+'\n' for line in route_suffix.splitlines()) +
                  "else:\n"
                  " matches=[key for key,value in commands.items() if value==argv]\n"
                  " if len(matches)!=1: sys.exit(22)\n"
                  " result=data[matches[0]]\n"
                  "print(json.dumps(result))\n")
        self.binary.write_text(script)
        self.binary.chmod(0o700)

    def test_complete_private_native_primary_decimal_scope_uses_name_not_index(self):
        self.source.write_bytes(b'nameserver fe80::1%2\n')
        self.executable(data=scope_snapshot())
        result = RESOLVER.observe()
        self.assertEqual(result['dns'], [{'interface': '2', 'address': 'fe80::1'}])
        ledger = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(len(ledger), 42)
        self.assertEqual([entry['argv'] for entry in ledger if 'get' in entry['argv']],
                         [['-j', '-N', '-6', 'route', 'get', 'fe80::1', 'oif', '2']] * 2)

    def test_complete_private_native_decimal_alias_is_bound_to_its_actual_interface(self):
        self.source.write_bytes(b'nameserver fe80::1%2\n')
        data = scope_snapshot('eth1')
        data['links'][2]['altnames'] = ['2']
        self.executable(data=data)
        result = RESOLVER.observe()
        self.assertEqual(result['dns'], [{'interface': 'eth1', 'address': 'fe80::1'}])
        self.assertEqual(result['kernel']['scope_names']['2'], 7)
        ledger = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(len(ledger), 42)
        self.assertEqual([entry['argv'][-1] for entry in ledger if 'get' in entry['argv']], ['eth1', 'eth1'])

    def test_complete_private_native_loopback_alias_refuses_before_route_lookup(self):
        self.source.write_bytes(b'nameserver fe80::1%2\n')
        data = snapshot()
        data['links'][0]['altnames'] = ['2']
        self.executable(data=data)
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.observe()
        ledger = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(len(ledger), 20)
        self.assertFalse(any('get' in entry['argv'] for entry in ledger))

    def test_complete_native_capture_file_and_production_predicates_without_host_network_commands(self):
        self.executable()
        with patch.dict(os.environ, {'DEBIAN13S4_DNS_PARENT': 'excluded'}):
            result = RESOLVER.observe()
        self.assertEqual(result['dns'], [{'interface': 'eth0', 'address': '8.8.8.8'},
                                        {'interface': 'eth0', 'address': 'fe80::1'}])
        ledger = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(len(ledger), 44)
        self.assertEqual(sum('get' in entry['argv'] for entry in ledger), 4)
        for entry in ledger:
            self.assertEqual(entry['argv'][:2], ['-j', '-N'])
            self.assertEqual(entry['pid'], entry['sid'])
            self.assertNotIn('DEBIAN13S4_DNS_PARENT', entry['env'])
        self.assertEqual(result['source']['sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_zero_exit_unobserved_native_gateway_cannot_publish_dns(self):
        self.executable("result[0]['gateway']='192.168.50.99'")
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.observe()
        self.assertEqual(len(self.ledger.read_text().splitlines()), 21)

    def test_native_route_warning_and_timeout_are_pending_with_no_cli_stdout(self):
        import io
        for suffix in ("print('ambiguous lookup',file=sys.stderr)", "import time; time.sleep(10)"):
            self.executable(suffix)
            stdout, stderr = io.StringIO(), io.StringIO()
            started = time.monotonic()
            with patch.object(KERNEL, 'QUERY_SECONDS', 1), patch.object(RESOLVER.sys, 'argv', ['resolver.py']), patch.object(RESOLVER.sys, 'stdout', stdout), patch.object(RESOLVER.sys, 'stderr', stderr):
                self.assertEqual(RESOLVER.main(), 75)
            self.assertEqual(stdout.getvalue(), '')
            self.assertIn('pending', stderr.getvalue())
            self.assertLess(time.monotonic() - started, 5)

    def test_native_source_replacement_between_read_and_query_never_certifies(self):
        self.executable(f"from pathlib import Path; Path({str(self.source)!r}).write_text('nameserver 9.9.9.9\\n')")
        with self.assertRaises(RESOLVER.Pending):
            RESOLVER.observe()


if __name__ == '__main__':
    unittest.main()
