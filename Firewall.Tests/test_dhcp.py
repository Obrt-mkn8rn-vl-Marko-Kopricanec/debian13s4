import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

from test_kernel import snapshot

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_dhcp', ROOT / 'Firewall/dhcp.py')
DHCP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DHCP)
KERNEL = DHCP.KERNEL


def value(signature, data):
    return {'type': signature, 'data': [data]}


def prop(signature, data):
    return value('v', {'type': signature, 'data': data})


def xml(families=(4, 6), declaration=True):
    body = '<node><interface name="org.freedesktop.DBus.Peer"><method name="Ping"/><method name="GetMachineId"><arg type="s" direction="out"/></method></interface>'
    body += '<interface name="org.freedesktop.DBus.Introspectable"><method name="Introspect"><arg type="s" direction="out"/></method></interface>'
    body += '<interface name="org.freedesktop.DBus.Properties"><method name="Get"/><method name="GetAll"/><method name="Set"/></interface>'
    body += f'<interface name="{DHCP.LINK}"><property name="AdministrativeState" type="s" access="read"/></interface>'
    for family in families:
        body += f'<interface name="{DHCP.CLIENTS[family]}"><property name="State" type="s" access="read"><annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="true"/></property></interface>'
    return (DHCP.DOCTYPE if declaration else '') + body + '</node>'


def replies(operation, deadline, owner=None, index=None, families=(4, 6)):
    if operation == 'owner':
        return value('s', ':1.88')
    if operation == 'pid':
        return value('u', os.getpid())
    if operation == 'namespace':
        return prop('t', KERNEL.namespace())
    if operation == 'links':
        return value('a(iso)', [[2, 'eth0', DHCP.link_path(2)], [1, 'lo', DHCP.link_path(1)]])
    if operation == 'introspect':
        return value('s', xml(families))
    if operation == 'admin':
        return prop('s', 'configured')
    if operation.startswith('state'):
        assert int(operation[-1]) in families, 'absent client must not be queried'
        return prop('s', 'bound')
    raise AssertionError(operation)


class ParsingTests(unittest.TestCase):
    def test_link_inventory_checks_native_order_types_names_and_exact_object_binding(self):
        result = DHCP.links(replies('links', 0))
        self.assertEqual([row['name'] for row in result], ['eth0', 'lo'])
        self.assertEqual(result[0]['index'], 2)
        self.assertEqual(DHCP.link_path(2147483647), DHCP.OBJECT + '/link/_2147483647')

    def test_indices_bool_zero_negative_overflow_and_guessable_object_aliases_refuse(self):
        for index in (True, 0, -1, 2147483648, '2', 2.0, None):
            with self.subTest(index=index), self.assertRaises(DHCP.Pending):
                DHCP.link_path(index)
        for path in ('/', DHCP.OBJECT + '/link/2', DHCP.OBJECT + '/link/_02', DHCP.link_path(3), None):
            rows = replies('links', 0)
            rows['data'][0][0][2] = path
            with self.subTest(path=path), self.assertRaises(DHCP.Pending):
                DHCP.links(rows)

    def test_empty_duplicate_incomplete_malformed_or_excessive_link_inventories_refuse(self):
        ordinary = replies('links', 0)['data'][0]
        for rows in ([], None, 'links', [None], [[1]], ordinary + [ordinary[0]],
                     [ordinary[0]], [[2, 'lo', DHCP.link_path(2)], ordinary[0]], ordinary * 17):
            with self.subTest(rows=type(rows).__name__), self.assertRaises(DHCP.Pending):
                DHCP.links(value('a(iso)', rows))
        for name in ('--eth0', 'a/b', 'x' * 16, 'eth0\n', 1):
            rows = copy.deepcopy(ordinary)
            rows[0][1] = name
            with self.subTest(name=name), self.assertRaises(DHCP.Pending):
                DHCP.links(value('a(iso)', rows))

    def test_native_xml_has_explicit_static_single_family_and_dual_client_cases(self):
        for families in ((), (4,), (6,), (4, 6)):
            for declaration in (True, False):
                document = xml(families, declaration)
                with self.subTest(families=families, declaration=declaration):
                    self.assertEqual(DHCP.client_interfaces(value('s', document)), (document, set(families)))

    def test_dtd_entities_processing_instructions_and_comment_refuse_without_expansion(self):
        for prefix in ('<!DOCTYPE node [<!ENTITY x "value">]>', '<!ENTITY x "value">',
                       '<?xml version="1.0"?>', '<!--hidden-->', '<!DOCTYPE node SYSTEM "file:///etc/passwd">'):
            with self.subTest(prefix=prefix), self.assertRaises(DHCP.Pending):
                DHCP.client_interfaces(value('s', prefix + xml(declaration=False)))
        with self.assertRaises(DHCP.Pending):
            DHCP.client_interfaces(value('s', xml().replace('bound', '&x;') + '&x;'))

    def test_unknown_or_duplicate_interface_server_role_and_nested_inventory_refuse(self):
        extra = [f'<interface name="{DHCP.CLIENTS[4]}"/>', f'<interface name="{DHCP.SERVICE}.DHCPServer"/>',
                 '<interface name="other.Client"/>', '<node name="_3"/>', '<interface name="other"><interface name="nested"/></interface>']
        for item in extra:
            with self.subTest(item=item), self.assertRaises(DHCP.Pending):
                DHCP.client_interfaces(value('s', xml().replace('</node>', item + '</node>')))

    def test_missing_core_interface_methods_link_property_and_state_contract_refuse(self):
        for old, new in (('<method name="Ping"/>', ''), ('<method name="GetAll"/>', ''),
                         ('<property name="AdministrativeState" type="s" access="read"/>', ''),
                         ('name="State" type="s" access="read"', 'name="State" type="u" access="read"'),
                         ('name="State" type="s" access="read"', 'name="Other" type="s" access="read"'),
                         ('name="State" type="s" access="read"', 'name="State" type="s" access="readwrite"'),
                         ('<node>', '<node name="wrong">'), ('<method name="Ping"/>', '<method/>')):
            with self.subTest(old=old, new=new), self.assertRaises(DHCP.Pending):
                DHCP.client_interfaces(value('s', xml().replace(old, new)))
        with self.assertRaises(DHCP.Pending):
            DHCP.client_interfaces(value('s', '<node/>'))

    def test_xml_size_element_depth_encoding_and_parse_failures_are_pending(self):
        for text in ('<node>', None, '\ud800', '<node>bad</node>', xml() + 'x' * DHCP.MAX_BYTES,
                     xml().replace('</node>', '<interface name="other"/>' * DHCP.MAX_XML_ITEMS + '</node>')):
            with self.subTest(type=type(text).__name__), self.assertRaises((DHCP.Pending, UnicodeError)):
                DHCP.client_interfaces(value('s', text))
        with patch.object(DHCP, 'MAX_XML_ITEMS', 2), self.assertRaises(DHCP.Pending):
            DHCP.client_interfaces(value('s', xml()))

    def test_properties_use_single_variant_native_signatures_and_unwrapped_scalars(self):
        self.assertEqual(DHCP.variant(prop('s', 'bound'), 's'), 'bound')
        for message in (value('s', 'bound'), prop('u', 1), {'type': 'v', 'data': []},
                        {'type': 'v', 'data': [{'type': 's', 'data': 'bound', 'extra': 1}]},
                        {'type': 'v', 'data': [{'data': 'bound'}]}, {'type': 'v', 'data': [None]}):
            with self.subTest(message=message), self.assertRaises(DHCP.Pending):
                DHCP.variant(message, 's')


class InventoryTests(unittest.TestCase):
    def read(self, query=replies, scope=DHCP.TIMESYNC.process_scope):
        return DHCP.read_inventory(KERNEL.now() + 30, query=query, scope=scope)

    def test_complete_read_pins_owner_pid_namespace_link_indices_and_all_client_states(self):
        calls = []
        def query(operation, deadline, owner=None, index=None):
            calls.append((operation, deadline, owner, index))
            return replies(operation, deadline, owner, index)
        result = self.read(query)
        self.assertEqual(result['namespace'], KERNEL.namespace())
        self.assertEqual(result['pid'], os.getpid())
        self.assertEqual(result['interfaces'][0], {'name': 'eth0', 'index': 2, 'path': DHCP.link_path(2),
                         'administrative': 'configured', 'dhcp4': True, 'dhcp6': True, 'state4': 'bound', 'state6': 'bound'})
        self.assertEqual([op for op, *_ in calls], ['owner', 'pid', 'namespace', 'links', 'introspect', 'admin', 'state4', 'state6', 'introspect', 'links', 'namespace', 'pid', 'owner'])
        self.assertEqual(len({deadline for _, deadline, *_ in calls}), 1)
        self.assertTrue(all(index is None or index == 2 for *_, index in calls))

    def test_static_and_single_family_absence_is_positive_introspection_without_failed_reads(self):
        for families in ((), (4,), (6,)):
            result = self.read(lambda op, deadline, **kw: replies(op, deadline, **kw, families=families))
            row = result['interfaces'][0]
            with self.subTest(families=families):
                for family in (4, 6):
                    self.assertEqual(row['dhcp' + str(family)], family in families)
                    self.assertEqual(row['state' + str(family)], 'bound' if family in families else None)

    def test_every_pinned_native_state_including_stopped_is_an_instance_not_a_lease_claim(self):
        for family in (4, 6):
            for state in DHCP.STATES[family]:
                def query(op, deadline, **kw):
                    return prop('s', state) if op == 'state' + str(family) else replies(op, deadline, **kw)
                with self.subTest(family=family, state=state):
                    row = self.read(query)['interfaces'][0]
                    self.assertTrue(row['dhcp' + str(family)])
                    self.assertEqual(row['state' + str(family)], state)

    def test_unknown_disabled_wrong_type_or_wrong_family_state_never_becomes_absence(self):
        for state in ('disabled', 'future-state', '', None, True, ['bound'], 1):
            def query(op, deadline, **kw):
                return prop('s', state) if op == 'state4' else replies(op, deadline, **kw)
            with self.subTest(state=state), self.assertRaises(DHCP.Pending):
                self.read(query)
        with self.assertRaises(DHCP.Pending):
            self.read(lambda op, deadline, **kw: prop('s', 'renew') if op == 'state4' else replies(op, deadline, **kw))

    def test_unmanaged_failed_lingering_unknown_and_nonstrings_admin_states_refuse(self):
        for state in ('unmanaged', 'failed', 'linger', 'pending', '', None, True):
            with self.subTest(state=state), self.assertRaises(DHCP.Pending):
                self.read(lambda op, deadline, **kw: prop('s', state) if op == 'admin' else replies(op, deadline, **kw))
        self.assertEqual(self.read(lambda op, deadline, **kw: prop('s', 'configuring') if op == 'admin' else replies(op, deadline, **kw))['interfaces'][0]['administrative'], 'configuring')

    def test_changed_introspection_can_neither_erase_nor_create_a_client_during_state_read(self):
        for initial, final in (((4,), ()), ((), (6,)), ((4, 6), (4,))):
            count = 0
            def query(op, deadline, **kw):
                nonlocal count
                if op == 'introspect':
                    count += 1
                    return value('s', xml(initial if count == 1 else final))
                return replies(op, deadline, **kw, families=initial)
            with self.subTest(initial=initial, final=final), self.assertRaises(DHCP.Pending):
                self.read(query)

    def test_owner_pid_namespace_and_link_changes_refuse_the_same_attempt(self):
        for operation in ('owner', 'pid', 'namespace', 'links'):
            count = 0
            def query(op, deadline, **kw):
                nonlocal count
                result = replies(op, deadline, **kw)
                if op == operation:
                    count += 1
                    if count == 2:
                        return {'owner': value('s', ':1.89'), 'pid': value('u', os.getpid() + 1),
                                'namespace': prop('t', KERNEL.namespace() + 1),
                                'links': value('a(iso)', [[3, 'eth0', DHCP.link_path(3)], [1, 'lo', DHCP.link_path(1)]])}[operation]
                return result
            with self.subTest(operation=operation), self.assertRaises(DHCP.Pending):
                self.read(query)

    def test_zero_wrong_kind_namespace_pid_and_foreign_or_changed_process_scope_refuse(self):
        for op, message in (('pid', value('u', 0)), ('pid', value('u', True)), ('namespace', prop('t', 0)),
                            ('namespace', prop('t', True)), ('namespace', prop('s', '0'))):
            with self.subTest(op=op, message=message), self.assertRaises(DHCP.Pending):
                self.read(lambda name, deadline, **kw: message if name == op else replies(name, deadline, **kw))
        with self.assertRaises(DHCP.Pending):
            self.read(scope=lambda pid: KERNEL.namespace() + 1)
        scopes = iter([KERNEL.namespace(), KERNEL.namespace() + 1])
        with self.assertRaises(DHCP.Pending):
            self.read(scope=lambda pid: next(scopes))

    def test_delivery_failure_and_unverifiable_xml_never_publish_an_empty_success(self):
        for stage in ('owner', 'pid', 'namespace', 'links', 'introspect', 'admin', 'state4', 'state6'):
            def query(op, deadline, **kw):
                if op == stage:
                    raise OSError('fixture failed read')
                return replies(op, deadline, **kw)
            with self.subTest(stage=stage), self.assertRaises(OSError):
                self.read(query)

    def test_expired_nonfinite_boolean_and_overflow_deadlines_do_not_read_manager(self):
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'deadline', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(DHCP.Pending):
                DHCP.read_inventory(deadline, query=lambda *a, **kw: self.fail('unexpected native admission'))


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.inventory = DHCP.read_inventory(KERNEL.now() + 30, query=replies)
        self.kernel = {'schema': 'debian13s4-kernel-1', 'namespace': KERNEL.namespace(), 'interfaces': KERNEL.normalize(snapshot())}

    def observe(self, read=None, topology=None):
        return DHCP.observe(read=read or (lambda deadline: copy.deepcopy(self.inventory)),
                            topology=topology or (lambda deadline: copy.deepcopy(self.kernel)))

    def test_three_complete_client_reads_and_two_complete_topologies_share_one_budget(self):
        calls = []
        def read(deadline):
            calls.append(('read', deadline))
            return copy.deepcopy(self.inventory)
        def topology(deadline):
            calls.append(('kernel', deadline))
            return copy.deepcopy(self.kernel)
        result = self.observe(read=read, topology=topology)
        self.assertEqual([kind for kind, _ in calls], ['read', 'kernel', 'read', 'kernel', 'read'])
        self.assertEqual(len({deadline for _, deadline in calls}), 1)
        self.assertEqual(result['interfaces'], self.inventory['interfaces'])
        self.assertEqual(result['schema'], 'debian13s4-networkd-dhcp-1')
        self.assertNotIn('dhcp4', result)
        self.assertEqual(result['source']['service'], DHCP.SERVICE)

    def test_name_index_inventory_namespace_and_inactive_instantiated_client_refuse(self):
        for field, bad in (('name', 'eth1'), ('index', 3)):
            inventory = copy.deepcopy(self.inventory)
            inventory['interfaces'][0][field] = bad
            with self.subTest(field=field), self.assertRaises(DHCP.Pending):
                self.observe(read=lambda deadline: inventory)
        for mutation in ('extra', 'missing', 'namespace', 'inactive'):
            kernel = copy.deepcopy(self.kernel)
            if mutation == 'extra':
                kernel['interfaces'].append(kernel['interfaces'][0] | {'name': 'eth1', 'index': 3})
            elif mutation == 'missing':
                kernel['interfaces'] = []
            elif mutation == 'namespace':
                kernel['namespace'] += 1
            else:
                kernel['interfaces'][0]['up'] = False
            with self.subTest(mutation=mutation), self.assertRaises(DHCP.Pending):
                self.observe(topology=lambda deadline: kernel)

    def test_managed_static_inactive_link_reports_no_networkd_instance_not_no_other_clients(self):
        self.inventory = DHCP.read_inventory(KERNEL.now() + 30, query=lambda op, deadline, **kw: replies(op, deadline, **kw, families=()))
        self.kernel['interfaces'][0]['up'] = False
        record = self.observe()['interfaces'][0]
        self.assertEqual((record['dhcp4'], record['dhcp6']), (False, False))
        self.assertEqual((record['state4'], record['state6']), (None, None))

    def test_second_and_third_client_changes_including_state_only_refuse(self):
        for turn in (2, 3):
            for field, changed in (('state4', 'renewing'), ('dhcp4', False), ('index', 3)):
                count = 0
                def read(deadline):
                    nonlocal count
                    count += 1
                    inventory = copy.deepcopy(self.inventory)
                    if count == turn:
                        inventory['interfaces'][0][field] = changed
                    return inventory
                with self.subTest(turn=turn, field=field), self.assertRaises(DHCP.Pending):
                    self.observe(read=read)

    def test_second_kernel_change_is_not_suppressed_by_unchanged_manager_facts(self):
        values = iter([self.kernel, self.kernel | {'namespace': self.kernel['namespace'] + 1}])
        with self.assertRaises(DHCP.Pending):
            self.observe(topology=lambda deadline: next(values))

    def test_final_namespace_change_and_expired_shared_window_refuse(self):
        with patch.object(KERNEL, 'namespace', return_value=self.kernel['namespace'] + 1), self.assertRaises(DHCP.Pending):
            self.observe()
        with patch.object(DHCP, 'ATTEMPT_SECONDS', 0), self.assertRaises(DHCP.Pending):
            self.observe()

    def test_cli_usage_pending_and_success_preserve_no_partial_output_and_checked_flush(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(DHCP.sys, 'argv', ['dhcp.py', 'extra']), contextlib.redirect_stdout(out):
            self.assertEqual(DHCP.main(), 64)
        self.assertEqual(out.getvalue(), '')
        with patch.object(DHCP.sys, 'argv', ['dhcp.py']), patch.object(DHCP, 'observe', side_effect=DHCP.Pending('fixture pending')), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(DHCP.main(), 75)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('pending', err.getvalue())
        with patch.object(DHCP.sys, 'argv', ['dhcp.py']), patch.object(DHCP, 'observe', return_value=self.observe()), contextlib.redirect_stdout(out):
            self.assertEqual(DHCP.main(), 0)
        self.assertEqual(json.loads(out.getvalue())['schema'], 'debian13s4-networkd-dhcp-1')


class PrivateFixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-dhcp-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.binary = self.root / 'busctl'
        self.ip = self.root / 'ip'
        self.ledger = self.root / 'ledger'
        self.settings = [patch.object(DHCP, 'BUS_BINARY', self.binary), patch.object(KERNEL, 'IP_BINARY', self.ip),
                         patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:
            setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):
            setting.stop()
        self.directory.cleanup()

    def executable(self, body, path=None):
        path = path or self.binary
        path.write_text('#!/usr/bin/python3 -B\n' + body + '\n')
        path.chmod(0o700)

    def query(self, operation='owner', owner=None, index=None):
        return DHCP.native_query(operation, KERNEL.now() + 10, owner=owner, index=index)


class NativeQueryTests(PrivateFixture):
    def test_command_profile_clears_environment_closes_descriptors_and_binds_all_fixed_operations(self):
        fd = os.open(self.root / 'inherited', os.O_CREAT | os.O_WRONLY, 0o600)
        os.set_inheritable(fd, True)
        self.executable(f"import json,os,sys\ntry:\n os.fstat({fd})\n leaked=True\nexcept OSError:\n leaked=False\nopen({str(self.ledger)!r},'w').write(json.dumps([sys.argv[1:],dict(os.environ),leaked]))\nprint('{{}}')")
        try:
            operations = {'owner': [*DHCP.BUS, 'GetNameOwner', 's', DHCP.SERVICE],
                          'pid': [*DHCP.BUS, 'GetConnectionUnixProcessID', 's', ':1.88'],
                          'links': [':1.88', DHCP.OBJECT, DHCP.MANAGER, 'ListLinks'],
                          'namespace': [':1.88', DHCP.OBJECT, DHCP.PROPERTIES, 'Get', 'ss', DHCP.MANAGER, 'NamespaceId'],
                          'introspect': [':1.88', DHCP.link_path(2), DHCP.INTROSPECT, 'Introspect'],
                          'admin': [':1.88', DHCP.link_path(2), DHCP.PROPERTIES, 'Get', 'ss', DHCP.LINK, 'AdministrativeState'],
                          'state4': [':1.88', DHCP.link_path(2), DHCP.PROPERTIES, 'Get', 'ss', DHCP.CLIENTS[4], 'State'],
                          'state6': [':1.88', DHCP.link_path(2), DHCP.PROPERTIES, 'Get', 'ss', DHCP.CLIENTS[6], 'State']}
            for operation, suffix in operations.items():
                with self.subTest(operation=operation), patch.dict(os.environ, {'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/bad', 'LD_PRELOAD': 'bad', 'TASK_SECRET': 'secret'}):
                    self.query(operation, None if operation == 'owner' else ':1.88', 2 if operation in ('introspect', 'admin', 'state4', 'state6') else None)
                arguments, environment, leaked = json.loads(self.ledger.read_text())
                self.assertEqual(arguments, ['--system', '--no-pager', '--json=short', '--auto-start=no', '--allow-interactive-authorization=no', '--expect-reply=yes', '--timeout=3s', 'call', *suffix])
                self.assertFalse(leaked)
                self.assertFalse(set(('TASK_SECRET', 'DBUS_SYSTEM_BUS_ADDRESS', 'LD_PRELOAD')) & set(environment))
        finally:
            os.close(fd)

    def test_unknown_mutation_owner_override_and_wrong_index_never_execute(self):
        marker = self.root / 'executed'
        self.executable(f"open({str(marker)!r},'w').write('unexpected')")
        for operation, owner, index in (('Set', None, None), ('renew', ':1.88', 2), ('owner', ':1.88', None),
                                       ('owner', None, 2), ('links', ':1.88', 2), ('state4', '--system', 2),
                                       ('state4', DHCP.SERVICE, 2), ('state6', ':1.88', True), ('state4', ':1.88', None),
                                       ('pid', None, None), ([], None, None)):
            with self.subTest(operation=operation), self.assertRaises(DHCP.Pending):
                self.query(operation, owner, index)
        self.assertFalse(marker.exists())

    def test_invalid_expired_nan_boolean_infinite_and_overflow_deadlines_never_execute(self):
        marker = self.root / 'executed'
        self.executable(f"open({str(marker)!r},'w').write('unexpected')")
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'time', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(DHCP.Pending):
                DHCP.native_query('owner', deadline)
        self.assertFalse(marker.exists())

    def test_nonzero_warnings_duplicate_keys_bad_json_and_invalid_utf8_refuse(self):
        for body in ("raise SystemExit(1)", "import sys; print('{}'); print('warning',file=sys.stderr)",
                     "print('{\"type\":\"s\",\"type\":\"u\",\"data\":[]}')", "print('bad')", "import os; os.write(1,b'\\xff')"):
            self.executable(body)
            with self.subTest(body=body), self.assertRaises(DHCP.Pending):
                self.query()

    def test_both_output_channels_have_checked_independent_limits(self):
        for channel in (1, 2):
            self.executable(f"import os\nos.write({channel},b'x'*{DHCP.MAX_BYTES + 1})")
            with self.subTest(channel=channel), self.assertRaises(DHCP.Pending):
                self.query()

    def test_completion_is_bounded_even_when_both_capture_pipes_close_first(self):
        self.executable('import os,time\nos.close(1); os.close(2); time.sleep(60)')
        started = time.monotonic()
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.1), self.assertRaises(DHCP.Pending):
            self.query()
        self.assertLess(time.monotonic() - started, 4)

    def test_unreaped_leader_descendant_is_cleaned_with_recorded_owned_group_signal(self):
        marker = self.root / 'child'
        self.executable(f"import json,os,time\npid=os.fork()\nif pid:\n fields=open('/proc/'+str(pid)+'/stat').read().rsplit(')',1)[1].split()\n open({str(marker)!r},'w').write(json.dumps({{'pid':pid,'start':fields[19],'group':os.getpgid(pid),'session':os.getsid(pid)}}))\n os._exit(0)\ntime.sleep(60)")
        signals = []
        killpg = DHCP.os.killpg
        owned = None
        def deliver(group, signum):
            signals.append([group, signum])
            return killpg(group, signum)
        def fields():
            if owned is None:
                return None
            try:
                row = Path(f"/proc/{owned['pid']}/stat").read_text().rsplit(')', 1)[1].split()
            except FileNotFoundError:
                return None
            if row[19] != owned['start']:
                return None
            self.assertEqual([int(row[2]), int(row[3])], [owned['group'], owned['session']])
            return row
        try:
            with patch.object(KERNEL, 'QUERY_SECONDS', 0.3), patch.object(DHCP.os, 'killpg', side_effect=deliver), self.assertRaises(DHCP.Pending):
                self.query()
            owned = json.loads(marker.read_text())
            self.assertIn([owned['group'], signal.SIGKILL], signals)
            for _ in range(100):
                row = fields()
                if row is None or row[0] == 'Z':
                    break
                time.sleep(0.01)
            self.assertTrue(row is None or row[0] == 'Z', json.dumps({'owned': owned, 'signals': signals, 'fields': row}))
        finally:
            if owned is None and marker.exists():
                owned = json.loads(marker.read_text())
            row = fields()
            if row is not None and row[0] != 'Z':
                os.kill(owned['pid'], signal.SIGKILL)

    def test_symlink_fifo_directory_and_unsafe_native_leaf_refuse_with_unchanged_victim(self):
        victim = self.root / 'victim'
        victim.write_bytes(b'unchanged\r\n')
        before = KERNEL.signature(victim.lstat())
        self.binary.symlink_to(victim)
        with self.assertRaises(DHCP.Pending):
            self.query()
        self.binary.unlink()
        os.mkfifo(self.binary, 0o600)
        started = time.monotonic()
        with self.assertRaises(DHCP.Pending):
            self.query()
        self.assertLess(time.monotonic() - started, 2)
        self.binary.unlink()
        self.binary.mkdir()
        with self.assertRaises(DHCP.Pending):
            self.query()
        self.binary.rmdir()
        self.executable("print('{}')")
        self.binary.chmod(0o777)
        with self.assertRaises(DHCP.Pending):
            self.query()
        self.assertEqual(victim.read_bytes(), b'unchanged\r\n')
        self.assertEqual(KERNEL.signature(victim.lstat()), before)

    def test_wrong_owner_unsafe_parent_nonexecutable_and_native_binary_drift_refuse(self):
        self.executable("print('{}')")
        with patch.object(KERNEL, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(DHCP.Pending):
            self.query()
        self.root.chmod(0o777)
        try:
            with self.assertRaises(DHCP.Pending):
                self.query()
        finally:
            self.root.chmod(0o700)
        self.binary.chmod(0o600)
        with self.assertRaises(DHCP.Pending):
            self.query()
        self.executable("import os,sys\nos.chmod(sys.argv[0],0o600)\nprint('{}')")
        with self.assertRaises(DHCP.Pending):
            self.query()


class NativeObservationTests(PrivateFixture):
    def fixtures(self, families=(4, 6), change_turn=0, changed_index=False, admin='configured'):
        descriptions = self.root / 'descriptions'
        descriptions.write_text(json.dumps(xml(families)))
        count = self.root / 'count'
        self.executable(f"""import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['bus',args])+'\\n')
if args[:8]!=['--system','--no-pager','--json=short','--auto-start=no','--allow-interactive-authorization=no','--expect-reply=yes','--timeout=3s','call']: raise SystemExit(1)
a=args[8:]
namespace=int(os.readlink('/proc/self/ns/net')[5:-1])
if a=={[*DHCP.BUS,'GetNameOwner','s',DHCP.SERVICE]!r}: value={{'type':'s','data':[':1.88']}}
elif a=={[*DHCP.BUS,'GetConnectionUnixProcessID','s',':1.88']!r}: value={{'type':'u','data':[os.getppid()]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.MANAGER,'ListLinks']!r}:
 index={3 if changed_index else 2}; value={{'type':'a(iso)','data':[[[1,'lo',{DHCP.link_path(1)!r}],[index,'eth0',{DHCP.link_path(3 if changed_index else 2)!r}]]]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.PROPERTIES,'Get','ss',DHCP.MANAGER,'NamespaceId']!r}: value={{'type':'v','data':[{{'type':'t','data':namespace}}]}}
elif a=={[':1.88',DHCP.link_path(3 if changed_index else 2),DHCP.INTROSPECT,'Introspect']!r}: value={{'type':'s','data':[json.loads(Path({str(descriptions)!r}).read_text())]}}
elif a=={[':1.88',DHCP.link_path(3 if changed_index else 2),DHCP.PROPERTIES,'Get','ss',DHCP.LINK,'AdministrativeState']!r}: value={{'type':'v','data':[{{'type':'s','data':{admin!r}}}]}}
elif len(a)==7 and a[:4]=={[':1.88',DHCP.link_path(3 if changed_index else 2),DHCP.PROPERTIES,'Get']!r} and a[4]=='ss' and a[6]=='State':
 family=4 if a[5]=={DHCP.CLIENTS[4]!r} else 6 if a[5]=={DHCP.CLIENTS[6]!r} else 0
 if family not in {families!r}: raise SystemExit(1)
 path=Path({str(count)!r}); turn=int(path.read_text())+1 if path.exists() else 1; path.write_text(str(turn))
 state='bound'
 if turn=={change_turn}: state='stopped'
 value={{'type':'v','data':[{{'type':'s','data':state}}]}}
else: raise SystemExit(1)
print(json.dumps(value))""")
        self.executable(f"""import json,sys
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['ip',args])+'\\n')
data={snapshot()!r}
commands={KERNEL.COMMANDS!r}
if args[:2]!=['-j','-N']: raise SystemExit(1)
keys=[key for key,value in commands.items() if list(value)==args[2:]]
if len(keys)!=1: raise SystemExit(1)
print(json.dumps(data[keys[0]]))""", self.ip)

    def observe(self):
        return DHCP.observe(read=lambda deadline: DHCP.read_inventory(deadline))

    def test_complete_private_native_collection_checks_bus_proc_kernel_and_fixed_command_ledger(self):
        self.fixtures()
        result = self.observe()
        self.assertEqual((result['interfaces'][0]['dhcp4'], result['interfaces'][0]['dhcp6']), (True, True))
        self.assertEqual(result['source']['pid'], os.getpid())
        ledger = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'bus' for kind, _ in ledger), 39)
        self.assertEqual(sum(kind == 'ip' for kind, _ in ledger), 40)
        self.assertFalse(any('get' in args for kind, args in ledger if kind == 'ip'))

    def test_complete_private_static_and_single_family_positive_absence_does_not_query_missing_client(self):
        for families in ((), (4,), (6,)):
            self.fixtures(families=families)
            result = self.observe()
            with self.subTest(families=families):
                for family in (4, 6):
                    self.assertEqual(result['interfaces'][0]['dhcp' + str(family)], family in families)

    def test_changed_middle_or_final_native_client_state_is_not_published(self):
        for turn in (3, 5):
            self.fixtures(change_turn=turn)
            count = self.root / 'count'
            if count.exists():
                count.unlink()
            with self.subTest(turn=turn), self.assertRaises(DHCP.Pending):
                self.observe()

    def test_zero_exit_native_manager_wrong_index_and_foreign_management_fail_actual_binding(self):
        for changed_index, admin in ((True, 'configured'), (False, 'unmanaged')):
            self.fixtures(changed_index=changed_index, admin=admin)
            with self.subTest(changed_index=changed_index, admin=admin), self.assertRaises(DHCP.Pending):
                self.observe()


if __name__ == '__main__':
    unittest.main()
