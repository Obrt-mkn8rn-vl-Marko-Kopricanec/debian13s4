import contextlib
import copy
import importlib.util
import io
import ipaddress
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
SPEC = importlib.util.spec_from_file_location('firewall_timesync', ROOT / 'Firewall/timesync.py')
TIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TIME)
KERNEL = TIME.KERNEL


def packet(address='192.168.50.1', name='time.example.test'):
    ip = ipaddress.ip_address(address)
    values = {
        'LinkNTPServers': {'type': 'as', 'data': []},
        'SystemNTPServers': {'type': 'as', 'data': [name]},
        'RuntimeNTPServers': {'type': 'as', 'data': []},
        'FallbackNTPServers': {'type': 'as', 'data': ['fallback.example.test']},
        'ServerName': {'type': 's', 'data': name},
        'ServerAddress': {'type': '(iay)', 'data': [2 if ip.version == 4 else 10, list(ip.packed)]},
        'RootDistanceMaxUSec': {'type': 't', 'data': 5000000},
        'PollIntervalMinUSec': {'type': 't', 'data': 32000000},
        'PollIntervalMaxUSec': {'type': 't', 'data': 2048000000},
        'PollIntervalUSec': {'type': 't', 'data': 32000000},
        'NTPMessage': {'type': '(uuuuittayttttbtt)', 'data': [0, 4, 4, 2, -20, 0, 0, [1, 2, 3, 4], 0, 0, 0, 0, False, 0, 0]},
        'Frequency': {'type': 'x', 'data': -100},
    }
    return {'type': 'a{sv}', 'data': [values]}


def replies(operation, deadline, owner=None):
    if operation == 'owner':
        return {'type': 's', 'data': [':1.77']}
    if operation == 'pid':
        return {'type': 'u', 'data': [os.getpid()]}
    if operation == 'peer':
        return packet()
    raise AssertionError(operation)


class PropertyTests(unittest.TestCase):
    def test_typed_native_ipv4_global_ipv6_and_private_peer_addresses(self):
        for address in ('192.168.50.1', '8.8.8.8', '2606:4700:4700::1111', 'fd50::20'):
            with self.subTest(address=address):
                self.assertEqual(TIME.properties(packet(address)), {'name': 'time.example.test', 'address': address})

    def test_no_selected_address_is_pending_rather_than_an_empty_permission(self):
        for family in ([0, []], [2, []], [10, []], [1, [1, 2, 3, 4]], [True, [1, 2, 3, 4]]):
            value = packet()
            value['data'][0]['ServerAddress']['data'] = family
            with self.subTest(family=family), self.assertRaises(TIME.Pending):
                TIME.properties(value)

    def test_missing_corrupt_wrong_kind_and_wrong_family_address_payload_refuses(self):
        for data in ([2], [2, [1, 2, 3]], [2, [1, 2, 3, 4, 5]], [10, [1, 2, 3, 4]],
                     [2, [1, 2, 3, True]], [2, [1, 2, 3, 256]], [2, [1, 2, 3, -1]],
                     [2, 'bytes'], [2, [1, 2, 3, 4], 'extra'], 'not a structure'):
            value = packet()
            value['data'][0]['ServerAddress']['data'] = data
            with self.subTest(data=data), self.assertRaises(TIME.Pending):
                TIME.properties(value)

    def test_local_multicast_unspecified_broadcast_mapped_and_unscoped_ipv6_refuse(self):
        for address in ('127.0.0.1', '::1', '0.0.0.0', '::', '224.0.0.1', 'ff02::1',
                        '255.255.255.255', '::ffff:192.168.50.1', 'fe80::1'):
            with self.subTest(address=address), self.assertRaises(TIME.Pending):
                TIME.properties(packet(address))

    def test_missing_unknown_or_incomplete_properties_are_not_native_complete_state(self):
        for name in TIME.PROPERTIES:
            value = packet()
            del value['data'][0][name]
            with self.subTest(name=name), self.assertRaises(TIME.Pending):
                TIME.properties(value)
        value = packet()
        value['data'][0]['UnknownProperty'] = {'type': 's', 'data': 'ignored?'}
        with self.assertRaises(TIME.Pending):
            TIME.properties(value)

    def test_variant_signature_fields_and_top_level_arity_are_checked(self):
        for value in (None, [], {'type': 'a{sv}', 'data': []}, {'type': 'a{sv}', 'data': [packet()['data'][0]] * 2},
                      packet() | {'extra': 1}, packet() | {'type': 'as'}, packet() | {'data': {}},
                      packet() | {'data': [None]}):
            with self.subTest(value=value), self.assertRaises(TIME.Pending):
                TIME.properties(value)
        for name in TIME.PROPERTIES:
            value = packet()
            value['data'][0][name]['type'] = 'v'
            with self.subTest(name=name), self.assertRaises(TIME.Pending):
                TIME.properties(value)
        value = packet()
        value['data'][0]['ServerAddress']['extra'] = 1
        with self.assertRaises(TIME.Pending):
            TIME.properties(value)

    def test_invalid_empty_long_and_control_server_names_refuse(self):
        for name in ('', 'x' * 256, 'name\nline', 'name\x00', 'time\x7f', '\ud800', 1, None):
            value = packet()
            value['data'][0]['ServerName']['data'] = name
            with self.subTest(name=repr(name)), self.assertRaises(TIME.Pending):
                TIME.properties(value)

    def test_native_server_lists_are_bounded_and_cannot_hide_malformed_names(self):
        for servers in (None, 'one', [''] , ['x\n'], [1], ['time'] * (TIME.MAX_SERVERS + 1)):
            value = packet()
            value['data'][0]['LinkNTPServers']['data'] = servers
            with self.subTest(servers=type(servers).__name__), self.assertRaises(TIME.Pending):
                TIME.properties(value)
        value = packet()
        value['data'][0]['LinkNTPServers']['data'] = ['time'] * TIME.MAX_SERVERS
        self.assertEqual(TIME.properties(value)['address'], '192.168.50.1')

    def test_numeric_boolean_and_message_widths_require_native_types(self):
        for name, values in (('Frequency', [True, 1 << 63, -(1 << 63) - 1, '0']),
                             ('PollIntervalUSec', [False, -1, 1 << 64, 1.0])):
            for bad in values:
                value = packet()
                value['data'][0][name]['data'] = bad
                with self.subTest(name=name, bad=bad), self.assertRaises(TIME.Pending):
                    TIME.properties(value)
        for index, bad in ((0, -1), (1, 1 << 32), (4, 1 << 31), (5, 1 << 64),
                           (7, [0] * 3), (12, 1), (13, False), (14, -1)):
            value = packet()
            value['data'][0]['NTPMessage']['data'][index] = bad
            with self.subTest(index=index), self.assertRaises(TIME.Pending):
                TIME.properties(value)
        for data in ([], [0] * 14, [0] * 16, 'message'):
            value = packet()
            value['data'][0]['NTPMessage']['data'] = data
            with self.subTest(data=type(data).__name__), self.assertRaises(TIME.Pending):
                TIME.properties(value)

    def test_changing_poll_frequency_and_packet_counters_does_not_change_selected_peer(self):
        first = packet()
        second = copy.deepcopy(first)
        second['data'][0]['NTPMessage']['data'][13] = 123
        second['data'][0]['NTPMessage']['data'][14] = 5000
        second['data'][0]['Frequency']['data'] = 1 << 62
        second['data'][0]['PollIntervalUSec']['data'] *= 2
        self.assertEqual(TIME.properties(first), TIME.properties(second))


class PeerTests(unittest.TestCase):
    def read(self, query=replies, scope=TIME.process_scope):
        return TIME.read_peer(KERNEL.now() + 30, query=query, scope=scope)

    def test_one_read_pins_unique_owner_pid_namespace_and_complete_peer(self):
        calls = []
        def query(operation, deadline, owner=None):
            calls.append((operation, deadline, owner))
            return replies(operation, deadline, owner)
        result = self.read(query)
        self.assertEqual(result, {'name': 'time.example.test', 'address': '192.168.50.1',
                                 'owner': ':1.77', 'pid': os.getpid(), 'namespace': KERNEL.namespace()})
        self.assertEqual([name for name, *_ in calls], ['owner', 'pid', 'peer', 'owner'])
        self.assertEqual([owner for _, _, owner in calls], [None, ':1.77', ':1.77', None])
        self.assertEqual(len({deadline for _, deadline, _ in calls}), 1)

    def test_owner_grammar_includes_zero_serial_and_rejects_untrusted_argument_text(self):
        for owner in (':1.0', ':1.77', ':4294967295.4294967295'):
            self.assertEqual(TIME.owner_name(owner), owner)
        for owner in (None, ':0.1', ':01.1', ':1.01', ':1.-1', ':1.4294967296',
                      '--system', TIME.SERVICE, ':1.1\n'):
            with self.subTest(owner=owner), self.assertRaises(TIME.Pending):
                TIME.owner_name(owner)

    def test_owner_change_after_getall_cannot_publish_the_old_peer(self):
        count = 0
        def query(operation, deadline, owner=None):
            nonlocal count
            value = replies(operation, deadline, owner)
            if operation == 'owner':
                count += 1
                if count == 2:
                    value['data'] = [':1.78']
            return value
        with self.assertRaises(TIME.Pending):
            self.read(query)

    def test_invalid_pid_is_refused_before_any_process_namespace_read(self):
        for pid in (0, -1, True, '1', 1 << 32):
            def query(operation, deadline, owner=None):
                return {'type': 'u', 'data': [pid]} if operation == 'pid' else replies(operation, deadline, owner)
            with patch.object(TIME, 'process_scope') as reader, self.subTest(pid=pid), self.assertRaises(TIME.Pending):
                self.read(query, scope=reader)
            reader.assert_not_called()

    def test_mismatching_or_changed_daemon_namespace_never_uses_host_route_permissions(self):
        actual = KERNEL.namespace()
        for observed in ([actual + 1, actual + 1], [actual, actual + 1]):
            values = iter(observed)
            with self.subTest(observed=observed), self.assertRaises(TIME.Pending):
                self.read(scope=lambda pid: next(values))

    def test_query_failure_wrong_reply_or_termination_remains_pending(self):
        for operation in ('owner', 'pid', 'peer'):
            def query(name, deadline, owner=None):
                if name == operation:
                    raise TIME.Pending('manager unavailable')
                return replies(name, deadline, owner)
            with self.subTest(operation=operation), self.assertRaises(TIME.Pending):
                self.read(query)
        with self.assertRaises(TIME.Pending):
            self.read(lambda *args, **kwargs: {'type': 's', 'data': []})

    def test_expired_read_does_not_publish_and_real_own_process_namespace_is_observed(self):
        self.assertEqual(TIME.process_scope(os.getpid()), KERNEL.namespace())
        with self.assertRaises(TIME.Pending):
            TIME.read_peer(KERNEL.now() - 1, query=replies)
        with patch.object(TIME.os, 'readlink', return_value='unexpected'), self.assertRaises(TIME.Pending):
            TIME.process_scope(os.getpid())
        with patch.object(TIME.os, 'readlink') as reader, self.assertRaises(TIME.Pending):
            TIME.process_scope(0)
        reader.assert_not_called()

    def test_invalid_or_expired_peer_admission_refuses_before_any_query(self):
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(kind=type(deadline).__name__), patch.object(TIME, 'native_query') as query, self.assertRaises(TIME.Pending):
                TIME.read_peer(deadline, query=query)
            query.assert_not_called()


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.kernel = {'schema': 'debian13s4-kernel-1', 'namespace': KERNEL.namespace(),
                       'interfaces': KERNEL.normalize(snapshot())}
        self.peer = {'name': 'time.example.test', 'address': '192.168.50.1',
                     'owner': ':1.77', 'pid': os.getpid(), 'namespace': self.kernel['namespace']}
        self.route = [{'dst': self.peer['address'], 'dev': 'eth0'}]

    def observe(self, read=None, topology=None, route=None):
        return TIME.observe(read=read or (lambda deadline: copy.deepcopy(self.peer)),
                            topology=topology or (lambda deadline: copy.deepcopy(self.kernel)),
                            route=route or (lambda *args: copy.deepcopy(self.route)))

    def test_three_peer_reads_two_complete_kernel_rounds_and_two_routes_share_one_deadline(self):
        calls = []
        def read(deadline):
            calls.append(('read', deadline))
            return TIME.read_peer(deadline, query=replies)
        def topology(deadline):
            calls.append(('topology', deadline))
            return KERNEL.observe(query=lambda name, window: copy.deepcopy(snapshot()[name]), deadline=deadline)
        def route(address, interface, deadline):
            self.assertIsNone(interface)
            calls.append(('route', deadline))
            return copy.deepcopy(self.route)
        result = self.observe(read, topology, route)
        self.assertEqual([name for name, _ in calls], ['read', 'topology', 'route', 'read', 'topology', 'route', 'read'])
        self.assertEqual(len({deadline for _, deadline in calls}), 1)
        self.assertEqual(result['ntp'], [{'interface': 'eth0', 'address': '192.168.50.1'}])
        self.assertEqual(result['schema'], 'debian13s4-timesync-1')
        self.assertEqual(result['kernel'], self.kernel)
        self.assertEqual(result['source'], {'service': TIME.SERVICE, 'owner': ':1.77', 'pid': os.getpid(), 'name': 'time.example.test'})

    def test_changed_peer_name_address_owner_pid_or_namespace_requires_retry(self):
        for field, changed in (('name', 'different.test'), ('address', '192.168.50.2'), ('owner', ':1.78'),
                               ('pid', os.getpid() + 1), ('namespace', self.peer['namespace'] + 1)):
            for turn in (2, 3):
                count = 0
                def read(deadline):
                    nonlocal count
                    count += 1
                    value = copy.deepcopy(self.peer)
                    if count == turn:
                        value[field] = changed
                    return value
                with self.subTest(field=field, turn=turn), self.assertRaises(TIME.Pending):
                    self.observe(read=read)

    def test_kernel_change_and_initial_namespace_mismatch_refuse(self):
        values = iter([self.kernel, self.kernel | {'namespace': self.kernel['namespace'] + 1}])
        with self.assertRaises(TIME.Pending):
            self.observe(topology=lambda deadline: next(values))
        with self.assertRaises(TIME.Pending):
            self.observe(topology=lambda deadline: self.kernel | {'namespace': self.kernel['namespace'] + 1})

    def test_missing_negative_local_unobserved_or_inactive_routes_refuse(self):
        for route in ([], [{'dst': self.peer['address'], 'dev': 'unknown'}],
                      [{'dst': self.peer['address'], 'dev': 'eth0', 'type': 'local'}],
                      [{'dst': self.peer['address'], 'dev': 'eth0', 'type': 'blackhole'}],
                      [{'dst': self.peer['address'], 'dev': 'eth0', 'gateway': '192.168.50.2'}]):
            with self.subTest(route=route), self.assertRaises(TIME.Pending):
                self.observe(route=lambda *args: route)
        self.kernel['interfaces'][0]['up'] = False
        with self.assertRaises(TIME.Pending):
            self.observe()

    def test_changed_route_rows_or_binding_never_certify_a_stale_endpoint(self):
        for second in ([{'dst': self.peer['address'], 'dev': 'eth0', 'metric': 2}],
                       [{'dst': self.peer['address'], 'dev': 'eth1'}]):
            routes = iter([self.route, second])
            with self.subTest(second=second), self.assertRaises(TIME.Pending):
                self.observe(route=lambda *args: next(routes))

    def test_gateway_binding_uses_real_postconditions_for_public_peer(self):
        self.peer['address'] = '8.8.8.8'
        self.route = [{'dst': '8.8.8.8', 'dev': 'eth0', 'gateway': '192.168.50.1'}]
        self.assertEqual(self.observe()['ntp'], [{'interface': 'eth0', 'address': '8.8.8.8'}])
        del self.route[0]['gateway']
        with self.assertRaises(TIME.Pending):
            self.observe()

    def test_final_namespace_change_or_expiry_is_pending(self):
        actual = self.kernel['namespace']
        with patch.object(KERNEL, 'namespace', return_value=actual + 1), self.assertRaises(TIME.Pending):
            self.observe()
        with patch.object(TIME, 'ATTEMPT_SECONDS', 0), self.assertRaises(TIME.Pending):
            self.observe()

    def test_cli_usage_pending_and_success_have_native_output_contracts(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(TIME.sys, 'argv', ['timesync.py', 'extra']), contextlib.redirect_stdout(out):
            self.assertEqual(TIME.main(), 64)
        self.assertEqual(out.getvalue(), '')
        with patch.object(TIME.sys, 'argv', ['timesync.py']), patch.object(TIME, 'observe', side_effect=TIME.Pending('unavailable')), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(TIME.main(), 75)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('pending', err.getvalue())
        result = self.observe()
        with patch.object(TIME.sys, 'argv', ['timesync.py']), patch.object(TIME, 'observe', return_value=result), contextlib.redirect_stdout(out):
            self.assertEqual(TIME.main(), 0)
        self.assertEqual(json.loads(out.getvalue()), result)


class NativeQueryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-timesync-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.binary = self.root / 'busctl'
        self.settings = [patch.object(TIME, 'BUS_BINARY', self.binary),
                         patch.object(KERNEL, 'TRUST_ROOT', self.root),
                         patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:
            setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):
            setting.stop()
        self.directory.cleanup()

    def executable(self, code):
        self.binary.write_text('#!/usr/bin/python3 -B\n' + code + '\n')
        self.binary.chmod(0o700)

    def query(self, operation='owner', owner=None):
        return TIME.native_query(operation, KERNEL.now() + 10, owner)

    def test_real_capture_fixed_readonly_commands_cleared_environment_and_closed_fds(self):
        ledger = self.root / 'delivery.json'
        fd = os.open(self.root / 'inherited', os.O_WRONLY | os.O_CREAT, 0o600)
        os.set_inheritable(fd, True)
        self.executable(f"import json,os,sys\ntry:\n os.fstat({fd})\n leaked=True\nexcept OSError:\n leaked=False\nopen({str(ledger)!r},'w').write(json.dumps([sys.argv[1:],dict(os.environ),leaked]))\nprint(json.dumps({{'type':'s','data':[':1.77']}}))")
        try:
            with patch.dict(os.environ, {'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/bad', 'LD_PRELOAD': 'bad', 'TASK_SECRET': 'secret'}):
                self.assertEqual(self.query(), {'type': 's', 'data': [':1.77']})
            arguments, environment, leaked = json.loads(ledger.read_text())
            self.assertFalse(leaked)
            for key in ('DBUS_SYSTEM_BUS_ADDRESS', 'LD_PRELOAD', 'TASK_SECRET'):
                self.assertNotIn(key, environment)
            self.assertEqual(arguments, ['--system', '--no-pager', '--json=short', '--auto-start=no',
                                        '--allow-interactive-authorization=no', '--expect-reply=yes', '--timeout=3s',
                                        'call', *TIME.BUS, 'GetNameOwner', 's', TIME.SERVICE])
            self.query('pid', ':1.77')
            self.assertEqual(json.loads(ledger.read_text())[0][-2:], ['s', ':1.77'])
            self.query('peer', ':1.77')
            self.assertEqual(json.loads(ledger.read_text())[0][-6:], [':1.77', TIME.OBJECT, 'org.freedesktop.DBus.Properties', 'GetAll', 's', TIME.INTERFACE])
        finally:
            os.close(fd)

    def test_unknown_mutating_operation_owner_override_and_injectable_peer_never_execute(self):
        marker = self.root / 'executed'
        self.executable(f"open({str(marker)!r},'w').write('unexpected')")
        for operation, owner in (('set-property', None), ('peer', '--system'), ('peer', TIME.SERVICE),
                                 ('owner', ':1.77'), ('pid', None), ([], None)):
            with self.subTest(operation=operation, owner=owner), self.assertRaises(TIME.Pending):
                self.query(operation, owner)
        self.assertFalse(marker.exists())

    def test_expired_boolean_nan_infinite_and_huge_deadlines_cannot_execute(self):
        marker = self.root / 'executed'
        self.executable(f"open({str(marker)!r},'w').write('unexpected')")
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(TIME.Pending):
                TIME.native_query('owner', deadline)
        self.assertFalse(marker.exists())

    def test_nonzero_warning_invalid_utf8_duplicate_and_malformed_json_refuse(self):
        for code in ("raise SystemExit(1)", "import sys; print('{}'); print('warning',file=sys.stderr)",
                     "import os; os.write(1,b'\\xff')", "print('{\"type\":\"s\",\"type\":\"u\",\"data\":[]}')", "print('not json')"):
            self.executable(code)
            with self.subTest(code=code), self.assertRaises(TIME.Pending):
                self.query()

    def test_both_real_output_channels_have_independent_finite_limits(self):
        for channel in (1, 2):
            self.executable(f"import os\nos.write({channel},b'x'*{TIME.MAX_BYTES + 1})")
            with self.subTest(channel=channel), self.assertRaises(TIME.Pending):
                self.query()

    def test_timeout_is_checked_even_after_both_capture_pipes_close(self):
        self.executable("import os,time\nos.close(1); os.close(2); time.sleep(60)")
        started = time.monotonic()
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.1), self.assertRaises(TIME.Pending):
            self.query()
        self.assertLess(time.monotonic() - started, 4)

    def test_exited_unreaped_leader_with_pipe_child_is_killed_without_reusing_group(self):
        marker = self.root / 'child'
        self.executable(f"import json,os,time\npid=os.fork()\nif pid:\n fields=open('/proc/'+str(pid)+'/stat').read().rsplit(')',1)[1].split()\n value={{'pid':pid,'start':fields[19],'parent':os.getpid(),'group':os.getpgid(pid),'session':os.getsid(pid)}}\n open({str(marker)!r},'w').write(json.dumps(value))\n os._exit(0)\ntime.sleep(60)")
        delivered = []
        native_kill = TIME.os.killpg
        def deliver(group, signum):
            delivered.append([group, signum])
            return native_kill(group, signum)
        owned = None
        def live_fields():
            if owned is None:
                return None
            try:
                fields = Path(f"/proc/{owned['pid']}/stat").read_text().rsplit(')', 1)[1].split()
            except FileNotFoundError:
                return None
            if fields[19] != owned['start']:
                return None
            self.assertEqual([int(fields[2]), int(fields[3])], [owned['group'], owned['session']])
            return fields
        try:
            with patch.object(KERNEL, 'QUERY_SECONDS', 0.3), patch.object(TIME.os, 'killpg', side_effect=deliver), self.assertRaises(TIME.Pending):
                self.query()
            owned = json.loads(marker.read_text())
            self.assertEqual(owned['parent'], owned['group'])
            self.assertEqual(owned['parent'], owned['session'])
            self.assertEqual(delivered, [[owned['parent'], signal.SIGKILL]])
            for _ in range(100):
                fields = live_fields()
                if fields is None or fields[0] == 'Z':
                    break
                time.sleep(0.01)
            else:
                self.fail(f'owned child still running: {owned}; stat={fields}; signals={delivered}')
        finally:
            fields = live_fields()
            if fields is not None and fields[0] != 'Z':
                # Only this fixture's start-time/group/session identity may be
                # signalled; failure cannot intentionally leave its sleeper.
                try:
                    os.kill(owned['pid'], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_symlink_fifo_directory_and_untrusted_leaves_leave_victim_untouched(self):
        victim = self.root / 'victim'
        victim.write_bytes(b'unchanged\r\n')
        before = KERNEL.signature(victim.lstat())
        self.binary.symlink_to(victim)
        with self.assertRaises(TIME.Pending):
            self.query()
        self.binary.unlink()
        os.mkfifo(self.binary, 0o600)
        started = time.monotonic()
        with self.assertRaises(TIME.Pending):
            self.query()
        self.assertLess(time.monotonic() - started, 2)
        self.binary.unlink()
        self.binary.mkdir()
        with self.assertRaises(TIME.Pending):
            self.query()
        self.binary.rmdir()
        self.executable("print('{}')")
        self.binary.chmod(0o777)
        with self.assertRaises(TIME.Pending):
            self.query()
        self.assertEqual(victim.read_bytes(), b'unchanged\r\n')
        self.assertEqual(KERNEL.signature(victim.lstat()), before)

    def test_unsafe_ancestry_wrong_owner_nonexecutable_and_changed_binary_refuse(self):
        self.executable("print('{}')")
        with patch.object(KERNEL, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(TIME.Pending):
            self.query()
        self.root.chmod(0o777)
        try:
            with self.assertRaises(TIME.Pending):
                self.query()
        finally:
            self.root.chmod(0o700)
        self.binary.chmod(0o600)
        with self.assertRaises(TIME.Pending):
            self.query()
        self.executable("import os,sys\nos.chmod(sys.argv[0],0o600)\nprint('{}')")
        with self.assertRaises(TIME.Pending):
            self.query()


class NativeObservationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-time-observer-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.bus = self.root / 'busctl'
        self.ip = self.root / 'ip'
        self.ledger = self.root / 'ledger'
        self.settings = [patch.object(TIME, 'BUS_BINARY', self.bus), patch.object(KERNEL, 'IP_BINARY', self.ip),
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

    def fixtures(self, address='192.168.50.1', change_turn=0, bad_route=False):
        peer_path = self.root / 'peer.json'
        peer_path.write_text(json.dumps(packet(address)))
        count = self.root / 'count'
        self.executable(self.bus, f"""import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['bus',args])+'\\n')
if args[:8]!=['--system','--no-pager','--json=short','--auto-start=no','--allow-interactive-authorization=no','--expect-reply=yes','--timeout=3s','call']: raise SystemExit(1)
method=args[11]
if method=='GetNameOwner' and args[12:]==['s',{TIME.SERVICE!r}]: value={{'type':'s','data':[':1.77']}}
elif method=='GetConnectionUnixProcessID' and args[12:]==['s',':1.77']: value={{'type':'u','data':[os.getppid()]}}
elif args[8:]==[':1.77',{TIME.OBJECT!r},'org.freedesktop.DBus.Properties','GetAll','s',{TIME.INTERFACE!r}]:
 path=Path({str(count)!r}); turn=int(path.read_text())+1 if path.exists() else 1; path.write_text(str(turn))
 value=json.loads(Path({str(peer_path)!r}).read_text())
 if turn=={change_turn}: value['data'][0]['ServerName']['data']='changed.test'
else: raise SystemExit(1)
print(json.dumps(value))""")
        data = snapshot()
        self.executable(self.ip, f"""import json,sys
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['ip',args])+'\\n')
data={data!r}
commands={KERNEL.COMMANDS!r}
if args[:2]!=['-j','-N']: raise SystemExit(1)
args=args[2:]
if len(args)==4 and args[1:3]==['route','get'] and args[3]=={address!r}:
 row={{'dst':args[3],'dev':'eth0'}}
 if {bad_route!r}: row['gateway']='192.168.50.2'
 elif ':' in args[3] and not args[3].startswith('fd50:'): row['gateway']='fe80::1'
 elif args[3]!='192.168.50.1': row['gateway']='192.168.50.1'
 value=[row]
else:
 keys=[key for key,value in commands.items() if list(value)==args]
 if len(keys)!=1: raise SystemExit(1)
 value=data[keys[0]]
print(json.dumps(value))""")

    def observe(self):
        return TIME.observe(read=lambda deadline: TIME.read_peer(deadline))

    def test_complete_real_private_delivery_runs_peer_namespace_kernel_and_route_predicates(self):
        self.fixtures()
        result = self.observe()
        self.assertEqual(result['ntp'], [{'interface': 'eth0', 'address': '192.168.50.1'}])
        self.assertEqual(result['source']['pid'], os.getpid())
        commands = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'bus' for kind, _ in commands), 12)
        self.assertEqual(sum(kind == 'ip' for kind, _ in commands), 42)
        self.assertEqual(sum('get' in args for kind, args in commands if kind == 'ip'), 2)

    def test_complete_private_global_ipv6_peer_requires_observed_gateway_binding(self):
        self.fixtures(address='2606:4700:4700::1111')
        self.assertEqual(self.observe()['ntp'], [{'interface': 'eth0', 'address': '2606:4700:4700::1111'}])

    def test_changed_middle_or_final_real_peer_cannot_publish(self):
        for turn in (2, 3):
            with self.subTest(turn=turn):
                self.fixtures(change_turn=turn)
                count = self.root / 'count'
                if count.exists():
                    count.unlink()
                with self.assertRaises(TIME.Pending):
                    self.observe()

    def test_zero_exit_unobserved_route_is_not_successful_time_endpoint(self):
        self.fixtures(bad_route=True)
        with self.assertRaises(TIME.Pending):
            self.observe()


class InheritedDeadlineTests(unittest.TestCase):
    def test_invalid_inherited_attempt_refuses_before_peer_or_native_delivery(self):
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(TIME.Pending):
                TIME.observe(deadline=deadline, read=lambda window: self.fail('unexpected read'))

    def test_inherited_window_is_shared_without_widening_the_default_cap(self):
        start = KERNEL.now()
        kernel = {'schema': 'debian13s4-kernel-1', 'namespace': KERNEL.namespace(), 'interfaces': KERNEL.normalize(snapshot())}
        peer = {'name': 'time.example.test', 'address': '192.168.50.1', 'owner': ':1.77', 'pid': os.getpid(), 'namespace': kernel['namespace']}
        for budget in (10, 1000):
            seen = []
            with self.subTest(budget=budget), patch.object(KERNEL, 'now', return_value=start):
                record = TIME.observe(deadline=start + budget, read=lambda deadline: seen.append(deadline) or peer,
                    topology=lambda deadline: seen.append(deadline) or kernel,
                    route=lambda address, interface, deadline: seen.append(deadline) or [{'dst': address, 'dev': 'eth0'}])
            self.assertEqual(seen, [start + min(budget, TIME.ATTEMPT_SECONDS)] * 7)
            self.assertEqual(record['ntp'][0]['address'], '192.168.50.1')


if __name__ == '__main__':
    unittest.main()
