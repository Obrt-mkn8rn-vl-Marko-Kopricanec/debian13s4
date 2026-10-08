import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from fixture_bus import script
from test_assemble import ASSEMBLY, DHCP, KERNEL, PrivateNative, TIME
from test_dhcp import xml
from test_timesync import packet


class BusDispatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-bus-dispatch-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.binary, self.ledger = self.root / 'busctl', self.root / 'ledger'
        self.fallback, self.state = self.root / 'live', self.root / 'state'
        self.state.write_text('first')
        self.fixed = tuple('argument ' + str(index) for index in range(1, 15))
        self.pid, self.namespace, self.dynamic = ('pid',), ('namespace',), ('live', 'query')
        self.fallback.write_text('#!/usr/bin/python3 -B\nimport json,os,sys\nfrom pathlib import Path\n'
                                 f'with open({str(self.ledger)!r},"a") as log:log.write(json.dumps(["bus",sys.argv[1:],dict(os.environ)])+"\\n")\n'
                                 f'print(json.dumps({{"parent":os.getppid(),"state":Path({str(self.state)!r}).read_text(),"argv":sys.argv[1:]}}))\n')
        self.fallback.chmod(0o700)

    def tearDown(self):
        self.directory.cleanup()

    def install(self, replies=None):
        self.binary.write_text(script(self.ledger, replies if replies is not None else {self.fixed: '{"fixed":true}\n'},
                                      (self.pid,), (self.namespace,), (self.dynamic,), self.fallback), encoding='utf-8')
        self.binary.chmod(0o700)

    def child(self, arguments, environment=None):
        return subprocess.run([str(self.binary), *arguments], capture_output=True, timeout=3,
                              env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'} if environment is None else environment,
                              cwd=self.root, close_fds=True, start_new_session=True)

    def records(self):
        return [json.loads(line) for line in self.ledger.read_bytes().splitlines()]

    def test_complete_long_static_arguments_and_reply_bytes_match_exactly(self):
        self.install()
        child = self.child(self.fixed)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'{"fixed":true}\n', b''))
        self.assertEqual(self.records(), [['bus', list(self.fixed), {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}]])

    def test_argc_empty_order_literal_patterns_and_positional_values_cannot_alias(self):
        self.install()
        variants = ((), self.fixed[:-1], (*self.fixed, ''), tuple(reversed(self.fixed)),
                    (*self.fixed[:9], 'different tenth', *self.fixed[10:]), ('*',), self.dynamic[:-1], (*self.dynamic, 'extra'))
        for arguments in variants:
            with self.subTest(arguments=arguments):
                child = self.child(arguments)
                self.assertEqual((child.returncode, child.stdout, child.stderr), (1, b'', b''))
        self.assertEqual([row[1] for row in self.records()], [list(arguments) for arguments in variants])

    def test_actual_environment_is_retained_for_both_static_and_live_records(self):
        self.install()
        environment = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'DBUS_SYSTEM_BUS_ADDRESS': 'do-not-hide',
                       'ASSEMBLY_SECRET': 'also-visible', 'PWD': 'incoming cwd', 'SHLVL': '12', '_': 'incoming underscore'}
        for arguments in (self.fixed, self.dynamic):
            child = self.child(arguments, environment)
            self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(self.records(), [['bus', list(arguments), environment] for arguments in (self.fixed, self.dynamic)])

    def test_control_unicode_and_quoted_environment_values_preserve_logical_strings(self):
        self.install()
        value = ''.join(chr(number) for number in range(1, 32)) + 'é中🦊"\\\x7f'
        environment = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'FIXTURE_LITERAL': value}
        for arguments in (self.fixed, self.dynamic):
            child = self.child(arguments, environment)
            self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(self.records(), [['bus', list(arguments), environment] for arguments in (self.fixed, self.dynamic)])
        self.assertEqual(len(self.ledger.read_bytes().splitlines()), 2)

    def test_metacharacters_in_actual_arguments_and_replies_do_not_execute(self):
        marker = self.root / 'executed'
        value = f"'; touch {marker}; # $(touch {marker}) `touch {marker}`"
        arguments = (value, '', '*', '?', '[ab]', '\\', '$HOME')
        self.install({arguments: value + '\n'})
        child = self.child(arguments)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, (value + '\n').encode(), b''))
        self.assertEqual(self.records()[0][1], list(arguments))
        self.assertFalse(marker.exists())

    def test_live_dispatcher_path_is_literal_and_unknown_queries_never_execute_it(self):
        marker = self.root / 'executed'
        self.fallback = self.root / f"live ' $(touch {marker.name}) `touch {marker.name}`"
        self.fallback.write_text("#!/bin/bash -p\nprintf '%s\\n' live\n");self.fallback.chmod(0o700)
        self.install()
        self.assertEqual(self.child(('unknown',)).returncode, 1)
        child = self.child(self.dynamic)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'live\n', b''))
        self.assertFalse(marker.exists())

    def test_pid_is_actual_unreplaced_parent_even_if_environment_claims_another(self):
        self.install()
        child = self.child(self.pid, {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'PPID': '1'})
        self.assertEqual((child.returncode, child.stderr), (0, b''))
        self.assertEqual(json.loads(child.stdout), {'type': 'u', 'data': [os.getpid()]})

    def test_namespace_is_current_own_namespace_not_an_environment_claim(self):
        self.install()
        child = self.child(self.namespace, {'PATH': '/not-installed', 'LC_ALL': 'C', 'NAMESPACE': '1'})
        self.assertEqual((child.returncode, child.stderr), (0, b''))
        self.assertEqual(json.loads(child.stdout), {'type': 'v', 'data': [{'type': 't', 'data': KERNEL.namespace()}]})

    def test_exec_retains_parent_pid_and_reads_the_current_private_state_on_each_call(self):
        self.install()
        first = self.child(self.dynamic)
        self.state.write_text('second')
        second = self.child(self.dynamic)
        self.assertEqual((first.returncode, second.returncode, first.stderr, second.stderr), (0, 0, b'', b''))
        self.assertEqual(json.loads(first.stdout), {'parent': os.getpid(), 'state': 'first', 'argv': list(self.dynamic)})
        self.assertEqual(json.loads(second.stdout), {'parent': os.getpid(), 'state': 'second', 'argv': list(self.dynamic)})
        self.assertEqual(len(self.records()), 2)

    def test_live_dispatcher_failure_cannot_be_replaced_with_a_static_success(self):
        self.install();self.fallback.unlink()
        child = self.child(self.dynamic)
        self.assertNotEqual(child.returncode, 0);self.assertEqual(child.stdout, b'');self.assertTrue(child.stderr)
        self.assertFalse(self.ledger.exists())

    def test_failed_ledger_delivery_prevents_fixed_pid_namespace_and_live_output(self):
        self.install();self.ledger.mkdir()
        for arguments in (self.fixed, self.pid, self.namespace, self.dynamic):
            with self.subTest(arguments=arguments):
                child = self.child(arguments)
                self.assertNotEqual(child.returncode, 0);self.assertEqual(child.stdout, b'');self.assertTrue(child.stderr)

    def test_static_reply_encoding_is_independent_of_text_stdout_settings(self):
        replies = {('unicode',): 'é\r\n中', ('empty',): '', ('control',): '\xff\n'}
        self.install(replies)
        for encoding in ('utf-32', 'ascii:replace', 'ascii:ignore'):
            for arguments, reply in replies.items():
                with self.subTest(encoding=encoding, arguments=arguments):
                    child = self.child(arguments, {'PATH': '/not-installed', 'LC_ALL': 'C', 'PYTHONIOENCODING': encoding})
                    self.assertEqual((child.returncode, child.stdout, child.stderr), (0, reply.encode('utf-8'), b''))

    def test_bash_startup_environment_cannot_execute_parent_code(self):
        marker, startup = self.root / 'startup-ran', self.root / 'startup.sh'
        startup.write_text('printf bad >' + str(marker) + '\n');self.install()
        environment = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'BASH_ENV': str(startup), 'ENV': str(startup)}
        for arguments in (self.fixed, self.dynamic):
            child = self.child(arguments, environment)
            self.assertEqual(child.returncode, 0, child.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(self.records(), [['bus', list(arguments), environment] for arguments in (self.fixed, self.dynamic)])

    def test_new_process_uses_current_generated_static_replies_without_a_server_cache(self):
        self.install({self.fixed: 'first\n'});self.assertEqual(self.child(self.fixed).stdout, b'first\n')
        self.install({self.fixed: 'second\n'});self.assertEqual(self.child(self.fixed).stdout, b'second\n')
        self.assertEqual([row[1] for row in self.records()], [list(self.fixed)] * 2)

    def test_generator_refuses_duplicate_or_unrepresentable_query_and_path_shapes(self):
        for pid, namespace, dynamic in (((self.fixed,), (self.namespace,), (self.dynamic,)),
                                        ((self.pid,), (self.pid,), (self.dynamic,)),
                                        ((self.pid,), (self.namespace,), (self.pid,)),
                                        ([self.pid], (self.namespace,), (self.dynamic,)),
                                        ((), (self.namespace,), (self.dynamic,)),
                                        (((),), (self.namespace,), (self.dynamic,)),
                                        ((('bad\0',),), (self.namespace,), (self.dynamic,))):
            with self.subTest(pid=pid, namespace=namespace, dynamic=dynamic), self.assertRaises(ValueError):
                script(self.ledger, {self.fixed: '[]'}, pid, namespace, dynamic, self.fallback)
        for path in (Path('relative'), str(self.fallback), self.root / '\ud800', self.root / 'bad\0'):
            with self.subTest(path=repr(path)), self.assertRaises((ValueError, UnicodeError)):
                script(self.ledger, {self.fixed: '[]'}, (self.pid,), (self.namespace,), (self.dynamic,), path)


class NativeBusTests(PrivateNative):
    def query(self, operation, **arguments):
        return DHCP.native_query(operation, KERNEL.now() + 3, **arguments)

    def test_complete_fixed_bus_argv_and_typed_capture_use_all_static_and_live_operations(self):
        self.fixtures(families=(4, 6))
        self.assertEqual(self.query('owner'), {'type': 's', 'data': [':1.88']})
        self.assertEqual(self.query('pid', owner=':1.88'), {'type': 'u', 'data': [os.getpid()]})
        self.assertEqual(self.query('namespace', owner=':1.88'), {'type': 'v', 'data': [{'type': 't', 'data': KERNEL.namespace()}]})
        self.assertEqual(self.query('links', owner=':1.88')['data'][0][1][1], 'eth0')
        self.assertEqual(self.query('introspect', owner=':1.88', index=2), {'type': 's', 'data': [xml((4, 6))]})
        for operation in ('admin', 'state4', 'state6'):
            value = self.query(operation, owner=':1.88', index=2)
            self.assertEqual(value['data'][0]['data'], 'configured' if operation == 'admin' else 'bound')
        self.assertEqual(json.loads(self.query('describe', owner=':1.88', index=2)['data'][0])['Name'], 'eth0')
        self.assertEqual(TIME.native_query('owner', KERNEL.now() + 3), {'type': 's', 'data': [':1.77']})
        self.assertEqual(TIME.native_query('pid', KERNEL.now() + 3, owner=':1.77'), {'type': 'u', 'data': [os.getpid()]})
        self.assertEqual(TIME.native_query('peer', KERNEL.now() + 3, owner=':1.77'), packet('192.168.50.3'))
        rows = [json.loads(line) for line in self.ledger.read_bytes().splitlines()]
        self.assertEqual(len(rows), 12)
        for kind, arguments, environment in rows:
            self.assertEqual(kind, 'bus');self.assertEqual(len(arguments[:8]), 8)
            self.assertEqual(environment, {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'})

    def test_live_description_and_peer_queries_read_current_files_instead_of_preencoded_cache(self):
        self.fixtures()
        node_path, peer_path = self.root / 'description.json', self.root / 'peer.json'
        first = self.query('describe', owner=':1.88', index=2)
        node = json.loads(node_path.read_text());node['Name'] = 'eth1';node_path.write_text(json.dumps(node))
        second = self.query('describe', owner=':1.88', index=2)
        self.assertEqual(json.loads(first['data'][0])['Name'], 'eth0')
        self.assertEqual(json.loads(second['data'][0])['Name'], 'eth1')
        peer_path.write_text(json.dumps(packet('192.168.50.2', name='new.example.test')))
        self.assertEqual(TIME.native_query('peer', KERNEL.now() + 3, owner=':1.77'), packet('192.168.50.2', name='new.example.test'))

    def test_provider_dns_and_time_drift_keep_exact_original_turn_thresholds(self):
        self.fixtures(change_provider=True, change_dns=True, change_time=True)
        descriptions = [json.loads(self.query('describe', owner=':1.88', index=2)['data'][0]) for _ in range(3)]
        self.assertEqual([row['Addresses'][0]['ConfigProvider'] for row in descriptions],
                         [[192, 168, 50, 1], [192, 168, 50, 1], [192, 168, 50, 2]])
        self.assertEqual(self.source.read_bytes(), b'nameserver 9.9.9.9\n')
        peers = [TIME.native_query('peer', KERNEL.now() + 3, owner=':1.77') for _ in range(4)]
        self.assertEqual([row['data'][0]['ServerName']['data'] for row in peers], ['time.example.test'] * 3 + ['changed.test'])
        self.assertEqual((self.root / 'descriptions').read_text(), '3');self.assertEqual((self.root / 'peers').read_text(), '4')
        self.fixtures();self.assertFalse((self.root / 'descriptions').exists());self.assertFalse((self.root / 'peers').exists())

    def test_live_warning_and_corrupt_registration_still_refuse_through_real_predicates(self):
        self.fixtures(warning=True)
        with self.assertRaisesRegex(TIME.Pending, 'time query failed or warned'):
            TIME.native_query('peer', KERNEL.now() + 3, owner=':1.77')
        self.fixtures(corrupt=True)
        node = json.loads(self.query('describe', owner=':1.88', index=2)['data'][0])
        self.assertEqual(node['Addresses'][0]['ConfigProvider'], [0, 0, 0, 0])

    def test_unsupported_full_argv_is_logged_but_cannot_reach_live_counter_updates(self):
        self.fixtures()
        command = ('--system', '--no-pager', '--json=short', '--auto-start=no', '--allow-interactive-authorization=no',
                   '--expect-reply=yes', '--timeout=3s', 'call', ':1.88', DHCP.OBJECT, DHCP.MANAGER, 'DescribeLink', 'i', '2')
        for arguments in (command[:-1], (*command, ''), (*command[:-1], '3'), ('--user', *command[1:])):
            child = subprocess.run([str(self.bus), *arguments], capture_output=True, timeout=3,
                                   env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
            self.assertEqual((child.returncode, child.stdout, child.stderr), (1, b'', b''))
        self.assertFalse((self.root / 'descriptions').exists())
        self.assertEqual(len(self.ledger.read_bytes().splitlines()), 4)

    def test_real_capture_trust_refuses_before_private_shell_delivery(self):
        self.fixtures();self.bus.chmod(0o720)
        with self.assertRaises(DHCP.Pending):self.query('owner')
        self.assertEqual(self.ledger.read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
