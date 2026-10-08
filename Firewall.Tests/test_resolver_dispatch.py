import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from fixture_resolver import script
import test_resolver as resolver_fixture

KERNEL = resolver_fixture.KERNEL


class InventoryDispatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-resolver-dispatch-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.binary, self.ledger = self.root / 'ip', self.root / 'ledger'
        self.fallback, self.state = self.root / 'route-read', self.root / 'state'
        self.state.write_text('first')
        self.fixed = ('-j', '-N', '-details', 'link', 'show')
        self.route = ('-j', '-N', '-4', 'route', 'get', '8.8.8.8')
        self.fallback.write_text('#!/usr/bin/python3 -B\nimport json,os,sys\nfrom pathlib import Path\n'
                                 f'with open({str(self.ledger)!r},"a") as stream:stream.write(json.dumps({{"argv":sys.argv[1:],"env":dict(os.environ),"pid":os.getpid(),"sid":os.getsid(0)}})+"\\n")\n'
                                 f'print(json.dumps({{"state":Path({str(self.state)!r}).read_text()}}))\n')
        self.fallback.chmod(0o700)

    def tearDown(self):
        self.directory.cleanup()

    def install(self, replies=None):
        self.binary.write_text(script(self.ledger, replies if replies is not None else {self.fixed: '[]\n'},
                                      (self.route,), self.fallback), encoding='utf-8')
        self.binary.chmod(0o700)

    def child(self, arguments, environment=None, session=True):
        return subprocess.run([str(self.binary), *arguments], capture_output=True, timeout=3,
                              env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'} if environment is None else environment,
                              cwd=self.root, close_fds=True, start_new_session=session)

    def records(self):
        return [json.loads(line) for line in self.ledger.read_bytes().splitlines()]

    def test_fixed_replies_and_actual_pid_session_environment_are_retained(self):
        self.install();child = self.child(self.fixed)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'[]\n', b''))
        row, = self.records()
        self.assertEqual(row['argv'], list(self.fixed));self.assertEqual(row['env'], {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'})
        self.assertIs(type(row['pid']), int);self.assertGreater(row['pid'], 0);self.assertEqual(row['sid'], row['pid'])

    def test_session_is_observed_rather_than_inferred_from_child_pid(self):
        self.install();child = self.child(self.fixed, session=False)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'[]\n', b''))
        row, = self.records()
        self.assertEqual(row['sid'], os.getsid(0));self.assertNotEqual(row['pid'], row['sid'])

    def test_initial_environment_is_not_hidden_or_augmented_on_static_or_live_queries(self):
        self.install()
        environment = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'DEBIAN13S4_DNS_PARENT': 'do-not-hide',
                       'PWD': 'original cwd', 'SHLVL': '37', '_': 'incoming value', 'BASHPID': '1'}
        for arguments in (self.fixed, self.route):
            child = self.child(arguments, environment);self.assertEqual(child.returncode, 0, child.stderr)
        for row in self.records():self.assertEqual(row['env'], environment);self.assertGreater(row['pid'], 1);self.assertEqual(row['sid'], row['pid'])

    def test_literal_long_argv_control_unicode_and_environment_strings_round_trip(self):
        arguments = tuple('field ' + str(index) for index in range(1, 13)) + ('é中🦊', '\\"\n\r\t', '')
        self.install({arguments: 'é\r\n中'})
        environment = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'FIXTURE_VALUE': ''.join(chr(n) for n in range(1, 32)) + 'é\\"'}
        child = self.child(arguments, environment)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, 'é\r\n中'.encode(), b''))
        row, = self.records();self.assertEqual(row['argv'], list(arguments));self.assertEqual(row['env'], environment)
        self.assertEqual(len(self.ledger.read_bytes().splitlines()), 1)

    def test_unknown_extra_reordered_and_wrong_prefix_queries_never_reach_routes(self):
        self.install()
        variants = ((), self.fixed[:-1], (*self.fixed, ''), tuple(reversed(self.fixed)),
                    ('--json', *self.fixed[1:]), (*self.route[:-1], '1.1.1.1'), (*self.route, ''), ('route', 'get'))
        for arguments in variants:
            with self.subTest(arguments=arguments):
                child = self.child(arguments);self.assertEqual((child.returncode, child.stdout, child.stderr), (1, b'', b''))
        self.assertEqual([row['argv'] for row in self.records()], [list(arguments) for arguments in variants])

    def test_quoted_paths_reply_and_argv_cannot_evaluate_shell_code(self):
        marker = self.root / 'executed'
        self.ledger = self.root / "ledger ' $ ` literal"
        self.fallback = self.root / 'route $(touch executed) `touch executed`'
        self.fallback.write_text("#!/bin/bash -p\nprintf '%s\\n' live\n");self.fallback.chmod(0o700)
        value = "'; touch executed; # $(touch executed) `touch executed`"
        self.install({(value, '*', '', '\\'): value + '\n'})
        child = self.child((value, '*', '', '\\'))
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, (value + '\n').encode(), b''))
        child = self.child(self.route);self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'live\n', b''))
        self.assertFalse(marker.exists())

    def test_new_process_uses_current_generated_inventory_and_live_state(self):
        self.install({self.fixed: 'first\n'});self.assertEqual(self.child(self.fixed).stdout, b'first\n')
        self.install({self.fixed: 'second\n'});self.assertEqual(self.child(self.fixed).stdout, b'second\n')
        self.assertEqual(json.loads(self.child(self.route).stdout), {'state': 'first'})
        self.state.write_text('second');self.assertEqual(json.loads(self.child(self.route).stdout), {'state': 'second'})
        self.assertEqual(len(self.records()), 4)

    def test_ledger_failure_or_missing_live_reader_cannot_publish_healthy_replies(self):
        self.install();self.ledger.mkdir()
        for arguments in (self.fixed, self.route):
            child = self.child(arguments);self.assertNotEqual(child.returncode, 0);self.assertEqual(child.stdout, b'')
        self.ledger.rmdir();self.fallback.unlink()
        child = self.child(self.route);self.assertNotEqual(child.returncode, 0);self.assertEqual(child.stdout, b'')
        self.assertFalse(self.ledger.exists())

    def test_static_utf8_bytes_are_independent_of_parent_stdout_encoding(self):
        self.install({self.fixed: 'é\r\n中'})
        for encoding in ('utf-32', 'ascii:replace', 'ascii:ignore'):
            child = self.child(self.fixed, {'PATH': '/not-installed', 'LC_ALL': 'C', 'PYTHONIOENCODING': encoding})
            self.assertEqual((child.returncode, child.stdout, child.stderr), (0, 'é\r\n中'.encode(), b''))

    def test_parent_startup_environment_cannot_execute_code(self):
        marker, startup = self.root / 'startup-ran', self.root / 'startup.sh'
        startup.write_text('printf bad >' + str(marker) + '\n');self.install()
        environment = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'BASH_ENV': str(startup), 'ENV': str(startup)}
        for arguments in (self.fixed, self.route):self.assertEqual(self.child(arguments, environment).returncode, 0)
        self.assertFalse(marker.exists())
        self.assertTrue(all(row['env'] == environment for row in self.records()))

    def test_generator_refuses_nonfixed_disjoint_or_unrepresentable_shapes(self):
        for replies, routes, fallback in (({}, (self.route,), self.fallback), ({self.fixed: '[]'}, [], self.fallback),
                                         ({self.fixed: '[]'}, (), self.fallback), ({self.fixed: '[]'}, (self.fixed,), self.fallback),
                                         ({self.fixed: '[]'}, ((),), self.fallback), ({self.fixed: '[]'}, (('bad\0',),), self.fallback),
                                         ({self.fixed: '[]'}, (self.route,), Path('relative')), ({self.fixed: '[]'}, (self.route,), str(self.fallback))):
            with self.subTest(replies=replies, routes=routes), self.assertRaises(ValueError):script(self.ledger, replies, routes, fallback)
        with self.assertRaises(UnicodeError):script(self.ledger, {self.fixed: '\ud800'}, (self.route,), self.fallback)


class NativeResolverDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = resolver_fixture.NativeObservationTests('test_native_route_warning_and_timeout_are_pending_with_no_cli_stdout')
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def test_all_ten_real_inventory_queries_use_fixed_argv_and_actual_capture_metadata(self):
        self.fixture.executable()
        for name in KERNEL.COMMANDS:
            value = KERNEL.native_query(name, KERNEL.now() + 3)
            self.assertIs(type(value), list)
        rows = [json.loads(line) for line in self.fixture.ledger.read_bytes().splitlines()]
        self.assertEqual([row['argv'] for row in rows], [['-j', '-N', *args] for args in KERNEL.COMMANDS.values()])
        for row in rows:self.assertEqual(row['pid'], row['sid']);self.assertEqual(row['env'], {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'})

    def test_live_route_fault_exec_preserves_real_session_and_current_source_mutation(self):
        self.fixture.executable(f"from pathlib import Path; Path({str(self.fixture.source)!r}).write_text('nameserver 9.9.9.9\\n')")
        value = KERNEL.native_route('8.8.8.8', None, KERNEL.now() + 3)
        self.assertEqual(value[0]['gateway'], '192.168.50.1');self.assertEqual(self.fixture.source.read_bytes(), b'nameserver 9.9.9.9\n')
        row, = [json.loads(line) for line in self.fixture.ledger.read_bytes().splitlines()]
        self.assertEqual(row['pid'], row['sid']);self.assertEqual(row['argv'], ['-j', '-N', '-4', 'route', 'get', '8.8.8.8'])

    def test_actual_private_handler_warning_remains_pending_in_real_capture(self):
        self.fixture.executable("print('ambiguous lookup',file=sys.stderr)")
        with self.assertRaisesRegex(KERNEL.Pending, 'native query failed or warned'):
            KERNEL.native_route('8.8.8.8', None, KERNEL.now() + 3)
        self.assertEqual(len(self.fixture.ledger.read_bytes().splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
