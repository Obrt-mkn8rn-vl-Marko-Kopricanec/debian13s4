import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fixture_dispatch import script
from test_kernel import KERNEL, snapshot


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-dispatch-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.binary, self.ledger = self.root / 'ip', self.root / 'ledger'

    def tearDown(self):
        self.directory.cleanup()

    def install(self, replies, kind='ip'):
        self.binary.write_text(script(self.ledger, kind, replies), encoding='utf-8')
        self.binary.chmod(0o700)

    def run_child(self, arguments, environment=None):
        return subprocess.run([str(self.binary), *arguments], capture_output=True, timeout=3,
                              env={'PATH': '/not-installed', 'LC_ALL': 'C'} if environment is None else environment,
                              close_fds=True, start_new_session=True)

    def records(self):
        return [json.loads(line) for line in self.ledger.read_bytes().splitlines()]

    def native(self, name='links'):
        with patch.object(KERNEL, 'IP_BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.root), \
                patch.object(KERNEL, 'TRUSTED_UID', os.geteuid()):
            return KERNEL.native_query(name, KERNEL.now() + 3)

    def test_all_fixed_ip_queries_return_exact_original_json_and_log_actual_arguments(self):
        data = snapshot()
        replies = {('-j', '-N', *arguments): json.dumps(data[name]) + '\n'
                   for name, arguments in KERNEL.COMMANDS.items()}
        self.install(replies)
        for arguments, reply in replies.items():
            with self.subTest(arguments=arguments):
                child = self.run_child(arguments)
                self.assertEqual((child.returncode, child.stdout, child.stderr), (0, reply.encode('utf-8'), b''))
        self.assertEqual(self.records(), [['ip', list(arguments), {}] for arguments in replies])

    def test_argument_count_order_empty_strings_and_literal_patterns_are_distinct(self):
        admitted = ('a b', '', '*', '[ab]', '?')
        self.install({admitted: 'exact\n'})
        variants = (('a', 'b', '', '*', '[ab]', '?'), admitted[:-1], (*admitted, ''),
                    ('a b', '', 'x', '[ab]', '?'), (), tuple(reversed(admitted)))
        for arguments in variants:
            with self.subTest(arguments=arguments):
                child = self.run_child(arguments)
                self.assertEqual((child.returncode, child.stdout, child.stderr), (1, b'', b''))
        self.assertEqual(self.run_child(admitted).stdout, b'exact\n')
        self.assertEqual(self.records(), [['ip', list(arguments), {}] for arguments in (*variants, admitted)])

    def test_shell_metacharacters_in_paths_arguments_kind_and_replies_cannot_execute(self):
        marker = self.root / 'executed'
        injection = f"' ; touch {marker} ; # $(touch {marker}) `touch {marker}`"
        self.binary = self.root / "ip ' quoted"
        self.ledger = self.root / "ledger ' $ ` quoted"
        arguments = (injection, '\\', '$HOME', '${PATH}', '"')
        self.install({arguments: injection + '\n'}, kind=injection)
        child = self.run_child(arguments)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, (injection + '\n').encode(), b''))
        self.assertEqual(self.records(), [[injection, list(arguments), {}]])
        self.assertFalse(marker.exists())

    def test_arguments_after_nine_match_their_complete_positional_values(self):
        arguments = tuple(f'argument {index}' for index in range(1, 13))
        self.install({arguments: 'complete\n'})
        child = self.run_child(arguments)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'complete\n', b''))
        changed = (*arguments[:9], 'different tenth', *arguments[10:])
        child = self.run_child(changed)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (1, b'', b''))
        self.assertEqual(self.records(), [['ip', list(arguments), {}], ['ip', list(changed), {}]])

    def test_every_nonzero_control_byte_and_unicode_argv_round_trip_in_one_ledger_record(self):
        arguments = (''.join(chr(value) for value in range(1, 32)), 'é中🦊', '\\"\x7f', '')
        self.install({arguments: '[]\n'})
        child = self.run_child(arguments)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'[]\n', b''))
        self.assertEqual(self.records(), [['ip', list(arguments), {}]])
        self.assertEqual(len(self.ledger.read_bytes().splitlines()), 1)

    def test_reply_bytes_are_utf8_independent_of_parent_encoding_and_final_newline(self):
        replies = {('with-lf',): 'é\r\n', ('no-lf',): '中', ('empty',): ''}
        self.install(replies)
        for encoding in ('utf-32', 'ascii:replace', 'ascii:ignore', 'ascii:backslashreplace'):
            for arguments, reply in replies.items():
                with self.subTest(encoding=encoding, arguments=arguments):
                    child = self.run_child(arguments, {'PATH': '/not-installed', 'PYTHONIOENCODING': encoding})
                    self.assertEqual((child.returncode, child.stdout, child.stderr), (0, reply.encode('utf-8'), b''))

    def test_privileged_bash_mode_does_not_read_parent_environment_startup_code(self):
        marker, startup = self.root / 'startup-ran', self.root / 'startup.sh'
        startup.write_text(f'printf bad >{marker}\n')
        self.install({('read',): '[]\n'})
        child = self.run_child(('read',), {'PATH': '/not-installed', 'BASH_ENV': str(startup), 'ENV': str(startup)})
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'[]\n', b''))
        self.assertFalse(marker.exists())

    def test_each_new_process_reads_the_current_generated_fixture_and_appends_its_own_record(self):
        self.install({('read',): 'first\n'})
        self.assertEqual(self.run_child(('read',)).stdout, b'first\n')
        self.install({('read',): 'second\n'})
        self.assertEqual(self.run_child(('read',)).stdout, b'second\n')
        self.assertEqual(self.records(), [['ip', ['read'], {}]] * 2)

    def test_failed_ledger_delivery_prevents_even_an_admitted_reply(self):
        self.install({('read',): 'must-not-publish\n'})
        self.ledger.mkdir()
        child = self.run_child(('read',))
        self.assertNotEqual(child.returncode, 0)
        self.assertEqual(child.stdout, b'')
        self.assertTrue(child.stderr)

    def test_real_production_capture_trust_and_json_predicates_consume_the_child(self):
        value = snapshot()['links']
        arguments = ('-j', '-N', *KERNEL.COMMANDS['links'])
        self.install({arguments: json.dumps(value) + '\n'})
        self.assertEqual(self.native(), value)
        self.assertEqual(self.records(), [['ip', list(arguments), {}]])

    def test_real_production_capture_refuses_unknown_command_empty_invalid_and_oversized_json(self):
        arguments = ('-j', '-N', *KERNEL.COMMANDS['links'])
        for replies in ({('other',): '[]\n'}, {arguments: ''}, {arguments: '{bad}\n'},
                        {arguments: '[' + ' ' * KERNEL.MAX_BYTES + ']'}):
            with self.subTest(reply_kind=next(iter(replies))):
                self.install(replies)
                with self.assertRaises(KERNEL.Pending):self.native()
        self.assertEqual(self.records(), [['ip', list(arguments), {}]] * 4)

    def test_wrong_kind_and_unsafe_actual_executable_refuse_before_child_delivery(self):
        arguments = ('-j', '-N', *KERNEL.COMMANDS['links'])
        self.install({arguments: '[]\n'})
        self.binary.chmod(0o720)
        with self.assertRaises(KERNEL.Pending):self.native()
        self.assertFalse(self.ledger.exists())
        self.binary.unlink();os.mkfifo(self.binary, 0o600)
        with self.assertRaises(KERNEL.Pending):self.native()
        self.assertFalse(self.ledger.exists())

    def test_generator_refuses_unrepresentable_strings_and_nonfixed_dispatch_shapes(self):
        for value in ('\0', '\ud800', '\udfff'):
            for field in ('kind', 'argument', 'reply', 'path'):
                with self.subTest(field=field, value=repr(value)), self.assertRaises((ValueError, UnicodeError)):
                    script(self.ledger if field != 'path' else self.root / value,
                           value if field == 'kind' else 'ip',
                           {(value if field == 'argument' else 'read',): value if field == 'reply' else '[]\n'})
        for ledger, replies in ((Path('relative'), {('read',): '[]'}), (str(self.ledger), {('read',): '[]'}),
                                (self.ledger, {}), (self.ledger, {(): '[]'}), (self.ledger, {'read': '[]'}),
                                (self.ledger, {('read',): b'[]'}), (self.ledger, {(1,): '[]'})):
            with self.subTest(ledger=ledger, replies=replies), self.assertRaises(ValueError):
                script(ledger, 'ip', replies)


if __name__ == '__main__':
    unittest.main()
