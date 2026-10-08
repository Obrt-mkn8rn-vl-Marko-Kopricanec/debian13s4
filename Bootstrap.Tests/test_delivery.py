import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from fixture_delivery import LIMIT, execute, request, serve


if os.geteuid() == 0:
    raise RuntimeError('Run private fixture delivery checks as an ordinary user.')


class ProtocolTests(unittest.TestCase):
    def test_exact_utf8_arguments_keep_empty_spaces_newlines_and_carriage_returns(self):
        args = ['systemctl', 'caller', '', 'name with spaces', 'héllo\r\n', 'last']
        wire = str(len(args)).encode() + b'\0' + b'\0'.join(value.encode() for value in args) + b'\0'
        stream = io.BytesIO(wire)
        self.assertEqual(request(stream), args)
        self.assertIsNone(request(stream))

    def test_bad_count_incomplete_utf8_and_unknown_action_refuse(self):
        cases = (b'1\0', b'02\0', b'65\0', b'256\0', b'-2\0', b'x\0', b'2',
                 b'2\0sync\0', b'2\0sync\0\xff\0', b'2\0unknown\0caller\0', b'2\0sync\0\0')
        for wire in cases:
            with self.subTest(wire=wire), self.assertRaises((ValueError, UnicodeDecodeError)):
                request(io.BytesIO(wire))

    def test_aggregate_bound_counts_separators_and_never_truncates(self):
        header = b'3\0sync\0caller\0'
        admitted = b'x' * (LIMIT - len(b'sync\0caller\0') - 1)
        self.assertEqual(request(io.BytesIO(header + admitted + b'\0'))[-1], admitted.decode())
        with self.assertRaisesRegex(ValueError, 'byte limit'):
            request(io.BytesIO(header + admitted + b'x\0'))

    def test_repeated_exec_has_fresh_globals_and_actual_disk_state(self):
        with tempfile.TemporaryDirectory(prefix='debian13s4-delivery-state.') as name:
            path = Path(name) / 'database'
            code = compile(r"""import sys
from pathlib import Path
assert 'previous_command' not in globals()
previous_command = True
path = Path(sys.argv[1]); value = path.read_text()
print(value, end=''); path.write_text(value + 'next\n')
sys.exit(19)
""", 'private model', 'exec')
            path.write_text('first\r\n')
            argv = list(__import__('sys').argv)
            self.assertEqual(execute(code, 'model', path, 'log', ['sync', 'caller']),
                             b'19\0first\n\0\0')
            path.write_text('external replacement\n')
            self.assertEqual(execute(code, 'model', path, 'log', ['sync', 'caller']),
                             b'19\0external replacement\n\0\0')
            self.assertEqual(path.read_text(), 'external replacement\nnext\n')
            self.assertEqual(__import__('sys').argv, argv)

    def test_model_exit_exception_and_exact_output_are_checked(self):
        cases = (("print('héllo\\r\\n', end=''); print('error',file=__import__('sys').stderr); raise SystemExit(75)",
                  b'75\0h\xc3\xa9llo\r\n\0error\n\0'),
                 ("raise SystemExit(None)", b'0\0\0\0'),
                 ("raise SystemExit('failed')", b'1\0\0failed\n\0'))
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(execute(compile(text, 'model', 'exec'), 'model', 'db', 'log',
                                         ['sync', 'caller']), expected)
        response = execute(compile("raise OSError('delivery failed')", 'model', 'exec'),
                           'model', 'db', 'log', ['sync', 'caller'])
        self.assertTrue(response.startswith(b'1\0\0Traceback'))
        self.assertIn(b'OSError: delivery failed\n', response)

    def test_nul_oversized_and_short_responses_cannot_succeed(self):
        for text in ("print('\\0')", f"print('x' * {LIMIT})"):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'response'):
                execute(compile(text, 'model', 'exec'), 'model', 'db', 'log', ['sync', 'caller'])
        class ShortSink(io.BytesIO):
            def write(self, data):
                return super().write(data[:-1])
        with tempfile.TemporaryDirectory(prefix='debian13s4-delivery-short.') as name:
            model = Path(name) / 'model.py'; model.write_text('pass\n')
            with self.assertRaisesRegex(OSError, 'short'):
                serve(model, 'db', 'log', io.BytesIO(b'2\0sync\0caller\0'), ShortSink())


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        # Keep discovery from collecting the original cases a second time.
        from test_bootstrap import BootstrapTests
        self.fixture = BootstrapTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def script(self, body, timeout=5):
        return self.fixture.run_script(self.fixture.harness(lock=False) +
                                       '\nfixture_body() {\n' + body + '\n}\nfixture_body\n', timeout=timeout)

    def test_command_substitution_and_pipeline_share_one_owned_interpreter(self):
        result = self.script('''
s4b_systemctl daemon-reload
value=$(s4b_systemctl show --property=ActiveState --value debian13s4-repair.timer)
[[ $value == inactive ]]
printf 'data\n' | s4b_atomic "$S4B_BOOT_DIR/target" 0600
printf 'done\n'
''')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'done\n', ''))
        self.assertEqual((self.fixture.boot / 'target').read_text(), 'data\n')
        events = self.fixture.events()
        self.assertEqual([event['action'] for event in events], ['systemctl', 'systemctl', 'sync'])
        self.assertEqual(events[-1]['caller'], 's4b_atomic')
        self.assertFalse(Path('/proc/' + (self.fixture.root / 'model.pid').read_text().strip()).exists())

    def test_parallel_callers_cannot_swap_replies_or_drop_events(self):
        (self.fixture.systemd / 'present').write_text('unit\n')
        result = self.script('''
jobs=()
for index in {1..8}; do
    (
        if (( index % 2 )); then unit=present; expected=loaded; else unit=absent; expected=not-found; fi
        value=$(s4b_systemctl show --property=LoadState --value "$unit")
        [[ $value == "$expected" ]]
    ) &
    jobs+=("$!")
done
for job in "${jobs[@]}"; do wait "$job"; done
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.fixture.events()), 8)
        self.assertEqual(sum(event['args'][-1] == 'present' for event in self.fixture.events()), 4)

    def test_failure_then_external_repair_is_reloaded_without_cached_success(self):
        self.fixture.faults(**{'daemon-reload': True})
        result = self.script('s4b_systemctl daemon-reload')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.fixture.events()[-1]['code'], 1)
        self.fixture.faults()
        result = self.script('s4b_systemctl daemon-reload')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([event['code'] for event in self.fixture.events()], [1, 0])

    def test_worker_death_withholds_success_and_next_attempt_can_retry(self):
        result = self.script('''
kill -KILL "$S4_FIXTURE_WORKER"
wait "$S4_FIXTURE_WORKER" 2>/dev/null || :
s4b_systemctl daemon-reload
printf 'unexpected success\n'
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('unexpected success', result.stdout)
        self.assertEqual(self.fixture.events(), [])
        self.assertEqual(self.script('s4b_systemctl daemon-reload').returncode, 0)

    def test_outer_timeout_still_cleans_the_model_and_owned_session(self):
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self.script("s4b_systemctl daemon-reload; printf 'ready\\r\\n'; sleep 60", timeout=2)
        self.assertEqual(raised.exception.timeout, 2)
        self.assertEqual(raised.exception.output, b'ready\r\n')
        worker = int((self.fixture.root / 'model.pid').read_text())
        self.assertFalse(Path(f'/proc/{worker}').exists())

    def test_original_model_state_events_and_failures_match_selected_native_commands(self):
        from test_bootstrap import BOOT, TIMER, BootstrapTests
        other = BootstrapTests(methodName='runTest'); other.setUp()
        self.addCleanup(other.doCleanups)
        fixtures = (self.fixture, other)
        for fixture in fixtures:
            fixture.boot.mkdir(parents=True, mode=0o700)
            fixture.library.mkdir(mode=0o700)
            for path in (fixture.boot / 'pending', fixture.boot / 'setup.sh',
                         fixture.library / 'repair.sh', fixture.library / 'tasks.list', fixture.systemd / BOOT):
                path.write_text('complete logical file\r\n')
                path.chmod(0o600)
        operations = [('sync', 's4b_atomic', 'boot/pending'),
                      ('sync', 's4b_arm', 'boot'),
                      ('systemctl', 's4b_arm', 'enable', BOOT),
                      ('systemctl', 's4b_arm', 'is-enabled', BOOT),
                      ('sync', 's4b_enablement_paths', 'systemd/multi-user.target.wants'),
                      ('systemctl', 's4b_quiesce', 'stop', TIMER),
                      ('sync', 's4b_publish', 'library/repair.sh'),
                      ('sync', 's4b_publish', 'library/tasks.list'),
                      ('systemctl', 's4b_finish', 'enable', TIMER),
                      ('sync', 's4b_enablement_paths', 'systemd/timers.target.wants'),
                      ('systemctl', 's4b_finish', 'start', TIMER),
                      ('systemctl', 's4b_finish', 'show', '--property=ActiveState', '--value', TIMER),
                      ('sync', 's4b_finish', 'boot')]
        def normalize(value, fixture):
            if isinstance(value, str): return value.replace(str(fixture.root), '<fixture>')
            if isinstance(value, dict): return {key: normalize(item, fixture) for key, item in value.items()}
            if isinstance(value, list): return [normalize(item, fixture) for item in value]
            return value
        code = compile(self.fixture.model.read_text(), str(self.fixture.model), 'exec')
        for index, operation in enumerate(operations):
            if index in (0, 1):
                for fixture in fixtures:
                    fixture.faults(sync_file_data=index == 0, persist_sync_errors=index == 0)
            arguments = []
            for fixture in fixtures:
                mapped = []
                for arg in operation:
                    directory, _, relative = arg.partition('/')
                    if directory in ('boot', 'library', 'systemd'):
                        mapped.append(str(getattr(fixture, directory) / relative))
                    else:
                        mapped.append(arg)
                arguments.append(mapped)
            wire = execute(code, self.fixture.model, self.fixture.database, self.fixture.log, arguments[0])
            result = subprocess.run(['python3', '-B', str(other.model), str(other.database), str(other.log),
                                     *arguments[1]], capture_output=True, timeout=5)
            status, stdout, stderr, ending = wire.split(b'\0')
            self.assertEqual((int(status), stdout, stderr, ending),
                             (result.returncode, result.stdout, result.stderr, b''))
            self.assertEqual(normalize(self.fixture.state(), self.fixture), normalize(other.state(), other))
            self.assertEqual(normalize(self.fixture.events(), self.fixture), normalize(other.events(), other))


if __name__ == '__main__':
    unittest.main()
