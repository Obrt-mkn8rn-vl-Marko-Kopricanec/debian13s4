"""Persistent real-model private transport and process-ownership controls."""
import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch
from fixture_web import PrivateWeb, MODEL
import fixture_manager as MANAGER


class WebManagerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateWeb()
        self.addCleanup(self.fixture.close)
        self.model = self.fixture.root / 'manager.py'
        self.code = MANAGER.compile_model(self.model)

    def response(self, args):
        raw = MANAGER.execute(self.code, self.model, self.fixture.root, args)
        status, out, err, tail = raw.split(b'\0')
        self.assertEqual(tail, b'')
        return int(status), out, err

    def test_complete_original_model_and_selected_cli_bytes_are_preserved(self):
        self.assertEqual(self.model.read_bytes(), MODEL.encode())
        calls = [
            ['package', '--show', '--showformat=${Status}\\n', '--', 'nginx'],
            ['audit', '--audit'],
            ['sync', str(self.fixture.root)],
            ['systemctl', 'show', '--property=LoadState', '--value', 'nginx.service'],
            ['systemctl', 'show', '--property=MainPID', '--value', 'nginx.service'],
            ['systemctl', 'show', '--property=ActiveState', '--property=MainPID', '--property=InvocationID', 'nginx.service'],
        ]
        for args in calls:
            with self.subTest(args=args):
                old = subprocess.run(['python3', '-B', str(self.model), str(self.fixture.root), *args], capture_output=True, timeout=10)
                self.assertEqual(self.response(args), (old.returncode, old.stdout, old.stderr))

    def test_same_compilation_reads_current_faults_and_state_on_every_request(self):
        call = ['package', '--show', '--showformat=${Status}\\n', '--', 'nginx']
        self.assertEqual(self.response(call), (0, b'install ok installed\n', b''))
        self.fixture.faults(packages=True)
        self.assertEqual(self.response(call), (0, b'not installed\n', b''))
        self.fixture.faults(packages=False)
        self.assertEqual(self.response(call), (0, b'install ok installed\n', b''))
        unit = 'debian13s4-web-server.service'
        self.assertEqual(self.response(['systemctl', 'start', unit]), (0, b'', b''))
        self.assertEqual(json.loads(self.fixture.database.read_bytes())['starts'], 1)
        self.assertEqual(self.response(['systemctl', 'stop', unit]), (0, b'', b''))
        self.assertFalse(json.loads(self.fixture.database.read_bytes())['active'][unit])

    def test_each_invocation_gets_fresh_globals(self):
        probe = self.fixture.root / 'probe.py'
        probe.write_text("import sys\nassert 'retained' not in globals()\nretained = True\nprint(sys.argv[2:])\n")
        code = MANAGER.compile_model(probe)
        expected = b"0\0['audit', '--audit']\n\0\0"
        for _ in range(2):
            self.assertEqual(MANAGER.execute(code, probe, self.fixture.root, ['audit', '--audit']), expected)

    def test_malformed_requests_refuse_before_model_execution(self):
        for args in ([], ['network'], ['audit', True], ['audit', '\0'], ['audit', 'x' * 65536], ['audit'] * 64):
            with self.subTest(args=type(args)), patch.object(MANAGER.DELIVERY, 'execute') as execute, self.assertRaises(ValueError):
                MANAGER.execute(self.code, self.model, self.fixture.root, args)
            execute.assert_not_called()
        with self.assertRaises(ValueError):
            MANAGER.serve(self.model, self.fixture.root, io.BytesIO(b'2\0sync\0--audit\0'), io.BytesIO())

    def test_successful_controller_reaps_one_compilation_worker(self):
        child = self.fixture.controller('s4m_systemctl show --property=LoadState --value nginx.service\ns4m_systemctl show --property=MainPID --value nginx.service')
        self.assertEqual(child.returncode, 0, child.stderr.decode())
        self.assertEqual(child.stdout, b'loaded\n0\n')
        self.assertEqual(self.fixture.private_processes(), [])
        self.assertTrue((self.fixture.root / 'model.pid').is_file())

    def test_nonzero_and_timeout_paths_join_owned_interpreter(self):
        child = self.fixture.controller('s4m_control dpkg --audit\nexit 7')
        self.assertEqual(child.returncode, 7)
        self.assertEqual(self.fixture.private_processes(), [])
        with self.assertRaises(subprocess.TimeoutExpired):
            self.fixture.controller('sleep 30', timeout=.05)
        self.assertEqual(self.fixture.private_processes(), [])

    def test_partial_response_poisons_the_attempt(self):
        # Retire the actual model worker after a deliberately partial frame.
        # The real shared client must poison the attempt before a second write.
        self.model.write_text("import os, pathlib, sys\n"
            "with (pathlib.Path(sys.argv[1]) / 'probe.entries').open('ab') as f: f.write(b'entry\\n')\n"
            "sys.__stdout__.buffer.write(b'0\\0partial')\n"
            "sys.__stdout__.buffer.flush()\nos._exit(0)\n")
        command = '''
if s4_fixture_call systemctl audit --audit; then exit 91; else [[ $? == 75 ]] || exit 92; fi
[[ -e $S4_FIXTURE_ROOT/model.failed ]] || exit 93
if s4_fixture_call systemctl audit --audit; then exit 94; else [[ $? == 75 ]] || exit 95; fi
'''
        child = self.fixture.controller(command)
        self.assertEqual(child.returncode, 0, child.stderr.decode())
        self.assertEqual(child.stdout, b'')
        self.assertEqual((self.fixture.root / 'probe.entries').read_bytes(), b'entry\n')
        self.assertEqual(self.fixture.private_processes(), [])

    def test_substitution_children_cannot_stop_the_parent_interpreter(self):
        child = self.fixture.controller('''
ignored=$(s4_web_model_stop)
[[ $S4_WEB_MODEL_OPEN == 1 ]]
s4m_systemctl show --property=MainPID --value nginx.service
s4_web_model_stop
[[ $S4_WEB_MODEL_OPEN == 0 ]]
s4_web_model_stop
''')
        self.assertEqual(child.returncode, 0, child.stderr.decode())
        self.assertEqual(child.stdout, b'0\n')
        self.assertEqual(self.fixture.private_processes(), [])


if __name__ == '__main__':
    unittest.main()
