"""Separate startup snapshots distinguish a fresh disk check from daemon state."""

import json
import hashlib
import os
from pathlib import Path
import subprocess
import unittest

from fixture_ssh import PrivateSSH, key


SERVER = 'debian13s4-admin-ssh.service'


class LoadedGenerationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateSSH(); self.addCleanup(self.fixture.close)
        self.fixture.install_native()

    def state(self, **faults):
        state = json.loads(self.fixture.database.read_bytes())
        if faults:
            state['faults'].update(faults)
            self.fixture.database.write_text(json.dumps(state))
        return state

    def run_script(self, command):
        return subprocess.run(['/bin/bash', '-p'], input=self.fixture.controller(command), text=True,
            capture_output=True, timeout=90, close_fds=True, start_new_session=True)

    def apply(self):
        child = self.run_script('s4s_apply')
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        return self.state()

    def add_existing_alternate(self):
        fixture = self.fixture
        home = fixture.home / 'alternate'; home.mkdir(mode=0o700)
        (home / '.ssh').mkdir(mode=0o700)
        fixture.write(home / '.ssh/authorized_keys', key())
        uid = os.geteuid() + 1
        for name, row in (
            ('passwd', f'alternate:x:{uid}:{uid}::{home}:/bin/bash\n'),
            ('group', f'alternate:x:{uid}:\n'),
            ('shadow', 'alternate:$y$j9T$fixture$0123456789012345678901234567890123456789:20000:0:99999:7:::\n')):
            path = fixture.etc / name
            fixture.write(path, path.read_bytes() + row.encode())

    def test_same_listener_administrator_change_restarts_loaded_configuration(self):
        self.add_existing_alternate()
        before = self.apply()
        group = self.fixture.etc / 'group'
        self.fixture.write(group, group.read_bytes().replace(b'sudo:x:27:operator\n', b'sudo:x:27:alternate\n'))
        plan = self.fixture.install_native()
        self.assertEqual(plan['binding']['listeners'], ['192.168.90.10', 'fd51:b089:f5e0:90::10'])
        self.assertIn(b'AllowUsers operator@', bytes.fromhex(before['loaded_configuration']))
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        after = self.state()
        self.assertEqual(bytes.fromhex(after['loaded_configuration']), plan['configuration'])
        self.assertGreater(after['server_starts'], before['server_starts'])
        self.assertNotIn(b'operator@', bytes.fromhex(after['loaded_configuration']))

    def test_same_path_host_key_change_restarts_loaded_key(self):
        before = self.apply()
        path = self.fixture.module.HOST_KEY
        replacement = b'REPLACED PRIVATE HOST KEY DELIVERY MODEL\n'
        self.fixture.write(path, replacement)
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        after = self.state()
        self.assertEqual(bytes.fromhex(after['loaded_host_key']), replacement)
        self.assertGreater(after['server_starts'], before['server_starts'])
        self.assertEqual(after['loaded_configuration'], before['loaded_configuration'])

    def test_changed_generation_failed_start_withholds_success_and_stays_inactive(self):
        before = self.apply()
        self.fixture.write(self.fixture.module.HOST_KEY, b'NEW HOST KEY DELIVERY MODEL\n')
        self.state(**{'start_' + SERVER: True})
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 75, child.stdout + child.stderr)
        after = self.state()
        self.assertFalse(after['active'].get(SERVER, False))
        self.assertEqual(after['server_starts'], before['server_starts'])
        self.assertEqual(after['loaded_host_key'], before['loaded_host_key'])

    def test_changed_generation_failed_stop_cannot_acknowledge_new_key(self):
        before = self.apply()
        self.fixture.write(self.fixture.module.HOST_KEY, b'NEW HOST KEY DELIVERY MODEL\n')
        self.state(**{'stop_' + SERVER: True})
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 75, child.stdout + child.stderr)
        after = self.state()
        self.assertEqual(after['server_starts'], before['server_starts'])
        self.assertEqual(after['loaded_host_key'], before['loaded_host_key'])

    def test_known_generation_no_op_preserves_start_snapshot_and_acknowledgment(self):
        before = self.apply()
        marker = self.fixture.root / 'state/ssh.loaded'
        original = (marker.stat().st_ino, marker.read_bytes())
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        after = self.state()
        self.assertEqual(after['server_starts'], before['server_starts'])
        self.assertEqual(after['invocations'], before['invocations'])
        self.assertEqual(after['loaded_configuration'], before['loaded_configuration'])
        self.assertEqual(after['loaded_host_key'], before['loaded_host_key'])
        self.assertEqual((marker.stat().st_ino, marker.read_bytes()), original)

    def test_unknown_generation_stops_revalidates_and_records_fresh_start(self):
        before = self.apply()
        marker = self.fixture.root / 'state/ssh.loaded'; marker.unlink()
        self.assertNotEqual(self.run_script('s4s_verify').returncode, 0)
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        after = self.state()
        self.assertEqual(after['server_starts'], before['server_starts'] + 1)
        self.assertEqual(after['loaded_configuration'], before['loaded_configuration'])
        self.assertIn(after['invocations'][SERVER].encode(), marker.read_bytes())

    def test_same_pid_new_invocation_cannot_reuse_previous_acknowledgment(self):
        before = self.apply()
        state = self.state(); state['invocations'][SERVER] = 'f' * 32
        self.fixture.database.write_text(json.dumps(state))
        self.assertNotEqual(self.run_script('s4s_verify').returncode, 0)
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        after = self.state()
        self.assertEqual(after['server_starts'], before['server_starts'] + 1)
        self.assertNotEqual(after['invocations'][SERVER], 'f' * 32)

    def test_complete_typed_instance_reply_required_without_unknown_or_duplicate_fields(self):
        before = self.apply()
        invocation = before['invocations'][SERVER]
        valid = 'ActiveState=active\nMainPID=42342\nInvocationID=' + invocation
        for reply in (valid.replace('42342', 'True'), valid.replace('42342', '2147483648'),
                      valid.replace('active\n', 'inactive\n'), valid.replace(invocation, '0' * 32),
                      valid.replace(invocation, 'x' * 32), valid + '\nMainPID=42342',
                      valid + '\nUnknown=yes', valid.rsplit('\n', 1)[0]):
            self.state(instance_reply=reply)
            with self.subTest(reply=reply):
                self.assertNotEqual(self.run_script('s4s_running_generation').returncode, 0)
        self.state(instance_reply=False)
        self.assertEqual(self.run_script('s4s_verify').returncode, 0)

    def test_key_damage_after_confirmed_stop_prevents_restart(self):
        before = self.apply()
        self.fixture.write(self.fixture.module.HOST_KEY, b'NEW HOST KEY DELIVERY MODEL\n')
        self.state(damage_after_stop=True)
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 75, child.stdout + child.stderr)
        after = self.state()
        self.assertFalse(after['active'].get(SERVER, False))
        self.assertEqual(after['server_starts'], before['server_starts'])
        self.assertFalse((self.fixture.root / 'state/ssh.loaded').exists())

    def test_startup_input_drift_during_start_withholds_acknowledgment(self):
        before = self.apply()
        self.fixture.write(self.fixture.module.HOST_KEY, b'NEW HOST KEY DELIVERY MODEL\n')
        self.state(damage_after_start=True)
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 75, child.stdout + child.stderr)
        after = self.state()
        self.assertFalse(after['active'].get(SERVER, False))
        self.assertEqual(after['server_starts'], before['server_starts'] + 1)
        self.assertNotEqual(bytes.fromhex(after['loaded_host_key']), self.fixture.module.HOST_KEY.read_bytes())
        self.assertFalse((self.fixture.root / 'state/ssh.loaded').exists())

    def test_failed_acknowledgment_sync_cannot_leave_healthy_controller_result(self):
        before = self.apply()
        self.fixture.write(self.fixture.module.HOST_KEY, b'NEW HOST KEY DELIVERY MODEL\n')
        self.state(sync_loaded=True)
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 75, child.stdout + child.stderr)
        after = self.state()
        self.assertFalse(after['active'].get(SERVER, False))
        self.assertEqual(after['server_starts'], before['server_starts'] + 1)
        self.assertNotEqual(self.run_script('s4s_verify').returncode, 0)

    def test_same_listener_admin_change_with_stable_native_binary_binds_config_bytes(self):
        self.add_existing_alternate()
        fixture = self.fixture
        # Only native DELIVERY formatting is modeled. This fixed executable
        # reads the current private disk config for -T, so an admin change
        # cannot be noticed merely through a changed fake executable hash.
        body = f'''#!/usr/bin/python3
import json, pathlib, sys
config = pathlib.Path({str(fixture.module.CONFIG)!r})
args = sys.argv[1:]
if args not in (['-t', '-f', str(config)], ['-T', '-f', str(config)]):
    raise SystemExit(64)
with pathlib.Path({str(fixture.ledger)!r}).open('a') as stream:
    stream.write(json.dumps(['sshd', args, {{}}]) + '\\n')
if args[0] == '-t':
    raise SystemExit(0)
entries = {{}}
for line in config.read_text(encoding='ascii').splitlines():
    if not line or line.startswith('#'):
        continue
    name, value = line.split(' ', 1)
    entries.setdefault(name.lower(), []).append(value)
entries.update({{'authorizedkeyscommand':['none'], 'trustedusercakeys':['none'],
                'authorizedprincipalsfile':['none']}})
for name, values in entries.items():
    for value in values:
        print(name + ' ' + value)
'''
        fixture.write(fixture.sshd, body.encode(), 0o700)
        native_sha = hashlib.sha256(fixture.sshd.read_bytes()).hexdigest()
        before = self.apply()
        group = fixture.etc / 'group'
        fixture.write(group, group.read_bytes().replace(b'sudo:x:27:operator\n', b'sudo:x:27:alternate\n'))
        plan = fixture.plan()
        child = self.run_script('s4s_repair')
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        after = self.state()
        self.assertEqual(hashlib.sha256(fixture.sshd.read_bytes()).hexdigest(), native_sha)
        self.assertEqual(after['loaded_configuration'], plan['configuration'].hex())
        self.assertEqual(after['server_starts'], before['server_starts'] + 1)
        self.assertEqual(after['loaded_host_key'], before['loaded_host_key'])
