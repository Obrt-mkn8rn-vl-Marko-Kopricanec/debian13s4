import base64
import configparser
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import signal
import shlex
import stat
import struct
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from fixture_ssh import PrivateSSH, ROOT, key, topology


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateSSH(); self.addCleanup(self.fixture.close)
        self.m = self.fixture.module

    def test_existing_admin_and_numeric_dual_stack_assignments_bind_exact_prefixes(self):
        plan = self.fixture.plan()
        self.assertEqual(plan['admin']['name'], 'operator')
        self.assertEqual(plan['binding']['listeners'], ['192.168.90.10', 'fd51:b089:f5e0:90::10'])
        self.assertEqual(plan['binding']['interface']['index'], 2)
        text = plan['configuration'].decode('ascii')
        self.assertIn('AuthenticationMethods publickey\n', text)
        self.assertIn('operator@192.168.90.0/24 operator@fd51:b089:f5e0:90::/64\n', text)
        self.assertIn('ListenAddress 192.168.90.10:22\n', text)
        self.assertIn('ListenAddress [fd51:b089:f5e0:90::10]:22\n', text)
        self.assertNotIn('Include ', text); self.assertNotIn('0.0.0.0:22', text)
        self.assertNotIn('[::]:22', text); self.assertNotIn('fc00::/7', text)

    def test_ipv4_only_does_not_invent_ipv6_listener_or_assignment(self):
        self.fixture.data = topology(False)
        plan = self.fixture.plan()
        self.assertEqual(plan['binding']['loopback'], ['127.0.0.1'])
        self.assertEqual(plan['binding']['listeners'], ['192.168.90.10'])
        self.assertNotIn('ListenAddress [', plan['configuration'].decode())

    def test_other_private_public_and_link_local_addresses_do_not_grant_admin_listeners(self):
        original = copy.deepcopy(self.fixture.data)
        for address in ('192.168.91.10', '10.1.2.3', '203.0.113.10'):
            self.fixture.data = copy.deepcopy(original)
            self.fixture.data['addresses'][1]['addr_info'][0]['local'] = address
            with self.subTest(address=address), self.assertRaises(self.m.Pending): self.fixture.plan()
        for address in ('fd52::10', 'fe80::10', '2001:db8::10'):
            self.fixture.data = copy.deepcopy(original)
            self.fixture.data['addresses'][1]['addr_info'][1]['local'] = address
            plan = self.fixture.plan()
            self.assertEqual(plan['binding']['listeners'], ['192.168.90.10'])

    def test_admin_assignment_mask_scope_boolean_lifetimes_and_status_are_positive(self):
        original = copy.deepcopy(self.fixture.data)
        changes = ({'prefixlen': 23}, {'scope': 'host'}, {'dynamic': 1}, {'tentative': True},
                   {'dadfailed': True}, {'deprecated': True}, {'temporary': True}, {'optimistic': True},
                   {'valid_life_time': 0}, {'preferred_life_time': True}, {'preferred_life_time': -1})
        for change in changes:
            self.fixture.data = copy.deepcopy(original)
            self.fixture.data['addresses'][1]['addr_info'][0].update(change)
            with self.subTest(change=change), self.assertRaises(self.m.Pending): self.fixture.plan()
        for missing in ('valid_life_time', 'preferred_life_time'):
            self.fixture.data = copy.deepcopy(original)
            self.fixture.data['addresses'][1]['addr_info'][0].pop(missing)
            with self.subTest(missing=missing), self.assertRaises(self.m.Pending): self.fixture.plan()

    def test_down_unknown_duplicate_and_vlan_parent_link_facts_are_not_guessed(self):
        original = copy.deepcopy(self.fixture.data)
        for mutation in ('down', 'unknown', 'duplicate', 'unresolved-vlan'):
            self.fixture.data = copy.deepcopy(original)
            if mutation == 'down':
                for rows in ('links', 'addresses'): self.fixture.data[rows][1]['flags'].remove('LOWER_UP')
            elif mutation == 'unknown': self.fixture.data['links'][1]['link_type'] = '[9999]'
            elif mutation == 'duplicate': self.fixture.data['links'].append(copy.deepcopy(self.fixture.data['links'][1]))
            else:
                self.fixture.data['links'][1].update({'link_index': 9, 'linkinfo':
                    {'info_kind': 'vlan', 'info_data': {'id': 90, 'protocol': '802.1Q'}}})
            with self.subTest(mutation=mutation), self.assertRaises(self.m.Pending): self.fixture.plan()

    def test_direct_route_and_preferred_source_must_agree(self):
        original = copy.deepcopy(self.fixture.data)
        for mutation in ('missing', 'duplicate', 'gateway', 'linkdown', 'prefsrc', 'wrong-table'):
            self.fixture.data = copy.deepcopy(original)
            row = self.fixture.data['routes4'][0]
            if mutation == 'missing': self.fixture.data['routes4'] = []
            elif mutation == 'duplicate': self.fixture.data['routes4'].append(copy.deepcopy(row))
            elif mutation == 'gateway': row['gateway'] = '192.168.90.1'
            elif mutation == 'linkdown': row['flags'] = ['linkdown']
            elif mutation == 'prefsrc': row['prefsrc'] = '192.168.90.11'
            else: row['table'] = 253
            with self.subTest(mutation=mutation), self.assertRaises(self.m.Pending): self.fixture.plan()

    def test_unusable_or_missing_loopback_is_not_inferred(self):
        original = copy.deepcopy(self.fixture.data)
        for mutation in ('missing', 'deprecated', 'no-life', 'down'):
            self.fixture.data = copy.deepcopy(original)
            if mutation == 'missing': self.fixture.data['addresses'][0]['addr_info'] = []
            elif mutation == 'deprecated': self.fixture.data['addresses'][0]['addr_info'][0]['deprecated'] = True
            elif mutation == 'no-life': self.fixture.data['addresses'][0]['addr_info'][0].pop('valid_life_time')
            else:
                for rows in ('links', 'addresses'): self.fixture.data[rows][0]['flags'].remove('UP')
            with self.subTest(mutation=mutation), self.assertRaises(self.m.Pending): self.fixture.plan()

    def test_account_discovery_missing_ambiguous_uid_and_locked_authentication_refuse(self):
        group = self.fixture.etc / 'group'; original = group.read_bytes()
        group.write_bytes(original.replace(b'sudo:x:27:operator', b'sudo:x:27:'))
        with self.assertRaises(self.m.Pending): self.fixture.plan()
        group.write_bytes(original)
        passwd = self.fixture.etc / 'passwd'; before = passwd.read_bytes()
        passwd.write_bytes(before + before.splitlines(keepends=True)[1].replace(b'operator', b'other'))
        with self.assertRaises(self.m.Pending): self.fixture.plan()
        passwd.write_bytes(before)
        shadow = self.fixture.etc / 'shadow'; before = shadow.read_bytes()
        for replacement in (b'!', b'', b'*', b'$y$short'):
            shadow.write_bytes(before.replace(before.splitlines()[1].split(b':')[1], replacement))
            with self.subTest(replacement=replacement), self.assertRaises(self.m.Pending): self.fixture.plan()
        shadow.write_bytes(before)

    def test_no_key_unsupported_options_duplicate_wire_and_bad_type_refuse(self):
        path = self.fixture.home / 'operator/.ssh/authorized_keys'
        for data in (b'', b'# no keys\n', b'from="192.168.90.0/24" ' + key(), key() + key(),
                     key().replace(b'ssh-ed25519 ', b'ssh-dss ', 1), b'ssh-ed25519 invalid\n', key().rstrip(b'\n')):
            path.write_bytes(data)
            with self.subTest(data=data[:50]), self.assertRaises(self.m.Pending): self.fixture.plan()

    def test_rsa_requires_canonical_positive_mpints_and_strong_modulus(self):
        def wire(bits, exponent=65537):
            number = ((1 << (bits - 1)) | 1).to_bytes((bits + 7) // 8, 'big')
            if number[0] & 128: number = b'\0' + number
            parts = (b'ssh-rsa', exponent.to_bytes(3, 'big'), number)
            return b'ssh-rsa ' + base64.b64encode(b''.join(struct.pack('!I', len(part)) + part for part in parts)) + b'\n'
        self.assertEqual(self.m.public_keys(wire(3072)), 1)
        for data in (wire(2048), wire(3072, 65536), wire(9216)):
            with self.subTest(bytes=len(data)), self.assertRaises(self.m.Pending): self.m.public_keys(data)

    def test_protected_descriptor_key_and_account_sources_refuse_unsafe_identity(self):
        path = self.fixture.home / 'operator/.ssh/authorized_keys'; before = path.read_bytes()
        path.chmod(0o640)
        with self.assertRaises(self.m.Pending): self.fixture.plan()
        path.chmod(0o600)
        saved = path.with_name('saved'); path.rename(saved); path.symlink_to(saved)
        with self.assertRaises(self.m.Pending): self.fixture.plan()
        path.unlink(); saved.rename(path)
        linked = path.with_name('linked'); os.link(path, linked)
        with self.assertRaises(self.m.Pending): self.fixture.plan()
        linked.unlink()
        self.assertEqual(path.read_bytes(), before)
        shadow = self.fixture.etc / 'shadow'; shadow.chmod(0o640)
        self.assertEqual(self.fixture.plan()['admin']['name'], 'operator')
        shadow.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.fixture.plan()

    def test_read_close_failure_retires_descriptor_once(self):
        path = self.fixture.home / 'operator/.ssh/authorized_keys'
        original = self.m.os.close; retired, reused = [], []
        def failed_close(fd):
            original(fd); retired.append(fd)
            other = os.open(path, os.O_RDONLY)
            self.assertEqual(other, fd); reused.append(other)
            raise OSError('retired close failed')
        try:
            with patch.object(self.m.os, 'close', side_effect=failed_close):
                with self.assertRaises(OSError): self.m.trusted_read(path, (os.geteuid(),), True)
            self.assertEqual(retired, reused)
            self.assertEqual(len(retired), 1); self.assertEqual(os.read(reused[0], len(key())), key())
        finally:
            for fd in reused: original(fd)

    def test_full_network_and_account_drift_withhold_configuration(self):
        calls = 0
        def drift(name, deadline):
            nonlocal calls
            calls += 1; value = self.fixture.query(name, deadline)
            if calls == 12: value[1]['addr_info'][0]['preferred_life_time'] -= 1
            return value
        with self.assertRaises(self.m.Pending): self.m.prepare(query=drift)
        account = self.m.administrator; count = 0
        def changed():
            nonlocal count
            count += 1; result = account()
            if count == 2: result['sources']['keys']['sha256'] = '0' * 64
            return result
        with self.assertRaises(self.m.Pending): self.m.prepare(query=self.fixture.query, account=changed)

    def test_deliveries_are_copied_before_later_callbacks_can_mutate_them(self):
        accounts, rows = [], []
        def account():
            if accounts: accounts[0]['sources']['keys']['sha256'] = '0' * 64
            result = self.m.administrator(); accounts.append(result); return result
        def query(name, deadline):
            if rows: rows[-1].clear()
            result = self.fixture.query(name, deadline); rows.append(result); return result
        plan = self.m.prepare(query=query, account=account)
        self.assertEqual(plan['binding']['listeners'][0], '192.168.90.10')
        self.assertNotEqual(plan['admin']['sources']['keys']['sha256'], '0' * 64)

    def test_unsafe_delivered_admin_cannot_inject_configuration(self):
        original = self.m.administrator()
        for field, value in (('name', 'operator\nPermitRootLogin yes'), ('uid', True),
                             ('key_file', '/tmp/keys'), ('key_count', 0)):
            changed = copy.deepcopy(original); changed[field] = value
            with self.subTest(field=field), self.assertRaises(self.m.Pending):
                self.m.prepare(query=self.fixture.query, account=lambda: changed)

    def test_final_namespace_is_typed_and_full_window_is_shared(self):
        for final in (True, 0, '4711', 4712):
            values = iter((4711, final))
            with self.subTest(final=final), self.assertRaises(self.m.Pending):
                self.m.prepare(query=self.fixture.query, scope=lambda: next(values))
        for deadline in (False, float('nan'), float('inf'), self.m.KERNEL.now() - 1):
            with self.subTest(deadline=deadline), self.assertRaises(self.m.Pending):
                self.m.prepare(query=self.fixture.query, deadline=deadline)

    def test_boolean_final_namespace_cannot_equal_integer_one(self):
        values = iter((1, True))
        with self.assertRaises(self.m.Pending):
            self.m.prepare(query=self.fixture.query, scope=lambda: next(values))

    def test_assignment_expiry_fences_later_native_work(self):
        self.fixture.data['addresses'][1]['addr_info'][0]['preferred_life_time'] = 2
        clock = [100.0]
        def query(name, deadline):
            clock[0] += 0.5
            return self.fixture.query(name, deadline)
        with patch.object(self.m.KERNEL, 'now', side_effect=lambda: clock[0]):
            with self.assertRaises(self.m.Pending): self.m.prepare(query=query)

    def test_effective_settings_cannot_enable_password_root_ca_or_public_binding(self):
        plan = self.fixture.plan(); raw = self.fixture.effective(plan)
        self.m.effective(raw, plan)
        for old, new in ((b'passwordauthentication no', b'passwordauthentication yes'),
                         (b'permitrootlogin no', b'permitrootlogin yes'),
                         (b'trustedusercakeys none', b'trustedusercakeys /foreign'),
                         (b'listenaddress 192.168.90.10:22', b'listenaddress 0.0.0.0:22'),
                         (b'operator@192.168.90.0/24', b'operator@192.168.0.0/16')):
            with self.subTest(new=new), self.assertRaises(self.m.Pending): self.m.effective(raw.replace(old, new), plan)
        with self.assertRaises(self.m.Pending): self.m.effective(raw + b'passwordauthentication no\n', plan)

    def test_socket_inventory_requires_all_bound_listeners_and_same_service_pid(self):
        plan = self.fixture.plan(); raw = self.fixture.sockets(plan)
        self.m.sockets(raw, plan, 42342)
        for data in (b'', raw.splitlines(keepends=True)[0], raw.replace(b'pid=42342', b'pid=42343'),
                     raw.replace(b'192.168.90.10:22', b'0.0.0.0:22'), raw + raw.splitlines(keepends=True)[0],
                     raw.replace(b'users:(("sshd",pid=42342,fd=3))', b'')):
            with self.subTest(bytes=len(data)), self.assertRaises(self.m.Pending): self.m.sockets(data, plan, 42342)
        with self.assertRaises(self.m.Pending): self.m.sockets(raw, plan, True)


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateSSH(); self.addCleanup(self.fixture.close)
        self.m = self.fixture.module
        self.plan = self.fixture.install_native()
        self.fixture.write(self.m.CONFIG, self.plan['configuration'])

    def cli(self, *arguments, encoding='utf-8'):
        return subprocess.run([sys.executable, '-I', '-B', str(self.fixture.wrapper), *arguments],
            env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'PYTHONIOENCODING': encoding},
            capture_output=True, timeout=30, close_fds=True, start_new_session=True)

    def test_complete_private_native_cli_and_real_byte_publication(self):
        for encoding in ('utf-8', 'utf-32', 'ascii:replace', 'ascii:ignore'):
            child = self.cli('--plan', encoding=encoding)
            self.assertEqual((child.returncode, child.stdout, child.stderr), (0, self.plan['configuration'], b''))
        for arguments in (('--check',), ('--live', '42342')):
            child = self.cli(*arguments)
            self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'', b''))
        entries = [json.loads(line) for line in self.fixture.ledger.read_bytes().splitlines()]
        self.assertEqual(sum(row[0] == 'ip' for row in entries), 120)
        self.assertEqual(sum(row[0] == 'sshd' for row in entries), 4)
        self.assertEqual(sum(row[0] == 'ss' for row in entries), 1)
        self.assertTrue(all(row[2] == {} for row in entries))
        self.assertEqual(entries[-1][1], ['-H', '-n', '-l', '-t', '-p', 'sport = :22'])

    def test_fixed_queries_refuse_caller_mutation_arguments_before_entry(self):
        for arguments in (('-f', str(self.m.CONFIG)), ('-T', '-f', '/foreign'), ('-D',), ('-t', '-f', str(self.m.CONFIG), '-o', 'Port=23')):
            with self.subTest(arguments=arguments), self.assertRaises(self.m.Pending):
                self.m.capture(self.m.SSHD, arguments, self.m.KERNEL.now() + 3)
        self.assertFalse(self.fixture.ledger.exists())

    def test_unhealthy_effective_configuration_or_foreign_socket_withhold_cli_success(self):
        self.fixture.install_native(effective=self.fixture.effective(self.plan).replace(b'passwordauthentication no', b'passwordauthentication yes'))
        child = self.cli('--check'); self.assertEqual(child.returncode, 75); self.assertEqual(child.stdout, b'')
        self.fixture.install_native(sockets=self.fixture.sockets(self.plan).replace(b'pid=42342', b'pid=9'))
        child = self.cli('--live', '42342'); self.assertEqual(child.returncode, 75); self.assertEqual(child.stdout, b'')

    def test_changed_installed_bytes_key_permission_and_argument_misuse_refuse(self):
        self.fixture.write(self.m.CONFIG, self.plan['configuration'] + b'PermitRootLogin yes\n')
        child = self.cli('--check'); self.assertEqual((child.returncode, child.stdout), (75, b''))
        self.fixture.write(self.m.CONFIG, self.plan['configuration'])
        (self.fixture.home / 'operator/.ssh/authorized_keys').chmod(0o644)
        child = self.cli('--plan'); self.assertEqual((child.returncode, child.stdout), (75, b''))
        for arguments in ((), ('--live', '0'), ('--live', 'True'), ('--plan', 'foreign')):
            self.assertEqual(self.cli(*arguments).returncode, 64)

    def test_capture_warning_nonzero_and_both_channel_limits_refuse(self):
        for body in ('printf warning >&2', 'exit 1', "printf '%262145s' x", "printf '%262145s' x >&2"):
            self.fixture.write(self.m.SSHD, ('#!/bin/bash -p\n' + body + '\n').encode(), 0o700)
            with self.subTest(body=body), self.assertRaises(self.m.Pending):
                self.m.capture(self.m.SSHD, ('-t', '-f', str(self.m.CONFIG)), self.m.KERNEL.now() + 3)

    def test_post_eof_root_completion_is_not_assumed(self):
        self.fixture.write(self.m.SSHD, b'#!/bin/bash -p\nexec 1>&- 2>&-\nsleep 5\n', 0o700)
        start = time.monotonic()
        with self.assertRaises((self.m.Pending, subprocess.TimeoutExpired)):
            self.m.capture(self.m.SSHD, ('-t', '-f', str(self.m.CONFIG)), self.m.KERNEL.now() + 0.3)
        self.assertLess(time.monotonic() - start, 3)

    def test_binary_sink_admission_and_short_count_withhold_success(self):
        with patch.object(self.m.sys, 'argv', ['policy.py', '--plan']), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.m.main(), 75)
        class Sink(io.BytesIO):
            def write(self, value):
                return True
        output = io.TextIOWrapper(Sink(), encoding='utf-32')
        with patch.object(self.m.sys, 'argv', ['policy.py', '--plan']), contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.m.main(), 75)

    def test_key_and_config_damage_after_real_native_checks_withholds_success(self):
        native = self.fixture.sshd.read_bytes()
        targets = (self.fixture.home / 'operator/.ssh/authorized_keys', self.m.CONFIG, self.m.HOST_KEY)
        for target in targets:
            before = target.read_bytes()
            # The real private child performs the damage after emitting its
            # valid effective reply; observer/check/health are never replaced.
            damage = f"\nprintf '%s\\n' '# changed after native delivery' >> {shlex.quote(str(target))}\n".encode()
            replacement = native.replace(b'    exit 0\nfi\n', damage + b'    exit 0\nfi\n')
            self.fixture.write(self.fixture.sshd, replacement, 0o700)
            child = self.cli('--check')
            self.assertEqual(child.returncode, 75); self.assertEqual(child.stdout, b'')
            self.fixture.write(target, before)
        self.fixture.write(self.fixture.sshd, native, 0o700)

    def test_oversized_pid_and_missing_binary_sink_refuse_before_native_reads(self):
        self.assertEqual(self.cli('--live', '2147483648').returncode, 64)
        self.assertFalse(self.fixture.ledger.exists())
        with patch.object(self.m.sys, 'argv', ['policy.py', '--plan']), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.m.main(), 75)
        self.assertFalse(self.fixture.ledger.exists())
class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateSSH(); self.addCleanup(self.fixture.close)
        self.plan = self.fixture.install_native()

    def state(self, **faults):
        path = self.fixture.database; state = json.loads(path.read_text())
        if faults: state['faults'].update(faults); path.write_text(json.dumps(state))
        return state

    def run_script(self, command):
        return subprocess.run(['/bin/bash', '-p'], input=self.fixture.controller(command), text=True,
            capture_output=True, timeout=90, start_new_session=True)

    def events(self):
        path = self.fixture.root / 'events.jsonl'
        return [json.loads(row) for row in path.read_text().splitlines()] if path.exists() else []

    def apply(self):
        result = self.run_script('s4s_apply')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_apply_masks_before_packages_checks_before_start_and_publishes_readiness(self):
        self.apply()
        self.assertTrue((self.fixture.root / 'state/ssh.ready').is_file())
        self.assertEqual(self.fixture.module.CONFIG.read_bytes(), self.plan['configuration'])
        events = self.events(); package = next(i for i, row in enumerate(events) if row['action'] == 'packages')
        self.assertEqual(sum(row['action'] == 'systemctl' and row['args'][0] == 'mask' for row in events[:package]), 3)
        for name in ('ssh.service', 'ssh.socket', 'sshd.service'):
            self.assertEqual((self.fixture.root / 'systemd' / name).readlink(), Path('/dev/null'))
        self.assertEqual(self.run_script('s4s_verify').returncode, 0)

    def test_missing_keys_leave_vendor_and_package_state_untouched(self):
        (self.fixture.home / 'operator/.ssh/authorized_keys').unlink()
        result = self.run_script('s4s_apply'); self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.fixture.root / 'state/ssh.ready').exists())
        self.assertFalse(any(row['action'] == 'packages' or row['action'] == 'systemctl' for row in self.events()))

    def test_foreign_local_vendor_unit_is_preserved_and_not_masked(self):
        path = self.fixture.root / 'systemd/ssh.service'; path.write_text('FOREIGN CONFIG\n'); path.chmod(0o600)
        before = (path.stat().st_ino, path.read_bytes())
        self.assertNotEqual(self.run_script('s4s_apply').returncode, 0)
        self.assertEqual((path.stat().st_ino, path.read_bytes()), before)
        self.assertFalse(self.events())

    def test_failed_package_effective_check_and_start_cannot_publish_readiness(self):
        self.state(packages=True)
        result = self.run_script('s4s_apply'); self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.fixture.root / 'state/ssh.ready').exists())
        self.assertFalse(self.state()['active'].get('debian13s4-admin-ssh.service', False))
        self.state(packages=False, start_incomplete=True)
        result = self.run_script('s4s_apply'); self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.fixture.root / 'state/ssh.ready').exists())

    def test_dropins_enablement_and_ready_sync_failures_are_not_success(self):
        self.state(dropin=True)
        self.assertNotEqual(self.run_script('s4s_apply').returncode, 0)
        self.assertFalse((self.fixture.root / 'state/ssh.ready').exists())
        self.state(dropin=False, sync_ready=True)
        self.assertNotEqual(self.run_script('s4s_apply').returncode, 0)
        self.assertFalse(self.state()['active'].get('debian13s4-admin-ssh.service', False))

    def test_same_source_apply_preserves_config_inode_and_rechecks_readiness(self):
        self.apply()
        config = self.fixture.module.CONFIG; before = (config.stat().st_ino, config.read_bytes())
        self.apply()
        self.assertEqual((config.stat().st_ino, config.read_bytes()), before)
        self.assertEqual(self.run_script('s4s_repair').returncode, 0)

    def test_new_bad_key_or_public_socket_stops_owned_server_without_retrying_entry(self):
        self.apply()
        self.fixture.install_native(sockets=self.fixture.sockets(self.plan).replace(b'192.168.90.10:22', b'0.0.0.0:22'))
        result = self.run_script('s4s_repair'); self.assertEqual(result.returncode, 75)
        self.assertFalse(self.state()['active'].get('debian13s4-admin-ssh.service', False))

    def test_pending_bootstrap_and_shared_lock_prevent_controller_operations(self):
        self.apply(); before = len(self.events())
        boot = self.fixture.root / 'state/bootstrap'; boot.mkdir(mode=0o700)
        (boot / 'pending').touch(mode=0o600)
        self.assertEqual(self.run_script('s4s_repair').returncode, 75)
        self.assertEqual(len(self.events()), before)
        (boot / 'pending').unlink()
        command = 's4m_lock\ns4s_repair'
        self.assertEqual(self.run_script(command).returncode, 75)
        self.assertEqual(len(self.events()), before)

    def test_units_keep_admin_elevation_and_fixed_boot_checks(self):
        server = configparser.ConfigParser(interpolation=None)
        server.read(ROOT / 'SSH/debian13s4-admin-ssh.service')
        self.assertEqual(server['Service']['ExecStart'], '/usr/sbin/sshd -D -e -f /etc/ssh/debian13s4-admin.conf')
        self.assertTrue(server['Service']['ExecStartPre'].endswith('policy.py --check'))
        self.assertNotIn('NoNewPrivileges', server['Service'])
        self.assertEqual(server['Unit']['ConditionPathExists'], '!/var/lib/debian13s4/bootstrap/pending')
        controller = configparser.ConfigParser(interpolation=None)
        controller.read(ROOT / 'SSH/debian13s4-ssh.service')
        self.assertEqual(controller['Service']['TimeoutStartSec'], '900s')
        self.assertIn('AF_NETLINK', controller['Service']['RestrictAddressFamilies'])


if __name__ == '__main__':
    unittest.main()
