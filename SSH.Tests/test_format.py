"""Pinned OpenSSH dump_cfg_strarray SOURCE spelling, with private delivery only."""

import configparser
import subprocess
import sys
import unittest
from unittest.mock import patch

from fixture_ssh import PrivateSSH, ROOT


def repeated_users(raw):
    result = []
    for line in raw.splitlines(keepends=True):
        if line.startswith(b'allowusers '):
            result.extend(b'allowusers ' + value + b'\n' for value in line.split()[1:])
        else:
            result.append(line)
    return b''.join(result)


class FormatterTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateSSH(); self.addCleanup(self.fixture.close)
        self.plan = self.fixture.plan()
        self.raw = repeated_users(self.fixture.effective(self.plan))

    def test_repeated_native_allowusers_retains_every_exact_pattern(self):
        self.fixture.module.effective(self.raw, self.plan)
        for bad in (self.raw + b'allowusers root@192.168.90.0/24\n',
                    self.raw.replace(b'operator@192.168.90.0/24', b'operator@192.168.0.0/16'),
                    self.raw + b'allowusers operator@192.168.90.0/24\n'):
            with self.assertRaises(self.fixture.module.Pending):
                self.fixture.module.effective(bad, self.plan)

    def test_complete_private_cli_accepts_actual_source_formatter_spelling(self):
        self.fixture.install_native(effective=self.raw)
        self.fixture.write(self.fixture.module.CONFIG, self.plan['configuration'])
        child = subprocess.run([sys.executable, '-I', '-B', str(self.fixture.wrapper), '--live', '42342'],
            capture_output=True, timeout=30, close_fds=True, start_new_session=True)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'', b''))

    def test_expired_future_or_malformed_shadow_age_cannot_admit_key_login(self):
        shadow = self.fixture.etc / 'shadow'
        original = shadow.read_bytes()
        for last, maximum in (('20000', '30'), ('22000', '99999'), ('bad', '99999'), ('20000', 'bad')):
            rows = original.decode('ascii').splitlines()
            fields = rows[1].split(':'); fields[2] = last; fields[4] = maximum
            rows[1] = ':'.join(fields); shadow.write_text('\n'.join(rows) + '\n')
            with self.subTest(last=last, maximum=maximum), patch('time.time', return_value=20700 * 86400):
                with self.assertRaises(self.fixture.module.Pending):
                    self.fixture.module.administrator()
        shadow.write_bytes(original)

    def test_system_account_case_does_not_grant_or_block_the_existing_admin_role(self):
        rows = {'passwd': 'Debian-exim:x:120:120:system fixture:/var/spool/exim4:/usr/sbin/nologin\n',
                'group': 'Debian-exim:x:120:\n', 'shadow': 'Debian-exim:!:20000:0:99999:7:::\n'}
        for name, row in rows.items():
            path = self.fixture.etc / name
            path.write_bytes(path.read_bytes() + row.encode('ascii'))
        plan = self.fixture.plan()
        self.assertEqual(plan['admin']['name'], 'operator')
        self.assertNotIn('Debian-exim', plan['configuration'].decode('ascii'))
        self.fixture.install_native()
        self.fixture.write(self.fixture.module.CONFIG, plan['configuration'])
        child = subprocess.run([sys.executable, '-I', '-B', str(self.fixture.wrapper), '--live', '42342'],
            capture_output=True, timeout=30, close_fds=True, start_new_session=True)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, b'', b''))


class UnitSourceTests(unittest.TestCase):
    def test_controller_can_read_private_admin_keys_without_widening_login_privileges(self):
        controller = configparser.ConfigParser(interpolation=None)
        controller.read(ROOT / 'SSH/debian13s4-ssh.service')
        self.assertEqual(controller['Service']['User'], 'root')
        self.assertEqual(controller['Service']['CapabilityBoundingSet'], 'CAP_DAC_READ_SEARCH CAP_SYS_PTRACE')
        self.assertEqual(controller['Service']['ProtectHome'], 'read-only')
        self.assertEqual(controller['Service']['NoNewPrivileges'], 'yes')
        server = configparser.ConfigParser(interpolation=None)
        server.read(ROOT / 'SSH/debian13s4-admin-ssh.service')
        self.assertNotIn('NoNewPrivileges', server['Service'])


if __name__ == '__main__':
    unittest.main()
