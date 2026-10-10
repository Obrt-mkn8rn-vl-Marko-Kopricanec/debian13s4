"""Finite private network DATA is not a deployment assignment or default."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from fixture_ssh import PrivateSSH


class NetworkInputTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateSSH(); self.addCleanup(self.fixture.close)
        self.m = self.fixture.module
        self.path = self.fixture.etc / 'ssh/debian13s4-admin-networks.json'
        self.m.ADMIN_NETWORKS = self.path

    def settings(self, ipv4='10.44.7.0/24', ipv6='fd9a:2112:3456:7::/64'):
        return {'schema': 1, 'admin_ipv4': ipv4, 'admin_ipv6': ipv6}

    def write(self, value=None, raw=None):
        self.fixture.write(self.path, raw if raw is not None else
            (json.dumps(self.settings() if value is None else value, sort_keys=True, separators=(',', ':'))+'\n').encode())

    def remap(self):
        self.fixture.data = json.loads(json.dumps(self.fixture.data).replace('192.168.90.', '10.44.7.')
            .replace('fd51:b089:f5e0:90:', 'fd9a:2112:3456:7:'))

    def test_missing_private_configuration_refuses_before_any_query(self):
        self.path.unlink(missing_ok=True)
        calls=[]
        def query(name, deadline):
            calls.append(name); return self.fixture.query(name, deadline)
        with self.assertRaises((self.m.Pending, OSError)):
            self.m.prepare(query=query)
        self.assertEqual(calls, [])

    def test_supplied_other_private_networks_drive_binding_and_allowusers(self):
        self.write(); self.remap()
        plan=self.fixture.plan()
        self.assertEqual(plan['binding']['listeners'], ['10.44.7.10','fd9a:2112:3456:7::10'])
        self.assertIn(b'operator@10.44.7.0/24 operator@fd9a:2112:3456:7::/64\n',plan['configuration'])
        self.assertNotIn(b'192.168.90.',plan['configuration'])
        self.assertNotIn(b'fd51:b089:f5e0:',plan['configuration'])
        self.assertEqual(plan['networks']['configuration'],self.settings())

    def test_null_ipv6_neither_selects_ula_nor_emits_ipv6_admin_pattern(self):
        self.write(self.settings(ipv6=None)); self.remap()
        plan=self.fixture.plan()
        self.assertEqual(plan['binding']['listeners'], ['10.44.7.10'])
        self.assertNotIn(b'operator@fd9a:',plan['configuration'])
        self.assertIn(b'operator@::1/128',plan['configuration'])

    def test_types_fields_and_schema_are_exact(self):
        original=self.settings()
        bad=[{},original|{'schema':True},original|{'schema':2},original|{'extra':'site'},
             original|{'admin_ipv4':None},original|{'admin_ipv4':24},original|{'admin_ipv6':False},
             original|{'admin_ipv6':['fd9a::/64']}]
        for value in bad:
            self.write(value)
            with self.subTest(value=value),self.assertRaises((self.m.Pending,ValueError)):
                self.fixture.plan()

    def test_public_link_local_loopback_broad_and_noncanonical_prefixes_refuse(self):
        for field,values in (('admin_ipv4',('0.0.0.0/0','10.0.0.0/8','192.168.90.10/24','127.0.0.0/24',
                '169.254.1.0/24','203.0.113.0/24','10.44.7.0/23','10.44.7.0/24\nPermitRootLogin yes')),
                ('admin_ipv6',('::/0','fc00::/7','fe80::/64','::1/128','2001:db8::/64',
                'fd9a::10/64','fd9a::/48','FD9A::/64'))):
            for value in values:
                self.write(self.settings()|{field:value})
                with self.subTest(field=field,value=value),self.assertRaises((self.m.Pending,ValueError)):
                    self.fixture.plan()

    def test_duplicate_nonfinite_unicode_invalid_and_oversized_bytes_refuse(self):
        for raw in (b'{"schema":1,"schema":1}',b'{"schema":NaN}',b'\xff',b'{}\0',b' '*4097):
            self.write(raw=raw)
            with self.subTest(raw=raw[:20]),self.assertRaises((self.m.Pending,ValueError)):
                self.fixture.plan()

    def test_unprotected_linked_symlink_and_missing_leaf_refuse(self):
        self.write();self.path.chmod(0o644)
        with self.assertRaises(self.m.Pending):self.fixture.plan()
        self.path.chmod(0o600)
        link=self.path.with_suffix('.link');os.link(self.path,link)
        with self.assertRaises(self.m.Pending):self.fixture.plan()
        link.unlink();target=self.path.with_suffix('.original');self.path.rename(target);self.path.symlink_to(target)
        with self.assertRaises(self.m.Pending):self.fixture.plan()

    def test_wrong_owner_delivery_refuses(self):
        self.write()
        with patch.object(self.m,'TRUSTED_UID',os.geteuid()+1),self.assertRaises(self.m.Pending):self.fixture.plan()

    def test_configuration_drift_between_rounds_withholds_plan(self):
        self.write();self.remap();count=[0]
        def query(name,deadline):
            count[0]+=1
            if count[0]==11:self.write(self.settings(ipv4='10.44.8.0/24'))
            return self.fixture.query(name,deadline)
        with self.assertRaises(self.m.Pending):self.m.prepare(query=query)

    def test_same_bytes_new_source_identity_between_rounds_refuses(self):
        self.write();self.remap();count=[0]
        def query(name,deadline):
            count[0]+=1
            if count[0]==11:
                raw=self.path.read_bytes();self.path.unlink();self.write(raw=raw)
            return self.fixture.query(name,deadline)
        with self.assertRaises(self.m.Pending):self.m.prepare(query=query)

    def test_late_private_configuration_damage_during_native_checks_refuses(self):
        self.write();self.remap();plan=self.fixture.install_native();self.fixture.write(self.m.CONFIG,plan['configuration'])
        def read(binary,arguments,deadline):
            if arguments[0]=='-T':self.write(self.settings(ipv4='10.44.8.0/24'));return self.fixture.effective(plan)
            return b''
        with self.assertRaises(self.m.Pending):self.m.check(plan,read=read)

    def test_complete_private_cli_uses_provided_configuration_and_original_fixed_argv(self):
        self.write();self.remap();plan=self.fixture.install_native();self.fixture.write(self.m.CONFIG,plan['configuration'])
        child=subprocess.run([sys.executable,'-I','-B',str(self.fixture.wrapper),'--plan'],capture_output=True,
            timeout=30,close_fds=True,start_new_session=True)
        self.assertEqual((child.returncode,child.stdout,child.stderr),(0,plan['configuration'],b''))
        child=subprocess.run([sys.executable,'-I','-B',str(self.fixture.wrapper),'--live','42342'],capture_output=True,
            timeout=30,close_fds=True,start_new_session=True)
        self.assertEqual((child.returncode,child.stdout,child.stderr),(0,b'',b''))
        entries=[json.loads(row) for row in self.fixture.ledger.read_bytes().splitlines()]
        self.assertEqual(sum(row[0]=='ip' for row in entries),40)
        self.assertTrue(all(row[2]=={} for row in entries))

    def test_missing_configuration_cli_stays_pending_with_zero_native_entries(self):
        self.fixture.install_native();self.path.unlink(missing_ok=True)
        child=subprocess.run([sys.executable,'-I','-B',str(self.fixture.wrapper),'--plan'],capture_output=True,
            timeout=30,close_fds=True,start_new_session=True)
        self.assertEqual((child.returncode,child.stdout),(75,b''))
        self.assertFalse(self.fixture.ledger.exists())

    def test_private_controller_refuses_missing_input_before_vendor_retirement(self):
        self.fixture.install_native(); self.path.unlink()
        child=subprocess.run(['/bin/bash','-p'],input=self.fixture.controller('s4s_apply'),text=True,
            capture_output=True,timeout=90,close_fds=True,start_new_session=True)
        self.assertEqual(child.returncode,1,child.stdout+child.stderr)
        events=self.fixture.root/'events.jsonl'
        rows=[json.loads(row) for row in events.read_text().splitlines()] if events.exists() else []
        self.assertFalse(any(row['args'][:1]==['mask'] for row in rows))
        self.assertFalse(self.fixture.ledger.exists())

    def test_deployment_bytes_are_bound_to_checked_started_generation(self):
        self.fixture.install_native()
        def command(value):
            return subprocess.run(['/bin/bash','-p'],input=self.fixture.controller(value),text=True,
                capture_output=True,timeout=90,close_fds=True,start_new_session=True)
        child=command('s4s_apply');self.assertEqual(child.returncode,0,child.stdout+child.stderr)
        state=json.loads(self.fixture.database.read_bytes());before=state['server_starts']
        acknowledgment=self.fixture.root/'state/ssh.loaded'
        import hashlib
        self.assertIn((hashlib.sha256(self.path.read_bytes()).hexdigest()+' deployment_configuration').encode(),
                      acknowledgment.read_bytes())
        self.write({'schema':1,'admin_ipv4':'192.168.90.0/24','admin_ipv6':None})
        self.fixture.install_native()
        child=command('s4s_repair');self.assertEqual(child.returncode,0,child.stdout+child.stderr)
        state=json.loads(self.fixture.database.read_bytes());self.assertEqual(state['server_starts'],before+1)
        self.assertIn((hashlib.sha256(self.path.read_bytes()).hexdigest()+' deployment_configuration').encode(),
                      acknowledgment.read_bytes())
        self.assertNotIn(b'operator@fd51:',bytes.fromhex(state['loaded_configuration']))

    def test_noncanonical_whitespace_and_non600_private_mode_refuse(self):
        self.write(raw=(json.dumps(self.settings())+'\n').encode())
        with self.assertRaises(self.m.Pending):self.fixture.plan()
        self.write();self.path.chmod(0o400)
        with self.assertRaises(self.m.Pending):self.fixture.plan()


if __name__=='__main__':unittest.main()
