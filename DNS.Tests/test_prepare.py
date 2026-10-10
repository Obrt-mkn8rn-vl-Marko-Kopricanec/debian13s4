"""Private source-intention controls: no DNS, CLR, manager or app execution.

Addresses, IDs, account names and ports are finite TEST DATA, not allocations.
Protected inputs use ordinary UID/private tmpfs delivery substitutions.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ReplicaPreparationTests(unittest.TestCase):
    def setUp(self):
        private = tempfile.TemporaryDirectory(dir='/dev/shm'); self.addCleanup(private.cleanup)
        self.root = Path(private.name); self.root.chmod(0o700)
        spec = importlib.util.spec_from_file_location('private_dns_prepare', ROOT / 'DNS/prepare.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.BASE.TRUST_ROOT = self.root; self.m.BASE.TRUSTED_UID = os.getuid()
        self.m.INPUT = self.root / 'dns.json'; self.m.PASSWD = self.root / 'passwd'
        self.m.GROUP = self.root / 'group'
        self.value = {'schema': 1, 'application_user': 'dns_app_demo',
            'gateway_user': 'dns_gateway_demo', 'ipc_group': 'dns_ipc_demo',
            'application_binary': '/opt/fixture-dns/application/mk8.dns.Application',
            'gateway_binary': '/opt/fixture-dns/gateway/mk8.dns.Gateway', 'node': 'test-replica-1',
            'zones': ['1'*32, '2'*32], 'listeners': [
                {'address': '198.51.100.53', 'health_port': 9101},
                {'address': '2001:db8::53', 'health_port': 9102}],
            'budgets': {k: minimum for k, (minimum, _) in self.m.BUDGETS.items()}}
        self.passwd = (b'root:x:0:0:root:/root:/bin/bash\n'
            b'dns_app_demo:x:401:401::/:/usr/sbin/nologin\n'
            b'dns_gateway_demo:x:402:402::/:/bin/false\n')
        self.group = (b'root:x:0:\ndns_app_demo:x:401:\ndns_gateway_demo:x:402:\n'
            b'dns_ipc_demo:x:403:dns_app_demo,dns_gateway_demo\n')
        self.write(); self.inventory()

    def write(self, value=None, raw=None):
        self.m.INPUT.write_bytes(self.m.BASE.canonical(self.value if value is None else value)
            if raw is None else raw); self.m.INPUT.chmod(0o600)

    def inventory(self, passwd=None, group=None):
        self.m.PASSWD.write_bytes(self.passwd if passwd is None else passwd)
        self.m.GROUP.write_bytes(self.group if group is None else group)
        self.m.PASSWD.chmod(0o644); self.m.GROUP.chmod(0o644)

    def prepare(self, **kw):
        return self.m.prepare(scope=lambda: 123456, **kw)

    def test_complete_canonical_receipt_binds_inputs_accounts_units_and_argv(self):
        raw = self.prepare(); receipt = json.loads(raw)
        self.assertEqual(raw, self.m.BASE.canonical(receipt))
        self.assertEqual(receipt['state'], 'dns-service-intention-only')
        self.assertEqual(receipt['namespace'], 123456)
        self.assertEqual(receipt['configuration']['value'], self.value)
        self.assertEqual(receipt['accounts']['ipc_group'], {'name': 'dns_ipc_demo', 'gid': 403})
        self.assertEqual(len(receipt['plan']['units']), 3)
        for name, text in receipt['plan']['units'].items():
            self.assertEqual(receipt['unit_sha256'][name], hashlib.sha256(text.encode('ascii')).hexdigest())
            self.assertEqual(text.count('ExecStart='), 1)
            self.assertIn('ExecStart='+' '.join(receipt['plan']['argv'][name])+'\n', text)
        for key, path in (('user_source', self.m.PASSWD), ('group_source', self.m.GROUP)):
            self.assertEqual(receipt[key]['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_application_is_unprivileged_private_replica_without_controller_or_network(self):
        plan = self.m.render(self.value); unit = plan['units'][self.m.APP_UNIT]
        argv = plan['argv'][self.m.APP_UNIT]
        self.assertEqual(argv[:11], [self.value['application_binary'], '--socket', self.m.SOCKET,
            '--state', self.m.STATE, '--node', 'test-replica-1', '--role', 'authoritative-replica',
            '--zones', '1'*32+','+'2'*32])
        for option, number in self.value['budgets'].items():
            self.assertEqual(argv[argv.index('--'+option)+1], str(number))
        self.assertIn('RestrictAddressFamilies=AF_UNIX\n', unit)
        self.assertIn('CapabilityBoundingSet=\nAmbientCapabilities=\n', unit)
        self.assertIn('ReadWritePaths='+self.m.STATE+' /run/debian13s4-dns\n', unit)
        self.assertNotIn('--control', argv); self.assertNotIn('--publication-socket', argv)
        self.assertNotIn('--tsig-key-file', argv); self.assertNotIn('--cookie-secret-file', argv)
        self.assertNotIn('StateDirectory=', unit)

    def test_each_explicit_family_has_both_dns_transports_and_unique_loopback_health(self):
        plan = self.m.render(self.value)
        for i, family in enumerate((4, 6)):
            unit_name = f'debian13s4-dns-gateway{family}.service'
            row = plan['listeners'][i]; argv = plan['argv'][unit_name]
            self.assertEqual(row, {'unit': unit_name, 'address': self.value['listeners'][i]['address'],
                'port': 53, 'transports': ['udp', 'tcp'], 'health_address': '127.0.0.1',
                'health_port': 9101+i})
            self.assertEqual(argv, [self.value['gateway_binary'], '--socket', self.m.SOCKET,
                '--role', 'query', '--health-port', str(9101+i), '--dns-address', row['address'], '--dns-port', '53'])
        value = copy.deepcopy(self.value); value['listeners'] = value['listeners'][1:]
        self.assertEqual(set(self.m.render(value)['units']), {self.m.APP_UNIT, 'debian13s4-dns-gateway6.service'})

    def test_gateway_has_only_bind_capability_no_snapshot_access_or_automatic_restart(self):
        units = self.m.render(self.value)['units']
        for name, unit in units.items():
            self.assertIn('Restart=no\n', unit); self.assertIn('NoNewPrivileges=yes\n', unit)
            self.assertIn('ProtectSystem=strict\n', unit); self.assertIn('KillMode=control-group\n', unit)
            self.assertNotIn('ExecStartPre=', unit); self.assertNotIn('ExecStartPost=', unit)
            self.assertNotIn('IPAddressAllow=', unit); self.assertNotIn('DevicePolicy=', unit)
            if name == self.m.APP_UNIT: continue
            self.assertIn('User=dns_gateway_demo\nGroup=dns_ipc_demo\n', unit)
            self.assertIn('InaccessiblePaths='+self.m.STATE+'\n', unit)
            self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE\n', unit)
            self.assertIn('CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n', unit)
            self.assertIn('Requires='+self.m.APP_UNIT+'\n', unit)
            self.assertNotIn('RuntimeDirectory=', unit); self.assertNotIn('ReadWritePaths=', unit)

    def test_only_application_owns_traversable_runtime_directory_and_shared_socket(self):
        plan = self.m.render(self.value); app = plan['units'][self.m.APP_UNIT]
        self.assertEqual(plan['ipc'], {'socket': self.m.SOCKET, 'directory_mode': '0710', 'socket_mode': '0660'})
        self.assertIn('RuntimeDirectoryMode=0710\n', app)
        self.assertIn('RuntimeDirectoryPreserve=yes\n', app)
        self.assertIn('User=dns_app_demo\nGroup=dns_ipc_demo\n', app)
        self.assertLess(len(self.m.SOCKET.encode('utf-8')), 101)

    def test_no_missing_input_or_implicit_site_capacity_role_or_zone_fallback(self):
        self.m.INPUT.unlink()
        with patch.object(self.m, 'accounts') as accounts, patch.object(self.m, 'render') as render:
            with self.assertRaises(OSError): self.prepare()
            accounts.assert_not_called(); render.assert_not_called()
        for field in self.value:
            value = copy.deepcopy(self.value); del value[field]
            with self.subTest(field=field), self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_closed_canonical_input_refuses_unknown_duplicate_nonfinite_and_wrong_schema(self):
        raw = self.m.BASE.canonical(self.value)
        for bad in (raw+b'\n', raw[:-1], raw.replace(b'"schema":1', b'"schema":true'),
            raw.replace(b'"schema":1', b'"schema":1.0'), raw.replace(b'"schema":1', b'"schema":NaN'),
            raw.replace(b'"schema":1', b'"schema":1e999'),
            raw.replace(b'"schema":1', b'"schema":1,"schema":1'), b'\xff\n'):
            with self.subTest(raw=bad), self.assertRaises(self.m.Pending):
                self.write(raw=bad); self.prepare()
        for field in ('compiler', 'role', 'control', 'zone_name', 'healthy', 'namespace'):
            value = copy.deepcopy(self.value); value[field] = 'unexpected'
            with self.subTest(field=field), self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_byte_bound_precedes_json_and_recursive_json_refuses(self):
        self.write(raw=b' '*8193)
        with patch.object(self.m.json, 'loads', side_effect=AssertionError('no decode')):
            with self.assertRaises(self.m.Pending): self.prepare()
        self.write(raw=b'['*1500+b'0'+b']'*1500)
        with self.assertRaises(self.m.Pending): self.prepare()

    def test_unit_paths_node_and_identities_cannot_inject_directives_or_substitution(self):
        for bad in ('../binary', '/opt/a/../b', '/opt//a', '/opt/a/', '/opt/a b',
            '/opt/a\nExecStart=/bin/sh', '/opt/%n', '/opt/$X', '/opt/`id`', '/opt/a"', '/bin/sh', True, None):
            with self.subTest(path=bad), self.assertRaises(self.m.Pending): self.m.binary_path(bad)
        for field in ('node', 'application_user', 'gateway_user', 'ipc_group'):
            for bad in ('', 'x\nUser=root', 'x y', '%n', '$VAR', 'é', True, None):
                value = copy.deepcopy(self.value); value[field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(self.m.Pending): self.m.checked(value)
        value = copy.deepcopy(self.value); value['gateway_user'] = value['application_user']
        with self.assertRaises(self.m.Pending): self.m.checked(value)
        value = copy.deepcopy(self.value); value['gateway_binary'] = value['application_binary']
        with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_address_requires_canonical_specific_unicast_without_scope_or_mapping(self):
        for bad in ('', 'example.invalid', '0.0.0.0', '0.0.0.1', '127.0.0.1', '169.254.1.1',
            '224.0.0.1', '255.255.255.255', '::', '::1', 'ff02::1', 'fe80::1',
            'fec0::1', '::ffff:198.51.100.53', '2001:0db8::53', '2001:DB8::53',
            'fe80::1%eth0', '198.051.100.53', '198.51.100.53/24', True, None):
            with self.subTest(address=bad), self.assertRaises(self.m.Pending): self.m.address(bad)
        self.assertEqual(self.m.address('fd00:1234:5678:90::53'), 6)

    def test_family_count_health_collisions_and_true_integer_ports_refuse(self):
        for listeners in ([], self.value['listeners']*2, [self.value['listeners'][0]]*2,
            [{'address':'198.51.100.53','health_port':9101}, {'address':'2001:db8::53','health_port':9101}]):
            value = copy.deepcopy(self.value); value['listeners'] = listeners
            with self.subTest(listeners=listeners), self.assertRaises(self.m.Pending): self.m.checked(value)
        for bad in (True, 9101.0, '9101', 1023, 65536, 5432):
            value = copy.deepcopy(self.value); value['listeners'][0]['health_port'] = bad
            with self.subTest(port=bad), self.assertRaises(self.m.Pending): self.m.checked(value)
        value = copy.deepcopy(self.value); value['listeners'][0]['port'] = 53
        with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_all_udp_capacity_fields_are_required_true_integers_and_provider_bounded(self):
        for key, (minimum, maximum) in self.m.BUDGETS.items():
            for bad in (True, float(minimum), str(minimum), minimum-1, maximum+1):
                value = copy.deepcopy(self.value); value['budgets'][key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(self.m.Pending): self.m.checked(value)
            value = copy.deepcopy(self.value); del value['budgets'][key]
            with self.assertRaises(self.m.Pending): self.m.checked(value)
        value = copy.deepcopy(self.value); value['budgets']['extra'] = 1
        with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_zone_ids_are_canonical_distinct_nonempty_and_bounded_preserving_order(self):
        for zones in ([], ['0'*32], ['1'*32]*2, ['A'*32], ['1'*31], ['1'*32+'\n'], [True], '1'*32):
            value = copy.deepcopy(self.value); value['zones'] = zones
            with self.subTest(zones=zones), self.assertRaises(self.m.Pending): self.m.checked(value)
        value = copy.deepcopy(self.value); value['zones'] = [f'{n:032x}' for n in range(1,65)]
        self.assertEqual(self.m.checked(value)['zones'], value['zones'])
        value['zones'].append(f'{65:032x}')
        with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_checked_settings_are_private_and_binaries_and_state_are_not_executed(self):
        checked = self.m.checked(self.value); self.value['node'] = 'changed'
        self.assertNotEqual(checked, self.value)
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('no native entry')):
            receipt = json.loads(self.prepare())
        self.assertEqual(receipt['state'], 'dns-service-intention-only')

    def test_inventory_exact_lf_controls_cannot_manufacture_selected_accounts(self):
        for separator in (b'\r', b'\r\n', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e'):
            for raw in (separator.join(self.passwd[:-1].split(b'\n'))+b'\n',
                self.passwd.replace(b'\n', separator, 1)):
                with self.subTest(separator=separator, raw=raw):
                    self.inventory(passwd=raw)
                    with patch.object(self.m, 'render') as render, self.assertRaises(self.m.Pending): self.prepare()
                    render.assert_not_called()
        for control in (*range(0,10), *range(11,32), 127, 255):
            with self.subTest(control=control), self.assertRaises(self.m.Pending):
                self.m.records(self.group.replace(b'root', b'root'+bytes([control]), 1), 4)

    def test_complete_inventory_byte_row_field_name_uid_gid_bounds_and_duplicates(self):
        for raw in (b'', self.passwd[:-1], self.passwd+b'\n', self.passwd+self.passwd,
            self.passwd.replace(b':401:401:', b':0401:401:'),
            self.passwd.replace(b':402:402:', b':401:402:'),
            self.passwd.replace(b':401:401:', b':2147483648:401:'),
            self.passwd.replace(b'dns_app_demo', b'-bad'), self.passwd+b'x'*262145):
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.m.accounts(raw,self.group,self.value)
        rows = b''.join(f'u{n}:x:{n}:\n'.encode() for n in range(4096))
        self.assertEqual(len(self.m.records(rows,4)),4096)
        with self.assertRaises(self.m.Pending): self.m.records(rows+b'u4096:x:4096:\n',4)

    def test_selected_accounts_require_distinct_dedicated_nonlogin_system_identities(self):
        for old, new in ((b':401:401:', b':99:401:'), (b':401:401:',b':1000:401:'),
            (b':401:401:',b':401:0:'), (b':x:401:',b':hash:401:'),
            (b'/usr/sbin/nologin',b'/bin/bash')):
            raw = self.passwd.replace(old,new)
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.m.accounts(raw,self.group,self.value)
        for extra in (b'other:x:404:401::/:/bin/false\n', b'other:x:404:403::/:/bin/false\n'):
            for raw in (self.passwd+extra, extra+self.passwd):
                with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.m.accounts(raw,self.group,self.value)

    def test_group_model_requires_unique_ids_exact_ipc_members_and_no_extra_privileged_membership(self):
        for raw in (self.group.replace(b'dns_app_demo,dns_gateway_demo',b'dns_app_demo'),
            self.group.replace(b'dns_app_demo,dns_gateway_demo',b'dns_app_demo,dns_gateway_demo,root'),
            self.group.replace(b'dns_app_demo,dns_gateway_demo',b'dns_app_demo,dns_app_demo'),
            self.group.replace(b'dns_app_demo,dns_gateway_demo',b'dns_app_demo,missing'),
            self.group.replace(b':403:',b':401:'), self.group+b'sudo:x:27:dns_app_demo\n',
            self.group.replace(b'dns_app_demo:x:401:',b'dns_app_demo:x:401:root'),
            self.group.replace(b'root:x:0:',b'root:x:0:dns_gateway_demo'),
            self.group.replace(b'dns_app_demo:x:401:',b'dns_app_demo:x:404:'), self.group+self.group):
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.m.accounts(self.passwd,raw,self.value)

    def test_account_or_group_refusal_precedes_render_and_all_native_entry(self):
        self.inventory(group=self.group+b'sudo:x:27:dns_app_demo\n')
        with patch.object(self.m,'render') as render, patch.object(subprocess,'Popen') as spawn:
            with self.assertRaises(self.m.Pending): self.prepare()
            render.assert_not_called(); spawn.assert_not_called()

    def test_private_input_modes_ancestry_hard_links_symbolic_links_and_fifo_refuse(self):
        self.m.INPUT.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.prepare()
        self.m.INPUT.chmod(0o600); other=self.root/'other'; os.link(self.m.INPUT,other)
        with self.assertRaises(self.m.Pending): self.prepare()
        other.unlink(); self.m.INPUT.rename(other); self.m.INPUT.symlink_to(other)
        with self.assertRaises(self.m.Pending): self.prepare()
        self.m.INPUT.unlink(); other.rename(self.m.INPUT)
        self.root.chmod(0o777)
        with self.assertRaises(self.m.Pending): self.prepare()
        self.root.chmod(0o700); self.m.GROUP.unlink(); os.mkfifo(self.m.GROUP,0o600)
        with self.assertRaises(self.m.Pending): self.prepare()

    def test_second_configuration_read_detects_valid_same_path_input_drift(self):
        original=self.m.render
        def renderer(value):
            result=original(value); self.value['node']='changed'; self.write(); return result
        with patch.object(self.m,'render',side_effect=renderer), self.assertRaises(self.m.Pending): self.prepare()

    def test_second_inventory_reads_detect_byte_or_inode_drift(self):
        original=self.m.render
        for path in (self.m.PASSWD,self.m.GROUP):
            def renderer(value):
                result=original(value); saved=path.read_bytes(); replacement=self.root/'replace'
                replacement.write_bytes(saved); replacement.chmod(0o644); os.replace(replacement,path); return result
            with self.subTest(path=path), patch.object(self.m,'render',side_effect=renderer), self.assertRaises(self.m.Pending): self.prepare()

    def test_complete_encoding_precedes_every_final_disk_read_context_and_time_fence(self):
        events=[]; read=self.m.BASE.read_protected; canonical=self.m.BASE.canonical
        def reader(path,*args): events.append(path.name); return read(path,*args)
        def encode(value):
            if type(value) is dict and value.get('state')=='dns-service-intention-only': events.append('encode')
            return canonical(value)
        with patch.object(self.m.BASE,'read_protected',side_effect=reader), patch.object(self.m.BASE,'canonical',side_effect=encode):
            self.m.prepare(scope=lambda:events.append('scope') or 123456)
        self.assertEqual(events,['scope','dns.json','passwd','group','encode','dns.json','passwd','group','scope'])

    def test_context_requires_true_positive_uint64_and_equal_final_delivery(self):
        for scope in (lambda:0,lambda:True,lambda:1.0,lambda:2**64):
            with self.subTest(scope=scope), self.assertRaises(self.m.Pending): self.m.prepare(scope=scope)
        values=iter((123456,123457))
        with self.assertRaises(self.m.Pending): self.m.prepare(scope=lambda:next(values))

    def test_inherited_invalid_or_expired_deadline_refuses_before_input(self):
        for end in (True,float('nan'),float('inf'),'10',self.m.KERNEL.now()-1):
            with patch.object(self.m,'configuration') as reader, self.assertRaises(self.m.Pending): self.prepare(deadline=end)
            reader.assert_not_called()

    def test_output_bound_and_final_expiry_withhold_receipt(self):
        with patch.object(self.m,'MAX_OUTPUT',1), self.assertRaises(self.m.Pending): self.prepare()
        original=self.m.configuration; count=0
        def reader(end):
            nonlocal count
            count+=1; value=original(end)
            if count==2: self.m.KERNEL.now=lambda:end
            return value
        with patch.object(self.m,'configuration',side_effect=reader), self.assertRaises(self.m.Pending): self.prepare()

    def test_cli_binary_sink_precedes_work_and_no_overrides_or_refusal_can_publish(self):
        raw=b'{}\n'; sink=io.BytesIO(); stdout=type('Output',(),{'buffer':sink})()
        with patch.object(sys,'argv',['prepare.py']), patch.object(sys,'stdout',stdout), patch.object(self.m,'prepare',return_value=raw):
            self.assertEqual(self.m.main(),0)
        self.assertEqual(sink.getvalue(),raw)
        for args,out in ((['prepare.py','--node','other'],stdout),(['prepare.py'],io.StringIO())):
            with patch.object(sys,'argv',args), patch.object(sys,'stdout',out), patch.object(sys,'stderr',io.StringIO()), patch.object(self.m,'prepare') as prepare:
                self.assertEqual(self.m.main(),75); prepare.assert_not_called()

    def test_cli_true_full_count_and_flush_are_required_for_success(self):
        class Sink:
            def __init__(self,count,fail): self.count=count; self.fail=fail
            def write(self,raw): return self.count
            def flush(self):
                if self.fail: raise OSError('fixture flush')
        for count,fail in ((0,False),(True,False),(None,False),(3,True)):
            out=type('Output',(),{'buffer':Sink(count,fail)})()
            with patch.object(sys,'argv',['prepare.py']), patch.object(sys,'stdout',out), patch.object(sys,'stderr',io.StringIO()), patch.object(self.m,'prepare',return_value=b'{}\n'):
                self.assertEqual(self.m.main(),75)

    def test_actual_cli_pipe_is_encoding_independent_and_malformed_inventory_has_no_output(self):
        program=("import importlib.util,os,sys;from pathlib import Path;"
            "s=importlib.util.spec_from_file_location('private_pipe',sys.argv[1]);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "m.BASE.TRUST_ROOT=Path(sys.argv[2]);m.BASE.TRUSTED_UID=os.getuid();"
            "m.INPUT=Path(sys.argv[2])/'dns.json';m.PASSWD=Path(sys.argv[2])/'passwd';"
            "m.GROUP=Path(sys.argv[2])/'group';m.KERNEL.namespace=lambda:123456;"
            "m.prepare.__defaults__=(None,m.KERNEL.namespace);sys.argv=['prepare.py'];sys.exit(m.main())")
        expected=self.prepare()
        for encoding in ('utf-8:strict','utf-32:ignore','ascii:replace'):
            env=dict(os.environ,PYTHONIOENCODING=encoding,TMPDIR='/dev/shm');env.pop('PYTHONPATH',None)
            child=subprocess.run([sys.executable,'-B','-c',program,str(ROOT/'DNS/prepare.py'),str(self.root)],
                env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertEqual(child.returncode,0); self.assertEqual(child.stdout,expected); self.assertEqual(child.stderr,b'')
        self.inventory(passwd=self.passwd.replace(b'\n',b'\r',1))
        child=subprocess.run([sys.executable,'-B','-c',program,str(ROOT/'DNS/prepare.py'),str(self.root)],
            env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(child.returncode,75); self.assertEqual(child.stdout,b'')


if __name__ == '__main__': unittest.main()
