"""Private complete release/account/DNS SOURCE joins; no app or host operation."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class DnsServiceTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('private_identity_fixture', ROOT/'Applications.Tests/test_identities.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        self.helper = fixture.IdentityTests(); self.addCleanup(self.helper.doCleanups); self.helper.setUp()
        self.root = self.helper.root
        spec = importlib.util.spec_from_file_location('private_dns_service', ROOT/'Applications/dns_service.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        ids = self.m.IDENTITIES; old = self.helper.m
        ids.BASE.TRUST_ROOT = self.root; ids.BASE.TRUSTED_UID = os.geteuid()
        ids.INPUT = old.INPUT; ids.PASSWD = old.PASSWD; ids.GROUP = old.GROUP
        ids.RELEASE.INPUT = old.RELEASE.INPUT; ids.RELEASE.RELEASE_ROOT = old.RELEASE.RELEASE_ROOT
        ids.KERNEL.namespace = lambda: 4711
        dns = self.m.DNS; dns.BASE.TRUST_ROOT = self.root; dns.BASE.TRUSTED_UID = os.geteuid()
        dns.INPUT = self.root/'dns.json'; dns.PASSWD = ids.PASSWD; dns.GROUP = ids.GROUP
        dns.KERNEL.namespace = lambda: 4711
        product_binary = dns.binary_path
        def private_binary(value):
            if type(value) is str and value.startswith(str(self.root)+'/'):
                return str(self.root)+product_binary(value[len(str(self.root)):])
            return product_binary(value)
        dns.binary_path = private_binary  # Only private trust-prefix delivery, retain the actual /opt grammar.
        release = self.helper.helper.value['applications']['mk8.dns']; directory = release['directory']
        self.value = {'schema': 1, 'application_user': 'dns_app', 'gateway_user': 'dns_gate', 'ipc_group': 'dns_ipc',
            'application_binary': directory+'/'+release['entry_points']['application'],
            'gateway_binary': directory+'/'+release['entry_points']['gateway'], 'node': 'test-replica',
            'zones': ['1'*32], 'listeners': [{'address': '198.51.100.53', 'health_port': 9101},
                                           {'address': '2001:db8::53', 'health_port': 9102}],
            'budgets': {k: low for k, (low, high) in dns.BUDGETS.items()}}
        self.write()

    def write(self, value=None):
        self.m.DNS.INPUT.write_bytes(self.m.BASE.canonical(self.value if value is None else value))
        self.m.DNS.INPUT.chmod(0o600)

    def receipts(self):
        ids = json.loads(self.m.IDENTITIES.prepare())
        dns = json.loads(self.m.DNS.prepare(scope=self.m.DNS.KERNEL.namespace))
        return ids, dns

    def test_real_release_account_and_dns_preparation_join_retains_whole_units_without_execution(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('no host or app entry')):
            raw = self.m.prepare()
        r = json.loads(raw)
        self.assertEqual(r['state'], 'protected-dns-release-service-intention-only')
        self.assertEqual(r['namespace'], 4711)
        self.assertEqual(r['identity_sha256'], hashlib.sha256(self.m.BASE.canonical(r['identities'])).hexdigest())
        self.assertEqual(r['dns_service_sha256'], hashlib.sha256(self.m.BASE.canonical(r['dns_service'])).hexdigest())
        self.assertEqual(r['dns_service']['plan'], self.m.DNS.render(self.value))
        self.assertEqual(set(r['unit_bindings']), {self.m.DNS.APP_UNIT, 'debian13s4-dns-gateway4.service', 'debian13s4-dns-gateway6.service'})
        for unit, row in r['unit_bindings'].items():
            role = 'application' if unit == self.m.DNS.APP_UNIT else 'gateway'
            self.assertEqual(row['role'], role)
            self.assertEqual(row['entry_point'], self.value[role+'_binary'])
            self.assertEqual(row['user'], self.value[role+'_user'])
            self.assertEqual(row['unit_group'], 'dns_ipc')
            self.assertEqual(row['unit_gid'], 322)
            self.assertIn('User='+row['user']+'\nGroup=dns_ipc\n', r['dns_service']['plan']['units'][unit])
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_single_ipv4_or_ipv6_family_preserves_the_exact_original_profile(self):
        for listener in self.value['listeners']:
            value = copy.deepcopy(self.value); value['listeners'] = [listener]; self.write(value)
            r = json.loads(self.m.prepare())
            self.assertEqual(r['dns_service']['plan'], self.m.DNS.render(value))
            self.assertEqual(len(r['unit_bindings']), 2)

    def test_otherwise_admissible_dns_binaries_must_match_both_actual_release_entries(self):
        for role in ('application', 'gateway'):
            value = copy.deepcopy(self.value); value[role+'_binary'] = '/opt/unadmitted/'+role
            self.write(value)
            self.assertEqual(json.loads(self.m.DNS.prepare(scope=self.m.DNS.KERNEL.namespace))['state'], 'dns-service-intention-only')
            with self.subTest(role=role), self.assertRaises(self.m.Pending): self.m.prepare()

    def test_otherwise_admissible_account_pair_cannot_substitute_a_different_product(self):
        value = copy.deepcopy(self.value)
        value.update(application_user='sava_app', gateway_user='sava_gate', ipc_group='sava_ipc')
        self.write(value)
        self.assertEqual(json.loads(self.m.DNS.prepare(scope=self.m.DNS.KERNEL.namespace))['accounts']['ipc_group']['name'], 'sava_ipc')
        with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_same_account_bytes_at_different_protected_path_or_inode_refuse_correspondence(self):
        for field in ('PASSWD', 'GROUP'):
            path = getattr(self.m.DNS, field); copyfile = self.root/('other-'+field.lower())
            copyfile.write_bytes(path.read_bytes()); copyfile.chmod(0o644)
            with self.subTest(field=field), patch.object(self.m.DNS, field, copyfile):
                with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_shared_group_name_gid_pair_and_typed_account_facts_must_match(self):
        ids, dns = self.receipts()
        for change in ('name', 'gid', 'groups', 'uid', 'primary_gid', 'shell', 'primary_name'):
            a, b = copy.deepcopy(ids), copy.deepcopy(dns); row = a['execution_bindings']['mk8.dns']['application']
            if change == 'name': row['name'] = 'sava_app'
            elif change == 'gid': b['accounts']['ipc_group']['gid'] += 1
            elif change == 'groups': row['shared_groups']['additional'] = 700
            elif change == 'uid': b['accounts']['users']['dns_app']['uid'] = float(row['uid'])
            elif change == 'primary_gid': row['primary_gid'] = True
            elif change == 'shell': b['accounts']['users']['dns_app']['shell'] = '/bin/bash'
            else: row['primary_group'] = 'other'
            with self.subTest(change=change), self.assertRaises(self.m.Pending): self.m.bindings(a, b)

    def test_whole_unit_and_argv_or_listener_changes_refuse_even_with_repaired_unit_hashes(self):
        ids, dns = self.receipts()
        for change in ('unit', 'argv', 'listener', 'ipc', 'extra_unit'):
            value = copy.deepcopy(dns); plan = value['plan']; unit = self.m.DNS.APP_UNIT
            if change == 'unit':
                plan['units'][unit] += 'AmbientCapabilities=CAP_SYS_ADMIN\n'
                value['unit_sha256'][unit] = hashlib.sha256(plan['units'][unit].encode()).hexdigest()
            elif change == 'argv': plan['argv'][unit].append('--control')
            elif change == 'listener': plan['listeners'][0]['port'] = 54
            elif change == 'ipc': plan['ipc']['socket_mode'] = '0666'
            else: plan['units']['foreign.service'] = '[Service]\nUser=root\n'
            with self.subTest(change=change), self.assertRaises(self.m.Pending): self.m.bindings(ids, value)

    def test_complete_unit_hash_dictionary_refuses_missing_extra_or_false_claims(self):
        ids, dns = self.receipts()
        for change in ('missing', 'extra', 'hash'):
            value = copy.deepcopy(dns)
            if change == 'missing': del value['unit_sha256'][self.m.DNS.APP_UNIT]
            elif change == 'extra': value['unit_sha256']['extra'] = 'a'*64
            else: value['unit_sha256'][self.m.DNS.APP_UNIT] = 'a'*64
            with self.subTest(change=change), self.assertRaises(self.m.Pending): self.m.bindings(ids, value)

    def test_initial_input_or_release_refusal_cannot_return_a_service_intention(self):
        self.helper.helper.path('mk8.dns').chmod(0o644)
        with patch.object(self.m.DNS, 'prepare') as dns:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            dns.assert_not_called()

    def test_dns_refusal_preserves_original_dependency_cause_in_the_public_pending_type(self):
        self.m.DNS.INPUT.chmod(0o644)
        with self.assertRaises(self.m.Pending) as caught: self.m.prepare()
        self.assertIsInstance(caught.exception.__cause__, self.m.DNS.Pending)

    def test_real_dependency_context_disagreement_refuses_before_outer_encoding(self):
        with patch.object(self.m.DNS.KERNEL, 'namespace', return_value=4712):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_unknown_dependency_and_nonbytes_or_oversize_refuse_before_decode(self):
        with self.assertRaises(self.m.Pending): self.m.prepared_bytes(object(), self.m.KERNEL.now()+5)
        for module in (self.m.IDENTITIES, self.m.DNS):
            for raw in (bytearray(b'{}\n'), b'x'*(module.MAX_OUTPUT+1)):
                with self.subTest(module=module, kind=type(raw)), patch.object(module, 'prepare', return_value=raw), patch.object(self.m.json, 'loads', side_effect=AssertionError('decode')):
                    with self.assertRaises(self.m.Pending): self.m.prepared(module, self.m.KERNEL.now()+5, 4711)

    def test_complete_dependency_schema_canonical_state_profile_and_true_context_are_required(self):
        ids, dns = self.receipts()
        for module, value in ((self.m.IDENTITIES, ids), (self.m.DNS, dns)):
            for field, bad in (('schema', True), ('schema', 1.0), ('profile', 'other'), ('state', 'ready'),
                               ('namespace', True), ('namespace', 4711.0), ('namespace', 4712), ('extra', 'value')):
                row = copy.deepcopy(value); row[field] = bad; raw = self.m.BASE.canonical(row)
                with self.subTest(module=module, field=field), patch.object(module, 'prepare', return_value=raw):
                    with self.assertRaises(self.m.Pending): self.m.prepared(module, self.m.KERNEL.now()+5, 4711)
            raw = self.m.BASE.canonical(value)+b'\n'
            with patch.object(module, 'prepare', return_value=raw):
                with self.assertRaises(self.m.Pending): self.m.prepared(module, self.m.KERNEL.now()+5, 4711)

    def test_outer_encode_precedes_second_complete_identity_and_dns_deliveries(self):
        events = []; prepared = self.m.prepared_bytes; canonical = self.m.BASE.canonical
        def delivered(module, end): events.append('identity' if module is self.m.IDENTITIES else 'dns'); return prepared(module, end)
        def encode(value):
            if type(value) is dict and value.get('state') == 'protected-dns-release-service-intention-only': events.append('encode')
            return canonical(value)
        with patch.object(self.m, 'prepared_bytes', side_effect=delivered), patch.object(self.m.BASE, 'canonical', side_effect=encode): self.m.prepare()
        self.assertEqual(events, ['identity', 'dns', 'encode', 'identity', 'dns'])

    def test_final_dependency_returns_are_compared_without_late_decode_or_reencoding(self):
        counts = {'dns': 0}; original = self.m.prepared_bytes
        loads = self.m.json.loads; canonical = self.m.BASE.canonical
        def bytes_only(module, end):
            raw = original(module, end)
            if module is self.m.DNS:
                counts['dns'] += 1
                if counts['dns'] == 2:
                    decoder.side_effect = AssertionError('late decode')
                    encoder.side_effect = AssertionError('late encode')
            return raw
        with patch.object(self.m.json, 'loads', wraps=loads) as decoder, patch.object(self.m.BASE, 'canonical', wraps=canonical) as encoder, patch.object(self.m, 'prepared_bytes', side_effect=bytes_only):
            raw = self.m.prepare()
        self.assertIs(type(raw), bytes)
        self.assertEqual(counts['dns'], 2)

    def test_exact_complete_output_cap_accepts_and_overflow_blocks_both_second_deliveries(self):
        raw = self.m.prepare(); prepared = self.m.prepared_bytes
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)): self.assertEqual(self.m.prepare(), raw)
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)-1), patch.object(self.m, 'prepared_bytes', wraps=prepared) as observed:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(observed.call_count, 2)

    def test_postencoding_dns_configuration_change_withholds_the_join(self):
        canonical = self.m.BASE.canonical
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == 'protected-dns-release-service-intention-only':
                self.value['node'] = 'changed'; self.write()
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_postencoding_same_byte_account_inode_change_withholds_the_join(self):
        canonical = self.m.BASE.canonical
        for field in ('PASSWD', 'GROUP'):
            path = getattr(self.m.IDENTITIES, field)
            def encode(value):
                raw = canonical(value)
                if type(value) is dict and value.get('state') == 'protected-dns-release-service-intention-only':
                    replacement = path.with_name('replace'); replacement.write_bytes(path.read_bytes()); replacement.chmod(0o644); os.replace(replacement, path)
                return raw
            with self.subTest(field=field), patch.object(self.m.BASE, 'canonical', side_effect=encode):
                with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_postencoding_actual_release_inode_change_withholds_the_join(self):
        canonical = self.m.BASE.canonical
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == 'protected-dns-release-service-intention-only':
                path = self.helper.helper.path('mk8.dns'); replacement = path.with_name('replace'); replacement.write_bytes(path.read_bytes()); replacement.chmod(0o755); os.replace(replacement, path)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_initial_namespace_and_invalid_deadline_refuse_before_any_dependency(self):
        for context in (0, True, 1.0, -1, 2**64):
            with patch.object(self.m.KERNEL, 'namespace', return_value=context), patch.object(self.m, 'prepared_bytes') as prepared:
                with self.assertRaises(self.m.Pending): self.m.prepare()
                prepared.assert_not_called()
        for deadline in (True, '10', float('nan'), float('inf'), self.m.KERNEL.now()-1):
            with patch.object(self.m, 'prepared_bytes') as prepared:
                with self.assertRaises(self.m.Pending): self.m.prepare(deadline)
                prepared.assert_not_called()

    def test_final_outer_namespace_refuses_after_all_complete_dependency_preparations(self):
        with patch.object(self.m.KERNEL, 'namespace', side_effect=[4711]*13+[4712]):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_positive_parent_and_independent_identity_release_dns_windows_never_widen(self):
        identity_read = self.m.BASE.read_protected; dns_read = self.m.DNS.BASE.read_protected
        for parent in (12, 1000):
            seen = []
            def ids(path, limit, private, end): seen.append(('identity',path,end)); return identity_read(path,limit,private,end)
            def dns(path, limit, private, end): seen.append(('dns',path,end)); return dns_read(path,limit,private,end)
            with patch.object(self.m.KERNEL, 'now', return_value=10), patch.object(self.m.DNS.KERNEL, 'now', return_value=10), patch.object(self.m.BASE, 'read_protected', side_effect=ids), patch.object(self.m.DNS.BASE, 'read_protected', side_effect=dns): self.m.prepare(parent)
            self.assertEqual(len(seen), 128)
            for channel, path, end in seen:
                expected = 12 if parent == 12 else 20 if channel == 'dns' else 140 if path in (self.m.IDENTITIES.INPUT,self.m.IDENTITIES.PASSWD,self.m.IDENTITIES.GROUP) else 70
                self.assertEqual(end, expected)

    def test_final_outer_expiry_after_real_last_dependency_return_withholds_receipt(self):
        prepared = self.m.prepared_bytes; calls = 0
        def delivered(module, end):
            nonlocal calls
            raw = prepared(module,end); calls += 1
            if calls == 4: clock.return_value = end
            return raw
        with patch.object(self.m.KERNEL, 'now', return_value=10) as clock, patch.object(self.m.DNS.KERNEL, 'now', return_value=10), patch.object(self.m, 'prepared_bytes', side_effect=delivered):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(calls,4)

    def test_no_caller_identity_settings_healthy_receipt_or_unit_override(self):
        for key in ('identity', 'settings', 'healthy', 'units', 'scope', 'binary', 'account'):
            with patch.object(self.m, 'prepared_bytes') as prepared:
                with self.assertRaises(TypeError): self.m.prepare(**{key:None})
                prepared.assert_not_called()

    def test_cli_closed_arguments_and_binary_sink_require_true_full_count_and_flush(self):
        class Sink:
            def __init__(self,count=None,fail=False): self.buffer=self;self.count=count;self.fail=fail;self.raw=b''
            def write(self,raw): self.raw=raw;return len(raw) if self.count is None else self.count
            def flush(self):
                if self.fail: raise OSError('private flush')
        for count,fail,code in ((None,False,0),(True,False,75),(1,False,75),(None,True,75)):
            sink=Sink(count,fail)
            with patch.object(sys,'argv',['dns_service.py']),patch.object(sys,'stdout',sink),patch.object(sys,'stderr',io.StringIO()),patch.object(self.m,'prepare',return_value=b'{}\n'):
                self.assertEqual(self.m.main(),code)
            self.assertEqual(sink.raw,b'{}\n')
        for args,sink in ((['dns_service.py','extra'],Sink()),(['dns_service.py'],io.StringIO())):
            with patch.object(sys,'argv',args),patch.object(sys,'stdout',sink),patch.object(sys,'stderr',io.StringIO()),patch.object(self.m,'prepare') as prepared:
                self.assertEqual(self.m.main(),75);prepared.assert_not_called()


if __name__ == '__main__':
    unittest.main()
