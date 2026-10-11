"""Real known FILE prerequisites inside one private ordinary-UID fixture only."""
import copy
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class PrerequisiteTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('private_paired_sava_fixture', ROOT/'Applications.Tests/test_sava_transport.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        self.helper = fixture.SavaTransportTests(); self.addCleanup(self.helper.doCleanups); self.helper.setUp()
        self.root = self.helper.root
        spec = importlib.util.spec_from_file_location('private_application_prerequisites', ROOT/'Applications/prepare.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        shared = self.helper.m.IDENTITIES
        self.m.SAVA = self.helper.m
        self.m.BASE, self.m.KERNEL, self.m.Pending = shared.BASE, shared.KERNEL, shared.Pending
        for module in (self.m.DNS, self.m.PG):
            module.IDENTITIES = shared; module.KERNEL = shared.KERNEL; module.Pending = shared.Pending
        self.m.DNS.BASE = shared.BASE; self.m.PG.PG = shared.BASE
        dns = self.m.DNS.DNS
        dns.KERNEL = shared.KERNEL; dns.BASE.KERNEL = shared.KERNEL
        dns.BASE.TRUST_ROOT = self.root; dns.BASE.TRUSTED_UID = os.geteuid()
        dns.INPUT = self.root/'dns.json'; dns.PASSWD = shared.PASSWD; dns.GROUP = shared.GROUP
        dns.KERNEL.namespace = lambda: 4711
        binary = dns.binary_path
        def private_binary(value):
            if type(value) is str and value.startswith(str(self.root)+'/'): return str(self.root)+binary(value[len(str(self.root)):])
            return binary(value)
        dns.binary_path = private_binary
        release = self.helper.helper.helper.value['applications']['mk8.dns']
        self.dns_value = {'schema': 1, 'application_user': 'dns_app', 'gateway_user': 'dns_gate', 'ipc_group': 'dns_ipc',
            'application_binary': release['directory']+'/'+release['entry_points']['application'],
            'gateway_binary': release['directory']+'/'+release['entry_points']['gateway'], 'node': 'test-replica',
            'zones': ['1'*32], 'listeners': [{'address': '198.51.100.53', 'health_port': 9101}],
            'budgets': {key: low for key, (low, high) in dns.BUDGETS.items()}}
        dns.INPUT.write_bytes(shared.BASE.canonical(self.dns_value)); dns.INPUT.chmod(0o600)
        pg = shared.BASE; pg.INPUT = self.root/'postgresql.json'; pg.PASSWD = shared.PASSWD
        self.pg_value = {'schema': 1, 'max_connections': 32, 'shared_buffers_mb': 64,
            'applications': {app: {'role': app.split('.')[1]+'_app', 'database': app.split('.')[1]+'_db', 'connection_limit': 8} for app in pg.APPLICATIONS}}
        pg.INPUT.write_bytes(pg.canonical(self.pg_value)); pg.INPUT.chmod(0o600)
        self.m.CHILDREN = tuple((tag, self.m.SAVA if tag == 'sava' else module, fields, profile, state)
            for tag, module, fields, profile, state in self.m.CHILDREN)

    def values(self):
        return {tag: json.loads(module.prepare()) for tag, module, _, _, _ in self.m.CHILDREN}

    def test_real_whole_known_prerequisites_share_identity_without_native_or_storage_entry(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('no native or app entry')), patch.object(Path, 'exists', side_effect=AssertionError('no storage existence operation')):
            raw = self.m.prepare()
        value = json.loads(raw)
        self.assertEqual(value['state'], 'application-file-prerequisites-source-only')
        self.assertEqual(value['namespace'], 4711); self.assertEqual(set(value['components']), {'dns', 'postgresql', 'sava'})
        common = None
        for tag, component in value['components'].items():
            self.assertEqual(value['component_sha256'][tag], hashlib.sha256(self.m.BASE.canonical(component)).hexdigest())
            identity = self.m.BASE.canonical(component['identities'])
            if common is None: common = identity
            self.assertEqual(identity, common)
        self.assertEqual(value['correspondence']['identity_sha256'], hashlib.sha256(common).hexdigest())
        self.assertEqual(value['correspondence']['dns_application_identity']['user'], 'dns_app')
        self.assertEqual(value['correspondence']['dns_unit_group'], 'dns_ipc')
        self.assertNotEqual(value['correspondence']['dns_unit_gid'], value['correspondence']['dns_application_identity']['primary_gid'])
        for secret in (self.helper.account_key, self.helper.data_key): self.assertNotIn(secret.encode(), raw)
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_each_dependency_bound_and_immutable_type_refuse_before_json(self):
        for child in self.m.CHILDREN:
            module = child[1]
            for bad in (bytearray(b'{}\n'), b'x'*(module.MAX_OUTPUT+1)):
                with self.subTest(tag=child[0], kind=type(bad)), patch.object(module, 'prepare', return_value=bad), patch.object(self.m.json, 'loads', side_effect=AssertionError('decode')):
                    with self.assertRaises(self.m.Pending): self.m.prepared(child, self.m.KERNEL.now()+10, 4711)

    def test_each_closed_dependency_schema_profile_state_and_context_refuse(self):
        values = self.values()
        for child in self.m.CHILDREN:
            tag, module = child[:2]
            for field, bad in (('schema', True), ('profile', 'foreign'), ('state', 'ready'), ('namespace', False), ('namespace', 4712), ('healthy', True)):
                value = copy.deepcopy(values[tag]); value[field] = bad
                with self.subTest(tag=tag, field=field), patch.object(module, 'prepare', return_value=self.m.BASE.canonical(value)):
                    with self.assertRaises(self.m.Pending): self.m.prepared(child, self.m.KERNEL.now()+10, 4711)

    def test_nested_complete_identity_schema_context_and_commitment_refuse(self):
        values = self.values()
        for child in self.m.CHILDREN:
            tag, module = child[:2]
            for field, bad in (('schema', True), ('profile', 'foreign'), ('state', 'ready'), ('namespace', False), ('namespace', 4712), ('healthy', True)):
                value = copy.deepcopy(values[tag]); value['identities'][field] = bad
                value['identity_sha256'] = hashlib.sha256(self.m.BASE.canonical(value['identities'])).hexdigest()
                with self.subTest(tag=tag, field=field), patch.object(module, 'prepare', return_value=self.m.BASE.canonical(value)):
                    with self.assertRaises(self.m.Pending): self.m.prepared(child, self.m.KERNEL.now()+10, 4711)
            value = copy.deepcopy(values[tag]); value['identity_sha256'] = 'f'*64
            with patch.object(module, 'prepare', return_value=self.m.BASE.canonical(value)):
                with self.assertRaises(self.m.Pending): self.m.prepared(child, self.m.KERNEL.now()+10, 4711)

    def test_complete_cross_component_identity_comparison_preserves_opaque_types(self):
        original = self.values()
        for tag in ('postgresql', 'sava'):
            value = copy.deepcopy(original)
            value[tag]['identities']['configuration']['value']['schema'] = True
            with self.subTest(tag=tag), self.assertRaises(self.m.Pending): self.m.correspondence(value)

    def test_real_dns_unit_and_pg_role_renderers_refuse_repaired_outer_hash_changes(self):
        original = self.values()
        for tag, mutate in (('dns', lambda v: v['dns_service']['plan']['units'].__setitem__('extra.service', 'User=root\n')),
                            ('postgresql', lambda v: v['postgresql']['plan']['files'].__setitem__('pg_hba.conf', 'local all all trust\n')),
                            ('dns', lambda v: v['unit_bindings'][self.m.DNS.DNS.APP_UNIT].__setitem__('uid', False)),
                            ('postgresql', lambda v: v['role_bindings']['mk8.dns'].__setitem__('user', 'root'))):
            values = copy.deepcopy(original); mutate(values[tag])
            with self.subTest(tag=tag), self.assertRaises(self.m.Pending): self.m.correspondence(values)

    def test_original_prerequisite_pending_is_retained_as_the_public_cause(self):
        for child in self.m.CHILDREN:
            module = child[1]; original = module.Pending('private prerequisite refusal')
            with patch.object(module, 'prepare', side_effect=original):
                with self.assertRaises(self.m.Pending) as caught: self.m.prepare()
            self.assertIs(caught.exception.__cause__, original)

    def test_outer_encoding_precedes_every_second_real_preparation_without_late_wrapper_encode(self):
        events = []; original = self.m.prepared_bytes; canonical = self.m.BASE.canonical
        names = {child[1]: child[0] for child in self.m.CHILDREN}
        def delivery(module, end): events.append(names[module]); return original(module, end)
        def encode(value):
            if type(value) is dict and value.get('state') == 'application-file-prerequisites-source-only': events.append('encode')
            return canonical(value)
        with patch.object(self.m, 'prepared_bytes', side_effect=delivery), patch.object(self.m.BASE, 'canonical', side_effect=encode): self.m.prepare()
        self.assertEqual(events, ['dns', 'postgresql', 'sava', 'encode', 'dns', 'postgresql', 'sava'])

    def test_exact_outer_cap_and_overflow_precede_all_second_deliveries(self):
        raw = self.m.prepare()
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)): self.assertEqual(self.m.prepare(), raw)
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)-1), patch.object(self.m, 'prepared_bytes', wraps=self.m.prepared_bytes) as delivery:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(delivery.call_count, 3)

    def test_each_second_complete_raw_byte_change_withholds_aggregate(self):
        for target in (child[1] for child in self.m.CHILDREN):
            original = self.m.prepared_bytes; calls = {child[1]: 0 for child in self.m.CHILDREN}
            def delivery(module, end):
                raw = original(module, end); calls[module] += 1
                return raw+b'\n' if module is target and calls[module] == 2 else raw
            with self.subTest(target=target), patch.object(self.m, 'prepared_bytes', side_effect=delivery):
                with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(calls[target], 2)

    def test_positive_outer_parent_cap_does_not_widen_existing_component_windows(self):
        original = self.m.prepared_bytes
        for parent, expected in ((12, 12), (10000, 1770)):
            seen = []
            def delivery(module, end): seen.append(end); return original(module, end)
            with patch.object(self.m.KERNEL, 'now', return_value=10), patch.object(self.m, 'prepared_bytes', side_effect=delivery): self.m.prepare(parent)
            self.assertEqual(seen, [expected]*6)

    def test_invalid_or_expired_window_and_initial_scope_refuse_before_owned_work(self):
        for end in (True, '10', float('nan'), float('inf'), self.m.KERNEL.now()-1):
            with self.subTest(end=end), patch.object(self.m, 'prepared_bytes') as delivery:
                with self.assertRaises(self.m.Pending): self.m.prepare(end)
                delivery.assert_not_called()
        for scope in (0, True, 1.0, -1, 2**64):
            with self.subTest(scope=scope), patch.object(self.m.KERNEL, 'namespace', return_value=scope), patch.object(self.m, 'prepared_bytes') as delivery:
                with self.assertRaises(self.m.Pending): self.m.prepare()
                delivery.assert_not_called()

    def test_final_namespace_or_expiry_after_sixth_real_return_withholds_cached_output(self):
        for fail in ('context', 'time'):
            original = self.m.prepared_bytes; calls = 0
            def delivery(module, end):
                nonlocal calls
                raw = original(module, end); calls += 1
                if calls == 6:
                    if fail == 'context': self.m.KERNEL.namespace = lambda: 4712
                    else: clock.return_value = end
                return raw
            with self.subTest(fail=fail), patch.object(self.m.KERNEL, 'now', return_value=10) as clock, patch.object(self.m, 'prepared_bytes', side_effect=delivery):
                with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(calls, 6); self.m.KERNEL.namespace = lambda: 4711

    def test_cli_no_overrides_full_true_count_and_flush_preserve_failure_stdout_qualification(self):
        class Sink:
            def __init__(self, count=None, fail=False): self.buffer=self; self.raw=b''; self.count=count; self.fail=fail
            def write(self, raw): self.raw=raw; return len(raw) if self.count is None else self.count
            def flush(self):
                if self.fail: raise OSError('private flush')
        for count, fail, expected in ((None, False, 0), (False, False, 75), (1, False, 75), (None, True, 75)):
            sink = Sink(count, fail)
            with patch.object(sys, 'argv', ['prepare.py']), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare', return_value=b'{}\n'):
                self.assertEqual(self.m.main(), expected)
            self.assertEqual(sink.raw, b'{}\n')
        for args, sink in ((['prepare.py', 'extra'], Sink()), (['prepare.py'], io.StringIO())):
            with patch.object(sys, 'argv', args), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare') as delivery:
                self.assertEqual(self.m.main(), 75); delivery.assert_not_called()

    def test_otherwise_valid_real_group_inventory_drift_between_first_components_refuses_before_encoding(self):
        original = self.m.prepared_bytes; target = self.helper.m.IDENTITIES.GROUP
        canonical = self.m.BASE.canonical; changed = False
        def delivery(module, end):
            nonlocal changed
            if module is self.m.PG and not changed:
                target.write_bytes(target.read_bytes()+b'unused:x:800:\n'); changed = True
            return original(module, end)
        def encode(value):
            if type(value) is dict and value.get('state') == 'application-file-prerequisites-source-only': raise AssertionError('no aggregate encoding')
            return canonical(value)
        with patch.object(self.m, 'prepared_bytes', side_effect=delivery), patch.object(self.m.BASE, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertTrue(changed)

    def test_postencoding_otherwise_valid_pg_dns_and_key_changes_withhold_aggregate(self):
        canonical = self.m.BASE.canonical
        for target in (self.m.PG.PG.INPUT, self.m.DNS.DNS.INPUT, Path(self.helper.descriptor['access_key'])):
            before = target.read_bytes()
            if target == self.m.PG.PG.INPUT:
                value = json.loads(before); value['max_connections'] = 64; after = canonical(value)
            elif target == self.m.DNS.DNS.INPUT:
                value = json.loads(before); value['zones'] = ['2'*32]; after = canonical(value)
            else: after = base64.b64encode(bytes(range(2, 34)))+b'\n'
            def encode(value):
                raw = canonical(value)
                if type(value) is dict and value.get('state') == 'application-file-prerequisites-source-only': target.write_bytes(after)
                return raw
            with self.subTest(target=target), patch.object(self.m.BASE, 'canonical', side_effect=encode):
                with self.assertRaises(self.m.Pending): self.m.prepare()
            target.write_bytes(before)

    def test_actual_nested_read_windows_stay_independent_under_the_aggregate_parent_cap(self):
        common, dns = self.m.BASE, self.m.DNS.DNS.BASE
        for parent in (12, 10000):
            points = []; common_read, dns_read = common.read_protected, dns.read_protected
            def read_common(path, limit, private, end): points.append((path, end)); return common_read(path, limit, private, end)
            def read_dns(path, limit, private, end): points.append((path, end)); return dns_read(path, limit, private, end)
            with patch.object(self.m.KERNEL, 'now', return_value=10), patch.object(common, 'read_protected', side_effect=read_common), patch.object(dns, 'read_protected', side_effect=read_dns): self.m.prepare(parent)
            self.assertEqual(len(points), 752)
            for path, count, end in ((self.helper.m.INPUT, 4, 290), (self.m.PG.PG.INPUT, 8, 20),
                                      (self.m.DNS.DNS.INPUT, 8, 20), (self.helper.m.IDENTITIES.INPUT, 24, 140),
                                      (self.helper.m.IDENTITIES.RELEASE.INPUT, 48, 70)):
                self.assertEqual([deadline for observed, deadline in points if observed == path], [min(parent, end)]*count)

    def test_each_canonical_whole_dependency_refuses_duplicate_nonfinite_and_extra_lf_spellings(self):
        values = self.values()
        for child in self.m.CHILDREN:
            raw = self.m.BASE.canonical(values[child[0]])
            for bad in (raw+b'\n', raw.replace(b'"schema":1', b'"schema":1,"schema":1'), raw.replace(b'"schema":1', b'"schema":NaN')):
                with self.subTest(tag=child[0], bad=bad), patch.object(child[1], 'prepare', return_value=bad):
                    with self.assertRaises(self.m.Pending): self.m.prepared(child, self.m.KERNEL.now()+10, 4711)

    def test_actual_private_interpreter_pipe_is_encoding_independent_and_refusal_has_no_stdout(self):
        program = '''import importlib.util,os,sys
from pathlib import Path
root=Path(sys.argv[1]);project=Path(sys.argv[2]);uid=int(sys.argv[3])
spec=importlib.util.spec_from_file_location('private_cli_prerequisites',project/'Applications/prepare.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
shared=m.SAVA.IDENTITIES;shared.BASE.TRUST_ROOT=root;shared.BASE.TRUSTED_UID=uid
shared.INPUT=root/'application-identities.json';shared.PASSWD=root/'passwd';shared.GROUP=root/'group'
shared.RELEASE.INPUT=root/'application-releases.json';shared.RELEASE.RELEASE_ROOT=root/'opt/debian13s4-apps'
shared.KERNEL.namespace=lambda:4711
m.BASE,m.KERNEL,m.Pending=shared.BASE,shared.KERNEL,shared.Pending
for child in (m.DNS,m.PG):child.IDENTITIES=shared;child.KERNEL=shared.KERNEL;child.Pending=shared.Pending
m.DNS.BASE=shared.BASE;m.PG.PG=shared.BASE;shared.BASE.INPUT=root/'postgresql.json';shared.BASE.PASSWD=shared.PASSWD
m.SAVA.INPUT=root/'sava-transport.json';m.SAVA.SETTINGS_ROOT=root/'etc/sava'
d=m.DNS.DNS;d.BASE.TRUST_ROOT=root;d.BASE.TRUSTED_UID=uid;d.KERNEL=shared.KERNEL;d.BASE.KERNEL=shared.KERNEL
d.INPUT=root/'dns.json';d.PASSWD=shared.PASSWD;d.GROUP=shared.GROUP
binary=d.binary_path
def private_binary(value):
 return str(root)+binary(value[len(str(root)):]) if type(value)is str and value.startswith(str(root)+'/') else binary(value)
d.binary_path=private_binary
sys.argv=['prepare.py'];sys.exit(m.main())
'''
        outputs = []
        for encoding in ('ascii', 'utf-8'):
            env = dict(os.environ, PYTHONIOENCODING=encoding); env.pop('PYTHONPATH', None)
            r = subprocess.run([sys.executable, '-B', '-c', program, str(self.root), str(ROOT), str(os.geteuid())], env=env, capture_output=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr); self.assertEqual(r.stderr, b''); outputs.append(r.stdout)
        self.assertEqual(outputs[0], outputs[1]); self.assertEqual(outputs[0], self.m.prepare())
        self.m.PG.PG.INPUT.chmod(0o644)
        r = subprocess.run([sys.executable, '-B', '-c', program, str(self.root), str(ROOT), str(os.geteuid())], capture_output=True, timeout=10)
        self.assertEqual(r.returncode, 75); self.assertEqual(r.stdout, b''); self.assertIn(b'Pending:', r.stderr)


if __name__ == '__main__':
    unittest.main()
