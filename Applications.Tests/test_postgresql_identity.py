"""Private complete FILE-intention joins; never connect or run application bytes."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class PostgresqlIdentityTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('private_pg_identity_fixture', ROOT/'Applications.Tests/test_identities.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        self.helper = fixture.IdentityTests(); self.addCleanup(self.helper.doCleanups); self.helper.setUp()
        self.root = self.helper.root
        spec = importlib.util.spec_from_file_location('private_pg_identity_join', ROOT/'Applications/postgresql_identity.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        ids, old = self.m.IDENTITIES, self.helper.m
        ids.INPUT, ids.PASSWD, ids.GROUP = old.INPUT, old.PASSWD, old.GROUP
        ids.RELEASE.INPUT, ids.RELEASE.RELEASE_ROOT = old.RELEASE.INPUT, old.RELEASE.RELEASE_ROOT
        self.m.PG.TRUST_ROOT = self.root; self.m.PG.TRUSTED_UID = os.geteuid()
        self.m.PG.INPUT = self.root/'postgresql.json'; self.m.PG.PASSWD = ids.PASSWD
        self.m.KERNEL.namespace = lambda: 4711
        self.value = {'schema': 1, 'max_connections': 32, 'shared_buffers_mb': 64,
            'applications': {app: {'role': self.helper.value['applications'][app]['application_user'],
                'database': app.split('.')[1]+'_db', 'connection_limit': 8} for app in self.m.PG.APPLICATIONS}}
        self.write()

    def write(self, value=None):
        self.m.PG.INPUT.write_bytes(self.m.PG.canonical(self.value if value is None else value))
        self.m.PG.INPUT.chmod(0o600)

    def receipts(self):
        return json.loads(self.m.IDENTITIES.prepare()), json.loads(self.m.PG.prepare(scope=self.m.KERNEL.namespace))

    def test_both_real_application_roles_and_whole_pg_intentions_join_without_native_entry(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('no SQL, process or app entry')):
            raw = self.m.prepare()
        value = json.loads(raw)
        self.assertEqual(value['state'], 'protected-application-postgresql-role-intention-only')
        self.assertEqual(value['namespace'], 4711)
        self.assertEqual(value['identity_sha256'], hashlib.sha256(self.m.PG.canonical(value['identities'])).hexdigest())
        self.assertEqual(value['postgresql_sha256'], hashlib.sha256(self.m.PG.canonical(value['postgresql'])).hexdigest())
        self.assertEqual(value['postgresql']['plan'], self.m.PG.render(self.value))
        self.assertEqual(set(value['role_bindings']), {'mk8.dns', 'mk8.email'})
        for app, row in value['role_bindings'].items():
            role = value['identities']['execution_bindings'][app]['application']
            self.assertEqual(row['user'], self.value['applications'][app]['role'])
            self.assertEqual(row['entry_point'], role['entry_point'])
            self.assertEqual(row['uid'], role['uid']); self.assertEqual(row['primary_gid'], role['primary_gid'])
            self.assertEqual(row['database'], self.value['applications'][app]['database'])
            self.assertEqual(row['execution_role'], 'application')
            self.assertEqual(row['connection_intention'], self.m.PG.render(self.value)['connections'][app])
            self.assertNotEqual(row['user'], value['identities']['execution_bindings'][app]['gateway']['name'])
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_otherwise_admissible_gateway_peer_role_refuses_before_outer_encoding(self):
        for app in self.m.PG.APPLICATIONS:
            value = copy.deepcopy(self.value)
            value['applications'][app]['role'] = self.helper.value['applications'][app]['gateway_user']; self.write(value)
            self.assertEqual(json.loads(self.m.PG.prepare(scope=self.m.KERNEL.namespace))['accounts'][app]['name'], value['applications'][app]['role'])
            with self.subTest(app=app), self.assertRaises(self.m.Pending): self.m.prepare()
        self.write()

    def test_otherwise_admissible_cross_product_peer_roles_do_not_change_the_selected_mapping(self):
        value = copy.deepcopy(self.value)
        value['applications']['mk8.dns']['role'], value['applications']['mk8.email']['role'] = 'email_app', 'dns_app'
        self.write(value); self.m.PG.prepare(scope=self.m.KERNEL.namespace)
        with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_complete_account_source_path_hash_and_typed_signature_must_correspond(self):
        identities, postgres = self.receipts()
        for field, bad in (('path', str(self.root/'other-passwd')), ('sha256', 'f'*64),
                           ('identity', [False, *postgres['account_source']['identity'][1:]])):
            value = copy.deepcopy(postgres); value['account_source'][field] = bad
            with self.subTest(field=field), self.assertRaises(self.m.Pending): self.m.bindings(identities, value)

    def test_typed_selected_uid_gid_name_shell_and_extra_account_facts_refuse(self):
        identities, postgres = self.receipts()
        for app in self.m.PG.APPLICATIONS:
            for field, bad in (('uid', True), ('uid', 1000), ('gid', False), ('gid', 0),
                               ('name', 'foreign'), ('shell', '/bin/bash'), ('healthy', True)):
                value = copy.deepcopy(postgres); value['accounts'][app][field] = bad
                with self.subTest(app=app, field=field), self.assertRaises(self.m.Pending): self.m.bindings(identities, value)

    def test_admitted_entry_point_and_dedicated_primary_group_must_remain_bound(self):
        identities, postgres = self.receipts()
        for app in self.m.PG.APPLICATIONS:
            for field, bad in (('entry_point', '/opt/foreign/main'), ('primary_group', 'foreign'),
                               ('uid', True), ('primary_gid', True), ('shell', '/bin/bash')):
                value = copy.deepcopy(identities); value['execution_bindings'][app]['application'][field] = bad
                with self.subTest(app=app, field=field), self.assertRaises(self.m.Pending): self.m.bindings(value, postgres)

    def test_complete_real_pg_plan_rejects_file_sql_connection_and_initdb_changes(self):
        identities, postgres = self.receipts()
        mutations = [lambda p: p['files'].__setitem__('pg_hba.conf', 'local all all trust\n'),
            lambda p: p['files'].__setitem__('extra', ''),
            lambda p: p['sql_steps'][0].__setitem__('transaction', False),
            lambda p: p['sql_steps'][0].__setitem__('sql', 'CREATE ROLE unsafe SUPERUSER;\n'),
            lambda p: p['connections'].__setitem__('mk8.email', 'Host=remote;Username=root'),
            lambda p: p['initdb_argv'].append('--auth=trust')]
        for mutate in mutations:
            value = copy.deepcopy(postgres); mutate(value['plan'])
            with self.subTest(mutate=mutate), self.assertRaises(self.m.Pending): self.m.bindings(identities, value)

    def test_owned_bytes_bound_precedes_delegated_json_for_each_preparation(self):
        for module in (self.m.IDENTITIES, self.m.PG):
            for bad in (bytearray(b'{}\n'), b'x'*(module.MAX_OUTPUT+1)):
                with self.subTest(module=module, kind=type(bad)), patch.object(module, 'prepare', return_value=bad), patch.object(self.m.json, 'loads', side_effect=AssertionError('decode')):
                    with self.assertRaises(self.m.Pending): self.m.prepared(module, self.m.KERNEL.now()+10, 4711)

    def test_closed_outer_dependency_schemas_profile_context_and_canonical_spelling_refuse(self):
        identities, postgres = self.receipts()
        for module, original in ((self.m.IDENTITIES, identities), (self.m.PG, postgres)):
            for field, bad in (('schema', True), ('profile', 'foreign'), ('state', 'ready'), ('namespace', False),
                               ('namespace', 4712), ('healthy', True)):
                value = copy.deepcopy(original); value[field] = bad
                with self.subTest(module=module, field=field), patch.object(module, 'prepare', return_value=self.m.PG.canonical(value)):
                    with self.assertRaises(self.m.Pending): self.m.prepared(module, self.m.KERNEL.now()+10, 4711)
            raw = self.m.PG.canonical(original)
            for bad in (raw+b'\n', raw.replace(b'"schema":1', b'"schema":1,"schema":1'), raw.replace(b'"schema":1', b'"schema":NaN')):
                with self.subTest(module=module, raw=bad), patch.object(module, 'prepare', return_value=bad):
                    with self.assertRaises(self.m.Pending): self.m.prepared(module, self.m.KERNEL.now()+10, 4711)

    def test_original_owned_dependency_pending_is_not_promoted_or_replaced(self):
        original = self.m.Pending('private prerequisite refusal')
        for module in (self.m.IDENTITIES, self.m.PG):
            with patch.object(module, 'prepare', side_effect=original):
                with self.assertRaises(self.m.Pending) as caught: self.m.prepare()
            self.assertIs(caught.exception, original)

    def test_outer_encode_precedes_both_final_real_preparations_and_no_late_encode(self):
        events = []; original = self.m.prepared_bytes; canonical = self.m.PG.canonical
        def delivered(module, end):
            events.append('identity' if module is self.m.IDENTITIES else 'postgresql')
            return original(module, end)
        def encode(value):
            if type(value) is dict and value.get('state') == 'protected-application-postgresql-role-intention-only': events.append('encode')
            return canonical(value)
        with patch.object(self.m, 'prepared_bytes', side_effect=delivered), patch.object(self.m.PG, 'canonical', side_effect=encode): self.m.prepare()
        self.assertEqual(events, ['identity', 'postgresql', 'encode', 'identity', 'postgresql'])

    def test_exact_outer_output_bound_and_overflow_precede_second_preparations(self):
        raw = self.m.prepare()
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)): self.assertEqual(self.m.prepare(), raw)
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)-1), patch.object(self.m, 'prepared_bytes', wraps=self.m.prepared_bytes) as delivery:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(delivery.call_count, 2)

    def test_whole_final_identity_and_pg_raw_bytes_are_compared_without_partial_decoding(self):
        for target in (self.m.IDENTITIES, self.m.PG):
            original = self.m.prepared_bytes; counts = {self.m.IDENTITIES: 0, self.m.PG: 0}
            def delivery(module, end):
                raw = original(module, end); counts[module] += 1
                return raw+b'\n' if module is target and counts[module] == 2 else raw
            with self.subTest(target=target), patch.object(self.m, 'prepared_bytes', side_effect=delivery):
                with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(counts[target], 2)

    def test_postencoding_pg_config_or_account_or_release_drift_withholds_join(self):
        canonical = self.m.PG.canonical
        for target in (self.m.PG.INPUT, self.m.IDENTITIES.PASSWD, self.helper.helper.path()):
            raw = target.read_bytes()
            def encode(value):
                result = canonical(value)
                if type(value) is dict and value.get('state') == 'protected-application-postgresql-role-intention-only': target.write_bytes(raw+b'\n')
                return result
            with self.subTest(target=target), patch.object(self.m.PG, 'canonical', side_effect=encode):
                with self.assertRaises(self.m.Pending): self.m.prepare()
            target.write_bytes(raw)

    def test_same_byte_pg_account_inode_replacement_cannot_satisfy_final_equality(self):
        target = self.m.PG.PASSWD; canonical = self.m.PG.canonical
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == 'protected-application-postgresql-role-intention-only':
                other = target.with_name('replacement'); other.write_bytes(target.read_bytes()); other.chmod(0o644); os.replace(other, target)
            return raw
        with patch.object(self.m.PG, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_positive_parent_cap_and_independent_identity_release_pg_windows_do_not_widen(self):
        read = self.m.PG.read_protected
        for parent, identity, release, pg in ((12, 12, 12, 12), (1000, 140, 70, 20)):
            seen = []
            def observed(path, limit, private, end): seen.append((path, end)); return read(path, limit, private, end)
            with patch.object(self.m.KERNEL, 'now', return_value=10), patch.object(self.m.PG, 'read_protected', side_effect=observed): self.m.prepare(parent)
            self.assertEqual(len(seen), 124)
            self.assertEqual([end for path, end in seen if path == self.m.PG.INPUT], [pg]*4)
            self.assertEqual([end for path, end in seen if path == self.m.IDENTITIES.INPUT], [identity]*4)
            self.assertEqual([end for path, end in seen if path not in (self.m.PG.INPUT, self.m.PG.PASSWD, self.m.IDENTITIES.INPUT, self.m.IDENTITIES.GROUP)], [release]*104)

    def test_invalid_and_expired_windows_refuse_before_owned_preparation(self):
        for end in (True, '10', float('nan'), float('inf'), self.m.KERNEL.now()-1):
            with self.subTest(end=end), patch.object(self.m, 'prepared_bytes') as delivery:
                with self.assertRaises(self.m.Pending): self.m.prepare(end)
                delivery.assert_not_called()

    def test_initial_scope_requires_true_positive_uint64_before_owned_work(self):
        for context in (0, True, 1.0, -1, 2**64):
            with self.subTest(context=context), patch.object(self.m.KERNEL, 'namespace', return_value=context), patch.object(self.m, 'prepared_bytes') as delivery:
                with self.assertRaises(self.m.Pending): self.m.prepare()
                delivery.assert_not_called()

    def test_final_original_scope_is_checked_after_both_real_preparations(self):
        original = self.m.prepared_bytes; calls = 0
        def delivery(module, end):
            nonlocal calls
            raw = original(module, end); calls += 1
            if calls == 4: self.m.KERNEL.namespace = lambda: 4712
            return raw
        with patch.object(self.m, 'prepared_bytes', side_effect=delivery):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(calls, 4)

    def test_final_expiry_after_actual_second_pg_return_withholds_cached_output(self):
        original = self.m.prepared_bytes; calls = 0
        def delivery(module, end):
            nonlocal calls
            raw = original(module, end); calls += 1
            if calls == 4: clock.return_value = end
            return raw
        with patch.object(self.m.KERNEL, 'now', return_value=10) as clock, patch.object(self.m, 'prepared_bytes', side_effect=delivery):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(calls, 4)

    def test_cli_has_no_overrides_and_requires_full_true_count_and_flush(self):
        class Sink:
            def __init__(self, count=None, fail=False): self.buffer=self; self.raw=b''; self.count=count; self.fail=fail
            def write(self, raw): self.raw=raw; return len(raw) if self.count is None else self.count
            def flush(self):
                if self.fail: raise OSError('private flush')
        for count, fail, expected in ((None, False, 0), (False, False, 75), (1, False, 75), (None, True, 75)):
            sink = Sink(count, fail)
            with patch.object(sys, 'argv', ['postgresql_identity.py']), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare', return_value=b'{}\n'):
                self.assertEqual(self.m.main(), expected)
            self.assertEqual(sink.raw, b'{}\n')
        for args, sink in ((['postgresql_identity.py', 'extra'], Sink()), (['postgresql_identity.py'], io.StringIO())):
            with patch.object(sys, 'argv', args), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare') as delivery:
                self.assertEqual(self.m.main(), 75); delivery.assert_not_called()

    def test_positive_outer_deadline_cap_is_independent_of_both_nested_windows(self):
        original = self.m.prepared_bytes
        for parent, expected in ((12, 12), (1000, 300)):
            seen = []
            def delivery(module, end): seen.append(end); return original(module, end)
            with patch.object(self.m.KERNEL, 'now', return_value=10), patch.object(self.m, 'prepared_bytes', side_effect=delivery): self.m.prepare(parent)
            self.assertEqual(seen, [expected]*4)

    def test_final_pg_expiry_after_actual_account_readback_refuses_under_longer_outer_window(self):
        original, read = self.m.prepared_bytes, self.m.PG.read_protected
        phase = None; account_reads = 0
        def delivery(module, end):
            nonlocal phase
            phase = module
            return original(module, end)
        def observed(path, limit, private, end):
            nonlocal account_reads
            raw = read(path, limit, private, end)
            if phase is self.m.PG and path == self.m.PG.PASSWD:
                account_reads += 1
                if account_reads == 4: clock.return_value = end
            return raw
        with patch.object(self.m.KERNEL, 'now', return_value=10) as clock, patch.object(self.m, 'prepared_bytes', side_effect=delivery), patch.object(self.m.PG, 'read_protected', side_effect=observed):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(account_reads, 4); self.assertEqual(clock.return_value, 20)

    def test_otherwise_valid_postencoding_pg_capacity_change_withholds_complete_join(self):
        canonical = self.m.PG.canonical; changed = copy.deepcopy(self.value); changed['max_connections'] = 64
        self.m.PG.checked(changed)
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == 'protected-application-postgresql-role-intention-only': self.write(changed)
            return raw
        with patch.object(self.m.PG, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(json.loads(self.m.PG.prepare(scope=self.m.KERNEL.namespace))['configuration']['value']['max_connections'], 64)

    def test_otherwise_valid_whole_release_manifest_change_withholds_final_identity_bytes(self):
        canonical = self.m.PG.canonical; release = self.helper.helper
        changed = copy.deepcopy(release.value); app = 'mk8.email'; row = changed['applications'][app]
        row['entry_points'] = {'application': 'gateway/main', 'gateway': 'application/main'}
        generation = release.m.generation(row['entry_points'], row['files'])
        old_directory = Path(row['directory']); new_directory = old_directory.with_name(generation)
        row['generation'], row['directory'] = generation, str(new_directory)
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == 'protected-application-postgresql-role-intention-only':
                old_directory.rename(new_directory); release.write(changed)
            return raw
        with patch.object(self.m.PG, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(json.loads(self.m.IDENTITIES.prepare())['execution_bindings'][app]['application']['entry_point'], str(new_directory/'gateway/main'))

    def test_actual_private_cli_pipe_is_encoding_independent_and_refusal_emits_no_stdout(self):
        program = '''import importlib.util,sys
from pathlib import Path
root=Path(sys.argv[1]); project=Path(sys.argv[2])
spec=importlib.util.spec_from_file_location('private_cli_join',project/'Applications/postgresql_identity.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.PG.TRUST_ROOT=root;m.PG.TRUSTED_UID=int(sys.argv[3]);m.PG.INPUT=root/'postgresql.json';m.PG.PASSWD=root/'passwd'
m.IDENTITIES.INPUT=root/'application-identities.json';m.IDENTITIES.PASSWD=root/'passwd';m.IDENTITIES.GROUP=root/'group'
m.IDENTITIES.RELEASE.INPUT=root/'application-releases.json';m.IDENTITIES.RELEASE.RELEASE_ROOT=root/'opt/debian13s4-apps'
m.KERNEL.namespace=lambda:4711
sys.argv=['postgresql_identity.py']
sys.exit(m.main())
'''
        outputs = []
        for encoding in ('ascii', 'utf-8'):
            env = dict(os.environ, PYTHONIOENCODING=encoding); env.pop('PYTHONPATH', None)
            r = subprocess.run([sys.executable, '-B', '-c', program, str(self.root), str(ROOT), str(os.geteuid())], env=env, capture_output=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr); self.assertEqual(r.stderr, b''); outputs.append(r.stdout)
        self.assertEqual(outputs[0], outputs[1]); self.assertEqual(outputs[0], self.m.prepare())
        self.m.PG.INPUT.chmod(0o644)
        r = subprocess.run([sys.executable, '-B', '-c', program, str(self.root), str(ROOT), str(os.geteuid())], capture_output=True, timeout=10)
        self.assertEqual(r.returncode, 75); self.assertEqual(r.stdout, b''); self.assertIn(b'Pending:', r.stderr)


if __name__ == '__main__':
    unittest.main()
