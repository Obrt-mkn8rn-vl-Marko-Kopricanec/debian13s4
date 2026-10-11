"""Private ordinary-UID account/release SOURCE controls, never NSS or apps."""
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


class IdentityTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('private_release_fixture', ROOT/'Applications.Tests/test_releases.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        self.helper = fixture.ReleaseTests(); self.addCleanup(self.helper.doCleanups); self.helper.setUp()
        self.root = self.helper.root
        spec = importlib.util.spec_from_file_location('private_identities', ROOT/'Applications/identities.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.BASE.TRUST_ROOT = self.root; self.m.BASE.TRUSTED_UID = os.geteuid()
        self.m.RELEASE.INPUT = self.helper.m.INPUT; self.m.RELEASE.RELEASE_ROOT = self.helper.m.RELEASE_ROOT
        self.m.KERNEL.namespace = lambda: 4711
        self.m.INPUT = self.root/'application-identities.json'
        self.m.PASSWD = self.root/'passwd'; self.m.GROUP = self.root/'group'
        self.value = {'schema': 1, 'applications': {}}
        users, groups = ['root:x:0:0:root:/root:/bin/bash'], ['root:x:0:']
        for index, app in enumerate(self.m.RELEASE.APPLICATIONS):
            tag = app.split('.')[1]; pair = [tag+'_app', tag+'_gate']; shared = tag+'_ipc'
            self.value['applications'][app] = {'application_user': pair[0], 'gateway_user': pair[1], 'shared_groups': [shared]}
            for role, account in enumerate(pair):
                uid = 200+2*index+role
                users.append(f'{account}:x:{uid}:{uid}:service:/nonexistent:/usr/sbin/nologin')
                groups.append(f'{account}:x:{uid}:')
            groups.append(f'{shared}:x:{320+index}:'+','.join(pair))
        self.passwd = ('\n'.join(users)+'\n').encode(); self.group = ('\n'.join(groups)+'\n').encode()
        self.write()

    def write(self, value=None, passwd=None, group=None, raw=None):
        for path, content, mode in ((self.m.INPUT, raw if raw is not None else self.m.BASE.canonical(self.value if value is None else value), 0o600),
                                    (self.m.PASSWD, self.passwd if passwd is None else passwd, 0o644),
                                    (self.m.GROUP, self.group if group is None else group, 0o644)):
            path.write_bytes(content); path.chmod(mode)

    def account(self, passwd=None, group=None, value=None):
        return self.m.accounts(self.passwd if passwd is None else passwd, self.group if group is None else group,
                               self.value if value is None else value)

    def test_real_complete_releases_bind_all_eight_dedicated_roles_without_execution_or_mutation(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('native or app entry')):
            raw = self.m.prepare()
        receipt = json.loads(raw)
        self.assertEqual(receipt['state'], 'protected-application-execution-identity-source-only')
        self.assertEqual(receipt['releases']['state'], 'protected-preinstalled-release-source-only')
        self.assertEqual(receipt['release_sha256'], hashlib.sha256(self.m.BASE.canonical(receipt['releases'])).hexdigest())
        self.assertEqual(receipt['namespace'], 4711)
        for app, roles in receipt['execution_bindings'].items():
            for role, row in roles.items():
                self.assertEqual(row['name'], self.value['applications'][app][role+'_user'])
                self.assertEqual(row['entry_point'], receipt['releases']['applications'][app]['entry_points'][role])
                self.assertEqual(row['primary_gid'], row['uid'])
                self.assertEqual(row['shared_groups'], {app.split('.')[1]+'_ipc': 320+self.m.RELEASE.APPLICATIONS.index(app)})
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_closed_input_requires_every_app_role_and_explicit_shared_group_list(self):
        for app in self.m.RELEASE.APPLICATIONS:
            for field in ('application_user', 'gateway_user', 'shared_groups'):
                value = copy.deepcopy(self.value); del value['applications'][app][field]
                with self.subTest(app=app, field=field), self.assertRaises(self.m.Pending): self.m.checked(value)
            value = copy.deepcopy(self.value); del value['applications'][app]
            with self.assertRaises(self.m.Pending): self.m.checked(value)
        for field in ('healthy', 'units', 'namespace', 'release', 'create_accounts'):
            value = copy.deepcopy(self.value); value[field] = True
            with self.subTest(field=field), self.assertRaises(self.m.Pending): self.m.checked(value)
        for schema in (True, 1.0, 2):
            value = copy.deepcopy(self.value); value['schema'] = schema
            with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_explicit_empty_shared_groups_are_supported_without_a_universal_ipc_requirement(self):
        value = copy.deepcopy(self.value); group = self.group
        for app, row in value['applications'].items():
            name = row['shared_groups'][0]; row['shared_groups'] = []
            group = b'\n'.join(line for line in group.split(b'\n') if not line.startswith(name.encode()+b':'))
        self.write(value, group=group)
        result = json.loads(self.m.prepare())
        self.assertTrue(all(not role['shared_groups'] for roles in result['execution_bindings'].values() for role in roles.values()))

    def test_names_and_cross_application_role_shared_group_aliases_refuse(self):
        for bad in ('root', '', 'Sava', 'user-name', 'name space', '%n', 'a'*32, 'u\nUser=root', False):
            with self.subTest(bad=bad), self.assertRaises(self.m.Pending): self.m.name(bad)
        for field, bad in (('gateway_user', 'sava_app'), ('application_user', 'dns_app'),
                           ('shared_groups', ['sava_ipc', 'sava_ipc']), ('shared_groups', ['sava_app']),
                           ('shared_groups', ['dns_ipc']), ('shared_groups', 'sava_ipc'), ('shared_groups', ['g'+str(n) for n in range(9)])):
            value = copy.deepcopy(self.value); value['applications']['mk8.sava'][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_input_canonical_ascii_lf_duplicate_and_nonfinite_refusal(self):
        raw = self.m.BASE.canonical(self.value)
        for bad in (raw+b'\n', raw[:-1], raw.replace(b'"schema":1', b'"schema":1,"schema":1'),
                    raw.replace(b'"schema":1', b'"schema":NaN'), raw.replace(b'"schema":1', b'"schema":1e999'), b'\xff\n'):
            self.write(raw=bad)
            with self.subTest(raw=bad), self.assertRaises(self.m.Pending): self.m.prepare()

    def test_private_input_bound_and_mode_refuse_before_decode_or_release(self):
        self.write(raw=b' '*(self.m.MAX_INPUT+1))
        with patch.object(self.m.json, 'loads', side_effect=AssertionError('decode')):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.write(); self.m.INPUT.chmod(0o644)
        with patch.object(self.m.RELEASE, 'prepare') as release:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            release.assert_not_called()

    def test_inventory_bytes_rows_columns_ascii_lf_and_names_are_bounded(self):
        for raw in ('root:x:0:0:a:/:/bin/bash\n', b'', b'\xff\n', self.passwd[:-1], self.passwd+b'\n',
                    self.passwd.replace(b'service', b'ser\x0bvice'), self.passwd.replace(b'sava_app:', b'bad name:'),
                    self.passwd.replace(b'root:x:0:0:', b'root:x:0:'), self.passwd+b'x'*self.m.MAX_INVENTORY):
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.account(passwd=raw)
        with patch.object(self.m, 'MAX_ROWS', 8):
            with self.assertRaises(self.m.Pending): self.account()
        with patch.object(self.m, 'MAX_INVENTORY', len(self.passwd)-1):
            with self.assertRaises(self.m.Pending): self.account()

    def test_whole_inventory_uid_name_gid_and_membership_ambiguities_refuse(self):
        for raw in (self.passwd+self.passwd.splitlines(keepends=True)[1],
                    self.passwd+b'alias:x:200:900:alias:/nonexistent:/usr/sbin/nologin\n',
                    b'alias:x:200:900:alias:/nonexistent:/usr/sbin/nologin\n'+self.passwd):
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.account(passwd=raw)
        for raw in (self.group+b'alias:x:200:\n', self.group+self.group.splitlines(keepends=True)[1],
                    self.group.replace(b'sava_app,sava_gate', b'sava_app,sava_app,sava_gate'),
                    self.group.replace(b'sava_app,sava_gate', b'sava_app,missing')):
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.account(group=raw)

    def test_inventory_numeric_id_spelling_type_and_width_refuse(self):
        for bad in (b'0200', b'-1', b'+200', b'200.0', b'2147483648', b'99999999999', b'', b'True'):
            for column in (2, 3):
                lines = self.passwd.splitlines(); fields = lines[1].split(b':'); fields[column] = bad; lines[1] = b':'.join(fields)
                with self.subTest(bad=bad, column=column), self.assertRaises(self.m.Pending): self.account(passwd=b'\n'.join(lines)+b'\n')
            with self.assertRaises(self.m.Pending): self.account(group=self.group.replace(b'sava_app:x:200:', b'sava_app:x:'+bad+b':'))

    def test_selected_uid_primary_gid_password_and_shell_require_nonlogin_system_shapes(self):
        for column, bad in ((2, b'99'), (2, b'1000'), (3, b'0'), (3, b'99'), (3, b'1000'),
                            (1, b''), (1, b'secret'), (6, b'/bin/bash'), (6, b'/usr/bin/nologin')):
            lines = self.passwd.splitlines(); fields = lines[1].split(b':'); fields[column] = bad; lines[1] = b':'.join(fields)
            with self.subTest(column=column, bad=bad), self.assertRaises(self.m.Pending): self.account(passwd=b'\n'.join(lines)+b'\n')

    def test_missing_accounts_named_primary_groups_and_mismatched_primary_gids_refuse(self):
        passwd = b'\n'.join(line for line in self.passwd.splitlines() if not line.startswith(b'sava_app:'))+b'\n'
        group = b'\n'.join(line for line in self.group.splitlines() if not line.startswith(b'sava_app:'))+b'\n'
        with self.assertRaises(self.m.Pending): self.account(passwd=passwd)
        with self.assertRaises(self.m.Pending): self.account(group=group)
        with self.assertRaises(self.m.Pending): self.account(group=self.group.replace(b'sava_app:x:200:', b'sava_app:x:500:'))

    def test_any_other_primary_gid_user_refuses_in_both_inventory_orders(self):
        foreign = b'foreign:x:700:200:foreign:/nonexistent:/usr/sbin/nologin\n'
        for raw in (foreign+self.passwd, self.passwd+foreign):
            with self.subTest(first=raw.startswith(foreign)), self.assertRaises(self.m.Pending): self.account(passwd=raw)

    def test_primary_group_membership_and_undeclared_supplementary_groups_refuse(self):
        for raw in (self.group.replace(b'sava_app:x:200:', b'sava_app:x:200:sava_gate'),
                    self.group+b'extra:x:800:sava_app\n', self.group+b'extra:x:800:email_gate\n'):
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.account(group=raw)
        allowed = self.group.replace(b'sava_app:x:200:', b'sava_app:x:200:sava_app')
        self.assertEqual(self.account(group=allowed)['mk8.sava']['roles']['application']['uid'], 200)

    def test_shared_groups_require_exact_pair_system_gid_and_no_primary_users(self):
        for replacement in (b'sava_ipc:x:320:', b'sava_ipc:x:320:sava_app',
                            b'sava_ipc:x:320:sava_app,sava_gate,dns_app',
                            b'sava_ipc:x:99:sava_app,sava_gate', b'sava_ipc:x:1000:sava_app,sava_gate'):
            raw = self.group.replace(b'sava_ipc:x:320:sava_app,sava_gate', replacement)
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.account(group=raw)
        with self.assertRaises(self.m.Pending): self.account(passwd=self.passwd+b'foreign:x:700:320:f:/nonexistent:/usr/sbin/nologin\n')
        raw = b'\n'.join(line for line in self.group.splitlines() if not line.startswith(b'sava_ipc:'))+b'\n'
        with self.assertRaises(self.m.Pending): self.account(group=raw)

    def test_input_and_account_inventory_refusals_precede_release_observation(self):
        self.write(passwd=self.passwd.replace(b'sava_app:x:200:', b'sava_app:x:99:'))
        with patch.object(self.m.RELEASE, 'prepare') as release:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            release.assert_not_called()

    def test_same_source_settings_are_privately_owned_after_caller_mutation(self):
        admitted = self.m.checked(self.value)
        self.value['applications']['mk8.sava']['shared_groups'].clear()
        self.assertEqual(admitted['applications']['mk8.sava']['shared_groups'], ['sava_ipc'])

    def test_outer_encoding_precedes_all_second_account_and_complete_release_deliveries(self):
        events = []; canonical = self.m.BASE.canonical; read = self.m.BASE.read_protected; release = self.m.RELEASE.prepare
        def observed(path, *args):
            if path in (self.m.INPUT, self.m.PASSWD, self.m.GROUP): events.append(path.name)
            return read(path, *args)
        def admitted(*args, **kwargs): events.append('release'); return release(*args, **kwargs)
        def encode(value):
            if type(value) is dict and value.get('state') == 'protected-application-execution-identity-source-only': events.append('encode')
            return canonical(value)
        with patch.object(self.m.BASE, 'read_protected', side_effect=observed), patch.object(self.m.RELEASE, 'prepare', side_effect=admitted), patch.object(self.m.BASE, 'canonical', side_effect=encode):
            self.m.prepare()
        self.assertEqual(events, ['application-identities.json', 'passwd', 'group', 'release', 'encode', 'application-identities.json', 'passwd', 'group', 'release'])

    def test_exact_output_cap_and_overflow_refuse_before_final_account_reads(self):
        raw = self.m.prepare(); cfg = self.m.configuration
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)): self.assertEqual(self.m.prepare(), raw)
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)-1), patch.object(self.m, 'configuration', wraps=cfg) as observed:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(observed.call_count, 1)

    def test_postencoding_configuration_passwd_and_group_byte_changes_withhold_receipt(self):
        canonical = self.m.BASE.canonical
        for path in (self.m.INPUT, self.m.PASSWD, self.m.GROUP):
            def encode(value):
                raw = canonical(value)
                if type(value) is dict and value.get('state') == 'protected-application-execution-identity-source-only': path.write_bytes(path.read_bytes()+b'\n')
                return raw
            with self.subTest(path=path), patch.object(self.m.BASE, 'canonical', side_effect=encode):
                with self.assertRaises(self.m.Pending): self.m.prepare()
            self.write()

    def test_postencoding_same_byte_account_inode_replacement_withholds_receipt(self):
        canonical = self.m.BASE.canonical
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == 'protected-application-execution-identity-source-only':
                path = self.m.PASSWD; replacement = path.with_name('replacement'); replacement.write_bytes(path.read_bytes()); replacement.chmod(0o644); os.replace(replacement, path)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_postencoding_release_file_identity_or_manifest_drift_withholds_receipt(self):
        canonical = self.m.BASE.canonical
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == 'protected-application-execution-identity-source-only':
                path = self.helper.path(); replacement = path.with_name('replacement'); replacement.write_bytes(path.read_bytes()); replacement.chmod(0o755); os.replace(replacement, path)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_owned_release_delivery_rejects_nonbytes_oversize_and_context_disagreement(self):
        raw = self.m.RELEASE.prepare(); value = json.loads(raw); value['namespace'] = 4712
        for bad in (bytearray(raw), b'x'*(self.m.RELEASE.MAX_OUTPUT+1), self.m.BASE.canonical(value)):
            with self.subTest(kind=type(bad)), patch.object(self.m.RELEASE, 'prepare', return_value=bad):
                with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_initial_context_requires_true_positive_uint64_before_any_inputs(self):
        for value in (0, True, 1.0, -1, 2**64):
            with patch.object(self.m.KERNEL, 'namespace', return_value=value), patch.object(self.m, 'configuration') as observed:
                with self.assertRaises(self.m.Pending): self.m.prepare()
                observed.assert_not_called()

    def test_final_outer_context_refuses_even_after_both_complete_release_preparations(self):
        with patch.object(self.m.KERNEL, 'namespace', side_effect=[4711]*5+[4712]):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_invalid_and_expired_deadlines_refuse_before_inputs(self):
        for deadline in (True, '10', float('nan'), float('inf'), self.m.KERNEL.now()-1):
            with patch.object(self.m, 'configuration') as observed:
                with self.assertRaises(self.m.Pending): self.m.prepare(deadline)
                observed.assert_not_called()

    def test_positive_inherited_cap_and_independent_nested_release_window_do_not_widen(self):
        read = self.m.BASE.read_protected
        for parent, outer, inner in ((12, 12, 12), (1000, 140, 70)):
            seen = []
            def observed(path, limit, private, end): seen.append((path, end)); return read(path, limit, private, end)
            with patch.object(self.m.KERNEL, 'now', return_value=10), patch.object(self.m.BASE, 'read_protected', side_effect=observed): self.m.prepare(parent)
            self.assertEqual(len(seen), 58)
            self.assertEqual([end for path, end in seen if path in (self.m.INPUT, self.m.PASSWD, self.m.GROUP)], [outer]*6)
            self.assertEqual([end for path, end in seen if path not in (self.m.INPUT, self.m.PASSWD, self.m.GROUP)], [inner]*52)

    def test_final_expiry_after_actual_second_complete_release_return_withholds_receipt(self):
        original = self.m.release_bytes; calls = 0
        def release(end):
            nonlocal calls
            raw = original(end); calls += 1
            if calls == 2: clock.return_value = end
            return raw
        with patch.object(self.m.KERNEL, 'now', return_value=10) as clock, patch.object(self.m, 'release_bytes', side_effect=release):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(calls, 2)

    def test_binary_cli_requires_full_true_count_flush_and_no_overrides(self):
        class Sink:
            def __init__(self, count=None, fail=False): self.buffer=self; self.raw=b''; self.count=count; self.fail=fail
            def write(self, raw): self.raw=raw; return len(raw) if self.count is None else self.count
            def flush(self):
                if self.fail: raise OSError('private flush')
        for count, fail, expected in ((None, False, 0), (False, False, 75), (1, False, 75), (None, True, 75)):
            sink = Sink(count, fail)
            with patch.object(sys, 'argv', ['identities.py']), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare', return_value=b'{}\n'):
                self.assertEqual(self.m.main(), expected)
            self.assertEqual(sink.raw, b'{}\n')
        for args, sink in ((['identities.py', 'extra'], Sink()), (['identities.py'], io.StringIO())):
            with patch.object(sys, 'argv', args), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare') as prepared:
                self.assertEqual(self.m.main(), 75); prepared.assert_not_called()


if __name__ == '__main__':
    unittest.main()
