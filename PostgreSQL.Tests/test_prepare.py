"""Ordinary-UID private input/pipe tests; no PostgreSQL or host operations.

All account names/capacities here are finite DATA, not deployed assignments.
Root/ancestry and caller context are explicitly substituted private deliveries.
"""

import copy
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


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name); self.root.chmod(0o700)
        spec = importlib.util.spec_from_file_location('private_postgresql_prepare', ROOT / 'PostgreSQL/prepare.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.TRUST_ROOT = self.root; self.m.TRUSTED_UID = os.getuid()
        self.m.INPUT = self.root / 'postgresql.json'; self.m.PASSWD = self.root / 'passwd'
        self.value = {'schema': 1, 'max_connections': 40, 'shared_buffers_mb': 128,
            'applications': {'mk8.dns': {'role': 'dns_demo', 'database': 'dns_store', 'connection_limit': 12},
                             'mk8.email': {'role': 'mail_demo', 'database': 'mail_store', 'connection_limit': 16}}}
        self.passwd = (b'root:x:0:0:root:/root:/bin/bash\n'
                       b'dns_demo:x:210:210:DNS:/nonexistent:/usr/sbin/nologin\n'
                       b'mail_demo:x:211:211:Mail:/nonexistent:/usr/sbin/nologin\n')
        self.write(); self.write_accounts()

    def write(self, value=None, raw=None):
        self.m.INPUT.write_bytes(self.m.canonical(self.value if value is None else value) if raw is None else raw)
        self.m.INPUT.chmod(0o600)

    def write_accounts(self, raw=None):
        self.m.PASSWD.write_bytes(self.passwd if raw is None else raw); self.m.PASSWD.chmod(0o644)

    def prepare(self, **kw):
        return self.m.prepare(scope=lambda: 123456, **kw)

    def record(self):
        return json.loads(self.prepare())

    def test_complete_local_peer_intention_binds_checked_private_inputs_and_accounts(self):
        raw = self.prepare(); value = json.loads(raw)
        self.assertEqual(raw, self.m.canonical(value))
        self.assertEqual(value['state'], 'local-peer-provisioning-intention-only')
        self.assertEqual(value['namespace'], 123456)
        self.assertEqual(value['configuration']['value'], self.value)
        self.assertEqual(value['accounts']['mk8.dns'],
                         {'name': 'dns_demo', 'uid': 210, 'gid': 210, 'shell': '/usr/sbin/nologin'})
        self.assertEqual(set(value['plan']), {'files', 'sql_steps', 'connections', 'initdb_argv'})
        self.assertLessEqual(len(raw), 262145)
        self.assertEqual(value['account_source']['path'], str(self.m.PASSWD))

    def test_missing_configuration_refuses_before_account_read_or_namespace_final(self):
        self.m.INPUT.unlink(); scopes = []
        original = self.m.read_protected; reads = []
        def reader(path, *args):
            reads.append(path); return original(path, *args)
        with patch.object(self.m, 'read_protected', side_effect=reader), self.assertRaises(OSError):
            self.m.prepare(scope=lambda: scopes.append(1) or 123456)
        self.assertEqual(reads, [self.m.INPUT]); self.assertEqual(scopes, [1])

    def test_canonical_schema_refuses_duplicate_unknown_nonfinite_and_noncanonical_bytes(self):
        good = self.m.canonical(self.value)
        cases = [good.replace(b'"schema":1', b'"schema":1,"schema":1'),
                 good.replace(b'"schema":1', b'"schema":true'),
                 good.replace(b'"schema":1', b'"schema":1.0'),
                 good.replace(b'"schema":1', b'"schema":NaN'),
                 good.replace(b'"schema":1', b'"schema":1,"host":"example.invalid"'),
                 good.replace(b'"schema":1', b'"schema":1e999'),
                 good + b'\n', good.rstrip(b'\n'), b'\xff\n', b'{"schema":1}\n']
        for raw in cases:
            with self.subTest(raw=raw):
                self.write(raw=raw)
                with self.assertRaises(self.m.Pending): self.prepare()

    def test_configuration_cap_precedes_json_decode_and_refuses_deep_json(self):
        self.write(raw=b' ' * 4097)
        with patch.object(self.m.json, 'loads', side_effect=AssertionError('must not decode')):
            with self.assertRaises(self.m.Pending): self.prepare()
        self.write(raw=b'[' * 1500 + b'0' + b']' * 1500)
        with self.assertRaises(self.m.Pending): self.prepare()

    def test_identifier_grammar_refuses_sql_hba_connection_and_shell_injections(self):
        for name in ('', 'PG_TEST', 'pg_test', 'postgres', 'template0', 'template1', 'root',
                     'a' * 32, 'a";DROP ROLE x;--', 'a;Host=outside', 'a\nlocal all all trust',
                     'a-b', 'a\\x', "a'", 'a b', '$(id)', 'é', None, True, 123):
            for field in ('role', 'database'):
                with self.subTest(name=name, field=field):
                    value = copy.deepcopy(self.value); value['applications']['mk8.dns'][field] = name
                    self.write(value)
                    with self.assertRaises(self.m.Pending): self.prepare()

    def test_database_and_role_keywords_remain_quoted_literal_identities(self):
        value = copy.deepcopy(self.value)
        value['applications']['mk8.dns'].update(role='all', database='replication')
        self.write(value); self.write_accounts(self.passwd.replace(b'dns_demo', b'all'))
        plan = self.record()['plan']
        self.assertIn('local "replication" "all" peer\n', plan['files']['pg_hba.conf'])
        self.assertIn('CREATE ROLE "all" LOGIN', plan['sql_steps'][0]['sql'])
        self.assertIn('CREATE DATABASE "replication" OWNER "all"', plan['sql_steps'][1]['sql'])

    def test_distinct_application_roles_databases_and_exact_two_provider_map_are_mandatory(self):
        cases = []
        for field in ('role', 'database'):
            value = copy.deepcopy(self.value)
            value['applications']['mk8.email'][field] = value['applications']['mk8.dns'][field]; cases.append(value)
        value = copy.deepcopy(self.value); del value['applications']['mk8.email']; cases.append(value)
        value = copy.deepcopy(self.value); value['applications']['mk8.sava'] = value['applications']['mk8.dns']; cases.append(value)
        value = copy.deepcopy(self.value); value['applications'] = []; cases.append(value)
        value = copy.deepcopy(self.value); value['applications']['mk8.dns']['password'] = 'not-accepted'; cases.append(value)
        for value in cases:
            with self.subTest(value=value):
                self.write(value)
                with self.assertRaises(self.m.Pending): self.prepare()

    def test_explicit_capacity_and_connection_limits_are_true_integer_and_leave_reserve(self):
        for field, bad in (('max_connections', True), ('max_connections', 15), ('max_connections', 513),
                           ('max_connections', 35), ('shared_buffers_mb', 15), ('shared_buffers_mb', 16385),
                           ('shared_buffers_mb', '128'), ('shared_buffers_mb', 128.0)):
            with self.subTest(field=field, bad=bad):
                value = copy.deepcopy(self.value); value[field] = bad; self.write(value)
                with self.assertRaises(self.m.Pending): self.prepare()
        for bad in (0, 65, True, 12.0, '12', None):
            value = copy.deepcopy(self.value); value['applications']['mk8.dns']['connection_limit'] = bad
            self.write(value)
            with self.subTest(limit=bad), self.assertRaises(self.m.Pending): self.prepare()

    def test_checked_settings_and_render_output_are_private_copies(self):
        original = copy.deepcopy(self.value); admitted = self.m.checked(self.value)
        self.value['applications']['mk8.dns']['role'] = 'later_change'
        self.assertEqual(admitted, original)
        plan = self.m.render(admitted); admitted['applications']['mk8.dns']['role'] = 'another_change'
        self.assertIn('"dns_demo"', plan['files']['pg_hba.conf'])

    def test_local_accounts_require_unique_system_uids_existing_roles_and_nonlogin_shells(self):
        cases = [self.passwd.replace(b'mail_demo', b'other_demo'),
                 self.passwd.replace(b':210:210:', b':0:210:'),
                 self.passwd.replace(b':210:210:', b':1000:210:'),
                 self.passwd.replace(b':210:210:', b':210:0:'),
                 self.passwd.replace(b':211:211:', b':210:211:'),
                 self.passwd.replace(b'/usr/sbin/nologin', b'/bin/bash'),
                 self.passwd.replace(b'dns_demo:x:', b'dns_demo:cleartext:'),
                 self.passwd + self.passwd.splitlines()[1] + b'\n',
                 self.passwd.replace(b':210:', b':0210:'), self.passwd[:-1],
                 self.passwd + b'bad:row\n', self.passwd + b'\xff\n']
        for raw in cases:
            with self.subTest(raw=raw):
                self.write_accounts(raw)
                with self.assertRaises(self.m.Pending): self.prepare()

    def test_account_inventory_is_bounded_and_malformed_before_plan_work(self):
        for raw in (b'x' * 262145, b'\n' * 4097, self.passwd + b'zero:x:2147483648:1::/:/bin/false\n'):
            self.write_accounts(raw)
            with self.subTest(raw_size=len(raw)), patch.object(self.m, 'render', side_effect=AssertionError('no render')):
                with self.assertRaises(self.m.Pending): self.prepare()

    def test_non_lf_passwd_separators_cannot_create_apparent_selected_accounts(self):
        root, dns, mail = self.passwd[:-1].split(b'\n')
        for separator in (b'\r', b'\r\n', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e'):
            cases = (separator.join((root, dns, mail)) + b'\n',
                     root + separator + dns + b'\n' + mail + b'\n')
            for raw in cases:
                with self.subTest(separator=separator, raw=raw):
                    self.write_accounts(raw)
                    with patch.object(self.m, 'render', wraps=self.m.render) as renderer:
                        with self.assertRaises(self.m.Pending): self.prepare()
                        self.assertEqual(renderer.call_count, 0)

    def test_control_bytes_in_account_fields_refuse_before_render(self):
        for value in (*range(10), *range(11, 32), 127):
            raw = self.passwd.replace(b':root:', b':root' + bytes((value,)) + b':', 1)
            with self.subTest(control=value):
                self.write_accounts(raw)
                with patch.object(self.m, 'render', wraps=self.m.render) as renderer:
                    with self.assertRaises(self.m.Pending): self.prepare()
                    self.assertEqual(renderer.call_count, 0)

    def test_valid_exact_lf_records_and_4096_row_limit_remain_admitted(self):
        value = self.record()
        self.assertEqual(value['accounts']['mk8.dns']['name'], 'dns_demo')
        self.assertEqual(value['accounts']['mk8.email']['name'], 'mail_demo')
        filler = b''.join(f'user{i}:x:{10000+i}:100::/nonexistent:/bin/false\n'.encode('ascii')
                          for i in range(4093))
        self.write_accounts(self.passwd + filler)
        self.assertEqual(self.record()['accounts'], value['accounts'])
        self.write_accounts(self.passwd + filler + b'overflow:x:20000:100::/nonexistent:/bin/false\n')
        with patch.object(self.m, 'render', wraps=self.m.render) as renderer:
            with self.assertRaises(self.m.Pending): self.prepare()
            self.assertEqual(renderer.call_count, 0)

    def test_input_mode_owner_links_symbolic_fifo_and_writable_ancestry_refuse(self):
        for mode in (0o644, 0o640, 0o660, 0o400):
            self.m.INPUT.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(self.m.Pending): self.prepare()
        self.m.INPUT.chmod(0o600)
        linked = self.root / 'other'; os.link(self.m.INPUT, linked)
        with self.assertRaises(self.m.Pending): self.prepare()
        linked.unlink(); self.m.INPUT.rename(linked); self.m.INPUT.symlink_to(linked)
        with self.assertRaises(self.m.Pending): self.prepare()
        self.m.INPUT.unlink(); os.mkfifo(self.m.INPUT)
        with self.assertRaises(self.m.Pending): self.prepare()
        self.m.INPUT.unlink(); linked.rename(self.m.INPUT)
        with patch.object(self.m, 'TRUSTED_UID', os.getuid() + 1), self.assertRaises(self.m.Pending): self.prepare()
        self.root.chmod(0o777)
        try:
            with self.assertRaises(self.m.Pending): self.prepare()
        finally: self.root.chmod(0o700)

    def test_open_requires_no_follow_nonblocking_and_close_on_exec(self):
        original = self.m.os.open; flags = []
        def opened(path, options, *args):
            flags.append(options); return original(path, options, *args)
        with patch.object(self.m.os, 'open', side_effect=opened): self.prepare()
        self.assertEqual(len(flags), 4)
        for options in flags:
            self.assertEqual(options, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)

    def test_descriptor_or_name_identity_drift_during_read_refuses(self):
        original = self.m.os.read; changed = []
        def read(fd, count):
            data = original(fd, count)
            if data and not changed:
                changed.append(1); self.m.INPUT.chmod(0o640)
            return data
        with patch.object(self.m.os, 'read', side_effect=read), self.assertRaises(self.m.Pending): self.prepare()
        self.assertEqual(changed, [1])

    def test_replaced_same_bytes_input_cannot_hide_inode_drift_between_reads(self):
        original = self.m.render
        def render(value):
            result = original(value); raw = self.m.INPUT.read_bytes()
            newer = self.root / 'replacement'; newer.write_bytes(raw); newer.chmod(0o600)
            newer.replace(self.m.INPUT); return result
        with patch.object(self.m, 'render', side_effect=render), self.assertRaises(self.m.Pending): self.prepare()

    def test_second_configuration_and_account_byte_changes_withhold_receipt(self):
        for field in ('configuration', 'accounts'):
            self.write(); self.write_accounts(); original = self.m.render
            def render(value):
                plan = original(value)
                if field == 'configuration':
                    newer = copy.deepcopy(self.value); newer['shared_buffers_mb'] = 256; self.write(newer)
                else: self.write_accounts(self.passwd.replace(b':210:210:', b':212:210:'))
                return plan
            with self.subTest(field=field), patch.object(self.m, 'render', side_effect=render):
                with self.assertRaises(self.m.Pending): self.prepare()

    def test_final_context_is_true_positive_uint64_and_exactly_equal(self):
        for value in (True, 0, -1, 1.5, '123456', 2**64):
            with self.subTest(initial=value), self.assertRaises(self.m.Pending): self.m.prepare(scope=lambda: value)
            contexts = iter((123456, value))
            with self.subTest(final=value), self.assertRaises(self.m.Pending): self.m.prepare(scope=lambda: next(contexts))
        contexts = iter((123456, 123457))
        with self.assertRaises(self.m.Pending): self.m.prepare(scope=lambda: next(contexts))

    def test_deadline_is_capped_inherited_and_expiry_refuses(self):
        for value in (True, float('nan'), float('inf'), '10'):
            with self.subTest(value=value), self.assertRaises(self.m.Pending): self.prepare(deadline=value)
        with patch.object(self.m.KERNEL, 'now', return_value=100):
            with self.assertRaises(self.m.Pending): self.prepare(deadline=100)
            original = self.m.read_protected; ends = []
            def reader(path, limit, private, end):
                ends.append(end); return original(path, limit, private, end)
            with patch.object(self.m, 'read_protected', side_effect=reader): self.prepare(deadline=200)
            self.assertEqual(ends, [110] * 4)
            ends.clear()
            with patch.object(self.m, 'read_protected', side_effect=reader): self.prepare(deadline=105)
            self.assertEqual(ends, [105] * 4)

    def test_receipt_encoding_precedes_final_reads_and_no_crypto_follows_final_scope(self):
        original = self.m.read_protected; events = []
        def reader(path, *args):
            events.append(path.name); return original(path, *args)
        original_canonical = self.m.canonical
        def encode(value):
            if type(value) is dict and value.get('state') == 'local-peer-provisioning-intention-only':
                events.append('receipt')
            return original_canonical(value)
        def scope():
            events.append('scope')
            if events.count('scope') == 2:
                self.m.canonical = lambda value: self.fail('encoding after final context')
                self.m.hashlib.sha256 = lambda value: self.fail('hash after final context')
            return 123456
        with patch.object(self.m, 'read_protected', side_effect=reader), patch.object(self.m, 'canonical', side_effect=encode), \
             patch.object(self.m.hashlib, 'sha256', wraps=self.m.hashlib.sha256):
            raw = self.m.prepare(scope=scope)
        self.assertEqual(events, ['scope', 'postgresql.json', 'passwd', 'receipt', 'postgresql.json', 'passwd', 'scope'])
        self.assertEqual(json.loads(raw)['namespace'], 123456)

    def test_final_clock_expiry_after_scope_withholds_prepared_receipt(self):
        def scope():
            if hasattr(scope, 'called'): self.m.KERNEL.now = lambda: 110
            scope.called = True; return 123456
        with patch.object(self.m.KERNEL, 'now', return_value=100), self.assertRaises(self.m.Pending):
            self.m.prepare(scope=scope)

    def test_read_close_error_retires_once_and_never_closes_reused_descriptor(self):
        original = os.close; closes = []; replacement = []
        def close(fd):
            closes.append(fd); original(fd)
            other = os.open(self.m.PASSWD, os.O_RDONLY); replacement.append(other)
            self.assertEqual(other, fd); raise OSError('injected retired close error')
        try:
            with patch.object(self.m.os, 'close', side_effect=close), self.assertRaises(OSError): self.prepare()
            self.assertEqual(closes, replacement)
            self.assertEqual(os.read(replacement[0], 4), b'root')
        finally:
            for fd in replacement: original(fd)

    def test_real_preparation_has_no_process_creation_or_sql_execution(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('no process')), \
             patch.object(os, 'system', side_effect=AssertionError('no shell')), \
             patch.object(os, 'execve', side_effect=AssertionError('no exec')):
            raw = self.prepare()
        self.assertEqual(json.loads(raw)['plan']['initdb_argv'][0], '/usr/lib/postgresql/17/bin/initdb')

    def test_server_config_is_socket_only_with_fixed_absolute_paths_and_sync_policy(self):
        config = self.record()['plan']['files']['postgresql.conf']
        self.assertIn("listen_addresses = ''\n", config)
        self.assertIn("unix_socket_directories = '/run/debian13s4-postgresql'\n", config)
        self.assertIn("data_directory = '/var/lib/debian13s4-postgresql'\n", config)
        self.assertIn("hba_file = '/etc/debian13s4-postgresql/pg_hba.conf'\n", config)
        self.assertIn('fsync = on\nfull_page_writes = on\nsynchronous_commit = on\n', config)
        self.assertIn('max_connections = 40\nshared_buffers = \'128MB\'\n', config)
        self.assertNotIn('include', config); self.assertNotIn('*', config)

    def test_postgres_data_is_outside_the_existing_root_private_recovery_state(self):
        recovery = (ROOT / 'Recovery/repair.sh').read_text()
        self.assertIn('S4_STATE_DIR=/var/lib/debian13s4\n', recovery)
        self.assertIn('install -d -o root -g root -m 0700', recovery)
        data = Path(self.record()['plan']['initdb_argv'][2])
        self.assertNotEqual(data, Path('/var/lib/debian13s4'))
        self.assertNotIn(Path('/var/lib/debian13s4'), data.parents)

    def test_complete_hba_exposes_only_exact_peer_pairs_and_rejects_other_and_replication(self):
        hba = self.record()['plan']['files']['pg_hba.conf']
        self.assertEqual(hba.splitlines(), ['local all postgres peer',
            'local "dns_store" "dns_demo" peer', 'local "mail_store" "mail_demo" peer',
            'local replication all reject', 'local all all reject', 'host all all 0.0.0.0/0 reject',
            'host all all ::/0 reject', 'host replication all 0.0.0.0/0 reject', 'host replication all ::/0 reject'])
        self.assertNotIn('trust', hba); self.assertNotIn('map=', hba)
        self.assertEqual(self.record()['plan']['files']['pg_ident.conf'], '# No peer identity remapping is admitted.\n')

    def test_fresh_role_sql_forbids_privilege_and_password_and_database_steps_preserve_autocommit(self):
        steps = self.record()['plan']['sql_steps']
        self.assertEqual(len(steps), 5)
        self.assertEqual(steps[0]['database'], 'postgres'); self.assertTrue(steps[0]['transaction'])
        for role, limit in (('dns_demo', 12), ('mail_demo', 16)):
            self.assertIn(f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                f'NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {limit} PASSWORD NULL;\n', steps[0]['sql'])
        for index, database, role, limit in ((1, 'dns_store', 'dns_demo', 12), (3, 'mail_store', 'mail_demo', 16)):
            self.assertFalse(steps[index]['transaction']); self.assertNotIn('BEGIN', steps[index]['sql'])
            self.assertEqual(steps[index]['sql'], f'CREATE DATABASE "{database}" OWNER "{role}" TEMPLATE template0 '
                             f"ENCODING 'UTF8' CONNECTION LIMIT {limit};\n")
            self.assertEqual(steps[index+1]['database'], database); self.assertTrue(steps[index+1]['transaction'])
            self.assertIn(f'REVOKE ALL ON DATABASE "{database}" FROM PUBLIC;\n', steps[index+1]['sql'])
            self.assertIn('REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n', steps[index+1]['sql'])
        all_sql = ''.join(item['sql'] for item in steps)
        for forbidden in ('IF NOT EXISTS', 'ALTER ROLE', 'DROP ', 'GRANT ', '\\', 'dblink', 'CREATE EXTENSION'):
            self.assertNotIn(forbidden, all_sql)

    def test_initdb_intention_disables_tcp_auth_trust_and_keeps_durable_creation_flags(self):
        argv = self.record()['plan']['initdb_argv']
        self.assertEqual(argv, ['/usr/lib/postgresql/17/bin/initdb', '--pgdata', '/var/lib/debian13s4-postgresql',
            '--username=postgres', '--auth-local=peer', '--auth-host=reject', '--encoding=UTF8',
            '--locale=C.UTF-8', '--data-checksums', '--no-instructions'])
        self.assertNotIn('--no-sync', argv); self.assertNotIn('--auth=trust', argv)

    def test_two_connection_strings_are_explicit_local_and_keep_other_storage_outside_profile(self):
        connections = self.record()['plan']['connections']
        self.assertEqual(set(connections), {'mk8.dns', 'mk8.email'})
        for app, role, database in (('mk8.dns', 'dns_demo', 'dns_store'), ('mk8.email', 'mail_demo', 'mail_store')):
            self.assertEqual(connections[app], f'Host=/run/debian13s4-postgresql;Port=5432;Database={database};'
                             f'Username={role};SSL Mode=Disable;Include Error Detail=false')
            self.assertNotIn('Password=', connections[app])

    def cli(self, stdout=None, argv=None):
        binary = io.BytesIO(); wrapper = stdout or io.TextIOWrapper(binary, encoding='utf-32', errors='replace')
        stderr = io.StringIO(); original = self.m.prepare
        with patch.object(self.m.sys, 'argv', ['prepare.py'] if argv is None else argv), \
             patch.object(self.m.sys, 'stdout', wrapper), patch.object(self.m.sys, 'stderr', stderr), \
             patch.object(self.m, 'prepare', side_effect=lambda: original(scope=lambda: 123456)):
            status = self.m.main()
        raw = binary.getvalue(); wrapper.close()
        return status, raw, stderr.getvalue()

    def test_cli_writes_the_same_actual_utf8_bytes_under_nondefault_text_encoding(self):
        expected = self.prepare(); status, raw, stderr = self.cli()
        self.assertEqual(status, 0); self.assertEqual(raw, expected); self.assertEqual(stderr, '')

    def test_malformed_account_separators_withhold_all_cli_output_bytes(self):
        root, dns, mail = self.passwd[:-1].split(b'\n')
        for separator in (b'\r', b'\r\n', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e'):
            for inventory in (separator.join((root, dns, mail)) + b'\n',
                              root + separator + dns + b'\n' + mail + b'\n'):
                with self.subTest(separator=separator, inventory=inventory):
                    self.write_accounts(inventory)
                    with patch.object(self.m, 'render', wraps=self.m.render) as renderer:
                        status, raw, stderr = self.cli()
                    self.assertEqual(status, 75); self.assertEqual(raw, b'')
                    self.assertEqual(renderer.call_count, 0); self.assertIn('Pending:', stderr)

    def test_cli_refuses_text_only_sink_and_arguments_before_any_input_reads(self):
        for stdout, argv in ((io.StringIO(), ['prepare.py']), (io.StringIO(), ['prepare.py', '--config', '/tmp/x'])):
            with patch.object(self.m, 'read_protected', side_effect=AssertionError('no input')):
                status, raw, stderr = self.cli(stdout, argv)
            self.assertEqual(status, 75); self.assertEqual(raw, b''); self.assertIn('Pending:', stderr)

    def test_cli_short_boolean_unknown_write_and_flush_error_cannot_report_success(self):
        class Sink:
            def __init__(self, count, flush_error=False): self.count=count; self.flush_error=flush_error; self.bytes=b''
            def write(self, data): self.bytes=data; return len(data) if self.count=='full' else self.count
            def flush(self):
                if self.flush_error: raise OSError('injected flush error')
        class Wrapper:
            def __init__(self, sink): self.buffer=sink
            def close(self): pass
        for count, flush_error in ((0, False), (True, False), (None, False), ('full', True)):
            sink = Sink(count, flush_error)
            with self.subTest(count=count, flush=flush_error):
                status, raw, stderr = self.cli(Wrapper(sink))
                self.assertEqual(status, 75); self.assertEqual(sink.bytes, self.prepare())
                self.assertEqual(raw, b''); self.assertIn('Pending:', stderr)

    def test_standalone_interpreter_pipe_bytes_ignore_pythonioencoding_with_real_private_prepare(self):
        driver = ('import importlib.util,os,sys\nfrom pathlib import Path\n'
            f'spec=importlib.util.spec_from_file_location("private_pg",{str(ROOT / "PostgreSQL/prepare.py")!r})\n'
            'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n'
            f'm.TRUST_ROOT=Path({str(self.root)!r});m.TRUSTED_UID=os.getuid()\n'
            f'm.INPUT=Path({str(self.m.INPUT)!r});m.PASSWD=Path({str(self.m.PASSWD)!r})\n'
            'original=m.prepare;m.prepare=lambda:original(scope=lambda:123456)\n'
            'sys.argv=["prepare.py"];sys.exit(m.main())\n')
        expected = self.prepare()
        for encoding in ('utf-32', 'ascii:replace', 'ascii:ignore', 'utf-8:strict'):
            env = dict(os.environ, PYTHONIOENCODING=encoding); env.pop('PYTHONPATH', None)
            with self.subTest(encoding=encoding):
                child = subprocess.run([sys.executable, '-B', '-c', driver], env=env, capture_output=True, timeout=10)
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(child.stdout, expected); self.assertEqual(child.stderr, b'')


if __name__ == '__main__':
    unittest.main()
