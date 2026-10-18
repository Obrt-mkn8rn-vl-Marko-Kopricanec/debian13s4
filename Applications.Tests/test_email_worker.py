"""Private file/credential intentions, never execute Email or systemd."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('private_email_'+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class EmailWorkerTests(unittest.TestCase):
    def setUp(self):
        fixture = load(ROOT/'Applications.Tests/test_postgresql_identity.py')
        self.helper = fixture.PostgresqlIdentityTests(methodName='runTest')
        self.addCleanup(self.helper.doCleanups); self.helper.setUp()
        self.root = self.helper.root
        self.m = load(ROOT/'Applications/email_worker.py')
        self.m.JOIN = self.helper.m
        self.m.BASE, self.m.KERNEL, self.m.Pending = self.helper.m.PG, self.helper.m.KERNEL, self.helper.m.Pending
        self.m.INPUT, self.m.SETTINGS_ROOT = self.root/'email-worker.json', self.root/'email'
        self.m.SETTINGS_ROOT.mkdir(mode=0o700)
        self.settings = self.m.SETTINGS_ROOT/'worker.json'
        self.descriptor = {'schema': 1, 'settings': str(self.settings), 'credentials': {
            name: str(self.m.SETTINGS_ROOT/name) for name in ('database.password', 'messaging.key', 'objects.connection')}}
        self.value = {
            'Database': {'Host': self.m.BASE.SOCKET_DIRECTORY, 'Port': 5432, 'Name': 'email_db',
                'Username': 'email_app', 'Password': '', 'PasswordFile': 'database.password'},
            'Messaging': {'Enabled': True, 'EncryptionKeyId': 'primary', 'EncryptionKey': '',
                'EncryptionKeyFile': 'messaging.key', 'DecryptionKeys': [], 'MaxPayloadBytes': 4194304,
                'InlinePayloadThresholdBytes': 262144, 'LeaseSeconds': 120,
                'NotificationFallbackSeconds': 30, 'WorkerId': 'explicit-fixture-worker'},
            'ObjectStorage': {'Provider': 'azure-blob', 'ConnectionString': '',
                'ConnectionStringFile': 'objects.connection', 'ContainerName': 'fixture-email',
                'ObjectPrefix': 'fixture', 'CreateContainerIfMissing': False},
            'OAuth': {'EnableOAuth': False, 'EnableOpenIdConnect': False}, 'Mfa': {'EnableTotp': False},
            'Dkim': {'EnableSigning': False}, 'Smtp': {'Hostname': 'mail.example.test'},
            'Limits': {'MaxMessageSizeBytes': 1048576}}
        self.secrets = {'database.password': b'PUBLIC-test-password\n',
            'messaging.key': base64.b64encode(b'p'*32)+b'\n',
            'objects.connection': b'PUBLIC-test-opaque-connection\n'}
        for name, raw in self.secrets.items(): self.write(Path(self.descriptor['credentials'][name]), raw)
        self.write(self.settings, self.m.BASE.canonical(self.value))
        self.write(self.m.INPUT, self.m.BASE.canonical(self.descriptor))

    def write(self, path, raw):
        path.write_bytes(raw); path.chmod(0o600)

    def test_real_inputs_bind_worker_only_fixed_modes_and_private_credentials_without_native_entry(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('no app/SQL/manager entry')):
            raw = self.m.prepare()
        value = json.loads(raw); plan = value['plan']
        self.assertEqual(value['state'], self.m.STATE)
        self.assertEqual(plan['application_identity']['name'], 'email_app')
        self.assertIn('Username=email_app', plan['database_intention'])
        self.assertNotIn('email_gateway', plan['unit'])
        self.assertEqual(plan['unit_sha256'], hashlib.sha256(plan['unit'].encode()).hexdigest())
        self.assertIn('WorkingDirectory=%d\n', plan['unit'])
        self.assertIn('Restart=no\n', plan['unit']); self.assertNotIn('[Install]', plan['unit'])
        self.assertTrue(plan['startup_database_mutations']); self.assertFalse(plan['full_native_configuration_validated'])
        for mode, argv in plan['commands'].items():
            self.assertEqual(argv[:2], ['/usr/bin/env', '-i'])
            self.assertEqual(argv[-2:], [plan['application_identity']['entry_point'], '--'+mode])
            self.assertIn('MK8EMAIL_CONFIG_FILE=${CREDENTIALS_DIRECTORY}/environment.json', argv)
            self.assertIn('DOTNET_ENVIRONMENT=Production', argv)
            self.assertNotIn('--contentRoot', argv)
        rows = plan['inputs']['credentials']
        self.assertEqual({r['id'] for r in rows}, {'environment.json', *self.secrets})
        for row in rows:
            self.assertEqual(row['bytes'], len(Path(row['source']['path']).read_bytes()))
            self.assertIn('LoadCredential='+row['id']+':'+row['source']['path']+'\n', plan['unit'])
        for secret in self.secrets.values(): self.assertNotIn(secret.rstrip(), raw)
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_typed_database_credential_and_messaging_mismatches_refuse(self):
        peer = {'database': 'email_db', 'user': 'email_app'}
        mutations = [lambda v: v['Database'].__setitem__('Username', 'email_gateway'),
            lambda v: v['Database'].__setitem__('Host', 'localhost'),
            lambda v: v['Database'].__setitem__('Port', True),
            lambda v: v['Database'].__setitem__('Password', 'unsafe-inline'),
            lambda v: v['Database'].__setitem__('PasswordFile', '../database.password'),
            lambda v: v['Messaging'].__setitem__('Enabled', 1),
            lambda v: v['Messaging'].__setitem__('WorkerId', None),
            lambda v: v['Messaging'].__setitem__('MaxPayloadBytes', 65536),
            lambda v: v['ObjectStorage'].__setitem__('CreateContainerIfMissing', True),
            lambda v: v['Mfa'].__setitem__('EncryptionKeyFile', 'unexpected.key')]
        for mutate in mutations:
            value = copy.deepcopy(self.value); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(self.m.Pending): self.m.configuration(value, peer)
        for value in ({'Database': {'Password': '', 'password': ''}}, {'Database:Password': ''}, {'value': float('inf')}):
            with self.subTest(value=value), self.assertRaises(self.m.Pending): self.m.structure(value)
        for filename in ('/etc/a%u', '/etc/a$b', '/etc/a b', '/etc/a:other', '/etc/a/../b'):
            with self.subTest(filename=filename), self.assertRaises(self.m.Pending): self.m.literal(filename)

    def test_rotation_and_secret_refusals_use_real_protected_files(self):
        peer = {'database': 'email_db', 'user': 'email_app'}
        self.value['Messaging']['DecryptionKeys'] = [{'Id': 'old', 'Key': '', 'KeyFile': 'messaging.decrypt-0.key'}]
        self.descriptor['credentials']['messaging.decrypt-0.key'] = str(self.m.SETTINGS_ROOT/'old.key')
        self.write(self.m.SETTINGS_ROOT/'old.key', base64.b64encode(b'q'*32)+b'\n')
        self.write(self.settings, self.m.BASE.canonical(self.value)); self.write(self.m.INPUT, self.m.BASE.canonical(self.descriptor))
        inputs, _ = self.m.observe(peer, self.m.KERNEL.now()+30)
        self.assertIn('messaging.decrypt-0.key', [row['id'] for row in inputs['credentials']])
        target = self.m.SETTINGS_ROOT/'old.key'
        target.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.m.observe(peer, self.m.KERNEL.now()+30)
        target.chmod(0o600)
        for raw in (base64.b64encode(b'\0'*32), base64.b64encode(b'q'*31), b'not-base64'):
            self.write(target, raw)
            with self.subTest(raw=raw), self.assertRaises(self.m.Pending): self.m.observe(peer, self.m.KERNEL.now()+30)
        self.write(target, base64.b64encode(b'q'*32))
        value = copy.deepcopy(self.value); value['Messaging']['DecryptionKeys'][0]['Id'] = 'primary'
        with self.assertRaises(self.m.Pending): self.m.configuration(value, peer)
        target.unlink(); target.symlink_to(self.settings)
        with self.assertRaises(self.m.Pending): self.m.observe(peer, self.m.KERNEL.now()+30)

    def test_encoding_precedes_both_fresh_observations_and_same_byte_secret_replacement_refuses(self):
        events = []; prerequisite, observe, encode = self.m.prerequisite, self.m.observe, self.m.BASE.canonical
        def child(*args): events.append('child'); return prerequisite(*args)
        def files(*args): events.append('files'); return observe(*args)
        def canonical(value):
            raw = encode(value)
            if type(value) is dict and value.get('state') == self.m.STATE: events.append('encode')
            return raw
        with patch.object(self.m, 'prerequisite', side_effect=child), patch.object(self.m, 'observe', side_effect=files), patch.object(self.m.BASE, 'canonical', side_effect=canonical):
            self.m.prepare()
        self.assertEqual(events, ['child', 'files', 'encode', 'child', 'files'])
        target = Path(self.descriptor['credentials']['messaging.key'])
        def replace(value):
            raw = encode(value)
            if type(value) is dict and value.get('state') == self.m.STATE:
                temporary = target.with_name('replacement'); self.write(temporary, target.read_bytes()); temporary.replace(target)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=replace), self.assertRaises(self.m.Pending): self.m.prepare()

    def test_original_dependency_cause_caps_and_final_deadline_are_preserved(self):
        error = self.m.JOIN.Pending('original owned refusal')
        with patch.object(self.m.JOIN, 'prepare', side_effect=error), self.assertRaises(self.m.Pending) as caught:
            self.m.prepare()
        self.assertIs(caught.exception.__cause__, error)
        with patch.object(self.m, 'MAX_OUTPUT', 1), patch.object(self.m, 'prerequisite', wraps=self.m.prerequisite) as child:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(child.call_count, 1)
        observe = self.m.observe; calls = 0
        with patch.object(self.m.KERNEL, 'now', return_value=10) as clock:
            def expire(*args):
                nonlocal calls
                result = observe(*args); calls += 1
                if calls == 2: clock.return_value = 20
                return result
            with patch.object(self.m, 'observe', side_effect=expire), self.assertRaises(self.m.Pending): self.m.prepare(deadline=20)
        self.assertEqual(calls, 2)

    def test_binary_unit_output_and_invalid_counts_fail_closed(self):
        raw = self.m.prepare(); sink = io.BytesIO()
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)):
            self.assertEqual(self.m.main(['--unit']), 0)
        self.assertEqual(sink.getvalue(), json.loads(raw)['plan']['unit'].encode('ascii'))
        sink = types.SimpleNamespace(write=lambda raw: True, flush=lambda: self.fail('invalid count must not flush'))
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)), patch.object(self.m.sys, 'stderr', io.StringIO()):
            self.assertEqual(self.m.main([]), 75)


if __name__ == '__main__':
    unittest.main()
