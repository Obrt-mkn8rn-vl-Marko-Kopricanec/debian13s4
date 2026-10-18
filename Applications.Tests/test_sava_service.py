"""Private source plans and file faults; no systemd or application execution."""
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
    spec = importlib.util.spec_from_file_location('private_sava_service_'+path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SavaServiceTests(unittest.TestCase):
    def setUp(self):
        fixture = load(ROOT/'Applications.Tests/test_sava_ingress.py')
        self.inputs = fixture.SavaIngressTests(methodName='runTest')
        self.addCleanup(self.inputs.doCleanups)
        self.inputs.setUp()
        self.root = self.inputs.root
        self.m = load(ROOT/'Applications/sava_service.py')
        self.m.INGRESS = self.inputs.m
        self.m.SAVA = self.inputs.m.SAVA
        self.m.BASE, self.m.KERNEL, self.m.Pending = self.inputs.m.BASE, self.inputs.m.KERNEL, self.inputs.m.Pending

    def test_real_sources_render_distinct_credentials_argv_storage_and_no_secret_or_native_entry(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        observations, original = [], self.m.prerequisite
        def prerequisite(*args):
            result = original(*args); observations.append(result[1]); return result
        with patch('subprocess.Popen', side_effect=AssertionError('no native entry')), \
             patch.object(self.m, 'prerequisite', side_effect=prerequisite):
            raw = self.m.prepare()
        value = json.loads(raw)
        self.assertEqual(value['state'], 'protected-sava-service-intention-only')
        plan = value['plan']; app, gateway = (plan['units'][role] for role in ('application', 'gateway'))
        identity = observations[0]['sava']['identities']
        self.assertEqual(plan['identity_sha256'], hashlib.sha256(self.m.BASE.canonical(identity)).hexdigest())
        self.assertEqual(plan['release_sha256'], hashlib.sha256(self.m.BASE.canonical(identity['releases'])).hexdigest())
        self.assertNotEqual(app['identity']['uid'], gateway['identity']['uid'])
        self.assertEqual([c['id'] for c in app['credentials']], ['appsettings.json', 'rpc.key'])
        self.assertEqual([c['id'] for c in gateway['credentials']],
                         ['appsettings.json', 'rpc.key', 'certificate.pem', 'private-key.pem'])
        for role, row in plan['units'].items():
            self.assertEqual(row['argv'][:2], ['/usr/bin/env', '-i'])
            self.assertIn('--contentRoot', row['argv'])
            self.assertIn('${CREDENTIALS_DIRECTORY}', row['argv'])
            self.assertIn('--ApplicationTransport:AccessKeyFile=${CREDENTIALS_DIRECTORY}/rpc.key', row['argv'])
            self.assertIn('DOTNET_ENVIRONMENT=Production', row['argv'])
            self.assertIn('ASPNETCORE_ENVIRONMENT=Production', row['argv'])
            self.assertEqual(row['unit_sha256'], hashlib.sha256(row['unit'].encode()).hexdigest())
            self.assertEqual(row['credential_bytes'], sum(c['bytes'] for c in row['credentials']))
            self.assertIn('Type=exec\n', row['unit'])
            self.assertIn('Restart=no\n', row['unit'])
            self.assertNotIn('[Install]', row['unit'])
            self.assertNotIn('ExecStartPre=', row['unit'])
            for credential in row['credentials']:
                self.assertIn('LoadCredential='+credential['id']+':'+credential['source']['path']+'\n', row['unit'])
        data = plan['required_storage']
        self.assertEqual((data['mode'], data['owner_uid'], data['observed'], data['created']),
                         ('0700', app['identity']['uid'], False, False))
        self.assertIn('ReadWritePaths='+data['path']+'\n', app['unit'])
        self.assertIn('InaccessiblePaths='+data['path']+'\n', gateway['unit'])
        self.assertNotIn('ReadWritePaths=', gateway['unit'])
        self.assertNotIn('--Kestrel:', ' '.join(app['argv']))
        self.assertIn('--Kestrel:Endpoints:Private:Certificate:KeyPath=${CREDENTIALS_DIRECTORY}/private-key.pem', gateway['argv'])
        for secret in (self.inputs.helper.account_key, self.inputs.helper.data_key):
            self.assertNotIn(secret.encode(), raw)
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_combined_credential_limit_and_literal_operand_refusals(self):
        _, value = self.m.prerequisite(self.m.KERNEL.now()+30, 4711)
        plan = self.m.render(value)
        largest = max(row['credential_bytes'] for row in plan['units'].values())
        with patch.object(self.m, 'MAX_CREDENTIAL_BYTES', largest):
            self.assertEqual(self.m.render(value), plan)
        with patch.object(self.m, 'MAX_CREDENTIAL_BYTES', largest-1), self.assertRaises(self.m.Pending):
            self.m.render(value)
        for filename in ('/etc/a%u', '/etc/a$b', '/etc/a b', '/etc/a\nb', '/etc/a/../b',
                         '/etc/a//b', '/etc/a:other', '/etc/a"b', '/etc/a\\b', '/etc/./a'):
            with self.subTest(filename=filename), self.assertRaises(self.m.Pending):
                self.m.path(filename)

    def test_application_overlay_and_dotnet_key_ambiguities_refuse_real_files(self):
        path = Path(self.inputs.helper.descriptor['application_settings'])
        original = path.read_bytes()
        cases = []
        value = json.loads(original); value['Kestrel'] = {'Endpoints': {}}; cases.append(value)
        value = json.loads(original); value['ApplicationHosting'] = {}; cases.append(value)
        value = json.loads(original); value['Sava']['accounts'] = value['Sava']['Accounts']; cases.append(value)
        value = json.loads(original); value['Sava']['AccountCapabilities']['fixtureacct']['VersioningEnabled:Other'] = False; cases.append(value)
        for value in cases:
            path.write_bytes(self.m.BASE.canonical(value))
            # Matching paired policy is required before the new key-shape check.
            gateway = copy.deepcopy(self.inputs.gateway)
            gateway['Sava'] = value['Sava']
            Path(self.inputs.helper.descriptor['gateway_settings']).write_bytes(self.m.BASE.canonical(gateway))
            with self.subTest(extra=set(value)-{'Sava', 'ApplicationTransport'}), self.assertRaises(self.m.Pending):
                self.m.prepare()
        path.write_bytes(original)

    def test_encoding_precedes_final_preparation_and_real_file_drift_withholds_output(self):
        events = []
        original_prepare, original_files, canonical = self.m.prerequisite, self.m.application_files, self.m.BASE.canonical
        def prepare(*args):
            events.append('prepare'); return original_prepare(*args)
        def files(*args):
            events.append('files'); return original_files(*args)
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == self.m.STATE:
                events.append('encode')
            return raw
        with patch.object(self.m, 'prerequisite', side_effect=prepare), patch.object(self.m, 'application_files', side_effect=files), patch.object(self.m.BASE, 'canonical', side_effect=encode):
            self.m.prepare()
        self.assertEqual(events, ['prepare', 'files', 'encode', 'prepare', 'files'])
        path = Path(self.inputs.helper.descriptor['access_key'])
        def change(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == self.m.STATE:
                replacement = path.with_name('replacement.key')
                replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600)
                replacement.replace(path)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=change), self.assertRaises(self.m.Pending):
            self.m.prepare()

    def test_owned_dependency_cause_output_cap_and_final_window_are_preserved(self):
        original = self.m.INGRESS.Pending('owned refusal')
        with patch.object(self.m.INGRESS, 'prepare', side_effect=original), self.assertRaises(self.m.Pending) as caught:
            self.m.prepare()
        self.assertIs(caught.exception.__cause__, original)
        raw = self.m.prepare()
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)-1), patch.object(self.m, 'prerequisite', wraps=self.m.prerequisite) as child:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(child.call_count, 1)
        clock = self.m.KERNEL.now()
        files = self.m.application_files
        calls = 0
        def expire(*args):
            nonlocal calls
            result = files(*args); calls += 1
            if calls == 2: self.m.KERNEL.now = lambda: clock+10
            return result
        original_now = self.m.KERNEL.now
        self.addCleanup(setattr, self.m.KERNEL, 'now', original_now)
        with patch.object(self.m, 'application_files', side_effect=expire), self.assertRaises(self.m.Pending):
            self.m.prepare(deadline=clock+10)
        self.assertEqual(calls, 2)

    def test_unit_output_uses_binary_stdout_and_short_write_fails(self):
        raw = self.m.prepare(); value = json.loads(raw)
        stream = io.BytesIO()
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=stream)):
            self.assertEqual(self.m.main(['--unit', 'gateway']), 0)
        self.assertEqual(stream.getvalue(), value['plan']['units']['gateway']['unit'].encode('ascii'))
        sink = types.SimpleNamespace(write=lambda raw: True, flush=lambda: self.fail('no flush after invalid count'))
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)), patch.object(self.m.sys, 'stderr', io.StringIO()):
            self.assertEqual(self.m.main([]), 75)


if __name__ == '__main__':
    unittest.main()
