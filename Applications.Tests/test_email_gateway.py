"""Private FILE correspondence; no Email, TLS, SQL or manager execution."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('private_email_gateway_'+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class EmailGatewayTests(unittest.TestCase):
    def setUp(self):
        fixture = load(ROOT/'Applications.Tests/test_email_worker.py')
        self.worker = fixture.EmailWorkerTests(methodName='runTest')
        self.addCleanup(self.worker.doCleanups); self.worker.setUp()
        self.root = self.worker.root
        self.m = load(ROOT/'Applications/email_gateway.py')
        self.m.EMAIL = self.worker.m
        self.m.BASE, self.m.KERNEL, self.m.Pending = self.worker.m.BASE, self.worker.m.KERNEL, self.worker.m.Pending
        self.m.INPUT = self.root/'email-gateway.json'
        self.m.WEB.BASE.TRUST_ROOT = self.root; self.m.WEB.BASE.TRUSTED_UID = os.geteuid()
        self.m.WEB.INPUT = self.root/'web.json'; self.m.WEB.KERNEL.namespace = lambda: 4711
        self.web = {'schema': 1, 'applications': {}}
        for index, app in enumerate(self.m.WEB.APPLICATIONS):
            row = {'hostname': f'web{index}.example.invalid', 'upstream_port': 9100+index,
                'upstream_name': f'gateway{index}.example.invalid', 'body_bytes': 1048576, 'idle_seconds': 60,
                'certificate': str(self.root/f'public{index}.pem'), 'private_key': str(self.root/f'public-key{index}.pem'),
                'upstream_ca': str(self.root/f'ca{index}.pem')}
            self.web['applications'][app] = row
            for name in ('certificate', 'private_key', 'upstream_ca'):
                self.worker.write(Path(row[name]), self.pem(name == 'private_key'))
        product = self.worker.m.SETTINGS_ROOT
        self.descriptor = {'schema': 1, 'settings': str(product/'gateway.json'),
            'https_settings': str(product/'gateway-https.json'), 'state_directory': '/srv/debian13s4-email/fixture-gateway',
            'credentials': {name: str(product/('gateway-'+name)) for name in
                ('database.password', 'messaging.key', 'objects.connection', 'certificate.pem', 'private-key.pem')}}
        self.value = copy.deepcopy(self.worker.value)
        self.value['Database']['Username'] = self.worker.helper.helper.value['applications']['mk8.email']['gateway_user']
        self.value['Messaging']['WorkerId'] = 'explicit-fixture-gateway'
        self.value['Smtp'].update(ListenAddress='127.0.0.1', EnableSmtp=False, EnableSubmission=False,
            EnableImplicitTls=False, EnableStartTls=False, RequireTls=False, AllowRelay=False, RequireAuth=True)
        self.value['Imap'] = {'EnableImap': False, 'EnableImplicitTls': False}
        self.value['Pop3'] = {'EnablePop3': False, 'EnableImplicitTls': False, 'EnableStartTls': False}
        self.value['Sieve'] = {'EnableManageSieve': False, 'EnableStartTls': False}
        self.value['Dav'] = {'EnableDav': False}; self.value['Tls'] = {}
        self.value['Jmap'] = {'EnableJmap': True, 'Port': 9102, 'PublicBaseUrl': 'https://web2.example.invalid',
            'MaxUploadSizeBytes': 1048576, 'MaxRequestSizeBytes': 65536}
        state = self.descriptor['state_directory']
        self.value['Admin'] = {'AllowedNetworks': ['127.0.0.1/32', '::1/128'], 'SessionMinutes': 20,
            'DataProtectionKeyPath': state+'/data-protection', 'AuditLogPath': state+'/audit.jsonl',
            'HealthStatusPath': state+'/health.json'}
        self.https = {'Kestrel': {'Endpoints': {'Private': {'Url': 'https://127.0.0.1:9102', 'Protocols': 'Http1',
            'Certificate': {'Path': 'certificate.pem', 'KeyPath': 'private-key.pem', 'Password': ''}}}}}
        self.secrets = dict(self.worker.secrets, **{'database.password': b'PUBLIC-Gateway-password\n',
            'certificate.pem': self.pem(), 'private-key.pem': self.pem(True)})
        for name, raw in self.secrets.items(): self.worker.write(Path(self.descriptor['credentials'][name]), raw)
        self.write()

    @staticmethod
    def pem(private=False):
        label = b'PRIVATE KEY' if private else b'CERTIFICATE'
        return b'-----BEGIN '+label+b'-----\n'+base64.b64encode(b'PUBLIC-invalid-native-PKI')+b'\n-----END '+label+b'-----\n'

    def write(self):
        for path, value in ((self.m.INPUT, self.descriptor), (Path(self.descriptor['settings']), self.value),
                            (Path(self.descriptor['https_settings']), self.https), (self.m.WEB.INPUT, self.web)):
            self.worker.write(path, self.m.BASE.canonical(value))

    def values(self):
        end = self.m.KERNEL.now()+30
        return self.m.EMAIL.prerequisite(end, 4711)[1], self.m.web_prepared(end, 4711)[1]

    def test_real_paired_files_preserve_distinct_gateway_role_and_report_missing_authorization(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('no native entry')):
            raw = self.m.prepare()
        value = json.loads(raw); gateway = value['gateway']
        self.assertEqual(value['state'], self.m.STATE)
        self.assertEqual(gateway['gateway_identity']['name'], self.value['Database']['Username'])
        self.assertNotEqual(gateway['gateway_identity']['name'], self.worker.value['Database']['Username'])
        self.assertFalse(gateway['database']['authorized_by_current_local_peer_plan'])
        self.assertFalse(gateway['unit_available']); self.assertFalse(gateway['required_state']['observed'])
        self.assertEqual(gateway['listener']['port'], 9102)
        self.assertEqual({r['id'] for r in gateway['credentials']}, {'environment.json', 'appsettings.json', *self.secrets})
        for secret in self.secrets.values(): self.assertNotIn(secret.rstrip(), raw)
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_typed_binding_listener_and_worker_secret_separation_refuse(self):
        role = {'name': self.value['Database']['Username']}; ingress = self.web['applications']['mk8.email']
        mutations = [lambda v: v['Database'].__setitem__('Username', self.worker.value['Database']['Username']),
            lambda v: v['Database'].__setitem__('Port', True),
            lambda v: v['Messaging'].__setitem__('WorkerId', self.worker.value['Messaging']['WorkerId']),
            lambda v: v['Messaging'].__setitem__('MaxPayloadBytes', 8388608),
            lambda v: v['OAuth'].__setitem__('SigningKeyFile', 'worker-only.pem'),
            lambda v: v['Mfa'].__setitem__('EncryptionKey', 'inline'),
            lambda v: v['Dkim'].__setitem__('PrivateKeyPath', 'worker-only.pem'),
            lambda v: v['Smtp'].__setitem__('EnableSmtp', True),
            lambda v: v['Pop3'].__setitem__('EnablePop3', 0),
            lambda v: v['Jmap'].__setitem__('Port', True),
            lambda v: v['Jmap'].__setitem__('PublicBaseUrl', 'https://other.example.invalid'),
            lambda v: v['Admin'].__setitem__('AllowedNetworks', ['192.0.2.1/24']),
            lambda v: v['Admin'].__setitem__('AuditLogPath', '/tmp/foreign'),
            lambda v: v['Tls'].__setitem__('CertificatePassword', 'inline')]
        for mutate in mutations:
            value = copy.deepcopy(self.value); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(self.m.Pending):
                self.m.configuration(value, self.worker.value, role, ingress, self.descriptor['state_directory'])
        for url in ('http://127.0.0.1:9102', 'https://localhost:9102', 'https://*:9102', 'https://127.0.0.1:9101'):
            value = copy.deepcopy(self.https); value['Kestrel']['Endpoints']['Private']['Url'] = url
            with self.subTest(url=url), self.assertRaises(self.m.Pending): self.m.https(value, ingress)

    def test_real_secret_mode_content_and_private_alias_faults_refuse(self):
        joined, web = self.values(); end = self.m.KERNEL.now()+30
        path = Path(self.descriptor['credentials']['messaging.key']); original = path.read_bytes()
        path.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.m.observe(joined, web, end)
        path.chmod(0o600); path.write_bytes(base64.b64encode(b'q'*32)+b'\n')
        with self.assertRaisesRegex(self.m.Pending, 'shared transport material'): self.m.observe(joined, web, end)
        path.write_bytes(original)
        self.descriptor['credentials']['database.password'] = self.worker.descriptor['credentials']['database.password']; self.write()
        with self.assertRaisesRegex(self.m.Pending, 'Worker-private'): self.m.observe(joined, web, end)

    def test_encoding_precedes_fresh_sources_and_same_byte_replacement_withholds_success(self):
        events = []; original, canonical = self.m.observe, self.m.BASE.canonical
        def observe(*args): events.append('observe'); return original(*args)
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == self.m.STATE: events.append('encode')
            return raw
        with patch.object(self.m, 'observe', side_effect=observe), patch.object(self.m.BASE, 'canonical', side_effect=encode):
            self.m.prepare()
        self.assertEqual(events, ['observe', 'encode', 'observe'])
        target = Path(self.descriptor['credentials']['private-key.pem'])
        def replace(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == self.m.STATE:
                other = target.with_name('new-private-key.pem'); self.worker.write(other, target.read_bytes()); other.replace(target)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=replace), self.assertRaises(self.m.Pending): self.m.prepare()

    def test_owned_real_renderer_refusal_retains_distinct_original_cause_and_final_deadline(self):
        web = json.loads(self.m.WEB.prepare(scope=self.m.WEB.KERNEL.namespace))
        web['configuration']['value']['schema'] = True
        real, refusals = self.m.WEB.checked, []
        def checked(value):
            try: return real(value)
            except self.m.WEB.Pending as error: refusals.append(error); raise
        self.assertIsNot(self.m.Pending, self.m.WEB.Pending)
        with patch.object(self.m.WEB, 'prepare', return_value=self.m.BASE.canonical(web)), \
             patch.object(self.m.WEB, 'checked', side_effect=checked), self.assertRaises(self.m.Pending) as caught:
            self.m.web_prepared(self.m.KERNEL.now()+30, 4711)
        self.assertEqual(len(refusals), 1); self.assertIs(caught.exception.__cause__, refusals[0])
        self.assertIs(type(refusals[0]), self.m.WEB.Pending)
        start = self.m.KERNEL.now(); real_observe = self.m.observe; calls = []
        def expire(*args):
            result = real_observe(*args); calls.append(1)
            if len(calls) == 2: self.m.KERNEL.now = lambda: start+30
            return result
        original_now = self.m.KERNEL.now; self.addCleanup(setattr, self.m.KERNEL, 'now', original_now)
        with patch.object(self.m, 'observe', side_effect=expire), self.assertRaises(self.m.Pending):
            self.m.prepare(deadline=start+30)
        self.assertEqual(len(calls), 2)

    def test_binary_output_and_short_writes_remain_separate_from_preparation(self):
        raw = self.m.prepare(); stream = io.BytesIO()
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=stream)):
            self.assertEqual(self.m.main([]), 0)
        self.assertEqual(stream.getvalue(), raw)
        sink = types.SimpleNamespace(write=lambda value: True, flush=lambda: self.fail('no flush after bad count'))
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)), \
             patch.object(self.m.sys, 'stderr', io.StringIO()):
            self.assertEqual(self.m.main([]), 75)


if __name__ == '__main__':
    unittest.main()
