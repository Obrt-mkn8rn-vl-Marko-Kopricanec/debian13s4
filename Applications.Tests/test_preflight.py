"""Focused private checks for the installed preflight command and its joins."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('private_preflight_'+path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.m = load(ROOT/'Applications/preflight.py')

    def fixture(self):
        fixture = load(ROOT/'Applications.Tests/test_prerequisites.py')
        self.inputs = fixture.PrerequisiteTests(methodName='runTest')
        self.addCleanup(self.inputs.doCleanups)
        self.inputs.setUp()
        root = self.inputs.root
        sava = self.inputs.helper
        # The old fixture health9101 conflicts with the Web fixture's Drava9101.
        self.inputs.dns_value['listeners'][0]['health_port'] = 9200
        self.inputs.m.DNS.DNS.INPUT.write_bytes(self.m.canonical(self.inputs.dns_value))
        web = {'schema': 1, 'applications': {}}
        for i, app in enumerate(('mk8.sava', 'mk8.drava', 'mk8.email')):
            row = {'hostname': f'web{i}.example.invalid', 'upstream_port': 9100+i,
                   'upstream_name': f'gateway{i}.example.invalid', 'body_bytes': 1048576,
                   'idle_seconds': 60, 'certificate': str(root/f'public{i}.pem'),
                   'private_key': str(root/f'key{i}.pem'), 'upstream_ca': str(root/f'ca{i}.pem')}
            web['applications'][app] = row
            for field in ('certificate', 'private_key', 'upstream_ca'):
                path = Path(row[field]); path.write_bytes(self.pem(field == 'private_key'))
                path.chmod(0o600 if field == 'private_key' else 0o644)
        (root/'web.json').write_bytes(self.m.canonical(web)); (root/'web.json').chmod(0o600)
        certificate, key = sava.m.SETTINGS_ROOT/'gateway-chain.pem', sava.m.SETTINGS_ROOT/'gateway-key.pem'
        certificate.write_bytes(self.pem()); certificate.chmod(0o644)
        key.write_bytes(self.pem(True)); key.chmod(0o600)
        gateway = copy.deepcopy(sava.value)
        gateway['Kestrel'] = {'Endpoints': {'Private': {'Url': 'https://127.0.0.1:9100', 'Protocols': 'Http1',
            'Certificate': {'Path': str(certificate), 'KeyPath': str(key), 'Password': ''}}}}
        sava.write(gateway=gateway)
        return root

    @staticmethod
    def pem(private=False):
        label = b'PRIVATE KEY' if private else b'CERTIFICATE'
        return b'-----BEGIN '+label+b'-----\n'+base64.b64encode(b'PUBLIC-TEST-INVALID-PKI')+b'\n-----END '+label+b'-----\n'

    def private_module(self, module, root, library):
        """Remap only the owned module graph; keep each real validator/class."""
        seen = set()
        def configure(current):
            if id(current) in seen: return
            seen.add(id(current))
            for value in tuple(vars(current).values()):
                if isinstance(value, types.ModuleType) and getattr(value, '__file__', None):
                    if Path(value.__file__).is_relative_to(library): configure(value)
            if hasattr(current, 'TRUSTED_UID'):
                current.TRUSTED_UID = os.geteuid(); current.TRUST_ROOT = root
            if hasattr(current, 'namespace'): current.namespace = lambda: 4711
            for name in ('INPUT', 'PASSWD', 'GROUP'):
                if isinstance(getattr(current, name, None), Path):
                    setattr(current, name, root/getattr(current, name).name)
            if hasattr(current, 'RELEASE_ROOT'): current.RELEASE_ROOT = root/'opt/debian13s4-apps'
            if hasattr(current, 'SETTINGS_ROOT'): current.SETTINGS_ROOT = root/'etc/sava'
            if hasattr(current, 'binary_path'):
                original = current.binary_path
                def binary(value):
                    if type(value) is str and value.startswith(str(root)+'/'):
                        return str(root)+original(value[len(str(root)):])
                    return original(value)
                current.binary_path = binary
        configure(module)
        return module

    def test_installed_lowercase_bundle_runs_all_real_checks_without_native_entry(self):
        root = self.fixture()
        temp = tempfile.TemporaryDirectory(prefix='debian13s4-preflight-bundle.')
        self.addCleanup(temp.cleanup)
        target = Path(temp.name)
        pack = load(ROOT/'Bootstrap/pack.py')
        for name, (raw, mode) in pack.assets().items():
            if not name.endswith('.py'): continue
            path = target/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(int(mode, 8))
        installed = load(target/'lib/applications/preflight.py')
        original = installed.owned
        def owned(check): return self.private_module(original(check), root, target/'lib')
        before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
        with patch.object(installed, 'owned', side_effect=owned), patch('subprocess.Popen', side_effect=AssertionError('no native entry')):
            raw = installed.prepare()
        report = json.loads(raw)
        self.assertEqual(set(report['checks']), {'prerequisites', 'ingress'})
        self.assertEqual(report['state'], 'application-preflight-source-only')
        self.assertEqual(len(report['listener_intentions']), 5)
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertNotIn(self.inputs.helper.account_key.encode(), raw)
        self.assertNotIn(self.inputs.helper.data_key.encode(), raw)

    def test_selected_release_check_uses_real_reader_and_retains_refusal_cause(self):
        root = self.fixture()
        module = self.private_module(self.m.owned('releases'), root, ROOT)
        with patch.object(self.m, 'owned', return_value=module):
            self.assertEqual(set(json.loads(self.m.prepare('releases'))['checks']), {'releases'})
            module.INPUT.chmod(0o644)
            with self.assertRaises(self.m.Pending) as caught: self.m.prepare('releases')
        self.assertIs(type(caught.exception.__cause__), module.Pending)
        self.assertIn('releases:', str(caught.exception))

    def plans(self):
        sava = {'settings': {'rpc': {'address': '127.0.0.1', 'port': 12345}}, 'same': 1}
        prerequisites = {'components': {'sava': sava, 'dns': {'dns_service': {'plan': {'listeners': [
            {'unit': 'dns4', 'health_address': '127.0.0.1', 'health_port': 9200}]}}}}}
        ingress = {'sava': copy.deepcopy(sava), 'ingress': {'configuration': {'value': {'applications': {
            'mk8.sava': {'upstream_port': 9100}, 'mk8.drava': {'upstream_port': 9101},
            'mk8.email': {'upstream_port': 9102}}}}}}
        return prerequisites, ingress

    def test_cross_profile_collisions_and_type_preserving_sava_equality(self):
        for port in (9100, 9101, 9102, 12345):
            a, b = self.plans(); a['components']['dns']['dns_service']['plan']['listeners'][0]['health_port'] = port
            with self.subTest(port=port), self.assertRaisesRegex(self.m.Pending, 'listener conflict'):
                self.m.listener_plan(a, b)
        a, b = self.plans(); b['sava']['same'] = True
        with self.assertRaisesRegex(self.m.Pending, 'observations differ'): self.m.listener_plan(a, b)
        a, b = self.plans()
        for sava in (a['components']['sava'], b['sava']): sava['settings']['rpc'] = {'address': '::1', 'port': 9100}
        self.assertEqual(len(self.m.listener_plan(a, b)), 5)

    def test_decode_bounds_aliases_and_canonical_types_fail_closed(self):
        raw = self.m.canonical({'schema': 1, 'profile': self.m.CHECKS['releases'][1],
            'state': self.m.CHECKS['releases'][2], 'namespace': 4711})
        module = types.SimpleNamespace(MAX_OUTPUT=1024, Pending=ValueError, prepare=lambda **kw: raw)
        for bad in (bytearray(raw), b' '*1025, raw.replace(b'"schema":1', b'"schema":true'),
                    raw.replace(b'"schema":1', b'"schema":1,"schema":1'),
                    raw.replace(b'4711', b'1e999'), raw+b' '):
            module.prepare = lambda _raw=bad, **kw: _raw
            with self.subTest(raw=bad), self.assertRaises(self.m.Pending):
                self.m.observe('releases', module, self.m.now()+10, 4711)

    def test_final_context_and_deadline_fences_prevent_success(self):
        raw = self.m.canonical({'schema': 1, 'profile': self.m.CHECKS['releases'][1],
            'state': self.m.CHECKS['releases'][2], 'namespace': 4711})
        context = iter((4711, 4712))
        kernel = types.SimpleNamespace(namespace=lambda: next(context), uint=lambda value, maximum: value)
        module = types.SimpleNamespace(KERNEL=kernel, MAX_OUTPUT=1024, Pending=ValueError, prepare=lambda **kw: raw)
        with patch.object(self.m, 'owned', return_value=module), self.assertRaisesRegex(self.m.Pending, 'namespace changed'):
            self.m.prepare('releases')
        for end in (True, float('nan'), float('inf'), self.m.now()-1):
            with patch.object(self.m, 'owned', side_effect=AssertionError('before import')), self.assertRaises(self.m.Pending):
                self.m.prepare('all', end)

    def test_cli_binary_json_and_write_failures_do_not_report_success(self):
        raw = self.m.canonical({'state': 'application-preflight-source-only'})
        for encoding in ('ascii:strict', 'utf-32:ignore'):
            program = "import importlib.util,sys;s=importlib.util.spec_from_file_location('p',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.prepare=lambda check:b'{\"state\":\"application-preflight-source-only\"}\\n';sys.exit(m.main(['--format','json']))"
            env = dict(os.environ, PYTHONIOENCODING=encoding)
            child = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(ROOT/'Applications/preflight.py')], env=env, capture_output=True, timeout=10)
            self.assertEqual((child.returncode, child.stdout, child.stderr), (0, raw, b''))
        for result in (True, len(raw)-1, None):
            sink = types.SimpleNamespace(write=lambda data: result, flush=lambda: self.fail('no flush after short write'))
            with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)), patch.object(self.m.sys, 'stderr', io.StringIO()):
                self.assertEqual(self.m.main(['--format', 'json']), 75)
        with patch.object(self.m, 'owned', side_effect=AssertionError('help must not import prerequisites')), patch.object(self.m.sys, 'stdout', io.StringIO()):
            with self.assertRaises(SystemExit) as caught: self.m.main(['--help'])
            self.assertEqual(caught.exception.code, 0)


if __name__ == '__main__':
    unittest.main()
