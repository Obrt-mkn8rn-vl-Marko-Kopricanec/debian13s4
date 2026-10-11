"""Private Source correspondence models; no CLR, TLS, nginx or app execution."""
import base64
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


class SavaIngressTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('private_sava_ingress_fixture', ROOT/'Applications.Tests/test_sava_transport.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        self.helper = fixture.SavaTransportTests(methodName='runTest')
        self.addCleanup(self.helper.doCleanups); self.helper.setUp(); self.root = self.helper.root
        spec = importlib.util.spec_from_file_location('private_sava_ingress', ROOT/'Applications/sava_ingress.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.SAVA = self.helper.m
        self.m.BASE, self.m.KERNEL, self.m.Pending = self.helper.m.BASE, self.helper.m.KERNEL, self.helper.m.Pending
        web = self.m.WEB; web.BASE.TRUST_ROOT = self.root; web.BASE.TRUSTED_UID = os.geteuid()
        web.INPUT = self.root/'web.json'; web.KERNEL.namespace = lambda: 4711
        self.web = {'schema': 1, 'applications': {}}
        for i, app in enumerate(web.APPLICATIONS):
            row = {'hostname': f'web{i}.example.invalid', 'upstream_port': 9100+i,
                'upstream_name': f'gateway{i}.example.invalid', 'body_bytes': 1048576, 'idle_seconds': 60,
                'certificate': str(self.root/f'public{i}.pem'), 'private_key': str(self.root/f'public-key{i}.pem'),
                'upstream_ca': str(self.root/f'ca{i}.pem')}
            self.web['applications'][app] = row
            for key in ('certificate', 'private_key', 'upstream_ca'):
                path = Path(row[key]); path.write_bytes(self.pem(key == 'private_key'))
                path.chmod(0o600 if key == 'private_key' else 0o644)
        self.certificate = self.helper.m.SETTINGS_ROOT/'gateway-chain.pem'
        self.private_key = self.helper.m.SETTINGS_ROOT/'gateway-key.pem'
        self.certificate.write_bytes(self.pem()); self.certificate.chmod(0o644)
        self.private_key.write_bytes(self.pem(True)); self.private_key.chmod(0o600)
        self.gateway = copy.deepcopy(self.helper.value)
        self.gateway['Kestrel'] = {'Endpoints': {'Private': {'Url': 'https://127.0.0.1:9100', 'Protocols': 'Http1',
            'Certificate': {'Path': str(self.certificate), 'KeyPath': str(self.private_key), 'Password': ''}}}}
        self.write()

    def pem(self, private=False, body=b'PUBLIC-TEST-invalid-native-certificate-or-key'):
        label = b'PRIVATE KEY' if private else b'CERTIFICATE'; encoded = base64.b64encode(body)
        return b'-----BEGIN '+label+b'-----\n'+b'\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64))+b'\n-----END '+label+b'-----\n'

    def write(self):
        self.helper.write(gateway=self.gateway)
        self.m.WEB.INPUT.write_bytes(self.m.BASE.canonical(self.web)); self.m.WEB.INPUT.chmod(0o600)

    def values(self):
        end = self.m.KERNEL.now()+30
        return self.m.prepared(self.m.SAVA, end, 4711)[1], self.m.prepared(self.m.WEB, end, 4711)[1]

    def test_real_complete_correspondence_binds_selected_listener_and_whole_sources_without_entry_or_secret_bytes(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('no app/native')), patch.object(Path, 'exists', side_effect=AssertionError('no storage existence')):
            raw = self.m.prepare()
        value = json.loads(raw)
        self.assertEqual(value['state'], 'protected-sava-gateway-ingress-source-only')
        self.assertEqual(value['namespace'], 4711)
        for field in ('sava', 'ingress'):
            self.assertEqual(value[field+'_sha256'], hashlib.sha256(self.m.BASE.canonical(value[field])).hexdigest())
        self.assertEqual(value['gateway']['listener']['port'], 9100)
        self.assertEqual(value['gateway']['listener']['server_name_intention'], 'gateway0.example.invalid')
        for secret in (self.helper.account_key, self.helper.data_key, base64.b64encode(self.helper.key).decode(),
                       base64.b64encode(b'PUBLIC-TEST-invalid-native-certificate-or-key').decode()):
            self.assertNotIn(secret.encode(), raw)
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_prior_unexamined_kestrel_positive_is_not_promoted_into_this_new_listener_profile(self):
        self.gateway['Kestrel'] = {'Endpoints': {'Private': {'Url': 'opaque'}}}; self.write()
        self.assertEqual(json.loads(self.m.SAVA.prepare())['state'], 'sava-split-transport-policy-source-only')
        with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_one_explicit_closed_gateway_root_and_endpoint_refuse_defaults_aliases_and_extra_listeners(self):
        cases = []
        for key in ('Kestrel', 'Sava', 'ApplicationTransport'):
            value = copy.deepcopy(self.gateway); del value[key]; cases.append(value)
        for key in ('urls', 'URLS', 'HTTP_PORTS', 'HTTPS_PORTS', 'kestrel'):
            value = copy.deepcopy(self.gateway); value[key] = 'https://*:443'; cases.append(value)
        value = copy.deepcopy(self.gateway); value['Kestrel']['EndpointDefaults'] = {}; cases.append(value)
        value = copy.deepcopy(self.gateway); value['Kestrel']['Endpoints']['Extra'] = value['Kestrel']['Endpoints']['Private']; cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(self.m.Pending):
                self.m.listener(value, self.web['applications']['mk8.sava'], {'port': 12345})

    def test_exact_ipv4_loopback_https_http1_url_refuses_wildcards_aliases_paths_and_other_ports(self):
        for url in ('http://127.0.0.1:9100', 'https://localhost:9100', 'https://[::1]:9100', 'https://0.0.0.0:9100',
                    'https://*:9100', 'https://127.0.0.1:09100', 'https://127.0.0.1:9101', 'https://127.0.0.1:9100/',
                    'https://127.0.0.1:9100?x=1', 'https://user@127.0.0.1:9100', True, None):
            value = copy.deepcopy(self.gateway); value['Kestrel']['Endpoints']['Private']['Url'] = url
            with self.subTest(url=url), self.assertRaises(self.m.Pending):
                self.m.listener(value, self.web['applications']['mk8.sava'], {'port': 12345})
        for protocol in ('Http2', 'Http1AndHttp2', True, None):
            value = copy.deepcopy(self.gateway); value['Kestrel']['Endpoints']['Private']['Protocols'] = protocol
            with self.assertRaises(self.m.Pending): self.m.listener(value, self.web['applications']['mk8.sava'], {'port': 12345})

    def test_true_port_types_reserved_range_and_rpc_collision_refuse(self):
        for port in (True, 9100.0, 0, 1023, 5432, 65536):
            row = dict(self.web['applications']['mk8.sava'], upstream_port=port)
            with self.assertRaises(self.m.Pending): self.m.listener(self.gateway, row, {'port': 12345})
        with self.assertRaises(self.m.Pending): self.m.listener(self.gateway, self.web['applications']['mk8.sava'], {'port': 9100})

    def test_closed_explicit_unencrypted_pem_paths_refuse_store_default_password_and_aliases(self):
        original = self.gateway['Kestrel']['Endpoints']['Private']['Certificate']
        for key, bad in (('Password', 'secret'), ('Password', False), ('Path', '/etc/passwd'), ('Path', str(self.private_key)),
                         ('KeyPath', str(self.root/'outside.pem')), ('KeyPath', str(self.private_key.with_suffix('.pfx'))), ('Store', 'My')):
            value = copy.deepcopy(self.gateway); value['Kestrel']['Endpoints']['Private']['Certificate'][key] = bad
            with self.subTest(key=key), self.assertRaises(self.m.Pending):
                self.m.listener(value, self.web['applications']['mk8.sava'], {'port': 12345})
        for key in original:
            value = copy.deepcopy(self.gateway); del value['Kestrel']['Endpoints']['Private']['Certificate'][key]
            with self.assertRaises(self.m.Pending): self.m.listener(value, self.web['applications']['mk8.sava'], {'port': 12345})

    def test_public_body_bound_cannot_exceed_selected_policy_even_when_each_independent_profile_is_valid(self):
        self.web['applications']['mk8.sava']['body_bytes'] = 1048577; self.write()
        self.m.SAVA.prepare(); self.m.WEB.prepare(scope=lambda: 4711)
        with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_whole_real_nginx_renderer_refuses_repaired_hash_and_real_profile_cause_is_retained(self):
        sava, web = self.values(); web['nginx'] += 'unsafe extra directive\n'
        web['nginx_sha256'] = hashlib.sha256(web['nginx'].encode()).hexdigest()
        with self.assertRaises(self.m.Pending): self.m.observe(sava, web, self.m.KERNEL.now()+10)
        sava, web = self.values(); web['configuration']['value']['schema'] = True
        self.assertIsNot(self.m.WEB.Pending, self.m.Pending)
        real = self.m.WEB.checked; originals = []
        def checked(value):
            try: return real(value)
            except self.m.WEB.Pending as error: originals.append(error); raise
        with patch.object(self.m.WEB, 'checked', side_effect=checked), self.assertRaises(self.m.Pending) as caught:
            self.m.observe(sava, web, self.m.KERNEL.now()+10)
        self.assertEqual(len(originals), 1); self.assertIs(caught.exception.__cause__, originals[0])
        self.assertIs(type(originals[0]), self.m.WEB.Pending)

    def test_tls_framing_is_only_grammar_and_invalid_native_data_can_remain_source_only(self):
        self.assertEqual(json.loads(self.m.prepare())['gateway']['certificate_blocks'], 1)
        for path, raw in ((self.certificate, b'bad'), (self.private_key, self.pem()), (self.private_key, self.pem(True)*2)):
            before = path.read_bytes(); path.write_bytes(raw)
            with self.assertRaises(self.m.Pending): self.m.prepare()
            path.write_bytes(before)

    def test_actual_private_key_mode_link_and_inode_guards_remain_active(self):
        self.private_key.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.m.prepare()
        self.private_key.chmod(0o600); other = self.private_key.with_name('link.pem'); os.link(self.private_key, other)
        with self.assertRaises(self.m.Pending): self.m.prepare()
        other.unlink(); self.assertEqual(json.loads(self.m.prepare())['state'], 'protected-sava-gateway-ingress-source-only')

    def test_dependency_bytes_are_capped_before_json_and_owned_pending_keeps_same_cause(self):
        for module in (self.m.SAVA, self.m.WEB):
            for bad in (bytearray(b'{}\n'), b'x'*(module.MAX_OUTPUT+1)):
                with patch.object(module, 'prepare', return_value=bad), patch.object(self.m.json, 'loads', side_effect=AssertionError('decode')):
                    with self.assertRaises(self.m.Pending): self.m.prepared(module, self.m.KERNEL.now()+10, 4711)
            original = module.Pending('private refusal')
            with patch.object(module, 'prepare', side_effect=original), self.assertRaises(self.m.Pending) as caught:
                self.m.prepared(module, self.m.KERNEL.now()+10, 4711)
            self.assertIs(caught.exception.__cause__, original)

    def test_closed_canonical_dependency_shape_schema_state_and_context_refuse(self):
        for module in (self.m.SAVA, self.m.WEB):
            raw = self.m.prepared(module, self.m.KERNEL.now()+30, 4711)[0]
            for key, bad in (('schema', True), ('schema', 1.0), ('profile', 'foreign'), ('state', 'ready'), ('namespace', True), ('namespace', 4712), ('extra', True)):
                value = json.loads(raw); value[key] = bad
                with self.subTest(key=key), patch.object(module, 'prepare', return_value=self.m.BASE.canonical(value)):
                    with self.assertRaises(self.m.Pending): self.m.prepared(module, self.m.KERNEL.now()+10, 4711)
            for bad in (raw+b'\n', raw.replace(b'"schema":1', b'"schema":1,"schema":1'), raw.replace(b'"schema":1', b'"schema":1e999')):
                with patch.object(module, 'prepare', return_value=bad), self.assertRaises(self.m.Pending):
                    self.m.prepared(module, self.m.KERNEL.now()+10, 4711)

    def test_outer_encoding_precedes_all_second_dependencies_and_own_file_observations(self):
        events = []; prepared = self.m.prepared; observe = self.m.observe; canonical = self.m.BASE.canonical
        def dependency(module, end, context): events.append('sava' if module is self.m.SAVA else 'web'); return prepared(module, end, context)
        def observation(*args): events.append('files'); return observe(*args)
        def encode(value):
            if type(value) is dict and value.get('state') == 'protected-sava-gateway-ingress-source-only': events.append('encode')
            return canonical(value)
        with patch.object(self.m, 'prepared', side_effect=dependency), patch.object(self.m, 'observe', side_effect=observation), patch.object(self.m.BASE, 'canonical', side_effect=encode): self.m.prepare()
        self.assertEqual(events, ['sava', 'web', 'files', 'encode', 'sava', 'web', 'files'])

    def test_exact_outer_cap_and_one_less_refuse_before_any_second_delivery(self):
        raw = self.m.prepare()
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)): self.assertEqual(self.m.prepare(), raw)
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)-1), patch.object(self.m, 'prepared', wraps=self.m.prepared) as children, patch.object(self.m, 'observe', wraps=self.m.observe) as files:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual((children.call_count, files.call_count), (2, 1))

    def test_postencoding_whole_gateway_key_ca_and_descriptor_changes_withhold_receipt(self):
        canonical = self.m.BASE.canonical
        for path in (Path(self.helper.descriptor['gateway_settings']), self.private_key,
                     Path(self.web['applications']['mk8.sava']['upstream_ca']), self.helper.m.INPUT):
            before = path.read_bytes()
            def encode(value):
                raw = canonical(value)
                if type(value) is dict and value.get('state') == 'protected-sava-gateway-ingress-source-only': path.write_bytes(before+b'\n')
                return raw
            with self.subTest(path=path), patch.object(self.m.BASE, 'canonical', side_effect=encode), self.assertRaises(self.m.Pending): self.m.prepare()
            path.write_bytes(before)

    def test_postencoding_same_bytes_new_private_key_inode_withholds_cached_output(self):
        canonical = self.m.BASE.canonical
        def encode(value):
            raw = canonical(value)
            if type(value) is dict and value.get('state') == 'protected-sava-gateway-ingress-source-only':
                replacement = self.private_key.with_name('replace.pem'); replacement.write_bytes(self.private_key.read_bytes()); replacement.chmod(0o600); os.replace(replacement, self.private_key)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=encode), self.assertRaises(self.m.Pending): self.m.prepare()

    def test_private_whole_byte_comparison_catches_change_even_when_metadata_is_held_equal(self):
        observe = self.m.observe; calls = 0
        def observation(*args):
            nonlocal calls
            row, private = observe(*args); calls += 1
            return row, private if calls == 1 else (*private[:-1], private[-1]+b'x')
        with patch.object(self.m, 'observe', side_effect=observation), self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(calls, 2)

    def test_invalid_scope_or_parent_window_refuses_before_all_owned_preparations(self):
        for context in (0, True, 1.0, -1, 2**64):
            with patch.object(self.m.KERNEL, 'namespace', return_value=context), patch.object(self.m, 'prepared') as children:
                with self.assertRaises(self.m.Pending): self.m.prepare()
                children.assert_not_called()
        for deadline in (True, '10', float('inf'), float('nan'), self.m.KERNEL.now()-1):
            with patch.object(self.m, 'prepared') as children:
                with self.assertRaises(self.m.Pending): self.m.prepare(deadline)
                children.assert_not_called()

    def test_positive_parent_narrows_outer_window_without_widening_real_inner_windows(self):
        read = self.m.BASE.read_protected; prepared = self.m.prepared
        for parent in (12, 10000):
            points = []; ends = []
            def reading(path, limit, private, end): points.append((path, end)); return read(path, limit, private, end)
            def dependency(module, end, context): ends.append(end); return prepared(module, end, context)
            with patch.object(self.m.KERNEL, 'now', return_value=10), patch.object(self.m.WEB.KERNEL, 'now', return_value=10), patch.object(self.m, 'prepared', side_effect=dependency), patch.object(self.m.BASE, 'read_protected', side_effect=reading): self.m.prepare(parent)
            self.assertEqual(ends, [min(parent, 610)]*4)
            self.assertEqual([end for path, end in points if path == self.m.SAVA.IDENTITIES.INPUT], [min(parent, 140)]*8)
            self.assertEqual([end for path, end in points if path == self.private_key], [min(parent, 610)]*2)

    def test_final_namespace_or_expiry_after_second_real_observation_withholds_receipt(self):
        for tag in ('context', 'time'):
            observe = self.m.observe; calls = 0
            def observation(*args):
                nonlocal calls
                result = observe(*args); calls += 1
                if calls == 2:
                    if tag == 'context': self.m.KERNEL.namespace = lambda: 4712
                    else: clock.return_value = args[-1]
                return result
            with patch.object(self.m.KERNEL, 'now', return_value=10) as clock, patch.object(self.m.WEB.KERNEL, 'now', return_value=10), patch.object(self.m, 'observe', side_effect=observation), self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(calls, 2); self.m.KERNEL.namespace = lambda: 4711

    def test_cli_no_overrides_true_full_count_and_flush_keep_failure_stdout_qualification(self):
        class Sink:
            def __init__(self, count=None, fail=False): self.buffer=self; self.count=count; self.fail=fail; self.raw=b''
            def write(self, raw): self.raw=raw; return len(raw) if self.count is None else self.count
            def flush(self):
                if self.fail: raise OSError('private flush')
        for count, fail, code in ((None, False, 0), (True, False, 75), (1, False, 75), (None, True, 75)):
            sink = Sink(count, fail)
            with patch.object(sys, 'argv', ['sava_ingress.py']), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare', return_value=b'{}\n'):
                self.assertEqual(self.m.main(), code)
            self.assertEqual(sink.raw, b'{}\n')
        with patch.object(sys, 'argv', ['sava_ingress.py', 'extra']), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare') as prepared:
            self.assertEqual(self.m.main(), 75); prepared.assert_not_called()

    def test_actual_private_interpreter_cli_has_encoding_independent_bytes_and_no_refused_stdout(self):
        program = '''import importlib.util,os,sys
from pathlib import Path
root=Path(sys.argv[1]);project=Path(sys.argv[2])
s=importlib.util.spec_from_file_location('private_sava_ingress_cli',project/'Applications/sava_ingress.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
i=m.SAVA.IDENTITIES;i.BASE.TRUST_ROOT=root;i.BASE.TRUSTED_UID=os.geteuid()
i.INPUT=root/'application-identities.json';i.PASSWD=root/'passwd';i.GROUP=root/'group'
i.RELEASE.INPUT=root/'application-releases.json';i.RELEASE.RELEASE_ROOT=root/'opt/debian13s4-apps'
i.KERNEL.namespace=lambda:4711;m.SAVA.INPUT=root/'sava-transport.json';m.SAVA.SETTINGS_ROOT=root/'etc/sava'
m.WEB.BASE.TRUST_ROOT=root;m.WEB.BASE.TRUSTED_UID=os.geteuid();m.WEB.INPUT=root/'web.json'
m.WEB.KERNEL.namespace=lambda:4711;sys.argv=['sava_ingress.py'];sys.exit(m.main())
'''
        expected = self.m.prepare()
        for encoding in ('ascii:strict', 'utf-32:ignore'):
            env = dict(os.environ, PYTHONIOENCODING=encoding); env.pop('PYTHONPATH', None)
            child = subprocess.run([sys.executable, '-B', '-c', program, str(self.root), str(ROOT)],
                env=env, capture_output=True, timeout=30)
            self.assertEqual((child.returncode, child.stdout, child.stderr), (0, expected, b''))
        self.private_key.chmod(0o644)
        child = subprocess.run([sys.executable, '-B', '-c', program, str(self.root), str(ROOT)],
            env=env, capture_output=True, timeout=30)
        self.assertEqual((child.returncode, child.stdout), (75, b''))

    def test_actual_main_function_pipe_with_cached_fixture_delivery_keeps_binary_bytes_and_refused_stdout_empty(self):
        # Execute the exact main AST with controlled prepare delivery, rather
        # than importing or rerunning the full failed preparation CLI.
        program = '''import ast,sys
from pathlib import Path
source=Path(sys.argv[1]);refuse=sys.argv[2]=='refuse'
tree=ast.parse(source.read_bytes());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
payload=sys.stdin.buffer.read()
def prepared():
 if refuse:raise OSError('controlled private delivery refusal')
 return payload
scope={'sys':sys,'Pending':ValueError,'prepare':prepared}
exec(compile(ast.Module(body=[main],type_ignores=[]),str(source),'exec'),scope)
sys.argv=['sava_ingress.py'];sys.exit(scope['main']())
'''
        payload = b'PUBLIC-TEST cached binary payload\x00\xff\r\n'
        for encoding in ('ascii:strict', 'utf-32:ignore'):
            env = dict(os.environ, PYTHONIOENCODING=encoding); env.pop('PYTHONPATH', None)
            child = subprocess.run([sys.executable, '-B', '-c', program, str(ROOT/'Applications/sava_ingress.py'), 'deliver'],
                input=payload, env=env, capture_output=True, timeout=30)
            self.assertEqual((child.returncode, child.stdout, child.stderr), (0, payload, b''))
        child = subprocess.run([sys.executable, '-B', '-c', program, str(ROOT/'Applications/sava_ingress.py'), 'refuse'],
            input=payload, env=env, capture_output=True, timeout=30)
        self.assertEqual((child.returncode, child.stdout), (75, b''))


if __name__ == '__main__':
    unittest.main()
