"""Private protected-byte/namespace/CLI models; no nginx, TLS or app execution.

PEM samples are arbitrary base64 DATA, deliberately not valid certificates.
Names/ports here are finite test DATA, never production deployment defaults.
"""
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
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class IngressPreparationTests(unittest.TestCase):
    def setUp(self):
        private = tempfile.TemporaryDirectory(dir='/dev/shm'); self.addCleanup(private.cleanup)
        self.root = Path(private.name); self.root.chmod(0o700)
        spec = importlib.util.spec_from_file_location('private_web_prepare', ROOT / 'Web/prepare.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.BASE.TRUST_ROOT = self.root; self.m.BASE.TRUSTED_UID = os.getuid()
        self.m.INPUT = self.root / 'web.json'
        self.value = {'schema': 1, 'applications': {}}
        for i, app in enumerate(self.m.APPLICATIONS):
            item = {'hostname': f'web{i}.example.invalid', 'upstream_port': 9100+i,
                'upstream_name': f'gateway{i}.example.invalid', 'body_bytes': 1048576,
                'idle_seconds': 60, 'certificate': str(self.root / f'chain{i}.pem'),
                'private_key': str(self.root / f'key{i}.pem'), 'upstream_ca': str(self.root / f'ca{i}.pem')}
            self.value['applications'][app] = item
            for field in ('certificate', 'private_key', 'upstream_ca'):
                raw = self.sample(field == 'private_key')
                path = Path(item[field]); path.write_bytes(raw); path.chmod(0o600 if field == 'private_key' else 0o644)
        self.write()

    def sample(self, private=False, body=b'not-a-native-certificate-or-private-key'):
        label = b'PRIVATE KEY' if private else b'CERTIFICATE'
        encoded = base64.b64encode(body)
        lines = b'\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64))
        return b'-----BEGIN '+label+b'-----\n'+lines+b'\n-----END '+label+b'-----\n'

    def write(self, value=None, raw=None):
        self.m.INPUT.write_bytes(self.m.BASE.canonical(self.value if value is None else value) if raw is None else raw)
        self.m.INPUT.chmod(0o600)

    def prepare(self, **kw):
        return self.m.prepare(scope=lambda: 123456, **kw)

    def test_complete_intention_binds_all_materials_without_disclosing_private_bytes(self):
        raw = self.prepare(); record = json.loads(raw)
        self.assertEqual(raw, self.m.BASE.canonical(record))
        self.assertEqual(record['state'], 'ingress-configuration-intention-only')
        self.assertEqual(record['namespace'], 123456)
        self.assertEqual(record['configuration']['value'], self.value)
        self.assertEqual(len(record['materials']), 9)
        self.assertEqual(record['nginx_sha256'], hashlib.sha256(record['nginx'].encode('ascii')).hexdigest())
        self.assertNotIn(base64.b64encode(b'not-a-native-certificate-or-private-key'), raw)
        for path, row in record['materials'].items():
            self.assertEqual(row['source']['sha256'], hashlib.sha256(Path(path).read_bytes()).hexdigest())

    def test_missing_input_refuses_before_materials_or_render(self):
        self.m.INPUT.unlink()
        with patch.object(self.m, 'render') as renderer, patch.object(self.m, 'materials') as materials:
            with self.assertRaises(OSError): self.prepare()
            renderer.assert_not_called(); materials.assert_not_called()

    def test_closed_canonical_json_schema_and_exact_three_provider_map(self):
        raw = self.m.BASE.canonical(self.value)
        for bad in (raw+b'\n', raw[:-1], raw.replace(b'"schema":1', b'"schema":true'),
                    raw.replace(b'"schema":1', b'"schema":1.0'),
                    raw.replace(b'"schema":1', b'"schema":NaN'),
                    raw.replace(b'"schema":1', b'"schema":1e999'),
                    raw.replace(b'"schema":1', b'"schema":1,"schema":1'), b'\xff\n'):
            with self.subTest(raw=bad):
                self.write(raw=bad)
                with self.assertRaises(self.m.Pending): self.prepare()
        for app in ('mk8.dns', 'extra'):
            value = copy.deepcopy(self.value); value['applications'][app] = value['applications']['mk8.sava']
            self.write(value)
            with self.assertRaises(self.m.Pending): self.prepare()
        value = copy.deepcopy(self.value); del value['applications']['mk8.email']; self.write(value)
        with self.assertRaises(self.m.Pending): self.prepare()

    def test_input_bound_precedes_decode_and_deep_input_refuses(self):
        self.write(raw=b' ' * 8193)
        with patch.object(self.m.json, 'loads', side_effect=AssertionError('no decode')):
            with self.assertRaises(self.m.Pending): self.prepare()
        self.write(raw=b'['*1500+b'0'+b']'*1500)
        with self.assertRaises(self.m.Pending): self.prepare()

    def test_names_are_literal_canonical_dns_and_cannot_inject_nginx(self):
        for bad in ('', 'localhost', '127.0.0.1', 'Name.example.invalid', 'a..invalid',
                    '.example.invalid', 'example.invalid.', '*.'+'example.invalid',
                    'a;include /secret', '$host', 'x\nreturn 200;', 'x".invalid',
                    'x\\.invalid', 'é.invalid', 'a_'+'x.invalid', '-a.invalid',
                    'a-.invalid', 'a.'+'9'*5, 'a'*64+'.invalid', True, None):
            for field in ('hostname', 'upstream_name'):
                with self.subTest(bad=bad, field=field):
                    value = copy.deepcopy(self.value); value['applications']['mk8.sava'][field] = bad
                    with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_paths_refuse_metacharacters_aliases_relative_and_empty_segments(self):
        for bad in ('relative.pem', '/a/../b', '/a/./b', '/a//b', '/a/', '//a',
                    '/a b', '/a;return', '/a$host', '/a"', '/a\n', '/a\\b', '/',
                    '/'+ 'a'*241, True, None):
            with self.subTest(path=bad), self.assertRaises(self.m.Pending): self.m.material_path(bad)

    def test_true_integer_capacities_are_explicit_and_bounded(self):
        for field, bad in (('upstream_port', 1023), ('upstream_port', 65536),
            ('upstream_port', 5432), ('body_bytes', 1023), ('body_bytes', 1073741825),
            ('idle_seconds', 9), ('idle_seconds', 601), ('idle_seconds', True),
            ('body_bytes', 1024.0), ('upstream_port', '9100')):
            value = copy.deepcopy(self.value); value['applications']['mk8.sava'][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(self.m.Pending): self.m.checked(value)
        for field in ('upstream_port', 'hostname'):
            value = copy.deepcopy(self.value)
            value['applications']['mk8.email'][field] = value['applications']['mk8.sava'][field]
            with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_private_keys_cannot_be_relabelled_as_public_ca_or_chain(self):
        for field in ('certificate', 'upstream_ca'):
            value = copy.deepcopy(self.value)
            value['applications']['mk8.email'][field] = value['applications']['mk8.sava']['private_key']
            with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_private_checked_settings_cannot_be_rewritten_by_caller(self):
        admitted = self.m.checked(self.value)
        self.value['applications']['mk8.sava']['hostname'] = 'later.example.invalid'
        self.assertNotEqual(admitted, self.value)
        self.assertIn('server_name web0.example.invalid;', self.m.render(admitted))

    def test_https_upstreams_validate_names_and_ca_without_dns_or_cleartext_fallback(self):
        text = json.loads(self.prepare())['nginx']
        for i in range(3):
            self.assertIn(f'proxy_pass https://127.0.0.1:{9100+i};', text)
            self.assertIn(f'proxy_ssl_name gateway{i}.example.invalid;', text)
        self.assertIn('proxy_ssl_verify on;', text)
        self.assertIn('proxy_ssl_server_name on;', text)
        self.assertIn('proxy_ssl_protocols TLSv1.2 TLSv1.3;', text)
        self.assertNotIn('proxy_pass http:', text); self.assertNotIn('resolver ', text)
        self.assertNotIn('proxy_ssl_verify off;', text)

    def test_streams_websockets_original_uri_and_mutations_have_no_automatic_retry(self):
        text = self.m.render(self.value)
        self.assertIn('proxy_http_version 1.1;', text)
        self.assertIn('proxy_set_header Upgrade $http_upgrade;', text)
        self.assertIn('proxy_request_buffering off;', text)
        self.assertIn('proxy_buffering off;', text)
        self.assertIn('proxy_next_upstream off;', text)
        self.assertNotIn('9100/;', text)
        self.assertIn('proxy_ignore_headers X-Accel-Redirect X-Accel-Buffering;', text)

    def test_public_host_and_sni_must_agree_unknown_tls_handshakes_refuse(self):
        text = self.m.render(self.value)
        self.assertIn('ssl_reject_handshake on;', text)
        self.assertIn('default_server', text)
        for i in range(3):
            self.assertIn(f'if ($ssl_server_name != web{i}.example.invalid) {{ return 421; }}', text)
            self.assertIn(f'map $http_host $s4_host_{i} {{ default 0; web{i}.example.invalid 1; web{i}.example.invalid:443 1; }}', text)
            self.assertIn(f'if ($s4_host_{i} = 0) {{ return 421; }}', text)
            self.assertIn(f'return 308 https://web{i}.example.invalid$request_uri;', text)

    def test_client_headers_are_overwritten_not_appended_or_locality_certified(self):
        text = self.m.render(self.value)
        self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;', text)
        self.assertNotIn('$proxy_add_x_forwarded_for', text)
        self.assertIn('proxy_set_header Forwarded "";', text)
        self.assertIn('proxy_set_header Proxy "";', text)
        self.assertIn('proxy_set_header X-Forwarded-Proto https;', text)
        self.assertNotIn('real_ip_header', text)
        self.assertIn('user www-data;', text)

    def test_email_public_allowlist_has_no_admin_or_health_catch_all(self):
        text = self.m.render(self.value).split('server_name web2.example.invalid;', 2)[2]
        self.assertIn('location / { return 404; }', text)
        for path in self.m.MAIL_EXACT: self.assertIn(f'location = {path}', text)
        for path in self.m.MAIL_PREFIX: self.assertIn(f'location ^~ {path}', text)
        self.assertNotIn('location / {\n            proxy_pass', text)
        self.assertNotIn('location = /Login', text); self.assertNotIn('location ^~ /admin', text)
        self.assertIn('"%25|%2f|%5c|%00"', text)

    def test_drava_registration_and_operator_routes_have_explicit_refusal(self):
        text = self.m.render(self.value)
        self.assertIn('location ^~ /mk8.drava.proxy.v1.ServiceRegistry/ { return 404; }', text)
        self.assertIn('^/(health|metrics|internal|admin|_drava)(/|$)', text)

    def test_pem_is_narrow_framing_only_not_crypto_or_native_attestation(self):
        self.assertEqual(self.m.pem(self.sample(), False), 1)
        self.assertEqual(self.m.pem(self.sample()*16, False), 16)
        for raw, private in ((b'', False), (self.sample()*17, False),
            (self.sample(True)*2, True), (self.sample(True), False), (self.sample(), True),
            (self.sample().replace(b'\n', b'\r\n'), False),
            (self.sample().replace(b'-----END', b'comment\n-----END'), False),
            (b'-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n', False),
            (b'-----BEGIN CERTIFICATE-----\nAB==\n-----END CERTIFICATE-----\n', False)):
            with self.subTest(raw=raw, private=private), self.assertRaises(self.m.Pending): self.m.pem(raw, private)

    def test_missing_bad_or_oversized_material_refuses_before_render(self):
        path = Path(self.value['applications']['mk8.sava']['certificate'])
        for raw in (b'', b'x'*65537, b'not PEM\n'):
            path.write_bytes(raw)
            with patch.object(self.m, 'render') as renderer, self.assertRaises(self.m.Pending): self.prepare()
            renderer.assert_not_called()
        path.unlink()
        with patch.object(self.m, 'render') as renderer, self.assertRaises(OSError): self.prepare()
        renderer.assert_not_called()

    def test_root_private_inputs_key_modes_links_and_ancestry_are_enforced(self):
        key = Path(self.value['applications']['mk8.sava']['private_key'])
        key.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.prepare()
        key.chmod(0o600); other = self.root / 'linked'; os.link(key, other)
        with self.assertRaises(self.m.Pending): self.prepare()
        other.unlink(); key.rename(other); key.symlink_to(other)
        with self.assertRaises(self.m.Pending): self.prepare()
        key.unlink(); other.rename(key)
        self.root.chmod(0o777)
        with self.assertRaises(self.m.Pending): self.prepare()
        self.root.chmod(0o700)
        self.m.INPUT.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.prepare()

    def test_fifo_material_is_refused_without_blocking(self):
        key = Path(self.value['applications']['mk8.sava']['private_key']); key.unlink(); os.mkfifo(key, 0o600)
        with self.assertRaises(self.m.Pending): self.prepare()

    def test_second_complete_settings_read_precedes_final_scope_and_detects_drift(self):
        original = self.m.configuration; calls = []
        def reader(end):
            calls.append('configuration'); result = original(end)
            if calls.count('configuration') == 1:
                self.value['applications']['mk8.email']['idle_seconds'] = 61; self.write()
            return result
        with patch.object(self.m, 'configuration', side_effect=reader), self.assertRaises(self.m.Pending):
            self.m.prepare(scope=lambda: calls.append('scope') or 123456)
        self.assertEqual(calls, ['scope', 'configuration', 'configuration'])

    def test_valid_same_path_material_replacement_withholds_intention(self):
        original = self.m.render
        def render(value):
            result = original(value)
            Path(value['applications']['mk8.sava']['private_key']).write_bytes(self.sample(True, b'new bytes'))
            return result
        with patch.object(self.m, 'render', side_effect=render), self.assertRaises(self.m.Pending): self.prepare()

    def test_receipt_encoding_is_before_all_final_reads_and_scope_fence(self):
        calls=[]; canonical=self.m.BASE.canonical; configuration=self.m.configuration; materials=self.m.materials
        def encode(value):
            if type(value) is dict and value.get('state')=='ingress-configuration-intention-only': calls.append('encode')
            return canonical(value)
        def conf(end): calls.append('settings'); return configuration(end)
        def files(value,end): calls.append('materials'); return materials(value,end)
        with patch.object(self.m.BASE,'canonical',side_effect=encode), patch.object(self.m,'configuration',side_effect=conf), patch.object(self.m,'materials',side_effect=files):
            self.m.prepare(scope=lambda: calls.append('scope') or 123456)
        self.assertEqual(calls, ['scope','settings','materials','encode','settings','materials','scope'])

    def test_context_true_positive_uint64_and_final_equality_are_required(self):
        for scope in (lambda:0, lambda:True, lambda:1.0, lambda:2**64):
            with self.subTest(scope=scope), self.assertRaises(self.m.Pending): self.m.prepare(scope=scope)
        values=iter((123456,123457))
        with self.assertRaises(self.m.Pending): self.m.prepare(scope=lambda:next(values))

    def test_inherited_expired_and_invalid_window_refuse_before_input(self):
        for end in (True, float('nan'), float('inf'), '10', self.m.KERNEL.now()-1):
            with patch.object(self.m,'configuration') as reader, self.assertRaises(self.m.Pending): self.prepare(deadline=end)
            reader.assert_not_called()

    def test_output_bound_withholds_receipt(self):
        with patch.object(self.m,'MAX_OUTPUT',1), self.assertRaises(self.m.Pending): self.prepare()

    def test_binary_sink_is_admitted_before_preparation_and_same_bytes_are_published(self):
        data=b'{"data":"ASCII fixture"}\n'; sink=io.BytesIO(); stdout=type('Output',(),{'buffer':sink})()
        with patch.object(sys,'argv',['prepare.py']), patch.object(sys,'stdout',stdout), patch.object(self.m,'prepare',return_value=data):
            self.assertEqual(self.m.main(),0)
        self.assertEqual(sink.getvalue(),data)
        with patch.object(sys,'argv',['prepare.py']), patch.object(sys,'stdout',io.StringIO()), patch.object(sys,'stderr',io.StringIO()), patch.object(self.m,'prepare') as prepare:
            self.assertEqual(self.m.main(),75); prepare.assert_not_called()

    def test_actual_private_cli_pipe_bytes_ignore_text_stdout_encoding(self):
        program = ("import importlib.util,os,sys;from pathlib import Path;"
            "spec=importlib.util.spec_from_file_location('pipe_web',sys.argv[1]);"
            "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);"
            "m.BASE.TRUST_ROOT=Path(sys.argv[2]);m.BASE.TRUSTED_UID=os.getuid();"
            "m.INPUT=Path(sys.argv[3]);m.KERNEL.namespace=lambda:123456;"
            "m.prepare.__defaults__=(None,m.KERNEL.namespace);sys.argv=['prepare.py'];sys.exit(m.main())")
        expected = self.prepare()
        for encoding in ('utf-8:strict', 'utf-32:ignore', 'ascii:replace'):
            env = dict(os.environ, PYTHONIOENCODING=encoding, TMPDIR='/dev/shm')
            env.pop('PYTHONPATH', None)
            child = subprocess.run([sys.executable, '-B', '-c', program,
                str(ROOT / 'Web/prepare.py'), str(self.root), str(self.m.INPUT)],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            with self.subTest(encoding=encoding):
                self.assertEqual(child.returncode, 0)
                self.assertEqual(child.stdout, expected)
                self.assertEqual(child.stderr, b'')

    def test_short_boolean_unknown_write_and_flush_errors_cannot_publish_success(self):
        class Sink:
            def __init__(self,count,fail=False): self.count=count; self.fail=fail
            def write(self,raw): return self.count
            def flush(self):
                if self.fail: raise OSError('flush fixture')
        data=b'{}\n'
        for count,fail in ((0,False),(True,False),(None,False),(len(data),True)):
            stdout=type('Output',(),{'buffer':Sink(count,fail)})()
            with patch.object(sys,'argv',['prepare.py']), patch.object(sys,'stdout',stdout), patch.object(sys,'stderr',io.StringIO()), patch.object(self.m,'prepare',return_value=data):
                self.assertEqual(self.m.main(),75)

    def test_cli_refusal_has_no_policy_output_and_overrides_never_reach_prepare(self):
        stdout=type('Output',(),{'buffer':io.BytesIO()})()
        with patch.object(sys,'argv',['prepare.py','--host','unexpected']), patch.object(sys,'stdout',stdout), patch.object(sys,'stderr',io.StringIO()), patch.object(self.m,'prepare') as prepare:
            self.assertEqual(self.m.main(),75); prepare.assert_not_called()
        self.assertEqual(stdout.buffer.getvalue(),b'')
        with patch.object(sys,'argv',['prepare.py']), patch.object(sys,'stdout',stdout), patch.object(sys,'stderr',io.StringIO()), patch.object(self.m,'prepare',side_effect=self.m.Pending('fixture refusal')):
            self.assertEqual(self.m.main(),75)
        self.assertEqual(stdout.buffer.getvalue(),b'')


if __name__ == '__main__': unittest.main()
