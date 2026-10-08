import contextlib
import copy
import errno
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_assemble import ASSEMBLY, KERNEL, POLICY, PrivateNative, records
from test_assemble import nft_receipt, legacy_receipt, classifier_receipt, bpf_receipt, bpf_link_receipt

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_auto_intent', ROOT / 'Firewall/auto_intent.py')
AUTO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTO)


def captured_main(call, encoding='utf-8'):
    sink = io.BytesIO();output = io.TextIOWrapper(sink, encoding=encoding, errors='replace');err = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(err):status = call()
    output.flush();data = sink.getvalue();output.detach();return status, data, err.getvalue()


class AutomaticTests(unittest.TestCase):
    def setUp(self):
        self.records = records();self.namespace = self.records['dhcp4']['kernel']['namespace']
        self.alias = patch.object(AUTO, 'ASSEMBLY', ASSEMBLY);self.alias.start();self.addCleanup(self.alias.stop)

    def readers(self):
        return {'dhcp': lambda deadline: self.records['dhcp4'], 'dns': lambda deadline: self.records['dns'],
                'ntp': lambda deadline: self.records['ntp'], 'nft': lambda deadline: nft_receipt(self.namespace),
                'legacy': lambda deadline: legacy_receipt(self.namespace),
                'classifiers': lambda deadline: classifier_receipt(self.records['dhcp4']['kernel']),
                'bpf': lambda deadline: bpf_receipt(self.namespace), 'bpf_links': lambda deadline: bpf_link_receipt(self.namespace)}

    def prepare(self, **overrides):
        return AUTO.prepare(**(self.readers() | overrides))

    def test_real_automatic_agreement_generates_the_complete_real_expected_manifest(self):
        payload = self.prepare();value = json.loads(payload)
        raw = json.dumps(value['topology'], sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(value['schema'], 'debian13s4-automatic-nft-intent-1')
        self.assertEqual(value['namespace'], self.namespace)
        self.assertEqual(value['admission_profile'], AUTO.ADMISSION)
        self.assertEqual(value['intention'], AUTO.MANIFEST.expected(raw))
        self.assertEqual(value['intention']['compiler_sha256'], hashlib.sha256(POLICY.compile_policy(raw).encode()).hexdigest())
        self.assertEqual(value['intention']['topology_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(value['intention']['policy']['sets']), 17)
        self.assertEqual(value['intention']['policy']['rules']['forward'], [])

    def test_same_compiler_callback_keeps_all_final_observations_after_manifest_encoding(self):
        events = [];real = AUTO.MANIFEST.expected
        def expected(raw):events.append('manifest');return real(raw)
        def reader(name, function):
            def call(deadline):events.append(name);return function(deadline)
            return call
        settings = {name: reader(name, function) for name, function in self.readers().items()}
        with patch.object(AUTO.MANIFEST, 'expected', side_effect=expected):AUTO.prepare(**settings)
        before, after = events[:events.index('manifest')], events[events.index('manifest') + 1:]
        self.assertEqual(before, ['nft', 'legacy', 'classifiers', 'bpf', 'bpf_links', 'dhcp', 'dns', 'ntp'] * 2)
        self.assertEqual(after, ['nft', 'legacy', 'classifiers', 'bpf', 'bpf_links'])

    def test_invalid_parent_deadlines_refuse_before_any_observer(self):
        for deadline in (True, float('nan'), float('inf'), 'future', KERNEL.now() - 1, 10 ** 10000):
            with self.subTest(kind=type(deadline).__name__), self.assertRaises(ValueError):
                self.prepare(deadline=deadline, nft=lambda **kw: self.fail('native'))

    def test_one_capped_parent_deadline_is_shared_by_every_source_and_service_turn(self):
        start = KERNEL.now()
        for seconds in (10, 1000):
            calls = [];settings = self.readers()
            for key, callback in tuple(settings.items()):
                settings[key] = lambda deadline, key=key, callback=callback: calls.append((key, deadline)) or callback(deadline)
            with patch.object(KERNEL, 'now', return_value=start):AUTO.prepare(deadline=start + seconds, **settings)
            self.assertEqual(len(calls), 21)
            self.assertEqual({deadline for _, deadline in calls}, {start + min(seconds, 60)})

    def test_input_topology_compiler_scope_and_unknown_overrides_are_not_admitted(self):
        for settings in ({'topology': {}}, {'compiler': POLICY.compile_policy}, {'scope': lambda: 1}, {'deadline_reader': lambda: 1}, {'nft': None}):
            with (self.subTest(settings=settings), patch.object(KERNEL, 'namespace', side_effect=AssertionError('scope')),
                  self.assertRaises(ValueError)):AUTO.prepare(**settings)

    def test_initial_current_namespace_requires_true_nonzero_uint64(self):
        for namespace in (0, True, '1', -1, 1 << 64):
            with self.subTest(namespace=namespace), patch.object(KERNEL, 'namespace', return_value=namespace), self.assertRaises(ValueError):
                self.prepare(nft=lambda **kw: self.fail('read'))

    def test_an_existing_reserved_or_foreign_table_is_not_relabelled_empty(self):
        for source in ({}, nft_receipt(self.namespace) | {'empty': False},
                       {'schema': 'debian13s4-nft-candidate-1', 'namespace': self.namespace, 'policy': {}}):
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.prepare(nft=lambda deadline: source, dhcp=lambda **kw: self.fail('service'))

    def test_failed_missing_nonempty_legacy_tc_program_and_link_reporting_blocks_intention(self):
        for name in ('legacy', 'classifiers', 'bpf', 'bpf_links'):
            def missing(deadline):raise OSError('missing reporting')
            with self.subTest(name=name), self.assertRaises(OSError):self.prepare(**{name: missing, 'dhcp': lambda **kw: self.fail('service')})
            with self.subTest(name=name), self.assertRaises(ValueError):self.prepare(**{name: lambda deadline: {}, 'dhcp': lambda **kw: self.fail('service')})

    def test_infrastructure_disagreement_or_instantiated_dhcp6_has_no_intention(self):
        self.records['dns']['kernel'] = copy.deepcopy(self.records['dns']['kernel']);self.records['dns']['kernel']['namespace'] += 1
        with self.assertRaises(ValueError):self.prepare()
        self.records = records();self.records['dhcp4']['interfaces'][0].update(dhcp6=True, state6='stopped')
        with self.assertRaisesRegex(ValueError, 'DHCPv6'):self.prepare(dns=lambda **kw: self.fail('dns'))

    def test_service_second_round_mutation_is_not_a_trusted_manifest_input(self):
        count = [0]
        def dns(deadline):
            count[0] += 1;value = copy.deepcopy(self.records['dns'])
            if count[0] == 2:value['source']['sha256'] = 'a' * 64
            return value
        with self.assertRaisesRegex(ValueError, 'between rounds'):self.prepare(dns=dns)
        self.assertEqual(count[0], 2)

    def test_later_callbacks_cannot_mutate_already_admitted_private_service_data(self):
        def ntp(deadline):self.records['dns']['source']['sha256'] = 'a' * 64;return self.records['ntp']
        with self.assertRaisesRegex(ValueError, 'between rounds'):self.prepare(ntp=ntp)

    def test_postmanifest_table_or_legacy_drift_withholds_the_prepared_bytes(self):
        for name in ('nft', 'legacy'):
            count = [0];original = self.readers()[name]
            def changed(deadline):
                count[0] += 1;value = original(deadline)
                if count[0] == 3:
                    if name == 'nft':value['source']['release_name'] = 'changed'
                    else:value['source']['identity'][1] += 100
                return value
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'changed'):self.prepare(**{name: changed})
            self.assertEqual(count[0], 3)

    def test_postmanifest_classifier_or_registered_id_drift_still_refuses(self):
        for name in ('classifiers', 'bpf', 'bpf_links'):
            count = [0];original = self.readers()[name]
            def changed(deadline):
                count[0] += 1;value = original(deadline)
                if count[0] == 3:
                    if name == 'classifiers':value['links'][1]['mtu'] = 1400
                    else:value['lookup'].update(result=0, errno=0, next_id=1)
                return value
            with self.subTest(name=name), self.assertRaises(ValueError):self.prepare(**{name: changed})
            self.assertEqual(count[0], 3)

    def test_lease_expiration_during_real_manifest_preparation_is_rechecked(self):
        start = KERNEL.now();clock = [start];real = AUTO.MANIFEST.expected
        row = self.records['dhcp4']['attributions'][0]
        row['preferred_until'] = row['valid_until'] = int((start + 1) * 1000000)
        def expected(raw):value = real(raw);clock[0] = start + 2;return value
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(AUTO.MANIFEST, 'expected', side_effect=expected), self.assertRaises(ValueError):self.prepare()

    def test_budget_expiration_during_encoding_prevents_final_native_reads(self):
        start = KERNEL.now();clock = [start];calls = [];real = AUTO.MANIFEST.STATE.encoded
        def encoded(value):
            payload = real(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-automatic-nft-intent-1':clock[0] = start + 61
            return payload
        def nft(deadline):calls.append(deadline);return nft_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(AUTO.MANIFEST.STATE, 'encoded', side_effect=encoded), self.assertRaises(ValueError):self.prepare(nft=nft)
        self.assertEqual(len(calls), 2)

    def test_aggregate_payload_bound_refuses_before_final_admission(self):
        calls = []
        def nft(deadline):calls.append(deadline);return nft_receipt(self.namespace)
        with patch.object(AUTO, 'MAX_OUTPUT', 1), self.assertRaises(ValueError):self.prepare(nft=nft)
        self.assertEqual(len(calls), 2)

    def test_different_real_compiler_serialization_cannot_supply_a_manifest_hash(self):
        original = POLICY.compile_policy
        with patch.object(POLICY, 'compile_policy', side_effect=lambda raw: original(raw) + '\n'), self.assertRaisesRegex(ValueError, 'identity disagrees'):
            self.prepare()

    def test_final_wrapper_scope_is_typed_and_must_equal_the_preparation_context(self):
        for final in (True, '1', self.namespace + 1):
            values = iter([self.namespace, self.namespace, final])
            with self.subTest(final=final), patch.object(KERNEL, 'namespace', side_effect=lambda: next(values)), self.assertRaises(ValueError):self.prepare()

    def test_bytes_are_prepared_before_publication_and_have_one_utf8_lf_encoding(self):
        value = self.prepare()
        self.assertIs(type(value), bytes);self.assertTrue(value.endswith(b'\n'));self.assertFalse(value.endswith(b'\n\n'))
        decoded = json.loads(value.decode('utf-8'));self.assertEqual(value, AUTO.MANIFEST.STATE.encoded(decoded) + b'\n')

    def test_no_serialization_is_added_after_the_real_preparer_final_freshness_fences(self):
        original_observe, original_dumps = ASSEMBLY.observe, json.dumps
        finished = [False]
        def observe(**settings):
            value = original_observe(**settings);finished[0] = True;return value
        def dumps(*args, **settings):
            self.assertFalse(finished[0], 'serialization after the final lease/source fences')
            return original_dumps(*args, **settings)
        with patch.object(ASSEMBLY, 'observe', side_effect=observe), patch.object(json, 'dumps', side_effect=dumps):
            self.assertIs(type(self.prepare()), bytes)

    def test_main_short_boolean_unknown_write_and_flush_delivery_withhold_success(self):
        original = AUTO.prepare
        class Sink:
            def __init__(self, kind):self.kind = kind;self.data = None
            def write(self, data):
                self.data = data
                if self.kind == 'write':raise OSError('write')
                return len(data) - 1 if self.kind == 'short' else True if self.kind == 'bool' else None if self.kind == 'none' else len(data)
            def flush(self):
                if self.kind == 'flush':raise OSError('flush')
        class Output:
            def __init__(self, sink):self.buffer = sink
        for kind in ('short', 'bool', 'none', 'write', 'flush'):
            sink = Sink(kind)
            with (self.subTest(kind=kind), patch.object(AUTO.sys, 'argv', ['auto_intent.py']),
                  patch.object(AUTO, 'prepare', side_effect=lambda: original(**self.readers())),
                  patch.object(AUTO.sys, 'stdout', Output(sink)), contextlib.redirect_stderr(io.StringIO())):
                self.assertEqual(AUTO.main(), 75)
            self.assertIs(type(sink.data), bytes)
            self.assertEqual(json.loads(sink.data)['namespace'], self.namespace)


class NativeTests(PrivateNative):
    def setUp(self):
        super().setUp();alias = patch.object(AUTO, 'ASSEMBLY', ASSEMBLY);alias.start();self.settings.append(alias)

    def cli(self, encoding='utf-8'):
        with patch.object(AUTO.sys, 'argv', ['auto_intent.py']):return captured_main(AUTO.main, encoding)

    def test_complete_private_capture_all_admissions_real_manifest_and_byte_cli(self):
        self.fixtures(tc_kind='fq_codel');status, payload, error = self.cli()
        self.assertEqual(status, 0, error);self.assertEqual(error, '')
        value = json.loads(payload.decode('utf-8'));self.assertEqual(value['namespace'], KERNEL.namespace())
        raw = json.dumps(value['topology'], sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(value['intention'], AUTO.MANIFEST.expected(raw))
        self.assertEqual(len(self.bpf_calls), 6);self.assertEqual(len(self.link_calls), 6)
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'ip' for kind, _, _ in rows), 258)
        self.assertEqual(sum(kind == 'bus' for kind, _, _ in rows), 100)
        self.assertEqual(sum(kind == 'tc' for kind, _, _ in rows), 12)
        self.assertEqual(sum(kind == 'nft' for kind, _, _ in rows), 6)
        self.assertEqual(sum('DescribeLink' in args for _, args, _ in rows), 4)
        self.assertEqual(sum(kind == 'ip' and 'get' in args for kind, args, _ in rows), 12)

    def test_existing_reserved_table_actual_read_refuses_before_native_services(self):
        self.fixtures();value = {'nftables': [{'metainfo': {'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}},
                                            {'table': {'family': 'inet', 'name': 'debian13s4', 'handle': 1}}]}
        self.executable(self.nft, 'print(' + repr(json.dumps(value)) + ')')
        status, data, error = self.cli();self.assertEqual(status, 75);self.assertEqual(data, b'');self.assertIn('pending', error)
        self.assertFalse(any(json.loads(line)[0] == 'bus' for line in self.ledger.read_text().splitlines()))

    def test_actual_postmanifest_program_or_link_registration_has_no_cli_intention(self):
        original = AUTO.MANIFEST.expected
        for kind in ('program', 'link'):
            self.fixtures();self.bpf_present = self.link_present = False;self.bpf_calls.clear();self.link_calls.clear()
            def expected(raw):
                value = original(raw)
                if kind == 'program':self.bpf_present = True
                else:self.link_present = True
                return value
            with patch.object(AUTO.MANIFEST, 'expected', side_effect=expected):status, data, error = self.cli()
            self.assertEqual(status, 75);self.assertEqual(data, b'');self.assertIn('pending', error)
            self.assertEqual(len(self.bpf_calls), 5 if kind == 'program' else 6)
            self.assertEqual(len(self.link_calls), 4 if kind == 'program' else 5)

    def test_actual_permission_refusal_remains_before_native_infrastructure(self):
        self.fixtures();self.link_error = errno.EPERM
        status, data, error = self.cli();self.assertEqual(status, 75);self.assertEqual(data, b'');self.assertIn('pending', error)
        self.assertEqual(len(self.link_calls), 1)
        self.assertFalse(any(json.loads(line)[0] == 'bus' for line in self.ledger.read_text().splitlines()))

    def test_actual_stdout_bytes_are_utf8_even_with_utf32_text_wrapper(self):
        for encoding in ('utf-8', 'utf-32', 'ascii'):
            self.fixtures();status, data, error = self.cli(encoding)
            with self.subTest(encoding=encoding):
                self.assertEqual(status, 0, error);self.assertTrue(data.startswith(b'{'));self.assertTrue(data.endswith(b'\n'))
                self.assertEqual(json.loads(data.decode('utf-8'))['admission_profile'], AUTO.ADMISSION)

    def test_usage_missing_sink_and_stdin_are_not_automatic_configuration_inputs(self):
        self.fixtures()
        class Input:
            @property
            def buffer(self):raise AssertionError('stdin read')
        with patch.object(AUTO.sys, 'stdin', Input()), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with patch.object(AUTO.sys, 'argv', ['auto_intent.py', 'topology.json']):self.assertEqual(AUTO.main(), 64)
            with patch.object(AUTO.sys, 'argv', ['auto_intent.py']):self.assertEqual(AUTO.main(), 75)
        self.assertEqual(self.ledger.read_text(), '')


if __name__ == '__main__':unittest.main()
