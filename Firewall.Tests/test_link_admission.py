import contextlib
import copy
import ctypes
import errno
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_assemble import ASSEMBLY, BPF, KERNEL, POLICY, PrivateNative, records
from test_assemble import bpf_receipt, classifier_receipt, legacy_receipt, nft_receipt

SPEC = importlib.util.spec_from_file_location('firewall_link_fixture', Path(__file__).resolve().parents[1] / 'Firewall/bpf_links.py')
LINKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINKS)


def link_receipt(namespace):
    return {'schema': 'debian13s4-bpf-link-id-empty-1', 'profile': 'global-link-id-zero-start-enoent-1',
            'namespace': namespace, 'lookup': {'source': LINKS.abi(), 'result': -1, 'errno': errno.ENOENT, 'next_id': 0}}


class LinkAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.records = records()
        self.namespace = self.records['dhcp4']['kernel']['namespace']

    def settings(self):
        return {'dhcp': lambda deadline: self.records['dhcp4'], 'dns': lambda deadline: self.records['dns'],
                'ntp': lambda deadline: self.records['ntp'], 'nft': lambda deadline: nft_receipt(self.namespace),
                'legacy': lambda deadline: legacy_receipt(self.namespace),
                'classifiers': lambda deadline: classifier_receipt(self.records['dhcp4']['kernel']),
                'bpf': lambda deadline: bpf_receipt(self.namespace),
                'bpf_links': lambda deadline: link_receipt(self.namespace)}

    def observe(self, **overrides):
        settings = self.settings();settings.update(overrides)
        return ASSEMBLY.observe(**settings)

    def test_three_complete_link_receipts_share_the_exact_inherited_deadline(self):
        value = link_receipt(self.namespace);calls = [];deadline = KERNEL.now() + 20
        result = self.observe(deadline=deadline, bpf_links=lambda deadline: calls.append(deadline) or value)
        self.assertEqual(calls, [deadline] * 3)
        self.assertEqual(result['bpf_links'], value)
        self.assertIsNot(result['bpf_links']['lookup']['source'], value['lookup']['source'])
        self.assertEqual(result['sources']['bpf_links'], value['lookup']['source'])
        self.assertEqual(result['bpf']['lookup']['source']['command'], 11)
        self.assertEqual(result['bpf_links']['lookup']['source']['command'], 31)
        self.assertEqual(result['profile'], 'nft-legacy-proc-tc-fq-bpf-program-link-id-empty-networkd-classic-timesyncd-no-dhcp6-1')
        self.assertEqual(result['policy'], POLICY.compile_policy(json.dumps(result['topology']).encode()))

    def test_link_receipt_admission_precedes_all_infrastructure_and_compilation(self):
        for value in (None, {}, link_receipt(self.namespace) | {'empty': True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.observe(bpf_links=lambda deadline: value, dhcp=lambda **kw: self.fail('infrastructure'),
                             compiler=lambda raw: self.fail('compile'))

    def test_program_receipts_and_other_commands_cannot_be_relabelled_as_link_receipts(self):
        values = [bpf_receipt(self.namespace)]
        for command in (11, 12, 30, True, '31'):
            value = link_receipt(self.namespace);value['lookup']['source']['command'] = command;values.append(value)
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.observe(bpf_links=lambda deadline: value, dhcp=lambda **kw: self.fail('infrastructure'))

    def test_missing_reporting_permission_and_present_link_refuse_before_infrastructure(self):
        values = []
        for result, error, next_id in ((-1, errno.EPERM, 0), (-1, errno.ENOSYS, 0), (0, 0, 1), (-1, errno.ENOENT, 1)):
            value = link_receipt(self.namespace);value['lookup'].update(result=result, errno=error, next_id=next_id);values.append(value)
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.observe(bpf_links=lambda deadline: value, dhcp=lambda **kw: self.fail('infrastructure'))
        def missing(deadline):raise OSError('missing link reporting')
        with self.assertRaises(OSError):self.observe(bpf_links=missing, dhcp=lambda **kw: self.fail('infrastructure'))

    def test_typed_nonzero_link_context_must_match_the_prior_receipts(self):
        for namespace in (0, True, '1', 1 << 64, self.namespace + 1):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                self.observe(bpf_links=lambda deadline: link_receipt(namespace), dhcp=lambda **kw: self.fail('foreign context'))

    def test_valid_second_or_final_context_drift_withholds_prepared_policy(self):
        for turn in (2, 3):
            calls = []
            def reader(deadline):
                calls.append(deadline);return link_receipt(self.namespace + (len(calls) == turn))
            with self.subTest(turn=turn), self.assertRaisesRegex(ASSEMBLY.Pending, 'link'):
                self.observe(bpf_links=reader)
            self.assertEqual(len(calls), turn)

    def test_complete_valid_abi_source_drift_is_retained_in_round_and_final_equality(self):
        actual = LINKS.abi()
        other = actual | {'machine': 'aarch64' if actual['machine'] == 'x86_64' else 'x86_64',
                          'syscall': 280 if actual['machine'] == 'x86_64' else 321}
        for turn in (2, 3):
            calls = [];source = [actual]
            def reader(deadline):
                calls.append(deadline)
                if len(calls) == turn:source[0] = other
                return link_receipt(self.namespace)
            with self.subTest(turn=turn), patch.object(LINKS, 'abi', side_effect=lambda: copy.deepcopy(source[0])), \
                    patch.object(ASSEMBLY.BPF_LINKS, 'abi', side_effect=lambda: copy.deepcopy(source[0])), \
                    self.assertRaisesRegex(ASSEMBLY.Pending, 'changed'):
                self.observe(bpf_links=reader)
            self.assertEqual(len(calls), turn)

    def test_later_reader_mutation_cannot_rewrite_the_first_private_link_receipt(self):
        first = link_receipt(self.namespace);calls = []
        def reader(deadline):
            calls.append(deadline);return first if len(calls) == 1 else link_receipt(self.namespace)
        def dhcp(deadline):
            first['lookup']['source']['command'] = 11;first['lookup']['next_id'] = 99
            return self.records['dhcp4']
        result = self.observe(bpf_links=reader, dhcp=dhcp)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result['bpf_links']['lookup']['source']['command'], 31)
        self.assertEqual(result['bpf_links']['lookup']['next_id'], 0)

    def test_program_expiry_prevents_first_link_admission(self):
        clock = [KERNEL.now()]
        def program(deadline):clock[0] = deadline;return bpf_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaisesRegex(ASSEMBLY.Pending, 'before BPF link'):
            self.observe(bpf=program, bpf_links=lambda **kw: self.fail('expired link admission'))

    def test_expired_link_delivery_cannot_admit_infrastructure(self):
        clock = [KERNEL.now()]
        def reader(deadline):clock[0] = deadline;return link_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(ASSEMBLY.Pending):
            self.observe(bpf_links=reader, dhcp=lambda **kw: self.fail('expired infrastructure'))

    def test_final_program_expiry_prevents_the_last_link_admission(self):
        clock = [KERNEL.now()];program_calls = [];link_calls = []
        def program(deadline):
            program_calls.append(deadline)
            if len(program_calls) == 3:clock[0] = deadline
            return bpf_receipt(self.namespace)
        def reader(deadline):link_calls.append(deadline);return link_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaisesRegex(ASSEMBLY.Pending, 'before final BPF link'):
            self.observe(bpf=program, bpf_links=reader)
        self.assertEqual(len(program_calls), 3);self.assertEqual(len(link_calls), 2)

    def test_final_link_expiry_is_not_a_completed_preparation(self):
        clock = [KERNEL.now()];calls = []
        def reader(deadline):
            calls.append(deadline)
            if len(calls) == 3:clock[0] = deadline
            return link_receipt(self.namespace)
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(ASSEMBLY.Pending):
            self.observe(bpf_links=reader)
        self.assertEqual(len(calls), 3)

    def test_postcompiler_link_presence_withholds_cli_text(self):
        value = link_receipt(self.namespace);original = ASSEMBLY.observe;out, err = io.StringIO(), io.StringIO()
        def compiler(raw):
            text = POLICY.compile_policy(raw);value['lookup'].update(result=0, errno=0, next_id=1);return text
        settings = self.settings() | {'compiler': compiler, 'bpf_links': lambda deadline: value}
        with patch.object(ASSEMBLY, 'observe', side_effect=lambda: original(**settings)), \
                patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = ASSEMBLY.main()
        self.assertEqual(status, 75);self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())

    def test_compiler_callback_cannot_rewrite_the_private_lease_and_link_receipts(self):
        attribution = self.records['dhcp4']['attributions'][0]
        attribution['preferred_until'] = attribution['valid_until'] = int((KERNEL.now() + 30) * 1000000)
        def compiler(raw):
            text = POLICY.compile_policy(raw);attribution['preferred_until'] = attribution['valid_until'] = 1;return text
        # The compiler mutates the original callback record, not the admitted copy.
        result = self.observe(compiler=compiler)
        self.assertEqual(result['bpf_links'], link_receipt(self.namespace))


class NativeLinkAdmissionTests(PrivateNative):
    def test_complete_private_program_and_link_syscall_delivery_join_and_compiler(self):
        self.fixtures(tc_kind='fq_codel');result = ASSEMBLY.observe()
        self.assertEqual(len(self.bpf_calls), 6);self.assertEqual(len(self.link_calls), 6)
        for call in self.link_calls:
            self.assertEqual(call, {'number': LINKS.abi()['syscall'], 'command': 31, 'bytes': 12, 'attribute': bytes(16)})
        self.assertEqual(result['bpf_links'], link_receipt(KERNEL.namespace()))
        self.assertEqual(result['bpf'], bpf_receipt(KERNEL.namespace()))
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'ip' for kind, _, _ in rows), 258)
        self.assertEqual(sum(kind == 'bus' for kind, _, _ in rows), 100)
        self.assertEqual(sum(kind == 'tc' for kind, _, _ in rows), 12)
        self.assertEqual(result['policy'], POLICY.compile_policy(json.dumps(result['topology']).encode()))

    def test_actual_link_permission_or_presence_refuses_before_native_infrastructure(self):
        for present, error in ((False, errno.EPERM), (False, errno.ENOSYS), (True, 0)):
            self.fixtures();self.link_present = present;self.link_error = error;self.bpf_calls.clear();self.link_calls.clear()
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(present=present, error=error), patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):status = ASSEMBLY.main()
            self.assertEqual(status, 75);self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())
            self.assertEqual(len(self.bpf_calls), 2);self.assertEqual(len(self.link_calls), 1)
            self.assertFalse(any(json.loads(line)[0] == 'bus' for line in self.ledger.read_text().splitlines()))

    def test_actual_postcompiler_link_registration_withholds_policy(self):
        self.fixtures();original = ASSEMBLY.observe;out, err = io.StringIO(), io.StringIO()
        def compiler(raw):
            text = POLICY.compile_policy(raw);self.link_present = True;return text
        with patch.object(ASSEMBLY, 'observe', side_effect=lambda: original(compiler=compiler)), \
                patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = ASSEMBLY.main()
        self.assertEqual(status, 75);self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())
        self.assertEqual(len(self.bpf_calls), 6);self.assertEqual(len(self.link_calls), 5)


if __name__ == '__main__':
    unittest.main()
