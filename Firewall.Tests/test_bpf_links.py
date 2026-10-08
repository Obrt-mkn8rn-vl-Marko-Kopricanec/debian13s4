import contextlib
import copy
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_bpf_links', ROOT / 'Firewall/bpf_links.py')
BPF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BPF)
KERNEL = BPF.KERNEL


def empty_lookup():
    return {'source': BPF.abi(), 'result': -1, 'errno': errno.ENOENT, 'next_id': 0}


class FakeSyscall:
    """Substitute only libc syscall delivery; never call the host BPF syscall."""
    def __init__(self, result=-1, error=errno.ENOENT, change=None):
        self.result, self.error, self.change = result, error, change
        self.calls = []

    def __call__(self, number, command, pointer, length):
        attr = ctypes.cast(pointer, ctypes.POINTER(BPF.IdAttr)).contents
        self.calls.append({'number': number.value, 'command': command.value, 'bytes': length.value,
                           'attribute': bytes(attr), 'errno_before': ctypes.get_errno()})
        if self.change:
            self.change(attr)
        if self.error is not None:
            ctypes.set_errno(self.error)
        return self.result


class ABItests(unittest.TestCase):
    def test_link_profile_keeps_program_command_and_common_layout_unchanged(self):
        self.assertEqual(BPF.COMMAND, 31)
        self.assertEqual(BPF.COMMON.COMMAND, 11)
        self.assertEqual(BPF.COMMON.abi()['command'], 11)
        self.assertEqual(BPF.abi(), {**BPF.COMMON.abi(), 'command': 31})
        self.assertIs(BPF.IdAttr, BPF.COMMON.IdAttr)
        self.assertIs(BPF.IdFields, BPF.COMMON.IdFields)
        source = BPF.abi();source['command'] = 28
        self.assertEqual(BPF.abi()['command'], 31)
        self.assertEqual(BPF.COMMON.abi()['command'], 11)

    def test_supported_lp64_architectures_have_checked_native_layout_and_fixed_numbers(self):
        for machine, number in (('x86_64', 321), ('aarch64', 280)):
            with self.subTest(machine=machine), patch.object(BPF.COMMON.os, 'uname', return_value=SimpleNamespace(machine=machine)):
                source = BPF.abi()
                self.assertEqual(source['syscall'], number)
                self.assertEqual(source['command'], 31)
                self.assertEqual(source['start_id'], 0)
                self.assertEqual(source['attr_bytes'], 12)
        self.assertEqual(ctypes.sizeof(BPF.IdAttr), 16)
        self.assertEqual(ctypes.alignment(BPF.IdAttr), 8)
        self.assertEqual([getattr(BPF.IdFields, key).offset for key in ('start_id', 'next_id', 'open_flags')], [0, 4, 8])
        self.assertEqual(bytes(BPF.IdAttr()), bytes(16))

    def test_unsupported_machine_platform_and_endian_refuse_before_loading_libc(self):
        for target, key, value in ((BPF.COMMON.os, 'uname', lambda: SimpleNamespace(machine='riscv64')),
                                  (BPF.sys, 'platform', 'freebsd'), (BPF.sys, 'byteorder', 'big')):
            with self.subTest(key=key), patch.object(target, key, value), \
                    patch.object(BPF.ctypes, 'CDLL', side_effect=AssertionError('libc must not load')), self.assertRaises(BPF.Pending):
                BPF.native_query(KERNEL.now() + 5)

    def test_ilp32_and_wrong_attribute_size_refuse_before_syscall(self):
        sizeof = ctypes.sizeof
        for kind, size in ((ctypes.c_void_p, 4), (ctypes.c_long, 4), (ctypes.c_int, 8),
                           (ctypes.c_uint32, 8), (BPF.IdFields, 16), (BPF.IdAttr, 12)):
            with self.subTest(kind=kind), patch.object(BPF.ctypes, 'sizeof', side_effect=lambda value: size if value is kind else sizeof(value)), \
                    patch.object(BPF.ctypes, 'CDLL', side_effect=AssertionError('libc must not load')), self.assertRaises(BPF.Pending):
                BPF.native_query(KERNEL.now() + 5)

    def test_incorrect_union_alignment_is_not_an_admitted_abi(self):
        alignment = ctypes.alignment
        with patch.object(BPF.ctypes, 'alignment', side_effect=lambda value: 4 if value is BPF.IdAttr else alignment(value)), \
                self.assertRaises(BPF.Pending):BPF.abi()


class NativeTests(unittest.TestCase):
    def query(self, lookup=None, **overrides):
        lookup = lookup or FakeSyscall()
        with patch.object(BPF.ctypes, 'CDLL', return_value=SimpleNamespace(syscall=lookup)) as loader:
            value = BPF.native_query(overrides.get('deadline', KERNEL.now() + 5))
            loader.assert_called_once_with(None, use_errno=True)
        return value, lookup

    def test_fixed_id_only_lookup_passes_zeroed_union_and_checked_ctypes_signature(self):
        value, lookup = self.query()
        self.assertEqual(value, empty_lookup())
        self.assertEqual(lookup.calls, [{'number': BPF.abi()['syscall'], 'command': 31, 'bytes': 12,
                                         'attribute': bytes(16), 'errno_before': 0}])
        self.assertEqual(lookup.argtypes, [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint])
        self.assertIs(lookup.restype, ctypes.c_long)

    def test_every_successful_link_lookup_refuses_even_unattached_or_invalid_id(self):
        for ident in (0, 1, 987, 0xffffffff):
            with self.subTest(ident=ident), self.assertRaises(BPF.Pending):
                self.query(FakeSyscall(0, 0, lambda attr: setattr(attr.ids, 'next_id', ident)))

    def test_permission_unsupported_interrupted_and_all_other_errors_are_not_empty(self):
        for error in (0, errno.EPERM, errno.EACCES, errno.ENOSYS, errno.EINVAL, errno.EINTR, errno.EFAULT, errno.EIO):
            with self.subTest(error=error), self.assertRaises(BPF.Pending):self.query(FakeSyscall(error=error))

    def test_only_true_integer_minus_one_result_can_be_enoent(self):
        for result in (True, False, None, '-1', -2, 1, 999):
            with self.subTest(result=result), self.assertRaises(BPF.Pending):self.query(FakeSyscall(result=result))

    def test_errno_is_cleared_so_stale_enoent_cannot_certify_a_failure(self):
        ctypes.set_errno(errno.ENOENT)
        lookup = FakeSyscall(error=None)
        with self.assertRaises(BPF.Pending):self.query(lookup)
        self.assertEqual(lookup.calls[0]['errno_before'], 0)

    def test_error_delivery_with_changed_start_next_flags_or_padding_refuses(self):
        changes = []
        for key in ('start_id', 'next_id', 'open_flags'):
            changes.append(lambda attr, key=key: setattr(attr.ids, key, 1))
        changes.append(lambda attr: ctypes.memset(ctypes.addressof(attr) + 12, 1, 4))
        for change in changes:
            with self.subTest(change=change), self.assertRaises(BPF.Pending):self.query(FakeSyscall(change=change))

    def test_invalid_deadlines_refuse_before_abi_loader_and_lookup(self):
        for deadline in (KERNEL.now() - 1, True, None, 'future', float('nan'), float('inf'), 10 ** 10000):
            with self.subTest(kind=type(deadline).__name__), patch.object(BPF, 'abi', side_effect=AssertionError('abi')), \
                    self.assertRaises(BPF.Pending):BPF.native_query(deadline)

    def test_expiration_during_loader_prevents_the_syscall(self):
        lookup = FakeSyscall();start = KERNEL.now();clock = [start]
        def loader(*args, **kwargs):clock[0] = start + 5;return SimpleNamespace(syscall=lookup)
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(BPF.ctypes, 'CDLL', side_effect=loader), \
                self.assertRaises(BPF.Pending):BPF.native_query(start + 2)
        self.assertEqual(lookup.calls, [])

    def test_zero_start_enoent_after_query_deadline_never_certifies_empty(self):
        start = KERNEL.now();clock = [start]
        lookup = FakeSyscall(change=lambda attr: clock.__setitem__(0, start + KERNEL.QUERY_SECONDS))
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(BPF.Pending):self.query(lookup, deadline=start + 5)
        self.assertEqual(len(lookup.calls), 1)

    def test_inherited_shorter_query_deadline_is_not_widened(self):
        start = KERNEL.now();clock = [start]
        lookup = FakeSyscall(change=lambda attr: clock.__setitem__(0, start + 0.5))
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(BPF.Pending):self.query(lookup, deadline=start + 0.5)

    def test_abi_change_after_return_is_not_a_stable_source(self):
        first = BPF.abi();second = first | {'syscall': first['syscall'] + 1}
        with patch.object(BPF, 'abi', side_effect=[first, second]), self.assertRaises(BPF.Pending):self.query()

    def test_unavailable_libc_or_missing_syscall_interface_cannot_succeed(self):
        with patch.object(BPF.ctypes, 'CDLL', side_effect=OSError('unavailable')), self.assertRaises(OSError):BPF.native_query(KERNEL.now() + 5)
        with patch.object(BPF.ctypes, 'CDLL', return_value=SimpleNamespace()), self.assertRaises(AttributeError):BPF.native_query(KERNEL.now() + 5)


class ObservationTests(unittest.TestCase):
    def observe(self, **overrides):
        settings = {'query': lambda deadline: empty_lookup()};settings.update(overrides)
        return BPF.observe(**settings)

    def test_two_positive_lookups_share_one_window_and_caller_namespace(self):
        seen = [];result = self.observe(query=lambda deadline: seen.append(deadline) or empty_lookup())
        self.assertEqual(len(seen), 2);self.assertEqual(seen[0], seen[1])
        self.assertEqual(result['namespace'], KERNEL.namespace())
        self.assertEqual(result['lookup'], empty_lookup())
        self.assertEqual(result['profile'], 'global-link-id-zero-start-enoent-1')

    def test_invalid_attempt_never_reads_namespace_or_lookup(self):
        for deadline in (True, 'future', float('nan'), float('inf'), 10 ** 10000, KERNEL.now() - 1):
            with self.subTest(kind=type(deadline).__name__), self.assertRaises(BPF.Pending):
                self.observe(deadline=deadline, scope=lambda: self.fail('scope'), query=lambda deadline: self.fail('lookup'))

    def test_inherited_window_is_capped_without_widening(self):
        start = KERNEL.now()
        for seconds in (1, 1000):
            seen = []
            with patch.object(KERNEL, 'now', return_value=start):self.observe(deadline=start + seconds, query=lambda deadline: seen.append(deadline) or empty_lookup())
            self.assertEqual(seen, [start + min(seconds, BPF.ATTEMPT_SECONDS)] * 2)

    def test_zero_boolean_and_noninteger_namespace_refuse_before_lookup(self):
        for namespace in (0, True, False, '1', None, 1 << 64):
            with self.subTest(namespace=namespace), self.assertRaises(BPF.Pending):self.observe(scope=lambda: namespace, query=lambda deadline: self.fail('lookup'))

    def test_namespace_change_or_boolean_final_namespace_withholds_receipt(self):
        for last in (2, True, '1', None):
            readings = iter([1, last])
            with self.subTest(last=last), self.assertRaises(BPF.Pending):self.observe(scope=lambda: next(readings))

    def test_scope_exhaustion_prevents_first_lookup(self):
        clock = [KERNEL.now()]
        def scope():clock[0] += BPF.ATTEMPT_SECONDS;return 1
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(BPF.Pending):self.observe(scope=scope, query=lambda deadline: self.fail('lookup'))

    def test_lookup_expiry_prevents_second_lookup_and_final_publication(self):
        clock = [KERNEL.now()];seen = []
        def query(deadline):seen.append(deadline);clock[0] = deadline;return empty_lookup()
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(BPF.Pending):self.observe(query=query)
        self.assertEqual(len(seen), 1)

    def test_first_or_second_unknown_failed_or_present_delivery_never_becomes_empty(self):
        for index in (0, 1):
            for bad in (None, {}, empty_lookup() | {'errno': errno.EPERM}, empty_lookup() | {'result': 0, 'next_id': 1}):
                values = [empty_lookup(), empty_lookup()];values[index] = bad;iterator = iter(values)
                with self.subTest(index=index, bad=bad), self.assertRaises(BPF.Pending):self.observe(query=lambda deadline: next(iterator))

    def test_query_io_failure_is_not_converted_into_an_empty_receipt(self):
        def failed(deadline):raise OSError('unverifiable')
        with self.assertRaises(OSError):self.observe(query=failed)

    def test_callback_mutation_cannot_rewrite_the_first_private_source_record(self):
        delivery = empty_lookup();calls = [0]
        def query(deadline):
            calls[0] += 1
            if calls[0] == 2:delivery['source']['command'] = 5
            return delivery
        with self.assertRaises(BPF.Pending):self.observe(query=query)
        self.assertEqual(calls[0], 2)


class ReceiptTests(unittest.TestCase):
    def receipt(self):return BPF.observe(query=lambda deadline: empty_lookup())

    def test_complete_receipt_returns_a_deep_private_source_copy(self):
        original = self.receipt();value = BPF.validate_receipt(original)
        original['lookup']['source']['command'] = 5
        self.assertEqual(value['lookup']['source']['command'], 31)
        self.assertIsNot(value['lookup'], original['lookup'])

    def test_missing_extra_schema_profile_and_namespace_fields_refuse(self):
        receipt = self.receipt()
        for key in receipt:
            value = copy.deepcopy(receipt);del value[key]
            with self.subTest(key=key), self.assertRaises(BPF.Pending):BPF.validate_receipt(value)
        for key, value in (('schema', 'other'), ('profile', 'other'), ('namespace', True), ('namespace', 0), ('extra', 1)):
            with self.subTest(key=key), self.assertRaises(BPF.Pending):BPF.validate_receipt(receipt | {key: value})

    def test_zero_result_wrong_errno_boolean_result_and_nonzero_next_are_not_receipts(self):
        for key, bad in (('result', 0), ('result', True), ('errno', errno.EPERM), ('errno', True), ('next_id', True), ('next_id', 1)):
            value = self.receipt();value['lookup'][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(BPF.Pending):BPF.validate_receipt(value)

    def test_foreign_command_architecture_id_size_and_incomplete_lookup_refuse(self):
        for key, bad in (('interface', 'bpftool'), ('machine', 'riscv64'), ('syscall', 0), ('command', 5), ('start_id', 1), ('attr_bytes', 16), ('start_id', False)):
            value = self.receipt();value['lookup']['source'][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(BPF.Pending):BPF.validate_receipt(value)
        for path in ('lookup', 'source'):
            value = self.receipt();target = value['lookup'] if path == 'lookup' else value['lookup']['source'];target['extra'] = 1
            with self.subTest(path=path), self.assertRaises(BPF.Pending):BPF.validate_receipt(value)


class CLITests(unittest.TestCase):
    def test_missing_native_syscall_symbol_is_pending_before_any_healthy_bytes(self):
        raw = io.BytesIO();out = io.TextIOWrapper(raw, encoding='utf-8');err = io.StringIO()
        with patch.object(BPF.ctypes, 'CDLL', return_value=SimpleNamespace()), \
                patch.object(BPF.sys, 'argv', ['bpf_links.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(BPF.main(), 75)
        self.assertEqual(raw.getvalue(), b'')
        self.assertIn('pending', err.getvalue())

    def test_program_receipts_and_other_link_operations_cannot_certify_link_absence(self):
        value = BPF.observe(query=lambda deadline: empty_lookup(), scope=lambda: 99)
        program = BPF.COMMON.observe(query=lambda deadline: {'source': BPF.COMMON.abi(),
                                       'result': -1, 'errno': errno.ENOENT, 'next_id': 0}, scope=lambda: 99)
        with self.assertRaises(BPF.Pending):BPF.validate_receipt(program)
        with self.assertRaises(BPF.COMMON.Pending):BPF.COMMON.validate_receipt(value)
        for command in (11, 12, 28, 29, 30, 32, True):
            changed = copy.deepcopy(value);changed['lookup']['source']['command'] = command
            with self.subTest(command=command), self.assertRaises(BPF.Pending):BPF.validate_receipt(changed)

    def execute(self, lookup=None, sink=None, encoding='utf-8', errors='strict'):
        raw = io.BytesIO()
        out = SimpleNamespace(buffer=sink) if sink is not None else io.TextIOWrapper(raw, encoding=encoding, errors=errors)
        lookup = lookup or FakeSyscall();err = io.StringIO()
        with patch.object(BPF.ctypes, 'CDLL', return_value=SimpleNamespace(syscall=lookup)), \
                patch.object(BPF.sys, 'argv', ['bpf_links.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = BPF.main()
        payload = raw.getvalue();out = None
        return result, payload, err.getvalue(), lookup

    def test_complete_native_predicate_emits_actual_utf8_bytes_under_other_text_encodings(self):
        for encoding, errors in (('utf-8', 'strict'), ('utf-32', 'strict'), ('ascii', 'replace'), ('ascii', 'ignore')):
            with self.subTest(encoding=encoding, errors=errors):
                result, payload, err, lookup = self.execute(encoding=encoding, errors=errors)
                self.assertEqual(result, 0);self.assertEqual(err, '')
                self.assertEqual(len(lookup.calls), 2);self.assertTrue(payload.endswith(b'\n'))
                self.assertLessEqual(len(payload), BPF.MAX_BYTES)
                self.assertEqual(json.loads(payload), BPF.validate_receipt(json.loads(payload)))

    def test_arguments_and_text_only_sink_refuse_before_any_syscall(self):
        with patch.object(BPF.sys, 'argv', ['bpf_links.py', 'load']), patch.object(BPF.ctypes, 'CDLL', side_effect=AssertionError('libc')):self.assertEqual(BPF.main(), 64)
        with patch.object(BPF.sys, 'argv', ['bpf_links.py']), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                patch.object(BPF.ctypes, 'CDLL', side_effect=AssertionError('libc')):self.assertEqual(BPF.main(), 75)

    def test_short_unknown_boolean_and_overlong_write_counts_cannot_report_success(self):
        for count in (0, None, True, 'full', 999999):
            sink = SimpleNamespace(write=lambda payload, count=count: count, flush=lambda: self.fail('must not flush'))
            with self.subTest(count=count):
                result, payload, err, lookup = self.execute(sink=sink)
                self.assertEqual(result, 75);self.assertEqual(len(lookup.calls), 2);self.assertIn('pending', err)

    def test_write_and_flush_errors_withhold_success_after_real_observation(self):
        def failed(*args):raise OSError('delivery')
        for sink in (SimpleNamespace(write=failed, flush=lambda: None), SimpleNamespace(write=lambda payload: len(payload), flush=failed)):
            result, payload, err, lookup = self.execute(sink=sink)
            self.assertEqual(result, 75);self.assertEqual(len(lookup.calls), 2);self.assertIn('pending', err)

    def test_real_successful_id_and_permission_failure_have_no_healthy_cli_bytes(self):
        for lookup in (FakeSyscall(result=0, error=0, change=lambda attr: setattr(attr.ids, 'next_id', 1)), FakeSyscall(error=errno.EPERM)):
            result, payload, err, observed = self.execute(lookup)
            self.assertEqual(result, 75);self.assertEqual(payload, b'');self.assertEqual(len(observed.calls), 1)

    def test_unavailable_native_interface_is_pending_without_bytes(self):
        out = io.TextIOWrapper(io.BytesIO(), encoding='utf-8');err = io.StringIO()
        with patch.object(BPF.ctypes, 'CDLL', side_effect=OSError('unavailable')), patch.object(BPF.sys, 'argv', ['bpf_links.py']), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(BPF.main(), 75)
        self.assertEqual(out.buffer.getvalue(), b'');self.assertIn('pending', err.getvalue())

    def test_separate_interpreter_pipe_bytes_preserve_utf8_with_explicit_syscall_substitution(self):
        with tempfile.TemporaryDirectory(prefix='debian13s4-bpf-link-cli-', dir='/dev/shm') as directory:
            driver = Path(directory) / 'driver.py'
            driver.write_text("import ctypes,errno,importlib.util,sys\nfrom pathlib import Path\nfrom types import SimpleNamespace\nfrom unittest.mock import patch\n"
                f"spec=importlib.util.spec_from_file_location('bpf_cli',Path({str(ROOT / 'Firewall/bpf_links.py')!r}));bpf=importlib.util.module_from_spec(spec);spec.loader.exec_module(bpf)\n"
                "calls=[]\nclass Lookup:\n def __call__(self,number,command,pointer,length):\n  attr=ctypes.cast(pointer,ctypes.POINTER(bpf.IdAttr)).contents\n  assert command.value==31 and length.value==12 and bytes(attr)==bytes(16)\n  calls.append(command.value);ctypes.set_errno(errno.ENOENT);return -1\n"
                "with patch.object(bpf.ctypes,'CDLL',return_value=SimpleNamespace(syscall=Lookup())),patch.object(bpf.sys,'argv',['bpf_links.py']):\n result=bpf.main()\nassert calls==[31,31]\nraise SystemExit(result)\n")
            for encoding in ('utf-8', 'utf-32', 'ascii:replace', 'ascii:ignore'):
                environment = os.environ.copy();environment['PYTHONIOENCODING'] = encoding
                completed = subprocess.run([sys.executable, '-B', str(driver)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=10)
                with self.subTest(encoding=encoding):
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stderr, b'');self.assertTrue(completed.stdout.endswith(b'\n'))
                    self.assertLessEqual(len(completed.stdout), BPF.MAX_BYTES)
                    self.assertEqual(json.loads(completed.stdout.decode('utf-8'))['lookup'], empty_lookup())


if __name__ == '__main__':unittest.main()
