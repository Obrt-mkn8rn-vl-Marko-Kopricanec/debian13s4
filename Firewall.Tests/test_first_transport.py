import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

import test_first_create as plan_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_transport', ROOT / 'Firewall/first_transport.py')
TRANSPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSPORT)
KERNEL, STATE = TRANSPORT.KERNEL, TRANSPORT.STATE


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.helper = plan_fixture.PlanTests();self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        self.payload = self.helper.prepare();self.plan = json.loads(self.payload)
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-transport-', dir='/dev/shm')
        self.addCleanup(directory.cleanup);self.root = Path(directory.name);self.root.chmod(0o700)
        self.binary, self.input, self.ledger = self.root / 'nft', self.root / 'input', self.root / 'ledger'
        for setting in (patch.object(TRANSPORT, 'BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.root),
                        patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())):
            setting.start();self.addCleanup(setting.stop)
        self.executable()

    def executable(self, after='', before=''):
        self.binary.write_text('#!/usr/bin/python3 -B\nimport json,os,sys,time\n' + before + '\n' +
            'data=sys.stdin.buffer.read()\n' + f'open({str(self.input)!r},"wb").write(data)\n' +
            f'open({str(self.ledger)!r},"w").write(json.dumps([sys.argv[1:],dict(os.environ),os.getpid(),os.getsid(0)]))\n' + after + '\n')
        self.binary.chmod(0o700)

    def transmit(self, **settings):return TRANSPORT.transmit(self.payload, **settings)

    def test_real_checker_compiler_and_byte_delivery_bind_complete_original_transaction(self):
        raw = self.transmit();value = json.loads(raw)
        self.assertIs(type(raw), bytes);self.assertEqual(raw, STATE.encoded(value) + b'\n')
        self.assertEqual(self.input.read_bytes(), self.plan['transaction'].encode('utf-8'))
        self.assertEqual(value['schema'], 'debian13s4-first-create-native-transport-1')
        self.assertEqual(value['state'], 'native-zero-exit-empty-capture')
        self.assertEqual(value['profile'], 'checked-historical-first-create-batch-1')
        self.assertEqual(value['input_bytes'], len(self.input.read_bytes()))
        self.assertEqual(value['proposal_sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(value['namespace'], self.plan['namespace']);self.assertEqual(value['correlation_id'], self.plan['correlation_id'])
        self.assertEqual(value['transaction_sha256'], self.plan['transaction_sha256'])
        self.assertLessEqual(len(raw), TRANSPORT.MAX_RECEIPT)

    def test_fixed_mutating_file_stdin_profile_clears_environment_and_inherited_descriptors(self):
        fd = os.open(self.root / 'inherited', os.O_CREAT | os.O_RDWR, 0o600);os.set_inheritable(fd, True)
        probe = self.root / 'probe'
        self.executable(f'try:\n os.fstat({fd});leaked=True\nexcept OSError:\n leaked=False\nopen({str(probe)!r},"w").write(json.dumps(leaked))')
        try:
            with patch.dict(os.environ, {'NFT_CTX_FLAGS': 'bad', 'TASK_SECRET': 'private', 'PYTHONIOENCODING': 'utf-32'}):self.transmit()
            argv, environment, pid, session = json.loads(self.ledger.read_bytes())
            self.assertEqual(argv, ['--file', '-']);self.assertEqual(pid, session)
            self.assertFalse(json.loads(probe.read_bytes()))
            self.assertFalse(set(environment) & {'NFT_CTX_FLAGS', 'TASK_SECRET', 'PYTHONIOENCODING'})
            self.assertEqual(environment['LC_ALL'], 'C');self.assertEqual(environment['PATH'], '/usr/bin:/usr/sbin')
        finally:os.close(fd)

    def test_actual_short_input_writes_still_deliver_exact_bytes_before_checked_eof(self):
        write = TRANSPORT.os.write;counts = []
        def short(fd, raw):
            count = write(fd, raw[:13]);counts.append(count);return count
        with patch.object(TRANSPORT.os, 'write', side_effect=short):self.transmit()
        self.assertGreater(len(counts), 1);self.assertEqual(sum(counts), len(self.plan['transaction'].encode()))
        self.assertEqual(self.input.read_bytes(), self.plan['transaction'].encode())

    def test_unicode_native_path_retains_explicit_utf8_receipt_and_binary_input(self):
        target = self.root / 'nft-é';self.binary.rename(target);self.binary = target
        with patch.object(TRANSPORT, 'BINARY', target):raw = self.transmit()
        self.assertIn('nft-é'.encode(), raw);self.assertEqual(json.loads(raw)['source']['binary'], str(target))
        self.assertEqual(self.input.read_bytes(), self.plan['transaction'].encode())

    def test_invalid_byte_delivery_and_noncanonical_history_refuse_before_spawn(self):
        class Bytes(bytes):pass
        for raw in (None, {}, self.payload.decode(), bytearray(self.payload), memoryview(self.payload), Bytes(self.payload), b'', b'broken', self.payload.rstrip()):
            with self.subTest(kind=type(raw).__name__), patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):
                TRANSPORT.transmit(raw)

    def test_rehashed_destructive_include_and_wrong_intention_cannot_reach_native_entry(self):
        for transaction in ('flush ruleset\n', 'include "/tmp/foreign"\n', 'destroy table inet debian13s4\n', self.plan['transaction'] + 'delete table inet foreign\n'):
            value = copy.deepcopy(self.plan);value.update(transaction=transaction, transaction_sha256=hashlib.sha256(transaction.encode()).hexdigest())
            with self.subTest(transaction=transaction), patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):
                TRANSPORT.transmit(STATE.encoded(value) + b'\n')
        value = copy.deepcopy(self.plan);value['intention']['policy']['chains']['input']['policy'] = 'accept'
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):TRANSPORT.transmit(STATE.encoded(value) + b'\n')

    def test_invalid_deadline_admission_precedes_checker_and_native_entry(self):
        for deadline in (True, False, float('nan'), float('inf'), 'later', KERNEL.now() - 1, 10 ** 10000):
            with self.subTest(kind=type(deadline).__name__), patch.object(TRANSPORT.MATCH, 'checked', side_effect=AssertionError('checker')), self.assertRaises(ValueError):
                self.transmit(deadline=deadline)

    def test_invalid_or_foreign_historical_namespace_refuses_before_entry(self):
        for context in (True, False, 0, -1, 1 << 64, '1', None):
            with self.subTest(context=context), patch.object(KERNEL, 'namespace', return_value=context), patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):self.transmit()
        value = self.plan | {'namespace': self.plan['namespace'] + 1}
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):TRANSPORT.transmit(STATE.encoded(value) + b'\n')

    def test_no_caller_binary_argv_executor_scope_or_config_override_is_available(self):
        for name in ('binary', 'argv', 'executor', 'scope', 'topology', 'config'):
            with self.subTest(name=name), patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(TypeError):self.transmit(**{name: lambda: None})

    def test_missing_symbolic_unsafe_binary_and_ancestry_refuse_before_spawn(self):
        self.binary.unlink()
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(OSError):self.transmit()
        actual = self.root / 'actual';actual.write_bytes(b'fixture');actual.chmod(0o700);self.binary.symlink_to(actual)
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):self.transmit()
        self.binary.unlink();self.executable()
        for path in (self.binary, self.root):
            path.chmod(0o720)
            with self.subTest(path=path), patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):self.transmit()
            path.chmod(0o700)

    def test_receipt_bound_and_encoding_expiry_refuse_before_spawn(self):
        with patch.object(TRANSPORT, 'MAX_RECEIPT', 1), patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):self.transmit()
        start = KERNEL.now();clock = [start];encoded = STATE.encoded
        def expired(value):
            raw = encoded(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-native-transport-1':clock[0] += 11
            return raw
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(STATE, 'encoded', side_effect=expired), patch.object(TRANSPORT.subprocess, 'Popen', side_effect=AssertionError('spawn')), self.assertRaises(ValueError):self.transmit()

    def test_inherited_transport_and_native_windows_are_never_widened(self):
        start = KERNEL.now();delivered = []
        with patch.object(KERNEL, 'now', return_value=start), patch.object(TRANSPORT, '_deliver', side_effect=lambda raw, identity, context, end: delivered.append(end) or b'model'):
            self.transmit(deadline=start + 2);self.transmit(deadline=start + 100)
        self.assertEqual(delivered, [start + 2, start + TRANSPORT.ATTEMPT_SECONDS])

    def test_all_hashing_and_encoding_precedes_attempt_and_no_work_follows_final_context(self):
        started = [];spawn, encoded, digest = TRANSPORT.subprocess.Popen, STATE.encoded, hashlib.sha256
        def process(*args, **kwargs):started.append(True);return spawn(*args, **kwargs)
        def encode(value):self.assertFalse(started);return encoded(value)
        def sha(value):self.assertFalse(started);return digest(value)
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=process), patch.object(STATE, 'encoded', side_effect=encode), patch.object(hashlib, 'sha256', side_effect=sha):raw = self.transmit()
        self.assertIs(type(raw), bytes);self.assertEqual(started, [True])

    def test_nonzero_exit_stdout_or_warning_is_uncertain_not_unchanged_or_retry(self):
        for body in ('raise SystemExit(1)', 'os.write(1,b"unexpected")', 'os.write(2,b"warning")'):
            self.executable(body)
            with self.subTest(body=body), patch.object(TRANSPORT.subprocess, 'Popen', wraps=TRANSPORT.subprocess.Popen) as spawn, self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
            self.assertEqual(spawn.call_count, 1);self.assertEqual(caught.exception.evidence['input_written'], len(self.plan['transaction'].encode()))
            self.assertEqual(caught.exception.evidence['input'], self.plan['transaction'].encode())

    def test_raw_invalid_utf8_and_crlf_capture_never_decodes_or_reencodes(self):
        out, err = b'out\r\n\xff\xe2\x82', b'err\r\xff\r\n'
        self.executable(f'os.write(1,{out!r});os.write(2,{err!r})')
        with self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertEqual(caught.exception.evidence['stdout'], out);self.assertEqual(caught.exception.evidence['stderr'], err)
        self.assertEqual(caught.exception.evidence['returncode'], 0)

    def test_both_capture_channels_are_independently_bounded_exact_prefixes(self):
        for channel, label in ((1, 'stdout'), (2, 'stderr')):
            self.executable(f'stream=sys.stdout.buffer if {channel}==1 else sys.stderr.buffer\nstream.write(b"x"*{TRANSPORT.MAX_BYTES+1});stream.flush()')
            with self.subTest(channel=channel), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
            self.assertEqual(caught.exception.evidence[label], b'x' * TRANSPORT.MAX_BYTES)
            self.assertGreater(caught.exception.evidence['received'][label], TRANSPORT.MAX_BYTES)
            self.assertLessEqual(len(caught.exception.evidence['stderr' if label == 'stdout' else 'stdout']), TRANSPORT.MAX_BYTES)

    def test_pipe_eof_does_not_admit_a_root_that_has_not_completed(self):
        self.executable('os.close(1);os.close(2);time.sleep(60)')
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.6), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertIsInstance(caught.exception.__cause__, TRANSPORT.subprocess.TimeoutExpired)
        self.assertEqual(caught.exception.evidence['stdout'], b'');self.assertEqual(caught.exception.evidence['stderr'], b'')

    def test_timeout_retains_original_raw_capture_input_command_and_actual_window(self):
        out, err = b'out\r\n\xff\xe2', b'err\r\n\xff'
        self.executable(f'os.write(1,{out!r});os.write(2,{err!r});time.sleep(60)')
        start = KERNEL.now();end = start + 10;entries = [];spawn = TRANSPORT.subprocess.Popen
        def entered(*args, **kwargs):entries.append(KERNEL.now());return spawn(*args, **kwargs)
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=entered), patch.object(KERNEL, 'QUERY_SECONDS', 0.6), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit(deadline=end)
        record = caught.exception.evidence
        self.assertEqual(record['stdout'], out);self.assertEqual(record['stderr'], err)
        self.assertEqual(record['command'], (str(self.binary), '--file', '-'))
        self.assertEqual(record['input'], self.plan['transaction'].encode());self.assertEqual(record['input_written'], len(record['input']))
        self.assertEqual(len(entries), 1);self.assertLessEqual(record['deadline'], end)
        self.assertLessEqual(record['deadline'], entries[0] + 0.6)

    def test_spawn_error_is_conservatively_uncertain_with_no_manufactured_exit(self):
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=OSError('spawn delivery')) as spawn, self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertEqual(spawn.call_count, 1);self.assertIsNone(caught.exception.evidence['returncode'])
        self.assertEqual(caught.exception.evidence['input_written'], 0);self.assertEqual(caught.exception.evidence['cleanup_errors'], ())

    def test_unknown_boolean_zero_negative_or_oversized_write_count_cannot_complete(self):
        for count in (None, True, 0, -1, 10 ** 6):
            with self.subTest(count=count), patch.object(TRANSPORT.os, 'write', return_value=count), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
            self.assertEqual(caught.exception.evidence['input_written'], 0)

    def test_early_stdin_close_cannot_be_a_completed_full_input_delivery(self):
        self.executable('raise SystemExit(1)', before='os.close(0)')
        with self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertIs(type(caught.exception.evidence['input_written']), int)
        self.assertLessEqual(caught.exception.evidence['input_written'], len(self.plan['transaction'].encode()))

    def test_binary_identity_drift_after_zero_exit_withholds_completion(self):
        trusted = KERNEL.trusted_binary;seen = []
        def changed(path):
            identity = trusted(path);seen.append(1);return identity if len(seen) == 1 else identity[:-1] + (identity[-1] + 1,)
        with patch.object(KERNEL, 'trusted_binary', side_effect=changed), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertEqual(len(seen), 2);self.assertEqual(caught.exception.evidence['returncode'], 0)

    def test_final_namespace_after_zero_exit_must_be_typed_equal(self):
        context = self.plan['namespace']
        for last in (True, '1', context + 1):
            with self.subTest(last=last), patch.object(KERNEL, 'namespace', side_effect=[context, context, last]), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
            self.assertEqual(caught.exception.evidence['returncode'], 0)

    def test_expiry_during_final_binary_check_is_uncertain_even_after_zero_exit(self):
        start = KERNEL.now();clock = [start];trusted = KERNEL.trusted_binary;seen = []
        def changed(path):
            result = trusted(path);seen.append(1)
            if len(seen) == 2:clock[0] += 4
            return result
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), patch.object(KERNEL, 'trusted_binary', side_effect=changed), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertEqual(caught.exception.evidence['returncode'], 0)

    def retired_close(self, label, timeout=False):
        spawn = TRANSPORT.subprocess.Popen;owned = [];resource = self.root / 'independent';resource.write_bytes(b'survives')
        class Retired:
            def __init__(self, stream):self.stream=stream;self.calls=0;self.reused=None
            def fileno(self):return self.stream.fileno()
            def close(self):
                self.calls += 1
                retired = self.stream.fileno();self.stream.close()
                fresh = os.open(resource, os.O_RDONLY)
                if fresh != retired:os.dup2(fresh, retired);os.close(fresh)
                self.reused = retired
                raise OSError('reported after actual pipe FD retirement/reuse')
        def opened(*args, **kwargs):
            process = spawn(*args, **kwargs);wrapper = Retired(getattr(process, label));setattr(process, label, wrapper);owned.append(wrapper);return process
        try:
            with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=opened), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
            self.assertEqual(len(owned), 1);self.assertEqual(owned[0].calls, 1)
            self.assertEqual(os.fstat(owned[0].reused).st_ino, resource.stat().st_ino)
            self.assertEqual(os.read(owned[0].reused, 8), b'survives')
            if timeout:self.assertTrue(caught.exception.evidence['cleanup_errors'])
            else:self.assertIn('retirement', str(caught.exception.__cause__))
        finally:
            for wrapper in owned:
                if wrapper.reused is not None:os.close(wrapper.reused)

    def test_checked_stdin_close_retires_ownership_once_and_preserves_reused_fd(self):self.retired_close('stdin')

    def test_checked_output_eof_close_retires_ownership_once_and_preserves_reused_fd(self):
        for label in ('stdout', 'stderr'):
            with self.subTest(label=label):self.retired_close(label)

    def test_cleanup_close_does_not_retry_retired_fd_and_cannot_upgrade_timeout(self):
        self.executable('time.sleep(60)')
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.6):self.retired_close('stdout', timeout=True)

    def test_cleanup_wait_error_retains_original_capture_failure_and_numeric_child_fact(self):
        self.executable('os.write(1,b"retained\\r\\n");time.sleep(60)');spawn = TRANSPORT.subprocess.Popen
        def opened(*args, **kwargs):
            process = spawn(*args, **kwargs);wait = process.wait
            def retired(timeout):wait(timeout=timeout);raise OSError('cleanup wait delivery')
            process.wait = retired;return process
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=opened), patch.object(KERNEL, 'QUERY_SECONDS', 0.6), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertEqual(caught.exception.evidence['stdout'], b'retained\r\n')
        self.assertEqual(caught.exception.evidence['returncode'], -signal.SIGKILL)
        self.assertEqual(caught.exception.evidence['cleanup_errors'], (('OSError', 'cleanup wait delivery'),))
        self.assertIsInstance(caught.exception.__cause__, TRANSPORT.Pending)

    def test_unreaped_leader_group_cleanup_signals_actual_owned_pipe_holder(self):
        marker = self.root / 'child';signals = [];kill = TRANSPORT.os.killpg
        self.executable(f'pid=os.fork()\nif pid:\n fields=open("/proc/"+str(pid)+"/stat").read().rsplit(")",1)[1].split()\n open({str(marker)!r},"w").write(json.dumps({{"pid":pid,"start":fields[19],"group":os.getpgid(pid),"session":os.getsid(pid)}}))\n os._exit(0)\ntime.sleep(60)')
        def signalled(group, value):signals.append((group,value));return kill(group,value)
        with patch.object(TRANSPORT.os, 'killpg', side_effect=signalled), patch.object(KERNEL, 'QUERY_SECONDS', 0.6), self.assertRaises(TRANSPORT.Uncertain):self.transmit()
        self.assertTrue(marker.exists());owned = json.loads(marker.read_bytes())
        self.assertEqual(owned['group'], owned['session']);self.assertIn((owned['group'], signal.SIGKILL), signals)
        fields = Path('/proc/' + str(owned['pid']) + '/stat')
        for _ in range(100):
            try:
                row = fields.read_text().rsplit(')',1)[1].split()
                if row[19] != owned['start'] or row[0] == 'Z':break
            except FileNotFoundError:break
            time.sleep(0.01)
        else:self.fail('recorded owned pipe holder remains live')

    def test_output_before_input_is_drained_concurrently_and_still_retains_exact_input(self):
        out, err = b'out\r\n' * 18000, b'err\r\n' * 18000
        self.executable(before=f'sys.stdout.buffer.write({out!r});sys.stdout.buffer.flush()\nsys.stderr.buffer.write({err!r});sys.stderr.buffer.flush()')
        with self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertEqual(self.input.read_bytes(), self.plan['transaction'].encode())
        self.assertEqual(caught.exception.evidence['stdout'], out);self.assertEqual(caught.exception.evidence['stderr'], err)
        self.assertEqual(caught.exception.evidence['returncode'], 0)

    def test_boolean_wait_delivery_cannot_be_a_verified_native_zero_exit(self):
        spawn = TRANSPORT.subprocess.Popen
        def opened(*args, **kwargs):
            process = spawn(*args, **kwargs);wait = process.wait
            def boolean(timeout):wait(timeout=timeout);return False
            process.wait = boolean;return process
        with patch.object(TRANSPORT.subprocess, 'Popen', side_effect=opened), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertIs(type(caught.exception.evidence['returncode']), int)
        self.assertEqual(caught.exception.evidence['returncode'], 0)

    def test_cancellation_after_actual_partial_write_preserves_uncertainty_and_cause(self):
        write = TRANSPORT.os.write;actual = []
        def interrupted(fd, data):actual.append(write(fd, data[:13]));raise KeyboardInterrupt('private delivery interruption')
        with patch.object(TRANSPORT.os, 'write', side_effect=interrupted), self.assertRaises(TRANSPORT.Uncertain) as caught:self.transmit()
        self.assertEqual(actual, [13]);self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        # The interrupted call returned NO count to the transport. Zero here is
        # its reported-count ledger, NOT proof that the pipe/native state is empty.
        self.assertEqual(caught.exception.evidence['input_written'], 0)
        self.assertEqual(caught.exception.evidence['input'], self.plan['transaction'].encode())

    def test_native_uncertainty_bypasses_retryable_pre_entry_pending_handlers(self):
        self.executable('os.write(2,b"warning")');route = [];caught = None
        with patch.object(TRANSPORT.subprocess, 'Popen', wraps=TRANSPORT.subprocess.Popen) as spawn:
            try:self.transmit()
            except TRANSPORT.Pending as error:route.append('retryable-pending');caught = error
            except TRANSPORT.Uncertain as error:route.append('uncertain');caught = error
        self.assertEqual(route, ['uncertain'], {'route':route,'returncode':caught.evidence['returncode'],
            'stderr':caught.evidence['stderr'],'input_written':caught.evidence['input_written']})
        self.assertEqual(spawn.call_count, 1);self.assertEqual(caught.evidence['returncode'], 0)
        self.assertEqual(caught.evidence['stderr'], b'warning')
        self.assertEqual(caught.evidence['input'], self.plan['transaction'].encode())
        self.assertEqual(self.input.read_bytes(), caught.evidence['input'])


if __name__ == '__main__':unittest.main()
