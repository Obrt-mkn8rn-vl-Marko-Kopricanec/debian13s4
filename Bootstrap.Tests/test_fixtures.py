import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest

from fixture_process import run_bash, session_processes
from fixture_snapshots import SnapshotStore


if os.geteuid() == 0:
    raise RuntimeError('Run private fixture checks as an ordinary user.')


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-fixture-snapshots.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = SnapshotStore(self.root / 'objects')

    def test_repeated_full_payload_has_one_immutable_object_and_small_metadata(self):
        data = 'payload\n' * 20000
        refs = [self.store.text(data) for _ in range(40)]
        expected = hashlib.sha256(data.encode()).hexdigest()
        self.assertEqual(list(self.store.directory.iterdir()), [self.store.directory / expected])
        self.assertEqual((self.store.directory / expected).read_bytes(), data.encode())
        self.assertLess(len(json.dumps(refs)), len(json.dumps([data] * 40)) // 100)
        self.assertEqual(self.store.expand(refs), [data] * 40)

    def test_references_preserve_before_and_after_bytes_when_live_file_is_deleted(self):
        path = self.root / 'live'
        before = 'old\n\x00héllo\n'; after = 'replacement\n'
        path.write_text(before)
        first = self.store.text(path.read_text())
        path.write_text(after)
        second = self.store.text(path.read_text()); path.unlink()
        self.assertNotEqual(first, second)
        self.assertEqual(self.store.expand({'before': first, 'after': second}),
                         {'before': before, 'after': after})

    def test_all_four_scopes_and_event_fields_keep_their_full_logical_view(self):
        expected = {'disk': {'state': {'status': 'pending\n'}, 'boot': {'setup.sh': 'code\n'},
                             'library': {'worker': 'code\n'}, 'units': {'unit': 'unit\n'},
                             'boot_enabled': True, 'timer_enabled': False},
                    'faults': {'sync': True}, 'active': {}, 'sync_counts': {'arm': 2}}
        encoded = self.store.compact_state(copy.deepcopy(expected))
        self.assertEqual(self.store.expand(encoded), expected)
        before = copy.deepcopy(encoded)
        encoded['disk']['state']['status'] = self.store.text('complete\n')
        events = [{'before': before, 'after': encoded, 'library': encoded['disk']['library'],
                   'pending': 'pending\n', 'code': 1, 'stage': 'manifest'}]
        decoded = self.store.expand(json.loads(json.dumps(events)))
        self.assertEqual(decoded[0]['before'], expected)
        self.assertEqual(decoded[0]['after']['disk']['state']['status'], 'complete\n')
        self.assertEqual(decoded[0]['library'], {'worker': 'code\n'})
        self.assertEqual((decoded[0]['code'], decoded[0]['pending'], decoded[0]['stage']),
                         (1, 'pending\n', 'manifest'))

    def test_missing_corrupt_and_malformed_references_fail_instead_of_inventing_bytes(self):
        ref = self.store.text('original\n'); path = self.store.directory / ref[self.store.TAG]
        path.unlink()
        with self.assertRaises(FileNotFoundError): self.store.expand(ref)
        path.write_bytes(b'wrong\n')
        with self.assertRaisesRegex(ValueError, 'corrupt'): self.store.expand(ref)
        with self.assertRaisesRegex(ValueError, 'changed'): self.store.text('original\n')
        for bad in ({self.store.TAG: '../outside'}, {self.store.TAG: 7},
                    {self.store.TAG: '0' * 64, 'other': 'data'}):
            with self.subTest(reference=bad), self.assertRaises(ValueError): self.store.expand(bad)

    def test_invalid_utf8_object_is_not_a_valid_text_snapshot(self):
        data = b'\xff'; digest = hashlib.sha256(data).hexdigest()
        (self.store.directory / digest).write_bytes(data)
        with self.assertRaises(UnicodeDecodeError): self.store.expand({self.store.TAG: digest})


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-fixture-process.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ready = self.root / 'ready.json'; self.writes = self.root / 'writes'

    def writer(self, ending, redirect=False):
        code = '''
import json,os,signal,sys,time
from pathlib import Path
signal.signal(signal.SIGTERM,signal.SIG_IGN)
Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'session':os.getsid(0),'group':os.getpgrp()}))
while True:
    with Path(sys.argv[2]).open('ab') as stream:stream.write(b'x')
    time.sleep(.01)
'''
        command = ['timeout', '60s', 'python3', '-B', '-u', '-c', code, str(self.ready), str(self.writes)]
        return ' '.join(shlex.quote(arg) for arg in command) + (' >/dev/null 2>&1' if redirect else '') + ''' &
while [[ ! -s ''' + shlex.quote(str(self.ready)) + ''' ]]; do sleep .01; done
''' + ending

    def assert_stopped(self):
        record = json.loads(self.ready.read_text())
        self.assertNotEqual(record['session'], record['group'])
        self.assertEqual(session_processes(record['session']), [])
        size = self.writes.stat().st_size if self.writes.exists() else 0
        time.sleep(.05)
        self.assertEqual(self.writes.stat().st_size if self.writes.exists() else 0, size)

    def assert_timeout_bytes(self, stdout, stderr):
        self.ready.unlink(missing_ok=True)
        out = ''.join(f'\\{byte:03o}' for byte in stdout)
        err = ''.join(f'\\{byte:03o}' for byte in stderr)
        script = self.writer(f"printf '{out}'; printf '{err}' >&2; wait")
        try:
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                run_bash(script, 2)
        finally:
            self.assert_stopped()
        self.assertEqual(raised.exception.cmd, ['/bin/bash', '--noprofile', '--norc', '-c', script])
        self.assertEqual(raised.exception.timeout, 2)
        self.assertEqual(raised.exception.output, stdout)
        self.assertEqual(raised.exception.stdout, stdout)
        self.assertEqual(raised.exception.stderr, stderr)

    def test_timeout_preserves_cr_and_crlf_in_both_raw_captures(self):
        self.assert_timeout_bytes(b'out\r\nnext\rtail\n', b'err\r\nnext\rtail\n')

    def test_timeout_preserves_invalid_utf8_in_each_raw_capture(self):
        for stdout, stderr in ((b'\xff', b'err\n'), (b'out\n', b'\xff')):
            with self.subTest(stdout=stdout, stderr=stderr):
                self.assert_timeout_bytes(stdout, stderr)

    def test_timeout_preserves_partial_utf8_in_each_raw_capture(self):
        for stdout, stderr in ((b'\xe2\x82', b'err\n'), (b'out\n', b'\xf0\x9f')):
            with self.subTest(stdout=stdout, stderr=stderr):
                self.assert_timeout_bytes(stdout, stderr)

    def test_outer_timeout_stops_writing_descendants_in_native_timeout_group(self):
        script = self.writer("printf 'stdout-once\\n'; printf 'stderr-once\\n' >&2; wait")
        with self.assertRaises(subprocess.TimeoutExpired) as raised: run_bash(script, 2)
        self.assertEqual(raised.exception.timeout, 2)
        self.assertEqual(raised.exception.output, b'stdout-once\n')
        self.assertEqual(raised.exception.stderr, b'stderr-once\n')
        self.assert_stopped()

    def test_success_stops_background_writer_that_closed_its_capture_pipes(self):
        result = run_bash(self.writer("printf 'ok\\n'; exit 0", redirect=True), 5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'ok\n', ''))
        self.assert_stopped()

    def test_decode_exception_also_stops_background_writer_before_cleanup(self):
        with self.assertRaises(UnicodeDecodeError):
            run_bash(self.writer("printf '\\xff'; exit 0", redirect=True), 5)
        self.assert_stopped()

    def test_cleanup_leaves_callers_other_owned_session_alive(self):
        other = subprocess.Popen(['sleep', '30'], start_new_session=True)
        try:
            result = run_bash('true', 5)
            self.assertEqual(result.returncode, 0)
            self.assertIsNone(other.poll())
            self.assertEqual(os.getsid(other.pid), other.pid)
        finally:
            other.kill(); other.wait(timeout=5)

    def test_nonzero_completion_preserves_native_capture_and_arguments(self):
        script = "printf 'out\\n'; printf 'err\\n' >&2; exit 19"
        result = run_bash(script, 5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (19, 'out\n', 'err\n'))
        self.assertEqual(result.args, ['/bin/bash', '--noprofile', '--norc', '-c', script])


class TrustFixtureTests(unittest.TestCase):
    def setUp(self):
        # Import locally so discovery does not collect the original cases twice.
        from test_bootstrap import BootstrapTests
        self.fixture = BootstrapTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.parent = self.fixture.root / 'parent'
        self.parent.mkdir(mode=0o700)
        self.leaf = self.parent / 'leaf'
        self.leaf.write_text('untouched\n'); self.leaf.chmod(0o600)

    def check(self, additions):
        return self.fixture.run_script(self.fixture.harness(lock=False) + additions, timeout=5)

    def test_unsafe_ancestor_symbolic_leaf_and_path_aliases_still_fail(self):
        original = self.leaf.stat()
        for mode in (0o720, 0o702):
            self.parent.chmod(mode)
            result = self.check(f'\ns4b_trusted {shlex.quote(str(self.leaf))}\n')
            self.assertNotEqual(result.returncode, 0)
        self.parent.chmod(0o700)
        alias = self.parent / 'alias'; alias.symlink_to(self.leaf)
        for name in (str(alias), str(self.parent) + '/../parent/leaf',
                     str(self.parent) + '/./leaf', str(self.parent) + '//leaf'):
            result = self.check(f'\ns4b_trusted {shlex.quote(name)}\n')
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.leaf.read_text(), 'untouched\n')
        self.assertEqual((self.leaf.stat().st_dev, self.leaf.stat().st_ino),
                         (original.st_dev, original.st_ino))

    def test_missing_extra_invalid_or_failed_native_mode_delivery_fails_closed(self):
        deliveries = ("return 1", "printf '600\\n'", "printf '600\\n700\\n700\\n700\\n'",
                      "printf '600\\n700\\ninvalid\\n'")
        for delivery in deliveries:
            with self.subTest(delivery=delivery):
                result = self.check(f'''\nstat() {{ {delivery}; }}
s4b_trusted {shlex.quote(str(self.leaf))}
''')
                self.assertNotEqual(result.returncode, 0)

    def test_valid_native_delivery_covers_every_ancestor_in_one_call(self):
        record = self.fixture.root / 'stat-arguments'
        result = self.check(f'''\nstat() {{
    printf '%s\\0' "$@" >> {shlex.quote(str(record))}
    /usr/bin/stat "$@"
}}
s4b_trusted {shlex.quote(str(self.leaf))}
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record.read_bytes().split(b'\x00')[:-1],
                         [os.fsencode(arg) for arg in ('--format=%a', '--', str(self.leaf),
                                                       str(self.parent), str(self.fixture.root))])


if __name__ == '__main__':
    unittest.main()
