import contextlib
import copy
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_legacy', ROOT / 'Firewall/legacy.py')
LEGACY = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(LEGACY)
KERNEL = LEGACY.KERNEL


class PrivateViews(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-legacy-', dir='/dev/shm')
        self.root = Path(self.directory.name);self.proc = self.root / 'proc';self.net = self.proc / str(os.getpid()) / 'net'
        self.net.mkdir(parents=True)
        for path in (self.proc, self.net.parent, self.net):path.chmod(0o700)
        for name in LEGACY.FILES:self.leaf(name).write_bytes(b'');self.leaf(name).chmod(0o440)
        self.settings = [patch.object(LEGACY, 'PROC', self.proc), patch.object(LEGACY, 'TRUST_ROOT', self.root),
                         patch.object(LEGACY, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def leaf(self, name=None):return self.net / (name or LEGACY.FILES[0])
    def write(self, data, name=None):
        path = self.leaf(name);path.chmod(0o640);path.write_bytes(data);path.chmod(0o440)
    def read(self, **kwargs):
        # Files and all path/FD/read/deadline predicates are real. Only the
        # synthetic fixture's filesystem type is substituted for procfs.
        with patch.object(LEGACY, 'filesystem', **kwargs):return LEGACY.read_views(KERNEL.now() + 10)
    def record(self):return self.read()


class FilesystemTests(unittest.TestCase):
    def test_native_abi_layout_matches_supported_lp64_contract(self):
        self.assertEqual(ctypes.sizeof(LEGACY.StatFS), 120);self.assertEqual(LEGACY.StatFS.type.offset, 0)
        self.assertEqual(LEGACY.StatFS.fsid.offset, 56);self.assertEqual(LEGACY.StatFS.spare.offset, 88)

    def test_real_own_process_proc_descriptor_is_procfs(self):
        fd = os.open('/proc/' + str(os.getpid()) + '/stat', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:self.assertIsNone(LEGACY.filesystem(fd))
        finally:os.close(fd)

    def test_real_private_tmpfs_descriptor_cannot_stand_in_for_procfs(self):
        with tempfile.TemporaryFile(dir='/dev/shm') as stream:
            with self.assertRaisesRegex(LEGACY.Pending, 'not on procfs'):LEGACY.filesystem(stream.fileno())

    def test_invalid_native_descriptor_preserves_observable_errno(self):
        with self.assertRaises(OSError) as captured:LEGACY.filesystem(-1)
        self.assertEqual(captured.exception.errno, errno.EBADF)

    def test_unsupported_abi_refuses_before_native_delivery(self):
        for settings in ({'platform': 'other'}, {'machine': 'i686'}, {'machine': 's390x'}, {'size': 4}):
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(LEGACY.ctypes, 'CDLL', side_effect=AssertionError('native call')))
                if 'platform' in settings:stack.enter_context(patch.object(LEGACY.sys, 'platform', settings['platform']))
                if 'machine' in settings:stack.enter_context(patch.object(LEGACY.platform, 'machine', return_value=settings['machine']))
                if 'size' in settings:stack.enter_context(patch.object(LEGACY.ctypes, 'sizeof', return_value=settings['size']))
                with self.subTest(settings=settings), self.assertRaises(LEGACY.Pending):LEGACY.filesystem(-1)


class ReadTests(PrivateViews):
    def test_complete_empty_views_use_exact_relative_read_only_paths_and_private_fds(self):
        opened = [];native_open = os.open;native_close = os.close;closed = []
        def tracked(path, flags, *args, **kwargs):
            fd = native_open(path, flags, *args, **kwargs);opened.append((path,flags,kwargs,fd));return fd
        def closing(fd):closed.append(fd);return native_close(fd)
        with patch.object(LEGACY.os, 'open', side_effect=tracked), patch.object(LEGACY.os, 'close', side_effect=closing):
            result = self.record()
        self.assertEqual(result['path'], str(self.net));self.assertEqual(set(result['files']), set(LEGACY.FILES))
        self.assertEqual([row[0] for row in opened], [self.net, *LEGACY.FILES])
        self.assertEqual(closed, [row[3] for row in opened[1:]] + [opened[0][3]])
        self.assertEqual(len(opened), 4)
        for path, flags, kwargs, fd in opened:
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY);self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_NONBLOCK);self.assertTrue(flags & os.O_CLOEXEC)
            if path != self.net:self.assertEqual(kwargs['dir_fd'], opened[0][3])
            with self.assertRaises(OSError):os.fstat(fd)
        for name,row in result['files'].items():
            self.assertEqual(row['bytes'], 0);self.assertEqual(row['sha256'], LEGACY.EMPTY_HASH)
            self.assertEqual(row['identity'], list(KERNEL.signature(self.leaf(name).lstat())))

    def test_each_missing_view_is_pending_instead_of_absence(self):
        for name in LEGACY.FILES:
            self.leaf(name).unlink()
            with self.subTest(name=name), self.assertRaises(FileNotFoundError):self.record()
            self.leaf(name).write_bytes(b'');self.leaf(name).chmod(0o440)

    def test_every_family_registered_nat_filter_or_unknown_bytes_refuses(self):
        for name in LEGACY.FILES:
            for data in (b'filter\n', b'nat\n', b'raw\nmangle\n', b'debian13s4\n', b'\n', b'\x00', b'\xff'):
                self.write(data, name)
                with self.subTest(name=name, data=data), self.assertRaisesRegex(LEGACY.Pending, 'legacy table state'):self.record()
            self.write(b'', name)

    def test_oversize_view_is_bounded_and_descriptors_close(self):
        self.write(b'x' * (LEGACY.MAX_BYTES + 1))
        with self.assertRaisesRegex(LEGACY.Pending, 'byte limit'):self.record()

    def test_symbolic_leaf_refuses_without_following_or_changing_victim(self):
        victim = self.root / 'victim';victim.write_bytes(b'unchanged\n');victim.chmod(0o440)
        original = victim.lstat();self.leaf().unlink();self.leaf().symlink_to(victim)
        with self.assertRaises(LEGACY.Pending):self.record()
        self.assertEqual(victim.read_bytes(), b'unchanged\n');self.assertEqual(KERNEL.signature(victim.lstat()), KERNEL.signature(original))

    def test_fifo_directory_and_socket_refuse_before_open_and_do_not_hang(self):
        for kind in ('fifo', 'directory', 'socket'):
            self.leaf().unlink();endpoint = None
            try:
                if kind == 'fifo':os.mkfifo(self.leaf(), 0o440)
                elif kind == 'directory':self.leaf().mkdir()
                else:endpoint = socket.socket(socket.AF_UNIX);endpoint.bind(str(self.leaf()))
                start = time.monotonic()
                with self.subTest(kind=kind), self.assertRaises(LEGACY.Pending):self.record()
                self.assertLess(time.monotonic() - start, 2)
            finally:
                if endpoint is not None:endpoint.close()
                if self.leaf().is_dir():self.leaf().rmdir()
                else:self.leaf().unlink()
                self.leaf().write_bytes(b'');self.leaf().chmod(0o440)

    def test_wrong_owner_leaf_mode_and_unsafe_ancestry_refuse(self):
        with patch.object(LEGACY, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(LEGACY.Pending):self.record()
        for mode in (0o640, 0o400, 0o444, 0o460):
            self.leaf().chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(LEGACY.Pending):self.record()
        self.leaf().chmod(0o440)
        for path in (self.root, self.proc, self.net.parent, self.net):
            old = path.stat().st_mode;path.chmod(0o770)
            try:
                with self.subTest(path=path.name), self.assertRaises(LEGACY.Pending):self.record()
            finally:path.chmod(stat.S_IMODE(old))

    def test_symbolic_parent_and_outside_trust_root_refuse(self):
        original = self.root / 'real';self.proc.rename(original);self.proc.symlink_to(original, target_is_directory=True)
        with self.assertRaises(LEGACY.Pending):self.record()
        self.proc.unlink();original.rename(self.proc)
        with patch.object(LEGACY, 'TRUST_ROOT', self.root / 'other'), self.assertRaises(LEGACY.Pending):self.record()

    def test_real_filesystem_refusal_applies_to_directory_and_each_leaf(self):
        with self.assertRaisesRegex(LEGACY.Pending, 'not on procfs'):LEGACY.read_views(KERNEL.now() + 10)
        calls = []
        def substitute(fd):
            calls.append(fd)
            if stat.S_ISREG(os.fstat(fd).st_mode):LEGACY.filesystem_original(fd)
        with patch.object(LEGACY, 'filesystem_original', LEGACY.filesystem, create=True):
            with self.assertRaisesRegex(LEGACY.Pending, 'not on procfs'):self.read(side_effect=substitute)
        self.assertEqual(len(calls), 2)

    def test_native_filesystem_error_never_certifies_empty(self):
        with self.assertRaises(OSError):self.read(side_effect=OSError(errno.EIO, 'fixture'))

    def test_read_error_is_not_a_zero_byte_result(self):
        with patch.object(LEGACY.os, 'read', side_effect=OSError(errno.EIO, 'fixture')), self.assertRaises(OSError):self.record()

    def test_changed_content_or_leaf_after_read_cannot_certify_empty(self):
        native_read = os.read
        def change(fd, count):
            data = native_read(fd,count)
            if self.leaf().exists():self.write(b'filter\n')
            return data
        with patch.object(LEGACY.os, 'read', side_effect=change), self.assertRaisesRegex(LEGACY.Pending, 'changed during read'):self.record()

    def test_replaced_regular_leaf_between_stat_and_open_refuses_and_closes_fds(self):
        native_open = os.open;opened = []
        def replace(path, flags, *args, **kwargs):
            if path == LEGACY.FILES[0]:
                self.leaf().rename(self.net / 'original');self.leaf().write_bytes(b'');self.leaf().chmod(0o440)
            fd = native_open(path, flags, *args, **kwargs);opened.append(fd);return fd
        with patch.object(LEGACY.os, 'open', side_effect=replace), self.assertRaisesRegex(LEGACY.Pending, 'descriptor changed'):self.record()
        for fd in opened:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_directory_replacement_after_read_refuses_pinned_old_view(self):
        native_read = os.read;changed = False
        def replace(fd, count):
            nonlocal changed
            data = native_read(fd,count)
            if not changed:
                changed = True;self.net.rename(self.net.parent / 'old');self.net.mkdir();self.net.chmod(0o700)
                for name in LEGACY.FILES:self.leaf(name).write_bytes(b'');self.leaf(name).chmod(0o440)
            return data
        with patch.object(LEGACY.os, 'read', side_effect=replace), self.assertRaisesRegex(LEGACY.Pending, 'directory changed'):self.record()

    def test_expired_invalid_deadline_refuses_before_any_filesystem_open(self):
        for value in (True, 'future', float('inf'), float('nan'), KERNEL.now() - 1, 10 ** 10000):
            with patch.object(LEGACY.os, 'open', side_effect=AssertionError('open')):
                with self.subTest(type=type(value).__name__), self.assertRaises(LEGACY.Pending):LEGACY.read_views(value)

    def test_window_expiry_after_successful_read_cannot_publish_a_view(self):
        native_read = os.read
        def expire(fd, count):
            data = native_read(fd,count);self.clock[0] = 11;return data
        self.clock = [0]
        with patch.object(KERNEL, 'now', side_effect=lambda:self.clock[0]), patch.object(LEGACY.os, 'read', side_effect=expire), \
                patch.object(LEGACY, 'filesystem'), self.assertRaises(LEGACY.Pending):LEGACY.read_views(10)

    def test_close_error_is_observable_and_remaining_directory_still_closes(self):
        native_close = os.close;closed = []
        def fail(fd):
            native_close(fd);closed.append(fd)
            if len(closed) == 1:raise OSError(errno.EIO, 'fixture close')
        with patch.object(LEGACY.os, 'close', side_effect=fail), self.assertRaises(OSError):self.record()
        self.assertEqual(len(closed), 2)


class ObservationTests(PrivateViews):
    def observe(self, **overrides):
        value = self.record();settings = {'read': lambda deadline: copy.deepcopy(value)};settings.update(overrides)
        return LEGACY.observe(**settings)

    def test_two_complete_private_observations_are_positive_in_same_namespace(self):
        with patch.object(LEGACY, 'filesystem'):result = LEGACY.observe()
        self.assertEqual(result['namespace'], KERNEL.namespace());self.assertIs(result['empty'], True)
        self.assertEqual(result['schema'], 'debian13s4-legacy-ip-ip6-arp-empty-1')
        self.assertEqual(set(result['source']['files']), set(LEGACY.FILES))

    def test_shared_inherited_window_is_capped_and_never_widened(self):
        value = self.record()
        for budget in (5, 1000):
            seen = []
            with patch.object(KERNEL, 'now', return_value=0):LEGACY.observe(read=lambda deadline:seen.append(deadline) or value, deadline=budget)
            self.assertEqual(seen, [min(budget, LEGACY.ATTEMPT_SECONDS)] * 2)

    def test_invalid_deadline_refuses_before_reader_or_scope(self):
        for value in (True, 'future', float('inf'), float('nan'), KERNEL.now() - 1, 10 ** 10000):
            with self.subTest(type=type(value).__name__), self.assertRaises(LEGACY.Pending):
                LEGACY.observe(deadline=value, read=lambda deadline:self.fail('read'), scope=lambda:self.fail('scope'))

    def test_every_missing_extra_or_false_empty_view_delivery_refuses(self):
        value = self.record()
        bad = [None, [], {}, value | {'extra': 1}, value | {'path': '/proc/net'}]
        for name in LEGACY.FILES:
            current = copy.deepcopy(value);del current['files'][name];bad.append(current)
            for key,bogus in (('bytes', True), ('bytes', 1), ('sha256', '0' * 64), ('identity', [])):
                current = copy.deepcopy(value);current['files'][name][key] = bogus;bad.append(current)
        for current in bad:
            with self.subTest(current=current), self.assertRaises(LEGACY.Pending):self.observe(read=lambda deadline:current)

    def test_invalid_initial_and_final_namespaces_refuse(self):
        for namespace in (True, 0, '1', None, 2 ** 64):
            with self.subTest(namespace=namespace), self.assertRaises(LEGACY.Pending):self.observe(scope=lambda:namespace)
        for final in (True, 2, '1', None):
            values = iter([1,final])
            with self.subTest(final=final), self.assertRaises(LEGACY.Pending):self.observe(scope=lambda:next(values))

    def test_first_snapshot_is_private_before_later_reader_mutates_it(self):
        value = self.record();seen = []
        def changed(deadline):
            seen.append(deadline)
            if len(seen) == 2:value['files'][LEGACY.FILES[0]]['identity'][1] += 1
            return value
        with self.assertRaisesRegex(LEGACY.Pending, 'changed'):self.observe(read=changed)

    def test_changed_or_disappeared_second_real_view_never_returns_a_receipt(self):
        calls = []
        def changed(deadline):
            calls.append(deadline)
            if len(calls) == 2:self.write(b'filter\n', LEGACY.FILES[2])
            return LEGACY.read_views(deadline)
        with patch.object(LEGACY, 'filesystem'), self.assertRaises(LEGACY.Pending):self.observe(read=changed)
        self.assertEqual(len(calls), 2)

    def test_late_reader_or_final_namespace_expiry_cannot_publish(self):
        value = self.record();clock = [0];seen = []
        def late(deadline):
            seen.append(deadline)
            if len(seen) == 2:clock[0] = 11
            return value
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(LEGACY.Pending):self.observe(read=late, deadline=10)
        clock[0] = 0;scopes = []
        def late_scope():
            scopes.append(1)
            if len(scopes) == 2:clock[0] = 11
            return 1
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(LEGACY.Pending):self.observe(scope=late_scope, deadline=10)

    def test_partial_reads_and_file_errors_do_not_get_converted_to_absence(self):
        def failed(deadline):raise FileNotFoundError('missing view')
        with self.assertRaises(FileNotFoundError):self.observe(read=failed)


class CliTests(PrivateViews):
    def test_success_prints_one_complete_receipt(self):
        output = io.StringIO()
        with patch.object(LEGACY, 'filesystem'), patch.object(LEGACY.sys, 'argv', ['legacy.py']), contextlib.redirect_stdout(output):
            self.assertEqual(LEGACY.main(), 0)
        self.assertEqual(len(output.getvalue().splitlines()), 1);self.assertIs(json.loads(output.getvalue())['empty'], True)

    def test_missing_nonempty_or_untrusted_views_have_no_healthy_stdout(self):
        self.write(b'nat\n')
        output,errors = io.StringIO(),io.StringIO()
        with patch.object(LEGACY, 'filesystem'), patch.object(LEGACY.sys, 'argv', ['legacy.py']), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):self.assertEqual(LEGACY.main(), 75)
        self.assertEqual(output.getvalue(), '');self.assertIn('pending', errors.getvalue())
        self.write(b'');self.leaf().unlink()
        with patch.object(LEGACY, 'filesystem'), patch.object(LEGACY.sys, 'argv', ['legacy.py']), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):self.assertEqual(LEGACY.main(), 75)
        self.assertEqual(output.getvalue(), '')

    def test_arguments_refuse_before_any_read(self):
        for argument in ('flush', '/proc/1/net', '--deadline=100'):
            output = io.StringIO()
            with patch.object(LEGACY.sys, 'argv', ['legacy.py', argument]), patch.object(LEGACY, 'observe', side_effect=AssertionError('read')), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):self.assertEqual(LEGACY.main(), 64)
            self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':unittest.main()
