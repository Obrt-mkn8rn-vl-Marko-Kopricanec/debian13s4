import configparser
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock


if os.geteuid() == 0:
    raise RuntimeError('Run these disposable fixtures as an ordinary user.')
ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'debian13s4-retention.service'
TIMER = 'debian13s4-retention.timer'
JOURNAL = 'systemd-journald.service'
MACHINE = 'a' * 32


def load(name):
    spec = importlib.util.spec_from_file_location('retention_' + name.replace('-', '_'), ROOT / 'Retention' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def trust(root, path, kind=stat.S_ISREG, owners=None):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path) or root not in (path, *path.parents):
        raise ValueError('outside private fixture')
    leaf = path
    while True:
        info = path.lstat()
        if not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('untrusted private fixture')
        if path == root: return leaf.lstat()
        path = path.parent


def file(path, data=b'fixture\n'):
    path.write_bytes(data); path.chmod(0o600)
    return path


def archive(directory, age=0, size=4096, sequence=1, unclean=False):
    stamp = int((time.time() - age) * 1000000)
    name = f'system@{stamp:016x}-0000000000000001.journal~' if unclean else f'system@{"b" * 32}-{sequence:016x}-{stamp:016x}.journal'
    return file(directory / name, b'x' * size)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-retention-journal.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.module = load('journal'); self.module.TRUSTED_UID = os.geteuid()
        self.module.trusted = lambda path, kind=stat.S_ISREG: trust(self.root, path, kind)
        self.prefix = self.root / 'etc'; self.prefix.mkdir(mode=0o700)
        self.dropins = self.prefix / 'journald.conf.d'; self.dropins.mkdir(mode=0o700)
        self.config = file(self.dropins / '90-debian13s4-retention.conf', (ROOT / 'Retention/journal.conf').read_bytes())
        self.module.PREFIXES = (self.prefix,)
        self.module.MACHINE = file(self.root / 'machine-id', (MACHINE + '\n').encode())
        self.var = self.root / 'var-journal'; self.run = self.root / 'run-journal'
        for path in (self.var, self.run):
            path.mkdir(mode=0o700); (path / MACHINE).mkdir(mode=0o700)
        self.module.JOURNALS = ((self.var, 128 * 1024**2, 32), (self.run, 32 * 1024**2, 8))

    def merged(self):
        return ''.join('# ' + str(p) + '\n' + p.read_text() + '\n' for p in sorted(self.dropins.glob('*.conf'))).encode()

    def test_native_merged_policy_and_stable_sources_are_checked(self):
        def native(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/systemd-analyze', '--no-pager', 'cat-config', 'systemd/journald.conf'])
            self.assertEqual(kwargs['timeout'], 5)
            return subprocess.CompletedProcess(args, 0, self.merged(), b'')
        with mock.patch.object(self.module.subprocess, 'run', side_effect=native):
            self.assertRegex(self.module.configuration(), r'^[0-9a-f]{64}$')

    def test_later_override_and_missing_policy_cannot_certify(self):
        for text in ('[Journal]\nSystemMaxUse=1G\n', '[Journal]\nStorage=volatile\n'):
            file(self.dropins / '99-local.conf', text.encode())
            with mock.patch.object(self.module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, self.merged(), b'')):
                with self.assertRaises(ValueError): self.module.configuration()
        self.config.unlink(); (self.dropins / '99-local.conf').unlink()
        with mock.patch.object(self.module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
            with self.assertRaises(ValueError): self.module.configuration()

    def test_continuation_and_unsupported_assignment_forms_are_refused(self):
        for line in ('SystemMaxUse=128M \\\n', 'SystemMaxUse="128M"\n', 'SystemMaxUse=128M # comment\n', 'broken\n'):
            with self.subTest(line=line), self.assertRaises(ValueError): self.module.policy(self.config.read_text() + line)

    def test_native_errors_output_errors_untrusted_sources_and_changes_fail(self):
        for result in (subprocess.CompletedProcess([], 0, self.merged(), b'warning'),
                       subprocess.CompletedProcess([], 0, b'# /outside\n' + self.config.read_bytes(), b''),
                       subprocess.CompletedProcess([], 0, self.merged() + b'\xff', b'')):
            with mock.patch.object(self.module.subprocess, 'run', return_value=result):
                with self.assertRaises((ValueError, UnicodeError)): self.module.configuration()
        with mock.patch.object(self.module.subprocess, 'run', side_effect=subprocess.TimeoutExpired([], 5)):
            with self.assertRaises(subprocess.TimeoutExpired): self.module.configuration()
        def changed(args, **kwargs):
            text = self.merged(); self.config.write_bytes(self.config.read_bytes() + b'# changed\n')
            return subprocess.CompletedProcess(args, 0, text, b'')
        with mock.patch.object(self.module.subprocess, 'run', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'configuration changed'): self.module.configuration()

    def test_wrong_kind_configuration_leaves_do_not_follow_or_block(self):
        self.config.unlink(); victim = file(self.root / 'victim', b'unchanged\n')
        identity = (victim.stat().st_ino, victim.read_bytes())
        for kind in ('symlink', 'fifo', 'socket', 'directory'):
            handle = None
            if kind == 'symlink': self.config.symlink_to(victim)
            elif kind == 'fifo': os.mkfifo(self.config, 0o600)
            elif kind == 'socket':
                handle = socket.socket(socket.AF_UNIX); handle.bind(str(self.config))
            else: self.config.mkdir(mode=0o700)
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.module.sources()
            self.assertEqual((victim.stat().st_ino, victim.read_bytes()), identity)
            if handle: handle.close()
            if kind == 'directory': self.config.rmdir()
            else: self.config.unlink()

    def test_descriptor_changes_stream_errors_and_size_caps_fail(self):
        with mock.patch.object(self.module.os, 'fstat', return_value=self.root.stat()):
            with self.assertRaises(ValueError): self.module.read(self.config)
        with mock.patch.object(self.module.os, 'read', side_effect=OSError('read failed')):
            with self.assertRaises(OSError): self.module.read(self.config)
        self.module.MAX_INPUT = 8
        with self.assertRaises(ValueError): self.module.read(self.config)

    def test_active_files_are_preserved_without_claiming_a_disk_quota(self):
        active = file(self.var / MACHINE / 'system.journal', b'active bytes\n')
        os.utime(active, (1, 1)); self.module.observe()
        self.assertEqual(active.read_bytes(), b'active bytes\n')

    def test_old_archives_and_unclean_files_detect_zero_exit_nonrepair(self):
        for unclean in (False, True):
            path = archive(self.var / MACHINE, age=15 * 86400, unclean=unclean)
            with self.subTest(unclean=unclean), self.assertRaisesRegex(ValueError, 'still exceed'): self.module.observe()
            path.unlink()
        self.module.observe()

    def test_archived_count_and_allocated_size_are_checked_for_both_stores(self):
        path = archive(self.run / MACHINE)
        self.module.JOURNALS = ((self.var, 1, 32), (self.run, 1, 8))
        with self.assertRaises(ValueError): self.module.observe()
        path.unlink(); self.module.JOURNALS = ((self.var, 128 * 1024**2, 0), (self.run, 32 * 1024**2, 8))
        archive(self.var / MACHINE)
        with self.assertRaises(ValueError): self.module.observe()

    def test_unverifiable_machine_paths_and_journal_entries_fail(self):
        for value in (b'', b'0' * 32, b'../other', b'F' * 32, b' ' + b'a' * 32, b'a' * 32 + b'\n\n'):
            self.module.MACHINE.write_bytes(value)
            with self.subTest(value=value), self.assertRaises(ValueError): self.module.directories()
        self.module.MACHINE.write_text(MACHINE + '\n')
        (self.var / MACHINE).rename(self.var / 'saved'); (self.var / MACHINE).symlink_to(self.var / 'saved')
        with self.assertRaises(ValueError): self.module.directories()
        (self.var / MACHINE).unlink(); (self.var / 'saved').rename(self.var / MACHINE)
        os.mkfifo(self.var / MACHINE / 'system.journal', 0o600)
        with self.assertRaises(ValueError): self.module.directories()

    def test_persistent_store_is_required_after_flush_but_runtime_is_optional(self):
        (self.run / MACHINE).rmdir(); self.run.rmdir(); self.module.observe()
        (self.var / MACHINE).rmdir()
        with self.assertRaisesRegex(ValueError, 'persistent default journal'): self.module.observe()

    def test_vacuum_flushes_rotates_then_checks_actual_archives(self):
        old = archive(self.var / MACHINE, age=15 * 86400)
        calls = []
        def native(args, **kwargs):
            calls.append(args); self.assertEqual(kwargs['timeout'], 40)
            if '--directory=' + str(self.var / MACHINE) in args: old.unlink()
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(self.module.subprocess, 'run', side_effect=native): self.module.vacuum()
        self.assertEqual(calls[:2], [['/usr/bin/journalctl', '--flush'], ['/usr/bin/journalctl', '--rotate']])
        self.assertEqual(calls[2][2:], ['--vacuum-size=134217728', '--vacuum-time=14days', '--vacuum-files=32'])
        self.assertEqual(calls[3][2:], ['--vacuum-size=33554432', '--vacuum-time=14days', '--vacuum-files=8'])

    def test_native_vacuum_zero_exit_and_failed_flush_do_not_certify(self):
        archive(self.var / MACHINE, age=15 * 86400)
        with mock.patch.object(self.module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaises(ValueError): self.module.vacuum()
        with mock.patch.object(self.module.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, [])) as native:
            with self.assertRaises(subprocess.CalledProcessError): self.module.vacuum()
            self.assertEqual(native.call_count, 1)

    def test_entrypoint_refuses_unprivileged_vacuum(self):
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(ROOT / 'Retention/journal.py'), '--vacuum'], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('trusted --vacuum', result.stderr)

    def test_combined_source_limit_is_checked_before_reading_an_entire_large_tree(self):
        first = self.config.read_bytes()
        file(self.dropins / '91-extra.conf', first)
        file(self.dropins / '92-extra.conf', first)
        self.module.MAX_INPUT = len(first) + 1
        original = self.module.read
        with mock.patch.object(self.module, 'read', side_effect=original) as reader:
            with self.assertRaisesRegex(ValueError, 'excessive'): self.module.sources()
            self.assertEqual(reader.call_count, 2)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-retention-cache.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.module = load('clean-cache'); self.module.TRUSTED_UID = os.geteuid()
        self.module.trusted = lambda path, kind=stat.S_ISREG, owners=None: trust(self.root, path, kind, owners)
        self.cache = self.root / 'archives'; self.cache.mkdir(mode=0o700)
        self.partial = self.cache / 'partial'; self.partial.mkdir(mode=0o700)
        self.lists = self.root / 'unused-lists'; self.lists.mkdir(mode=0o700)
        self.module.CACHE = self.cache; self.module.LISTS = self.lists

    def test_complete_and_partial_downloads_are_observed_but_lock_is_preserved(self):
        lock = file(self.cache / 'lock', b'preserve lock inode\n')
        first = file(self.cache / 'package_1_amd64.deb'); second = file(self.partial / 'download.deb')
        self.assertEqual(set(self.module.inventory(self.cache)), {first, second})
        first.unlink(); second.unlink(); self.assertEqual(self.module.inventory(self.cache), [])
        self.assertEqual(lock.read_bytes(), b'preserve lock inode\n')

    def test_native_reserved_directories_remain_outside_archive_erasure_scope(self):
        for name in ('lost+found', 'auxfiles'):
            path = self.cache / name; path.mkdir(mode=0o700); file(path / 'preserved')
        self.assertEqual(self.module.inventory(self.cache), [])
        self.assertEqual(len(list(self.cache.glob('*/preserved'))), 2)

    def test_wrong_kind_lock_or_cache_leaves_are_rejected_without_touching_victim(self):
        victim = file(self.root / 'victim', b'preserve\n'); identity = (victim.stat().st_ino, victim.read_bytes())
        for directory in (self.cache, self.partial):
            for name in ('lock', 'download.deb'):
                path = directory / name
                for kind in ('symlink', 'fifo', 'directory', 'socket'):
                    handle = None
                    if kind == 'symlink': path.symlink_to(victim)
                    elif kind == 'fifo': os.mkfifo(path, 0o600)
                    elif kind == 'directory': path.mkdir(mode=0o700)
                    else:
                        handle = socket.socket(socket.AF_UNIX); handle.bind(str(path))
                    with self.subTest(directory=directory, name=name, kind=kind), self.assertRaises(ValueError): self.module.inventory(self.cache)
                    self.assertEqual((victim.stat().st_ino, victim.read_bytes()), identity)
                    if handle: handle.close()
                    if kind == 'directory': path.rmdir()
                    else: path.unlink()

    def test_symbolic_partial_ancestry_and_unsafe_modes_fail(self):
        self.partial.rmdir(); self.partial.symlink_to(self.lists)
        with self.assertRaises(ValueError): self.module.prepare()
        self.partial.unlink(); self.partial.mkdir(mode=0o700)
        path = file(self.partial / 'part'); path.chmod(0o622)
        with self.assertRaises(ValueError): self.module.inventory(self.cache)

    def test_missing_cache_and_private_unused_lists_are_recreated(self):
        self.partial.rmdir(); self.cache.rmdir(); self.lists.rmdir()
        self.module.prepare()
        self.assertTrue(self.cache.is_dir() and self.lists.is_dir())

    def test_nonempty_or_failed_audit_prevents_cleanup(self):
        for result in (subprocess.CompletedProcess([], 0, b'pending package\n', b''),
                       subprocess.CompletedProcess([], 0, b'', b'audit warning\n')):
            with mock.patch.object(self.module.subprocess, 'run', return_value=result):
                with self.assertRaises(ValueError): self.module.audit()
        with mock.patch.object(self.module.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, [])):
            with self.assertRaises(subprocess.CalledProcessError): self.module.audit()

    def test_package_lock_encloses_audit_clean_and_postconditions(self):
        target = file(self.cache / 'package.deb'); events = []
        class Lock:
            def __enter__(inner): events.append('lock')
            def __exit__(inner, *args): events.append('unlock')
        def native(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/apt-get', 'clean']); self.assertEqual(kwargs['timeout'], 120)
            events.append('clean'); target.unlink()
        with mock.patch.object(self.module, 'configuration', return_value=type('Apt', (), {'SystemLock': Lock})), \
             mock.patch.object(self.module, 'audit', side_effect=lambda: events.append('audit')), \
             mock.patch.object(self.module.subprocess, 'run', side_effect=native):
            self.module.clean()
        self.assertEqual(events, ['lock', 'audit', 'clean', 'audit', 'unlock'])

    def test_failed_or_zero_exit_cleanup_keeps_pending_downloads(self):
        target = file(self.cache / 'package.deb')
        class Lock:
            def __enter__(inner): return inner
            def __exit__(inner, *args): pass
        with mock.patch.object(self.module, 'configuration', return_value=type('Apt', (), {'SystemLock': Lock})), \
             mock.patch.object(self.module, 'audit'), mock.patch.object(self.module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaisesRegex(ValueError, 'left downloaded'): self.module.clean()
        self.assertTrue(target.exists())

    def test_pending_package_audit_retains_cached_offline_repair_bytes(self):
        target = file(self.cache / 'offline-repair.deb', b'keep until dpkg is healthy\n')
        class Lock:
            def __enter__(inner): return inner
            def __exit__(inner, *args): pass
        with mock.patch.object(self.module, 'configuration', return_value=type('Apt', (), {'SystemLock': Lock})), \
             mock.patch.object(self.module, 'audit', side_effect=ValueError('pending dpkg')), \
             mock.patch.object(self.module.subprocess, 'run') as native:
            with self.assertRaises(ValueError): self.module.clean()
            native.assert_not_called()
        self.assertEqual(target.read_bytes(), b'keep until dpkg is healthy\n')

    def test_native_partial_apt_owner_is_allowed_only_at_the_fixed_partial_directory(self):
        m = load('clean-cache'); m.CACHE = Path('/var/cache/apt/archives'); m.LISTS = Path('/var/lib/debian13s4/retention-empty-lists')
        apt_uid = 1234
        def metadata(path):
            path = Path(path); partial = m.CACHE / 'partial'
            mode = stat.S_IFREG | 0o600 if path.name == 'package.deb' else stat.S_IFDIR | 0o700
            owner = apt_uid if path in (partial, partial / 'package.deb') else 0
            return type('Metadata', (), {'st_mode': mode, 'st_uid': owner})()
        with mock.patch.object(m.pwd, 'getpwnam', return_value=type('User', (), {'pw_uid': apt_uid})()), \
             mock.patch.object(Path, 'lstat', autospec=True, side_effect=metadata):
            m.trusted(m.CACHE / 'partial/package.deb', owners={0, apt_uid})
            with self.assertRaises(ValueError): m.trusted(m.CACHE / 'partial/package.deb')

    def test_entrypoint_requires_privileges_and_exact_mode(self):
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(ROOT / 'Retention/clean-cache.py'), '--apply'], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires trusted', result.stderr)

    def test_native_auxiliary_directory_owner_is_admitted_without_widening_parent_trust(self):
        m = load('clean-cache')
        apt_uid = 1234
        def metadata(path):
            return type('Metadata', (), {'st_mode': stat.S_IFDIR | 0o755,
                                        'st_uid': apt_uid if path.name == 'auxfiles' else 0})()
        with mock.patch.object(m.pwd, 'getpwnam', return_value=type('User', (), {'pw_uid': apt_uid})()), \
             mock.patch.object(Path, 'lstat', autospec=True, side_effect=metadata), \
             mock.patch.object(Path, 'iterdir', autospec=True, side_effect=lambda path: iter([path / 'auxfiles'])):
            self.assertEqual(m.inventory(m.LISTS), [])
            with self.assertRaises(ValueError): m.trusted(m.LISTS / 'auxfiles')


# Delivery is confined to a private fixture. Production policy/inventory and
# cache postconditions are real; owner/ancestry, manager, sync, dpkg and native
# cleanup/IPC are replaced. Native timeout/env/lock-FD closure remain real.
MODEL = r'''
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
root, action, *args = sys.argv[1:]; root = Path(root)
db = root / 'manager.json'; state = json.loads(db.read_text()); faults = state['faults']
code, output = 0, ''
def trust(path, kind=stat.S_ISREG, owners=None):
    path = Path(path); leaf = path
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path) or root not in (path, *path.parents):
        raise ValueError('outside fixture')
    while True:
        info = path.lstat()
        if not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('untrusted fixture')
        if path == root: return leaf.lstat()
        path = path.parent

def load(name):
    spec = importlib.util.spec_from_file_location('production_' + name, root / 'library' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.TRUSTED_UID = os.geteuid(); module.trusted = trust
    return module

try:
    if action == 'journal':
        assert len(args) == 1 and args[0] in ('--config', '--observe', '--vacuum'), args
        m = load('journal'); m.MACHINE = root / 'machine-id'; m.PREFIXES = (root / 'etc',)
        m.JOURNALS = ((root / 'var-journal', 128 * 1024**2, 32), (root / 'run-journal', 32 * 1024**2, 8))
        def native(command, **kwargs):
            if command[:1] == ['/usr/bin/systemd-analyze']:
                assert command == ['/usr/bin/systemd-analyze', '--no-pager', 'cat-config', 'systemd/journald.conf'], command
                if faults.get('policy'): raise subprocess.CalledProcessError(1, command)
                text = ''.join('# ' + str(p) + '\n' + p.read_text() + '\n' for p in sorted((root / 'etc/journald.conf.d').glob('*.conf')))
                return subprocess.CompletedProcess(command, 0, text.encode(), b'')
            assert command[0] == '/usr/bin/journalctl', command
            if faults.get('journal'): raise subprocess.CalledProcessError(1, command)
            if faults.get('journal_sleep'): time.sleep(faults['journal_sleep'])
            if command[1] in ('--flush', '--rotate'):
                assert len(command) == 2, command
                if command[1] == '--rotate' and faults.get('journal_generation_during_vacuum'):
                    state['invocation'] = f"{int(state['invocation'], 16) + 1:032x}"
            else:
                directory = Path(command[1].split('=', 1)[1]); assert root in directory.parents, directory
                assert command[2:] == ['--vacuum-size=' + ('134217728' if directory.parent.name == 'var-journal' else '33554432'),
                                       '--vacuum-time=14days', '--vacuum-files=' + ('32' if directory.parent.name == 'var-journal' else '8')], command
                if not faults.get('journal_noop'):
                    for name, _, _ in m.inventory(directory): (directory / name).unlink()
            return subprocess.CompletedProcess(command, 0)
        m.subprocess.run = native
        if args == ['--config']: m.directories(); output = m.configuration()
        elif args == ['--observe']: m.observe()
        else: m.vacuum()
    elif action == 'cache':
        assert args == ['--apply'], args
        m = load('clean-cache'); m.CACHE = root / 'archives'; m.LISTS = root / 'unused-lists'
        class Lock:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        m.configuration = lambda: type('Apt', (), {'SystemLock': Lock})
        def native(command, **kwargs):
            if command == ['/usr/bin/dpkg', '--audit']:
                return subprocess.CompletedProcess(command, 0, b'pending\n' if faults.get('dpkg_pending') else b'', b'')
            assert command == ['/usr/bin/apt-get', 'clean'], command
            if faults.get('cache'): raise subprocess.CalledProcessError(1, command)
            if faults.get('cache_sleep'): time.sleep(faults['cache_sleep'])
            if not faults.get('cache_noop'):
                for path in m.inventory(m.CACHE): path.unlink()
                for path in m.inventory(m.LISTS): path.unlink()
            return subprocess.CompletedProcess(command, 0)
        m.subprocess.run = native; m.clean()
    elif action == 'sync':
        assert all(Path(arg).exists() for arg in args), args
        if faults.get('sync') or (faults.get('sync_ready') and any('retention.ready' in arg for arg in args)): code = 1
    elif action == 'systemctl':
        command, unit = args[0], args[-1]
        if faults.get(command): code = 1
        elif command == 'show':
            prop = args[1].split('=', 1)[1]
            if prop == 'LoadState': output = 'loaded' if (root / 'systemd' / unit).is_file() else 'not-found'
            elif prop == 'ActiveState': output = 'active' if state['active'].get(unit) else 'inactive'
            elif prop == 'FragmentPath': output = '/usr/lib/systemd/system/systemd-journald.service' if unit == 'systemd-journald.service' else str(root / 'systemd' / unit)
            elif prop == 'DropInPaths': output = 'foreign.conf' if faults.get('dropin') else ''
            elif prop == 'Result': output = 'failed' if faults.get('restart_result') else 'success'
            elif prop == 'InvocationID':
                reads = state.get('invocation_reads', 0)
                if faults.get('journal_generation_between_queries') and reads == 1:
                    state['invocation'] = f"{int(state['invocation'], 16) + 1:032x}"
                state['invocation_reads'] = reads + 1
                output = state['invocation']
            else: raise AssertionError(prop)
        elif command == 'restart':
            assert unit == 'systemd-journald.service', args
            if not faults.get('restart_noop'):
                state['invocation'] = f"{int(state['invocation'], 16) + 1:032x}"
            state['active'][unit] = not faults.get('restart_inactive')
        elif command == 'stop':
            assert unit in ('debian13s4-retention.timer', 'debian13s4-retention.service'), args
            if not faults.get('stop_incomplete'): state['active'][unit] = False
        elif command == 'daemon-reload': pass
        elif command == 'enable':
            assert unit == 'debian13s4-retention.timer'
            directory = root / 'systemd/timers.target.wants'; directory.mkdir(mode=0o700, exist_ok=True)
            link = directory / unit
            if not link.is_symlink(): link.symlink_to(root / 'systemd' / unit)
            state['enabled'] = True
        elif command == 'is-enabled':
            output = 'enabled' if state['enabled'] else 'disabled'; code = 0 if state['enabled'] else 1
        elif command == 'start':
            if not faults.get('start_incomplete'): state['active'][unit] = True
        else: raise AssertionError(args)
    else: raise AssertionError(action)
except (ValueError, OSError, subprocess.SubprocessError) as error:
    print(error, file=sys.stderr); code = 1
# Children time out before this model checkpoint. That deliberately does not
# pretend to simulate physical storage ordering or a native process crash.
db.write_text(json.dumps(state))
with (root / 'events.jsonl').open('a') as stream:
    stream.write(json.dumps({'action': action, 'args': args, 'code': code}) + '\n')
if output: print(output)
sys.exit(code)
'''


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-retention-controller.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.library = self.root / 'library'; self.state = self.root / 'state'
        self.systemd = self.root / 'systemd'; self.shared = self.root / 'shared'; self.etc = self.root / 'etc'
        for path in (self.library, self.state, self.systemd, self.shared, self.etc, self.root / 'archives', self.root / 'unused-lists'):
            path.mkdir(mode=0o700)
        (self.root / 'archives/partial').mkdir(mode=0o700)
        for source in (ROOT / 'Retention').iterdir():
            target = self.library / source.name; target.write_bytes(source.read_bytes())
            target.chmod(0o755 if source.name == 'repair.sh' else 0o644)
        file(self.shared / 'common.sh', (ROOT / 'Maintenance/common.sh').read_bytes())
        self.model = file(self.root / 'delivery.py', MODEL.encode())
        self.db = file(self.root / 'manager.json', json.dumps({'enabled': False, 'active': {JOURNAL: True}, 'faults': {}, 'invocation': '1'.zfill(32)}).encode())
        file(self.root / 'machine-id', (MACHINE + '\n').encode())
        for name in ('var-journal', 'run-journal'):
            path = self.root / name; path.mkdir(mode=0o700); (path / MACHINE).mkdir(mode=0o700)
            file(path / MACHINE / 'system.journal', b'active journal\n')
        self.config = self.etc / 'journald.conf.d/90-debian13s4-retention.conf'

    def harness(self):
        q = shlex.quote
        common = (self.library / 'common.sh').read_text().replace('. /usr/local/lib/debian13s4/maintenance/common.sh', '. ' + q(str(self.shared / 'common.sh')))
        return f'''set -Eeuo pipefail
umask 077
{common}
S4M_LIBRARY={q(str(self.shared))}
S4M_STATE={q(str(self.state))}
S4M_SYSTEMD={q(str(self.systemd))}
S4R_LIBRARY={q(str(self.library))}
S4R_CONFIG={q(str(self.config))}
s4m_trusted() {{
    local path=$1 mode
    [[ $path == {q(str(self.root))} || $path == {q(str(self.root))}/* ]] || return 1
    [[ $path != *'/../'* && $path != */.. && $path != *'/./'* && $path != */. && $path != *'//'* ]] || return 1
    while :; do
        [[ -e $path && ! -L $path && -O $path ]] || return 1
        mode=$(stat --format='%a' -- "$path") || return 1
        (( (8#$mode & 8#022) == 0 )) || return 1
        [[ $path == {q(str(self.root))} ]] && return 0
        path=${{path%/*}}
    done
}}
s4m_systemctl() {{ python3 -B {q(str(self.model))} {q(str(self.root))} systemctl "$@"; }}
s4m_sync() {{ python3 -B {q(str(self.model))} {q(str(self.root))} sync "$@"; }}
s4m_control() {{
    [[ $1 == /usr/bin/python3 && $2 == -I && $3 == -B && $4 == "$S4R_LIBRARY/journal.py" && $# == 5 ]] || return 99
    python3 -B {q(str(self.model))} {q(str(self.root))} journal "$5"
}}
eval "$(declare -f s4r_bounded | sed '1s/s4r_bounded/s4r_native_bounded/')"
s4r_bounded() {{
    if [[ $1 == /usr/bin/python3 && $2 == -I && $3 == -B && $4 == "$S4R_LIBRARY/journal.py" && $5 == --vacuum && $# == 5 ]]; then
        s4r_native_bounded /usr/bin/python3 -B {q(str(self.model))} {q(str(self.root))} journal --vacuum
    elif [[ $1 == /usr/bin/env && $2 == "APT_CONFIG=$S4R_LIBRARY/apt.conf" && $3 == /usr/bin/python3 && $4 == -I && $5 == -B && $6 == "$S4R_LIBRARY/clean-cache.py" && $7 == --apply && $# == 7 ]]; then
        s4r_native_bounded /usr/bin/python3 -B {q(str(self.model))} {q(str(self.root))} cache --apply
    else return 99; fi
}}
'''

    def run_script(self, script, timeout=30):
        return subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', self.harness() + '\n' + script], text=True, capture_output=True, timeout=timeout)

    def faults(self, **faults):
        state = json.loads(self.db.read_text()); state['faults'] = faults; self.db.write_text(json.dumps(state))

    def events(self):
        path = self.root / 'events.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def apply(self):
        self.assert_success(self.run_script('s4r_apply'))

    def test_initial_apply_persists_policy_restart_generation_and_timer_readiness(self):
        self.apply(); self.assert_success(self.run_script('s4r_verify'))
        self.assertEqual(self.config.read_bytes(), (self.library / 'journal.conf').read_bytes())
        self.assertTrue((self.state / 'journal.applied').exists() and (self.state / 'retention.ready').exists())
        events = self.events(); restart = next(i for i, e in enumerate(events) if e['args'][:1] == ['restart'])
        enable = next(i for i, e in enumerate(events) if e['args'][:1] == ['enable'])
        self.assertLess(restart, enable)
        self.assertFalse(any(e['args'] == ['stop', JOURNAL] for e in events))

    def test_idempotent_repair_keeps_files_and_does_not_restart_journald_again(self):
        self.apply(); identity = (self.config.stat().st_ino, self.config.read_bytes())
        before = sum(e['args'][:1] == ['restart'] for e in self.events())
        self.assert_success(self.run_script('s4r_repair'))
        self.assertEqual((self.config.stat().st_ino, self.config.read_bytes()), identity)
        self.assertEqual(sum(e['args'][:1] == ['restart'] for e in self.events()), before)

    def test_failed_inactive_or_noop_restart_cannot_publish_initial_readiness(self):
        for fault in ('restart', 'restart_noop', 'restart_result', 'restart_inactive'):
            self.faults(**{fault: True})
            with self.subTest(fault=fault):
                self.assertNotEqual(self.run_script('s4r_apply').returncode, 0)
                self.assertFalse((self.state / 'retention.ready').exists())
            self.faults()
        self.apply()

    def test_zero_exit_vacuum_and_cache_nonrepair_remain_pending_then_recover(self):
        self.apply()
        for fault in ('journal_noop', 'cache_noop'):
            old = archive(self.root / 'var-journal' / MACHINE, age=15 * 86400)
            cached = file(self.root / 'archives/package.deb')
            self.faults(**{fault: True})
            with self.subTest(fault=fault): self.assertEqual(self.run_script('s4r_repair').returncode, 75)
            self.assertTrue(old.exists() if fault == 'journal_noop' else cached.exists())
            self.faults(); self.assert_success(self.run_script('s4r_repair'))
            self.assertFalse(old.exists() or cached.exists())

    def test_journal_failure_does_not_suppress_independent_cache_cleanup(self):
        self.apply(); target = file(self.root / 'archives/package.deb')
        self.faults(journal=True)
        self.assertEqual(self.run_script('s4r_repair').returncode, 75)
        self.assertFalse(target.exists())
        self.faults(); self.assert_success(self.run_script('s4r_repair'))

    def test_cache_failure_does_not_suppress_journal_retention(self):
        self.apply(); old = archive(self.root / 'var-journal' / MACHINE, age=15 * 86400)
        self.faults(cache=True)
        self.assertEqual(self.run_script('s4r_repair').returncode, 75)
        self.assertFalse(old.exists())

    def test_scaled_journal_timeout_leaves_cache_a_finite_turn(self):
        self.apply(); target = file(self.root / 'archives/package.deb')
        self.faults(journal_sleep=5)
        self.assertEqual(self.run_script('S4R_SECONDS=2\nS4R_GRACE_SECONDS=0.1\ns4r_repair', timeout=10).returncode, 75)
        self.assertFalse(target.exists())
        self.faults(); self.assert_success(self.run_script('s4r_repair'))

    def test_offline_boot_generation_and_config_drift_are_reconciled(self):
        self.apply(); state = json.loads(self.db.read_text()); state['invocation'] = '9'.zfill(32); self.db.write_text(json.dumps(state))
        self.config.write_text('[Journal]\nStorage=volatile\n')
        self.assertNotEqual(self.run_script('s4r_verify').returncode, 0)
        self.assert_success(self.run_script('s4r_repair')); self.assert_success(self.run_script('s4r_verify'))
        self.assertIn('0000000000000000000000000000000a', (self.state / 'journal.applied').read_text())

    def test_missing_config_directory_is_recreated(self):
        self.apply(); self.config.unlink(); self.config.parent.rmdir()
        self.assert_success(self.run_script('s4r_repair')); self.assert_success(self.run_script('s4r_verify'))

    def test_generation_replacement_between_queries_is_compared_and_republished(self):
        self.apply()
        state = json.loads(self.db.read_text()); state['invocation_reads'] = 0; self.db.write_text(json.dumps(state))
        self.faults(journal_generation_between_queries=True)
        before = sum(e['args'][:1] == ['restart'] for e in self.events())
        self.assert_success(self.run_script('s4r_repair'))
        self.assertEqual(sum(e['args'][:1] == ['restart'] for e in self.events()), before + 1)
        self.assert_success(self.run_script('s4r_verify'))

    def test_generation_replacement_during_vacuum_is_pending_and_cache_still_progresses(self):
        self.apply(); target = file(self.root / 'archives/package.deb')
        self.faults(journal_generation_during_vacuum=True)
        self.assertEqual(self.run_script('s4r_repair').returncode, 75)
        self.assertFalse(target.exists())
        self.assertNotEqual(self.run_script('s4r_verify').returncode, 0)
        self.faults(); self.assert_success(self.run_script('s4r_repair'))
        self.assert_success(self.run_script('s4r_verify'))

    def test_bootstrap_pending_and_shared_lock_contention_precede_mutation(self):
        self.apply(); log = self.root / 'events.jsonl'; log.unlink()
        (self.state / 'bootstrap').mkdir(mode=0o700); file(self.state / 'bootstrap/pending')
        self.assertEqual(self.run_script('s4r_repair').returncode, 75); self.assertFalse(log.exists())
        (self.state / 'bootstrap/pending').unlink()
        with (self.state / 'repair.lock').open('a') as stream:
            (self.state / 'repair.lock').chmod(0o600); fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_script('s4r_repair').returncode, 75)
        self.assertFalse(log.exists()); self.assert_success(self.run_script('s4r_repair'))

    def test_code_controller_and_dependency_identity_drift_refuse_recurring_mutation(self):
        self.apply()
        for path in (self.library / 'journal.py', self.library / 'apt.conf', self.shared / 'common.sh'):
            before = path.read_bytes(); path.write_bytes(before + b'\n# changed\n')
            with self.subTest(path=path): self.assertEqual(self.run_script('s4r_repair').returncode, 75)
            path.write_bytes(before)
        self.faults(dropin=True); self.assertEqual(self.run_script('s4r_repair').returncode, 75)

    def test_persistence_and_timer_observation_errors_cannot_certify(self):
        self.faults(sync=True); self.assertNotEqual(self.run_script('s4r_apply').returncode, 0)
        self.assertFalse((self.state / 'retention.ready').exists())
        self.faults(); self.apply()
        for fault in ('stop_incomplete', 'start_incomplete', 'enable', 'sync_ready'):
            self.faults(**{fault: True})
            with self.subTest(fault=fault): self.assertNotEqual(self.run_script('s4r_apply').returncode, 0)
            self.assertFalse((self.state / 'retention.ready').exists())
            self.faults(); self.apply()

    def test_unsafe_configuration_leaf_refuses_without_following_or_blocking(self):
        self.config.parent.mkdir(mode=0o700); victim = file(self.root / 'victim', b'preserve\n')
        identity = (victim.stat().st_ino, victim.read_bytes())
        for kind in ('symlink', 'fifo', 'directory'):
            if kind == 'symlink': self.config.symlink_to(victim)
            elif kind == 'fifo': os.mkfifo(self.config, 0o600)
            else: self.config.mkdir(mode=0o700)
            with self.subTest(kind=kind): self.assertNotEqual(self.run_script('s4r_apply', timeout=10).returncode, 0)
            self.assertEqual((victim.stat().st_ino, victim.read_bytes()), identity)
            if kind == 'directory': self.config.rmdir()
            else: self.config.unlink()

    def test_pending_dpkg_preserves_downloads_while_journals_progress(self):
        self.apply(); old = archive(self.root / 'var-journal' / MACHINE, age=15 * 86400)
        target = file(self.root / 'archives/offline-repair.deb')
        self.faults(dpkg_pending=True); self.assertEqual(self.run_script('s4r_repair').returncode, 75)
        self.assertFalse(old.exists()); self.assertTrue(target.exists())
        self.faults(); self.assert_success(self.run_script('s4r_repair')); self.assertFalse(target.exists())

    def test_native_stage_clears_environment_closes_lock_and_bounds_termination(self):
        # The harness already evaluated the production common with its shared
        # source relocated. Invoke its saved real bounded primitive directly.
        result = self.run_script('''s4m_lock
trap s4m_unlock EXIT
export DEBIAN13S4_FOREIGN=unsafe
s4r_native_bounded /bin/bash -c '[[ ! -e /proc/self/fd/$1 && -z ${DEBIAN13S4_FOREIGN+x} ]]' fixture "$S4M_REPAIR_FD"
S4R_SECONDS=0.05
S4R_GRACE_SECONDS=0.05
if s4r_native_bounded /bin/bash -c 'trap "" TERM; sleep 5'; then exit 98; fi
''', timeout=10)
        self.assert_success(result)

    def test_unit_deadline_and_retry_are_independent_of_inventory_size(self):
        service = configparser.ConfigParser(interpolation=None); service.read(ROOT / 'Retention' / SERVICE)
        self.assertEqual(service['Service']['TimeoutStartSec'], '900s')
        self.assertGreater(900, 32 * 11 + 2 * (180 + 10) + 60)
        self.assertEqual(service['Service']['Restart'], 'on-failure'); self.assertEqual(service['Service']['RestartSec'], '15min')
        self.assertEqual(service['Unit']['StartLimitIntervalSec'], '0')
        self.assertIn('/etc/systemd ', service['Service']['ReadWritePaths']); self.assertIn('/var/cache/apt ', service['Service']['ReadWritePaths'])
        self.assertEqual(service['Service']['RestrictAddressFamilies'], 'AF_UNIX')
        timer = configparser.ConfigParser(interpolation=None); timer.read(ROOT / 'Retention' / TIMER)
        self.assertEqual(timer['Timer']['OnBootSec'], '5min'); self.assertEqual(timer['Timer']['OnUnitInactiveSec'], '1h')
        self.assertEqual(timer['Install']['WantedBy'], 'timers.target')

    def test_entrypoint_refuses_unprivileged_activation(self):
        result = subprocess.run(['/bin/bash', '-p', str(ROOT / 'Retention/repair.sh')], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 77)


class NativeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-retention-native.', dir='/dev/shm')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)

    def test_real_native_journal_vacuum_deletes_only_private_archives(self):
        path = self.root / 'journal'; path.mkdir(mode=0o700)
        active = file(path / 'system.journal', b'active bytes unchanged\n')
        old = archive(path, age=15 * 86400, size=128)
        identity = (active.stat().st_ino, active.read_bytes())
        # This command addresses only the private directory. No --flush,
        # --rotate, default namespace, host log writer or manager is called.
        result = subprocess.run(['/usr/bin/journalctl', '--directory=' + str(path), '--vacuum-time=14days'],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(old.exists())
        self.assertEqual((active.stat().st_ino, active.read_bytes()), identity)

    def test_real_native_merged_config_uses_only_an_explicit_private_root(self):
        directory = self.root / 'etc/systemd/journald.conf.d'; directory.mkdir(mode=0o700, parents=True)
        for path in (self.root / 'etc', self.root / 'etc/systemd'): path.chmod(0o700)
        conf = file(directory / '90-debian13s4-retention.conf', (ROOT / 'Retention/journal.conf').read_bytes())
        module = load('journal'); module.PREFIXES = (self.root / 'etc/systemd',)
        module.trusted = lambda path, kind=stat.S_ISREG: trust(self.root, path, kind)
        real_run = subprocess.run
        def native(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/systemd-analyze', '--no-pager', 'cat-config', 'systemd/journald.conf'])
            return real_run(['/usr/bin/systemd-analyze', '--root=' + str(self.root), '--no-pager', 'cat-config', 'systemd/journald.conf'], **kwargs)
        with mock.patch.object(module.subprocess, 'run', side_effect=native):
            self.assertRegex(module.configuration(), r'^[0-9a-f]{64}$')
            file(directory / '99-local.conf', b'[Journal]\nSystemMaxUse=1G\n')
            with self.assertRaises(ValueError): module.configuration()
        self.assertEqual(conf.read_bytes(), (ROOT / 'Retention/journal.conf').read_bytes())

    def native_cache(self, mode):
        for name in ('archives', 'lists', 'dpkg', 'log'):
            (self.root / name).mkdir(mode=0o700)
        (self.root / 'archives/partial').mkdir(mode=0o700)
        (self.root / 'dpkg/updates').mkdir(mode=0o700)
        file(self.root / 'dpkg/status', b'')
        archived = file(self.root / 'archives/package_1_amd64.deb', b'private cached bytes\n')
        partial = file(self.root / 'archives/partial/package.part', b'private partial bytes\n')
        lock = file(self.root / 'archives/lock', b'lock inode and bytes retained\n')
        policy = (ROOT / 'Retention/apt.conf').read_text().replace('/var/cache/apt/archives', str(self.root / 'archives')).replace('/var/lib/debian13s4/retention-empty-lists', str(self.root / 'lists'))
        policy += f'\nDir::State "{self.root / "dpkg"}";\nDir::State::status "{self.root / "dpkg/status"}";\nDir::Cache "{self.root}";\nDir::Log "{self.root / "log"}";\n'
        file(self.root / 'apt.conf', policy.encode())
        runner = r'''
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
root, source, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
spec = importlib.util.spec_from_file_location('production_cache', source)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.TRUSTED_UID = os.geteuid(); m.POLICY = root / 'apt.conf'; m.CACHE = root / 'archives'; m.LISTS = root / 'lists'; m.STATUS = root / 'dpkg/status'
def trust(path, kind=stat.S_ISREG, owners=None):
    path = Path(path); leaf = path
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path) or root not in (path, *path.parents): raise ValueError('outside fixture')
    while True:
        info = path.lstat()
        if not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022: raise ValueError('unsafe fixture')
        if path == root: return leaf.lstat()
        path = path.parent
m.trusted = trust
os.environ.clear(); os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C', LC_ALL='C', APT_CONFIG=str(m.POLICY))
real = subprocess.run
commands = []
def native(command, **kwargs):
    commands.append(command)
    if command == ['/usr/bin/dpkg', '--audit']:
        return real(['/usr/bin/dpkg', '--admindir=' + str(root / 'dpkg'), '--audit'], **kwargs)
    if command != ['/usr/bin/apt-get', 'clean']: raise AssertionError(command)
    return real(command, **kwargs)
m.subprocess.run = native
try:
    m.clean()
except Exception as error:
    print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
    if mode != 'contention': raise
    assert isinstance(error, subprocess.CalledProcessError) and error.returncode == 100, error
    assert commands == [['/usr/bin/dpkg', '--audit'], ['/usr/bin/apt-get', 'clean']], commands
    sys.exit(75)
assert mode == 'success'
assert commands == [['/usr/bin/dpkg', '--audit'], ['/usr/bin/apt-get', 'clean'], ['/usr/bin/dpkg', '--audit']], commands
print('Private native SystemLock, dpkg audit, APT clean and production postconditions passed')
'''
        script = file(self.root / 'native.py', runner.encode())
        before = (lock.stat().st_ino, lock.read_bytes())
        if mode == 'contention':
            with lock.open('r+') as stream:
                fcntl.lockf(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(script), str(self.root), str(ROOT / 'Retention/clean-cache.py'), mode], text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 75, result.stdout + result.stderr)
            self.assertTrue(archived.exists() and partial.exists())
        else:
            result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(script), str(self.root), str(ROOT / 'Retention/clean-cache.py'), mode], text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(archived.exists() or partial.exists())
        self.assertEqual((lock.stat().st_ino, lock.read_bytes()), before)
        return result

    def test_real_native_cache_clean_and_package_locks_are_confined_to_private_profile(self):
        self.native_cache('success')

    def test_real_native_archive_lock_contention_retains_downloads(self):
        result = self.native_cache('contention')
        self.assertIn('lock', result.stderr.lower())
