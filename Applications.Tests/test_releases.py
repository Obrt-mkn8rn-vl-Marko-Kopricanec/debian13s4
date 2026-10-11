"""Ordinary-UID private file observations; never execute admitted app bytes."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if os.geteuid() == 0:
    raise RuntimeError('Run private release controls as an ordinary user.')


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-releases.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        spec = importlib.util.spec_from_file_location('private_release', ROOT / 'Applications/releases.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.BASE.TRUST_ROOT = self.root; self.m.BASE.TRUSTED_UID = os.geteuid()
        self.m.RELEASE_ROOT = self.root / 'opt/debian13s4-apps'
        self.m.INPUT = self.root / 'application-releases.json'
        self.m.KERNEL.namespace = lambda: 4711
        self.value = {'schema': 1, 'applications': {}}
        self.contents = {}
        for app in self.m.APPLICATIONS:
            content = {'application/main': (app+' INVALID APPLICATION\n').encode(),
                       'gateway/main': (app+' INVALID GATEWAY\n').encode(),
                       'shared/library.dll': b'INVALID CLR LIBRARY\x00\xff'}
            files = {name: {'bytes': len(raw), 'mode': '0755' if name.endswith('/main') else '0644',
                            'sha256': hashlib.sha256(raw).hexdigest()} for name, raw in content.items()}
            entries = {'application': 'application/main', 'gateway': 'gateway/main'}
            generation = self.m.generation(entries, files)
            directory = self.m.RELEASE_ROOT / app / generation
            for name, raw in content.items():
                path = directory / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw); path.chmod(int(files[name]['mode'], 8))
            self.value['applications'][app] = {'generation': generation, 'directory': str(directory),
                                              'entry_points': entries, 'files': files}
            self.contents[app] = content
        for path in (self.root / 'opt', *self.m.RELEASE_ROOT.rglob('*')):
            if path.is_dir(): path.chmod(0o755)
        self.m.RELEASE_ROOT.chmod(0o755)
        self.write()

    def write(self, value=None, raw=None):
        self.m.INPUT.write_bytes(raw if raw is not None else self.m.BASE.canonical(value or self.value))
        self.m.INPUT.chmod(0o600)

    def path(self, app='mk8.sava', name='application/main'):
        return Path(self.value['applications'][app]['directory']) / name

    def test_all_four_whole_releases_and_both_entries_are_bound_without_execution(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('no application entry')):
            raw = self.m.prepare()
        value = json.loads(raw)
        self.assertEqual(value['state'], 'protected-preinstalled-release-source-only')
        self.assertEqual(value['namespace'], 4711)
        self.assertEqual(set(value['applications']), set(self.m.APPLICATIONS))
        for app, row in value['applications'].items():
            self.assertEqual(set(row['files']), set(self.contents[app]))
            self.assertEqual(set(row['directories']), {'.', 'application', 'gateway', 'shared'})
            for role in self.m.SERVICES:
                self.assertEqual(row['entry_points'][role], str(self.path(app, role+'/main')))
            for name, source in row['files'].items():
                self.assertEqual(source['sha256'], hashlib.sha256(self.contents[app][name]).hexdigest())
                self.assertEqual(source['identity'], list(self.m.KERNEL.signature(self.path(app, name).stat())))

    def test_closed_schema_all_apps_and_fields_are_required(self):
        for field in self.value:
            value = copy.deepcopy(self.value); del value[field]
            with self.subTest(field=field), self.assertRaises(self.m.Pending): self.m.checked(value)
        for app in self.m.APPLICATIONS:
            value = copy.deepcopy(self.value); del value['applications'][app]
            with self.subTest(app=app), self.assertRaises(self.m.Pending): self.m.checked(value)
        for extra in ('healthy', 'compiler', 'namespace', 'units', 'signature'):
            value = copy.deepcopy(self.value); value[extra] = True
            with self.subTest(extra=extra), self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_input_is_private_canonical_exact_ascii_lf_and_duplicate_nonfinite_refusing(self):
        raw = self.m.BASE.canonical(self.value)
        for bad in (raw+b'\n', raw[:-1], raw.replace(b'"schema":1', b'"schema":true'),
                    raw.replace(b'"schema":1', b'"schema":1.0'), raw.replace(b'"schema":1', b'"schema":1,"schema":1'),
                    raw.replace(b'"schema":1', b'"schema":NaN'), raw.replace(b'"schema":1', b'"schema":1e999'), b'\xff\n'):
            with self.subTest(raw=bad):
                self.write(raw=bad)
                with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_input_byte_bound_precedes_decode(self):
        self.write(raw=b' '*(self.m.MAX_INPUT+1))
        with patch.object(self.m.json, 'loads', side_effect=AssertionError('decode')):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_relative_paths_refuse_alias_controls_metacharacters_and_excess_depth(self):
        for name in ('', '.', '..', '../a', '/a', 'a/./b', 'a/../b', 'a//b', 'a/',
                     'a b', '%n', '$ENV', '`id`', 'a\nUser=root', 'é', '/'.join(['a']*9), 'a'*65, True):
            with self.subTest(name=name), self.assertRaises(self.m.Pending): self.m.relative(name)

    def test_entry_points_require_distinct_declared_nonempty_executables(self):
        for change in ('same', 'missing', 'mode', 'empty'):
            value = copy.deepcopy(self.value); row = value['applications']['mk8.sava']
            if change == 'same': row['entry_points']['gateway'] = row['entry_points']['application']
            elif change == 'missing': row['entry_points']['gateway'] = 'missing'
            elif change == 'mode': row['files']['gateway/main']['mode'] = '0644'
            else: row['files']['gateway/main']['bytes'] = 0
            with self.subTest(change=change), self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_true_integer_file_counts_sizes_modes_and_hash_spellings_are_closed(self):
        for field, bad in (('bytes', True), ('bytes', 1.0), ('bytes', -1), ('bytes', self.m.MAX_FILE_BYTES+1),
                           ('mode', 755), ('mode', '0777'), ('sha256', 'A'*64), ('sha256', '0'*64), ('sha256', False)):
            value = copy.deepcopy(self.value); value['applications']['mk8.sava']['files']['application/main'][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(self.m.Pending): self.m.checked(value)
        value = copy.deepcopy(self.value); value['applications']['mk8.sava']['files']['application/main']['extra'] = 0
        with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_generation_and_exact_product_directory_bind_full_inventory_before_observation(self):
        for change in ('hash', 'directory', 'generation'):
            value = copy.deepcopy(self.value); row = value['applications']['mk8.sava']
            if change == 'hash': row['files']['shared/library.dll']['sha256'] = 'a'*64
            elif change == 'directory': row['directory'] += '/other'
            else: row['generation'] = 'b'*64
            self.write(value)
            with self.subTest(change=change), patch.object(self.m, 'observe') as observe:
                with self.assertRaises(self.m.Pending): self.m.prepare()
                observe.assert_not_called()

    def test_file_count_and_whole_declared_byte_capacity_are_bounded(self):
        value = copy.deepcopy(self.value); row = value['applications']['mk8.sava']
        template = row['files']['shared/library.dll']
        for index in range(self.m.MAX_FILES): row['files'][f'extra{index}'] = template.copy()
        with self.assertRaises(self.m.Pending): self.m.checked(value)
        value = copy.deepcopy(self.value)
        for row in value['applications'].values():
            for item in row['files'].values(): item['bytes'] = self.m.MAX_FILE_BYTES
        with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_changed_bytes_wrong_size_mode_and_missing_file_refuse(self):
        path = self.path(name='shared/library.dll'); original = path.read_bytes()
        for raw in (b'x'*len(original), original[:-1], original+b'x'):
            path.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(self.m.Pending): self.m.prepare()
        path.write_bytes(original); path.chmod(0o600)
        with self.assertRaises(self.m.Pending): self.m.prepare()
        path.chmod(0o644); path.unlink()
        with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_complete_tree_rejects_extra_files_and_empty_directories(self):
        parent = self.path().parent
        extra = parent/'extra'; extra.write_bytes(b'unknown')
        with self.assertRaises(self.m.Pending): self.m.prepare()
        extra.unlink(); extra.mkdir(mode=0o755)
        with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_file_links_fifo_and_hard_links_refuse_without_adopting_target(self):
        path = self.path(); raw = path.read_bytes(); victim = self.root/'victim'
        victim.write_bytes(raw); victim.chmod(0o755); path.unlink(); path.symlink_to(victim)
        with self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(victim.read_bytes(), raw)
        path.unlink(); os.mkfifo(path, 0o600)
        with self.assertRaises(self.m.Pending): self.m.prepare()
        path.unlink(); path.write_bytes(raw); path.chmod(0o755); os.link(path, self.root/'alias')
        with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_unsafe_ancestor_and_symbolic_release_refuse_before_scandir(self):
        parent = self.m.RELEASE_ROOT.parent; parent.chmod(0o777)
        with patch.object(self.m.os, 'scandir', side_effect=AssertionError('enumerate')):
            with self.assertRaises(self.m.Pending): self.m.prepare()
        parent.chmod(0o755)
        directory = Path(self.value['applications']['mk8.sava']['directory']); renamed = directory.with_name('saved')
        directory.rename(renamed); directory.symlink_to(renamed, target_is_directory=True)
        with patch.object(self.m.os, 'scandir', side_effect=AssertionError('enumerate')):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_directory_modes_depth_and_inventory_counts_are_bounded(self):
        path = self.path().parent; path.chmod(0o700)
        with self.assertRaises(self.m.Pending): self.m.prepare()
        path.chmod(0o755)
        for constant, limit in (('MAX_FILES', 2), ('MAX_DIRECTORIES', 2), ('MAX_TREE_ITEMS', 2)):
            with self.subTest(constant=constant), patch.object(self.m, constant, limit):
                with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_owned_settings_do_not_change_when_caller_mutates_input(self):
        checked = self.m.checked(self.value)
        self.value['applications']['mk8.sava']['files'].clear()
        self.assertEqual(len(checked['applications']['mk8.sava']['files']), 3)

    def test_encoding_precedes_second_full_input_and_every_repeated_file_read(self):
        events = []; original = self.m.BASE.read_protected; canonical = self.m.BASE.canonical
        def read(path, *args):
            events.append('input' if path == self.m.INPUT else 'file')
            return original(path, *args)
        def encode(value):
            if isinstance(value, dict) and value.get('state') == 'protected-preinstalled-release-source-only': events.append('encode')
            return canonical(value)
        with patch.object(self.m.BASE, 'read_protected', side_effect=read), patch.object(self.m.BASE, 'canonical', side_effect=encode):
            self.m.prepare()
        self.assertEqual(events, ['input']+['file']*12+['encode', 'input']+['file']*12)

    def test_receipt_output_bound_precedes_all_final_observations(self):
        original = self.m.configuration
        with patch.object(self.m, 'MAX_OUTPUT', 1), patch.object(self.m, 'configuration', wraps=original) as cfg:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(cfg.call_count, 1)

    def test_postencoding_same_bytes_new_file_inode_withholds_receipt(self):
        original = self.m.BASE.canonical
        def encode(value):
            raw = original(value)
            if isinstance(value, dict) and value.get('state') == 'protected-preinstalled-release-source-only':
                path = self.path(); new = path.with_name('replacement'); new.write_bytes(path.read_bytes()); new.chmod(0o755); os.replace(new, path)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=encode):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_postencoding_content_and_extra_tree_drift_withhold_receipt(self):
        original = self.m.BASE.canonical
        for extra in (False, True):
            def encode(value):
                raw = original(value)
                if isinstance(value, dict) and value.get('state') == 'protected-preinstalled-release-source-only':
                    path = self.path()
                    if extra: (path.parent/'extra').write_bytes(b'x')
                    else: path.write_bytes(b'x'*path.stat().st_size)
                return raw
            with self.subTest(extra=extra), patch.object(self.m.BASE, 'canonical', side_effect=encode):
                with self.assertRaises(self.m.Pending): self.m.prepare()
            self.path().write_bytes(self.contents['mk8.sava']['application/main'])

    def test_postencoding_configuration_change_withholds_before_new_release_reads(self):
        original = self.m.BASE.canonical; configuration = self.m.configuration
        def encode(value):
            raw = original(value)
            if isinstance(value, dict) and value.get('state') == 'protected-preinstalled-release-source-only': self.m.INPUT.write_bytes(raw)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=encode), patch.object(self.m, 'observe', wraps=self.m.observe) as observe:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(observe.call_count, 4)

    def test_initial_context_true_positive_uint64_and_final_identity_are_required(self):
        for value in (0, True, 1.0, -1, 2**64):
            with patch.object(self.m.KERNEL, 'namespace', return_value=value), patch.object(self.m, 'configuration') as cfg:
                with self.assertRaises(self.m.Pending): self.m.prepare()
                cfg.assert_not_called()
        with patch.object(self.m.KERNEL, 'namespace', side_effect=[4711, 4712]):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_invalid_or_expired_inherited_windows_refuse_before_input(self):
        for value in (True, '10', float('nan'), float('inf'), self.m.KERNEL.now()-1):
            with patch.object(self.m, 'configuration') as cfg:
                with self.assertRaises(self.m.Pending): self.m.prepare(value)
                cfg.assert_not_called()

    def test_positive_parent_caps_every_reader_and_later_parent_cannot_extend_own_window(self):
        original = self.m.BASE.read_protected
        for parent, expected in ((12, 12), (100, 70)):
            values = []
            def read(path, limit, private, end): values.append(end); return original(path, limit, private, end)
            with patch.object(self.m.KERNEL, 'now', return_value=10), patch.object(self.m.BASE, 'read_protected', side_effect=read):
                self.m.prepare(parent)
            self.assertEqual(values, [expected]*26)

    def test_final_expiry_after_complete_second_read_withholds_receipt(self):
        original = self.m.observe; calls = 0
        def observe(row, end):
            nonlocal calls
            calls += 1; result = original(row, end)
            if calls == 8: self.clock.return_value = end
            return result
        with patch.object(self.m.KERNEL, 'now', return_value=10) as self.clock, patch.object(self.m, 'observe', side_effect=observe):
            with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_cli_no_overrides_and_binary_sink_require_full_true_count_and_flush(self):
        class Sink:
            def __init__(self, count=None, fail=False): self.buffer=self; self.raw=b''; self.count=count; self.fail=fail
            def write(self, raw): self.raw=raw; return len(raw) if self.count is None else self.count
            def flush(self):
                if self.fail: raise OSError('private flush')
        for count, fail, expected in ((None, False, 0), (False, False, 75), (1, False, 75), (None, True, 75)):
            sink = Sink(count, fail)
            with patch.object(sys, 'argv', ['releases.py']), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare', return_value=b'{}\n'):
                self.assertEqual(self.m.main(), expected)
            self.assertEqual(sink.raw, b'{}\n')
        for args, sink in ((['releases.py', 'extra'], Sink()), (['releases.py'], io.StringIO())):
            with patch.object(sys, 'argv', args), patch.object(sys, 'stdout', sink), patch.object(sys, 'stderr', io.StringIO()), patch.object(self.m, 'prepare') as prepare:
                self.assertEqual(self.m.main(), 75); prepare.assert_not_called()


    def test_reported_foreign_file_owner_refuses_before_file_descriptor_entry(self):
        from types import SimpleNamespace
        path = self.path(); original = Path.lstat
        def lstat(current):
            value = original(current)
            if current == path:
                names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size',
                         'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
                facts = {name: getattr(value, name) for name in names}
                facts['st_uid'] += 1
                return SimpleNamespace(**facts)
            return value
        with patch.object(Path, 'lstat', lstat), patch.object(self.m.BASE.os, 'open') as opened:
            with self.assertRaises(self.m.Pending):
                self.m.observe(self.value['applications']['mk8.sava'], self.m.KERNEL.now()+5)
            opened.assert_not_called()

    def test_reported_directory_device_drift_refuses_before_any_release_bytes(self):
        from types import SimpleNamespace
        original = self.m.protected_directory; selected = self.path().parent
        def directory(path, end):
            value = original(path, end)
            if path == selected:
                names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size',
                         'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
                facts = {name: getattr(value, name) for name in names}
                facts['st_dev'] += 1
                return SimpleNamespace(**facts)
            return value
        with patch.object(self.m, 'protected_directory', side_effect=directory), patch.object(self.m.BASE, 'read_protected') as read:
            with self.assertRaises(self.m.Pending):
                self.m.observe(self.value['applications']['mk8.sava'], self.m.KERNEL.now()+5)
            read.assert_not_called()

    def test_exact_file_count_ceiling_accepts_and_one_more_refuses(self):
        value = copy.deepcopy(self.value); row = value['applications']['mk8.sava']
        empty = {'bytes': 0, 'mode': '0644', 'sha256': hashlib.sha256(b'').hexdigest()}
        for index in range(self.m.MAX_FILES-len(row['files'])):
            row['files'][f'empty{index}'] = empty.copy()
        row['generation'] = self.m.generation(row['entry_points'], row['files'])
        row['directory'] = str(self.m.RELEASE_ROOT/'mk8.sava'/row['generation'])
        self.assertEqual(len(self.m.checked(value)['applications']['mk8.sava']['files']), self.m.MAX_FILES)
        row['files']['one_more'] = empty.copy()
        with self.assertRaises(self.m.Pending): self.m.checked(value)

    def test_exact_complete_receipt_cap_accepts_and_one_less_blocks_final_input(self):
        raw = self.m.prepare(); original = self.m.configuration
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)):
            self.assertEqual(self.m.prepare(), raw)
        with patch.object(self.m, 'MAX_OUTPUT', len(raw)-1), patch.object(self.m, 'configuration', wraps=original) as cfg:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(cfg.call_count, 1)

    def test_actual_private_cli_pipe_is_encoding_independent_and_refusal_has_no_stdout(self):
        program = ("import importlib.util,os,sys;from pathlib import Path;"
            "s=importlib.util.spec_from_file_location('private_cli',sys.argv[1]);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "m.BASE.TRUST_ROOT=Path(sys.argv[2]);m.BASE.TRUSTED_UID=os.geteuid();"
            "m.INPUT=Path(sys.argv[2])/'application-releases.json';"
            "m.RELEASE_ROOT=Path(sys.argv[2])/'opt/debian13s4-apps';"
            "m.KERNEL.namespace=lambda:4711;sys.argv=['releases.py'];sys.exit(m.main())")
        expected = self.m.prepare()
        for encoding in ('ascii:strict', 'utf-32:ignore'):
            env = dict(os.environ, PYTHONIOENCODING=encoding); env.pop('PYTHONPATH', None)
            child = subprocess.run([sys.executable, '-B', '-c', program, str(ROOT/'Applications/releases.py'), str(self.root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=10)
            self.assertEqual((child.returncode, child.stdout, child.stderr), (0, expected, b''))
        self.m.INPUT.chmod(0o644)
        child = subprocess.run([sys.executable, '-B', '-c', program, str(ROOT/'Applications/releases.py'), str(self.root)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=10)
        self.assertEqual((child.returncode, child.stdout), (75, b''))


if __name__ == '__main__':
    unittest.main()
