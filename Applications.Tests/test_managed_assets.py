"""Inert selected dependency declarations and real private release files."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('private_assets_'+path.stem, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class ManagedAssetTests(unittest.TestCase):
    def setUp(self):
        fixture = load(ROOT/'Applications.Tests/test_managed_runtime.py')
        self.h = fixture.ManagedRuntimeTests('runTest'); self.addCleanup(self.h.doCleanups); self.h.setUp()
        self.m = load(ROOT/'Applications/managed_assets.py'); self.m.RUNTIME = self.h.m
        self.m.RELEASE, self.m.BASE, self.m.KERNEL, self.m.Pending = self.h.m.RELEASE, self.h.m.BASE, self.h.m.KERNEL, self.h.m.Pending
        self.release, self.target = self.h.release, self.h.target
        self.deps = copy.deepcopy(self.h.deps)
        self.deps['libraries']['fixture/1.0.0'].update(serviceable=False, sha512='')
        self.deps['libraries']['Local.Support/1.2.3'] = {'type': 'package', 'serviceable': True, 'sha512': '',
            'path': 'local.support/1.2.3', 'hashPath': 'local.support.1.2.3.nupkg.sha512'}
        self.deps['targets'][self.target]['fixture/1.0.0']['dependencies'] = {'Local.Support': '1.2.3'}
        self.deps['targets'][self.target]['Local.Support/1.2.3'] = {
            'runtime': {'lib/net10.0/support.dll': {'assemblyVersion': '1.2.3.0', 'fileVersion': '1.2.3.0'}},
            'native': {'runtimes/linux-x64/native/libfixture.so': {}},
            'resources': {'lib/net10.0/hr/Support.resources.dll': {'locale': 'hr'}}}
        for row in self.release.value['applications'].values():
            directory = Path(row['directory'])
            for entry in row['entry_points'].values():
                parent = Path(entry).parent
                for name, raw in ((entry+'.deps.json', json.dumps(self.deps, indent=2).encode()),
                    (str(parent/'support.dll'), b'INVALID SUPPORT ASSEMBLY'),
                    (str(parent/'libfixture.so'), b'INVALID NATIVE LIBRARY'),
                    (str(parent/'hr/Support.resources.dll'), b'INVALID RESOURCE ASSEMBLY')):
                    path = directory/name; path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    path.parent.chmod(0o755)
                    path.write_bytes(raw); path.chmod(0o644)
                    row['files'][name] = {'bytes': len(raw), 'mode': '0644', 'sha256': hashlib.sha256(raw).hexdigest()}
        self.declare()

    def declare(self):
        for row in self.release.value['applications'].values():
            directory = Path(row['directory'])
            marker = self.m.RELEASE.generation(row['entry_points'], row['files']); target = directory.with_name(marker)
            if target != directory: directory.rename(target)
            row.update(directory=str(target), generation=marker)
        self.release.write()

    def components(self):
        _, value = self.h.m.IMAGE.prerequisite(self.m.KERNEL.now()+30, 4711)
        return value['configuration']['value']['applications']['mk8.sava'], value['applications']['mk8.sava']

    def test_all_eight_selected_asset_sets_bind_actual_files_without_loading_or_probing(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no loader or package/native entry')):
            raw = self.m.prepare()
        value = json.loads(raw); self.assertEqual(value['state'], self.m.STATE)
        self.assertEqual(set(value['applications']), set(self.m.RELEASE.APPLICATIONS))
        for roles in value['applications'].values():
            for role, row in roles.items():
                self.assertEqual(row['libraries'], 2); self.assertEqual(len(row['assets']), 4)
                self.assertFalse(row['framework_resolution_verified']); self.assertFalse(row['loader_resolution_verified'])
                self.assertFalse(row['package_hashes_verified'])
                assets = {item['release_path']: item for item in row['assets']}
                self.assertEqual(set(assets), {role+'/main.dll', role+'/support.dll', role+'/libfixture.so', role+'/hr/Support.resources.dll'})
                for item in assets.values():
                    self.assertEqual(item['source']['sha256'], hashlib.sha256(Path(item['source']['path']).read_bytes()).hexdigest())
                self.assertEqual(Path(assets[role+'/libfixture.so']['source']['path']).read_bytes(), b'INVALID NATIVE LIBRARY')
        sink = io.BytesIO()
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'argv', ['managed_assets.py']), \
             patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)):
            self.assertEqual(self.m.main(), 0)
        self.assertEqual(sink.getvalue(), raw)
        bad = types.SimpleNamespace(write=lambda raw: True, flush=lambda: self.fail('no invalid-count flush'))
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'argv', ['managed_assets.py']), \
             patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=bad)), patch.object(self.m.sys, 'stderr', io.StringIO()):
            self.assertEqual(self.m.main(), 75)

    def test_missing_empty_and_wrong_mode_assets_refuse_even_with_new_valid_release_declaration(self):
        declared, observed = self.components()
        self.assertEqual(len(self.m.bind(self.deps, 'x86_64', 'application/main', declared, observed)['assets']), 4)
        for kind in ('empty', 'mode'):
            entry = 'application/main.dll'; declared_copy, observed_copy = copy.deepcopy(declared), copy.deepcopy(observed)
            if kind == 'empty': declared_copy['files'][entry]['bytes'] = 0
            else: declared_copy['files'][entry]['mode'] = '0755'
            with self.subTest(kind=kind), self.assertRaises(self.m.Pending):
                self.m.bind(self.deps, 'x86_64', 'application/main', declared_copy, observed_copy)
        row = self.release.value['applications']['mk8.sava']; name = 'application/support.dll'
        self.release.path(name=name).unlink(); del row['files'][name]; self.declare()
        with self.assertRaises(self.m.Pending) as caught: self.m.prepare()
        self.assertIn('absent from the whole release', str(caught.exception))

    def test_target_alias_paths_collisions_and_external_resolution_features_refuse(self):
        declared, observed = self.components()
        group = lambda value: value['targets'][self.target]
        changes = [lambda v: group(v)['fixture/1.0.0'].__setitem__('runtimeTargets', {}),
            lambda v: group(v)['fixture/1.0.0']['dependencies'].__setitem__('Absent', '1.0.0'),
            lambda v: group(v)['Local.Support/1.2.3']['runtime'].__setitem__('other/main.dll', {}),
            lambda v: group(v)['Local.Support/1.2.3']['runtime'].__setitem__('../escape.dll', {}),
            lambda v: group(v)['Local.Support/1.2.3']['native']['runtimes/linux-x64/native/libfixture.so'].__setitem__('localPath', '/tmp/foreign'),
            lambda v: group(v)['Local.Support/1.2.3']['resources']['lib/net10.0/hr/Support.resources.dll'].__setitem__('locale', 'en'),
            lambda v: group(v)['Local.Support/1.2.3']['runtime'].__setitem__('lib/net10.0/_._', {}),
            lambda v: v['libraries']['Local.Support/1.2.3'].__setitem__('type', 'runtimepack'),
            lambda v: v['libraries']['Local.Support/1.2.3'].__setitem__('serviceable', 1),
            lambda v: v['libraries']['Local.Support/1.2.3'].__setitem__('sha512', 'not-base64'),
            lambda v: v['libraries']['Local.Support/1.2.3'].__setitem__('runtimeStoreManifestName', 'external'),
            lambda v: group(v)['Local.Support/1.2.3']['runtime']['lib/net10.0/support.dll'].__setitem__('fileVersion', '65536.0'),
            lambda v: group(v)['fixture/1.0.0'].__setitem__('runtime', {})]
        self.assertEqual(len(self.m.bind(self.deps, 'x86_64', 'application/main', declared, observed)['assets']), 4)
        for index, mutate in enumerate(changes):
            value = copy.deepcopy(self.deps); mutate(value)
            with self.subTest(index=index), self.assertRaises(self.m.Pending):
                self.m.bind(value, 'x86_64', 'application/main', declared, observed)
        with patch.object(self.m, 'MAX_ASSETS', 3), self.assertRaises(self.m.Pending):
            self.m.bind(self.deps, 'x86_64', 'application/main', declared, observed)

    def test_postencoding_identical_dependency_inode_replacement_prevents_return(self):
        encode = self.m.BASE.canonical; target = self.release.path(name='application/main.deps.json')
        encoded = []
        def replace(value):
            raw = encode(value)
            if type(value) is dict and value.get('state') == self.m.STATE:
                encoded.append(True)
                other = target.with_name('replacement'); other.write_bytes(target.read_bytes()); other.chmod(0o644); other.replace(target)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=replace), self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(encoded, [True])

    def test_parent_deadline_and_output_cap_block_later_preparation(self):
        with patch.object(self.m.RUNTIME, 'prepare', side_effect=AssertionError('no prerequisite')):
            for end in (True, float('inf'), float('nan'), self.m.KERNEL.now()-1):
                with self.subTest(end=str(end)), self.assertRaises(self.m.Pending): self.m.prepare(deadline=end)
        calls = []; original = self.m.prerequisites
        def observe(*args): calls.append(args); return original(*args)
        with patch.object(self.m, 'prerequisites', side_effect=observe), patch.object(self.m, 'MAX_OUTPUT', 1), \
             self.assertRaises(self.m.Pending) as caught: self.m.prepare()
        self.assertEqual(str(caught.exception), 'dependency file report exceeds its bound')
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
