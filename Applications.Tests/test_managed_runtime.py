"""SDK-shaped inert metadata; no CLR, package or application execution."""
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
    spec = importlib.util.spec_from_file_location('private_managed_'+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class ManagedRuntimeTests(unittest.TestCase):
    def setUp(self):
        fixture = load(ROOT/'Applications.Tests/test_linux_images.py')
        self.helper = fixture.LinuxImageTests(methodName='runTest'); self.addCleanup(self.helper.doCleanups); self.helper.setUp()
        self.release = self.helper.helper
        self.m = load(ROOT/'Applications/managed_runtime.py'); self.m.IMAGE = self.helper.m
        self.m.RELEASE, self.m.BASE, self.m.KERNEL, self.m.Pending = self.helper.m.RELEASE, self.helper.m.BASE, self.helper.m.KERNEL, self.helper.m.Pending
        self.runtime = {'runtimeOptions': {'tfm': 'net10.0', 'rollForward': 'LatestPatch',
            'frameworks': [{'name': 'Microsoft.NETCore.App', 'version': '10.0.0'},
                           {'name': 'Microsoft.AspNetCore.App', 'version': '10.0.1'}],
            'configProperties': {'System.GC.Server': True,
                                 'System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization': False}}}
        self.target = '.NETCoreApp,Version=v10.0/linux-x64'
        self.deps = {'runtimeTarget': {'name': self.target, 'signature': ''},
            'targets': {self.target: {'fixture/1.0.0': {'runtime': {'main.dll': {}}}}},
            'libraries': {'fixture/1.0.0': {'type': 'project'}}}
        for row in self.release.value['applications'].values():
            directory = Path(row['directory'])
            for entry in row['entry_points'].values():
                for suffix, data in (('.dll', b'INVALID CLR ASSEMBLY'),
                    ('.runtimeconfig.json', json.dumps(self.runtime, indent=2).encode()),
                    ('.deps.json', json.dumps(self.deps, indent=2).encode())):
                    name = entry+suffix; (directory/name).write_bytes(data); (directory/name).chmod(0o644)
                    row['files'][name] = {'bytes': len(data), 'mode': '0644', 'sha256': hashlib.sha256(data).hexdigest()}
            marker = self.m.RELEASE.generation(row['entry_points'], row['files'])
            target = directory.with_name(marker); directory.rename(target); row.update(generation=marker, directory=str(target))
        self.release.write()

    def test_eight_actual_companion_sets_keep_sdk_bytes_and_emit_only_source_intentions(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no dotnet/package/assembly entry')):
            raw = self.m.prepare()
        value = json.loads(raw); self.assertEqual(value['state'], self.m.STATE)
        for app, roles in value['applications'].items():
            for role, row in roles.items():
                self.assertEqual(row['runtime']['frameworks'], {'Microsoft.NETCore.App': '10.0.0', 'Microsoft.AspNetCore.App': '10.0.1'})
                self.assertEqual(row['runtime']['roll_forward'], 'LatestPatch')
                self.assertEqual(row['dependencies']['runtime_target'], self.target)
                for source in row['sources'].values():
                    self.assertEqual(source['sha256'], hashlib.sha256(Path(source['path']).read_bytes()).hexdigest())
                self.assertEqual(Path(row['sources']['assembly']['path']).read_bytes(), b'INVALID CLR ASSEMBLY')
        self.assertIn(b'\n  ', self.release.path(name='application/main.runtimeconfig.json').read_bytes())

    def test_framework_and_runtime_property_policy_refuses_aliases_and_widening(self):
        mutations = [lambda v: v['runtimeOptions'].__setitem__('tfm', 'net9.0'),
            lambda v: v['runtimeOptions'].pop('rollForward'),
            lambda v: v['runtimeOptions'].__setitem__('rollForward', 'Major'),
            lambda v: v['runtimeOptions'].__setitem__('applyPatches', False),
            lambda v: v['runtimeOptions']['frameworks'][0].__setitem__('version', '10.1.0'),
            lambda v: v['runtimeOptions']['frameworks'][0].__setitem__('version', '10.0.1-preview'),
            lambda v: v['runtimeOptions']['frameworks'][0].__setitem__('rollForward', 'Minor'),
            lambda v: v['runtimeOptions']['frameworks'].append(v['runtimeOptions']['frameworks'][0]),
            lambda v: v['runtimeOptions'].__setitem__('additionalProbingPaths', ['/tmp']),
            lambda v: v['runtimeOptions']['configProperties'].__setitem__('System.GC.Server', 1),
            lambda v: v['runtimeOptions']['configProperties'].__setitem__('System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization', True)]
        for mutate in mutations:
            value = copy.deepcopy(self.runtime); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(self.m.Pending): self.m.runtime(value)
        value = copy.deepcopy(self.runtime); value['runtimeOptions']['framework'] = value['runtimeOptions'].pop('frameworks')[0]
        self.assertEqual(self.m.runtime(value)['frameworks'], {'Microsoft.NETCore.App': '10.0.0'})

    def test_dependency_target_architecture_tables_and_strict_json_are_bounded(self):
        for change in ('target', 'library', 'table', 'architecture'):
            value = copy.deepcopy(self.deps)
            if change == 'target': value['runtimeTarget']['name'] = '.NETCoreApp,Version=v10.0/linux-arm64'
            elif change == 'library': value['libraries'] = {}
            elif change == 'table': value['targets'][self.target] = {'missing/1': {}}
            with self.subTest(change=change), self.assertRaises(self.m.Pending): self.m.dependencies(value, 'unknown' if change == 'architecture' else 'x86_64')
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'\xff', b' '*(self.m.MAX_JSON+1)):
            with self.subTest(size=len(raw)), self.assertRaises(self.m.Pending): self.m.decoded(raw)
        value = {'runtimeOptions': {}}
        for _ in range(25): value = {'child': value}
        with self.assertRaises(self.m.Pending): self.m.decoded(json.dumps(value).encode())

    def test_missing_declared_companion_and_development_config_refuse_without_fallback(self):
        _, value = self.m.IMAGE.prerequisite(self.m.KERNEL.now()+30, 4711)
        declared = value['configuration']['value']['applications']['mk8.sava']['files']
        original = copy.deepcopy(declared)
        for change in ('missing', 'mode', 'empty', 'dev'):
            declared.clear(); declared.update(copy.deepcopy(original))
            if change == 'missing': del declared['application/main.dll']
            elif change == 'mode': declared['application/main.dll']['mode'] = '0755'
            elif change == 'empty': declared['application/main.dll']['bytes'] = 0
            else: declared['application/main.runtimeconfig.dev.json'] = original['application/main.runtimeconfig.json']
            with self.subTest(change=change), self.assertRaises(self.m.Pending): self.m.metadata(value, 'x86_64', self.m.KERNEL.now()+30)

    def test_actual_metadata_replacement_after_encoding_refuses_and_binary_cli_count_is_checked(self):
        raw = self.m.prepare(); stream = io.BytesIO()
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'argv', ['managed_runtime.py']), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=stream)):
            self.assertEqual(self.m.main(), 0)
        self.assertEqual(stream.getvalue(), raw)
        stream = types.SimpleNamespace(write=lambda data: True, flush=lambda: self.fail('no flush'))
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'argv', ['managed_runtime.py']), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=stream)), patch.object(self.m.sys, 'stderr', io.StringIO()):
            self.assertEqual(self.m.main(), 75)
        canonical = self.m.BASE.canonical; target = self.release.path(name='application/main.deps.json')
        def replace(value):
            result = canonical(value)
            if type(value) is dict and value.get('state') == self.m.STATE:
                other = target.with_name('replacement'); other.write_bytes(target.read_bytes()); other.chmod(0o644); other.replace(target)
            return result
        with patch.object(self.m.BASE, 'canonical', side_effect=replace), self.assertRaises(self.m.Pending): self.m.prepare()


if __name__ == '__main__':
    unittest.main()
