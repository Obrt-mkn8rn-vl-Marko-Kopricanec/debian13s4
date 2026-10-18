"""Whole private release preparations plus explicitly modeled join faults."""
import copy
from contextlib import ExitStack
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
    spec = importlib.util.spec_from_file_location('private_release_join_'+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class ReleasePreflightTests(unittest.TestCase):
    def setUp(self): self.m = load(ROOT/'Applications/preflight.py')

    def model(self):
        """Reported shapes for cross-component refusal controls, not file proof."""
        config = {'value': {'schema': 1, 'architecture': 'x86_64', 'interpreter': None}}
        values = {}
        for tag in self.m.GROUPS['release-files']:
            values[tag] = {'schema': 1, 'profile': self.m.CHECKS[tag][1], 'state': self.m.CHECKS[tag][2],
                'namespace': 4711, 'release_sha256': 'a'*64, 'applications': {}}
            values[tag]['configuration' if tag == 'linux-images' else 'image_configuration'] = copy.deepcopy(config)
            if tag != 'linux-images': values[tag]['runtime_sha256'] = 'b'*64
        for app in ('mk8.dns', 'mk8.drava', 'mk8.email', 'mk8.sava'):
            for value in values.values(): value['applications'][app] = {}
            for role in ('application', 'gateway'):
                source = {'path': '/protected/'+app+'/'+role+'/main', 'sha256': 'c'*64,
                          'identity': [1, 2, 0o100755, 0, 0, 64, 10, 10]}
                assembly = copy.deepcopy(source); assembly.update(path=source['path']+'.dll', sha256='d'*64)
                assembly['identity'][2] = 0o100644
                values['linux-images']['applications'][app][role] = {'source': source, 'image': {'architecture': 'x86_64'}}
                values['managed-images']['applications'][app][role] = {'source': assembly}
                values['managed-assets']['applications'][app][role] = {'assets': [{'kind': 'runtime', 'source': copy.deepcopy(assembly)}]}
        return values

    def test_real_three_preparations_bind_eight_entries_and_selected_files_without_loading(self):
        fixture = load(ROOT/'Applications.Tests/test_managed_assets.py')
        helper = fixture.ManagedAssetTests('runTest'); self.addCleanup(helper.doCleanups); helper.setUp()
        binary = load(ROOT/'Applications.Tests/test_managed_images.py').assembly()[0]
        for row in helper.release.value['applications'].values():
            for entry in row['entry_points'].values():
                name = entry+'.dll'; (Path(row['directory'])/name).write_bytes(binary)
                row['files'][name] = {'bytes': len(binary), 'mode': '0644', 'sha256': hashlib.sha256(binary).hexdigest()}
        helper.declare()
        managed = load(ROOT/'Applications/managed_images.py'); managed.RUNTIME = helper.h.m
        managed.BASE, managed.KERNEL, managed.Pending = helper.m.BASE, helper.m.KERNEL, helper.m.Pending
        modules = {'linux-images': helper.h.helper.m, 'managed-images': managed, 'managed-assets': helper.m}
        receipts, order = {}, []
        def capture(tag, original):
            def run(deadline=None):
                order.append(tag); raw = original(deadline=deadline); receipts[tag] = raw; return raw
            return run
        with ExitStack() as stack:
            for tag, module in modules.items():
                stack.enter_context(patch.object(module, 'prepare', side_effect=capture(tag, module.prepare)))
            stack.enter_context(patch.object(self.m, 'owned', side_effect=modules.__getitem__))
            stack.enter_context(patch('subprocess.Popen', side_effect=AssertionError('no CLR/apphost/native entry')))
            raw = self.m.prepare('release-files')
        value = json.loads(raw); joined = value['release_file_correspondence']
        self.assertEqual(order, list(self.m.GROUPS['release-files'])); self.assertEqual(len(joined['entries']), 8)
        self.assertFalse(joined['runtime_compatibility_verified']); self.assertFalse(joined['publisher_authenticated'])
        for tag, receipt in receipts.items():
            self.assertEqual(value['checks'][tag]['sha256'], hashlib.sha256(receipt).hexdigest())
            self.assertEqual(value['checks'][tag]['bytes'], len(receipt))
        for row in joined['entries']:
            self.assertEqual(row['selected_assets'], 4); self.assertEqual(row['assembly_sha256'], hashlib.sha256(binary).hexdigest())
        self.assertFalse(json.loads(receipts['managed-images'])['applications']['mk8.sava']['application']['structure']['il_validated'])
        sink = io.BytesIO()
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)):
            self.assertEqual(self.m.main(['--check', 'release-files']), 0)
        self.assertIn(b'8 entries for x86_64', sink.getvalue())

    def test_release_runtime_configuration_and_whole_entry_correspondence_refuse_drift(self):
        original = self.model(); self.assertEqual(len(self.m.release_file_correspondence(original)['entries']), 8)
        assembly = lambda value: value['managed-images']['applications']['mk8.sava']['application']['source']
        assets = lambda value: value['managed-assets']['applications']['mk8.sava']['application']['assets']
        changes = [lambda v: v['managed-assets'].__setitem__('release_sha256', 'e'*64),
            lambda v: v['managed-assets'].__setitem__('runtime_sha256', 'e'*64),
            lambda v: v['managed-images']['image_configuration']['value'].__setitem__('schema', True),
            lambda v: v['managed-images']['applications'].pop('mk8.email'),
            lambda v: v['managed-assets']['applications']['mk8.sava'].pop('gateway'),
            lambda v: assembly(v).__setitem__('path', '/different/entry.dll'),
            lambda v: assets(v).clear(), lambda v: assets(v).append(copy.deepcopy(assets(v)[0])),
            lambda v: assets(v)[0]['source'].__setitem__('sha256', 'e'*64),
            lambda v: assets(v)[0]['source']['identity'].__setitem__(0, True)]
        for index, change in enumerate(changes):
            value = copy.deepcopy(original); change(value)
            with self.subTest(index=index), self.assertRaises(self.m.Pending): self.m.release_file_correspondence(value)

    def test_group_retains_shared_deadline_and_postencoding_namespace_time_fences(self):
        values, delivered = self.model(), []
        context, clock = [4711], [10]
        def uint(value, maximum):
            if type(value) is not int or not 0 <= value <= maximum: raise self.m.Pending('modeled uint refusal')
            return value
        def owned(tag):
            def prepare(deadline): delivered.append((tag, deadline)); return self.m.canonical(values[tag])
            return types.SimpleNamespace(KERNEL=types.SimpleNamespace(namespace=lambda: context[0], uint=uint),
                Pending=self.m.Pending, MAX_OUTPUT=65536, prepare=prepare)
        with patch.object(self.m, 'owned', side_effect=owned), patch.object(self.m, 'now', side_effect=lambda: clock[0]):
            raw = self.m.prepare('release-files', deadline=20)
            self.assertEqual(delivered, [(tag, 20) for tag in self.m.GROUPS['release-files']])
            canonical = self.m.canonical
            for mode in ('namespace', 'time'):
                context[0], clock[0] = 4711, 10; delivered.clear()
                def encode(value):
                    result = canonical(value)
                    if value.get('state') == 'application-preflight-source-only':
                        if mode == 'namespace': context[0] = 4712
                        else: clock[0] = 20
                    return result
                with self.subTest(mode=mode), patch.object(self.m, 'canonical', side_effect=encode), self.assertRaises(self.m.Pending):
                    self.m.prepare('release-files', deadline=20)
                self.assertEqual(len(delivered), 3)
        self.assertEqual(json.loads(raw)['requested'], 'release-files')


if __name__ == '__main__':
    unittest.main()
