"""Real ordinary-UID directory observations; no account or service operations."""
import errno
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('private_directory_'+name, ROOT/'Applications'/name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivateDirectoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='application-storage.')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.root.chmod(0o700)
        self.parent = self.root/'parent'; self.parent.mkdir(mode=0o755)
        self.data = self.parent/'data'; self.data.mkdir(mode=0o700)
        self.m = load('private_directory.py')
        self.m.BASE.TRUST_ROOT = self.root; self.m.BASE.TRUSTED_UID = os.geteuid()
        self.m.KERNEL.namespace = lambda: 4711
        self.uid, self.gid = os.geteuid(), os.getegid()

    def observe(self):
        return self.m.observe(self.data, self.uid, self.gid)

    def test_actual_owned_directory_is_read_only_without_content_inspection(self):
        sentinel = self.data/'not-an-archive'; sentinel.write_bytes(b'opaque original data')
        with patch.object(Path, 'iterdir', side_effect=AssertionError('no content scan')), patch('os.scandir', side_effect=AssertionError('no content scan')), patch('subprocess.Popen', side_effect=AssertionError('no native entry')):
            raw = self.observe()
        value = json.loads(raw)
        self.assertEqual(value['state'], self.m.STATE)
        self.assertEqual((value['owner_uid'], value['owner_gid']), (self.uid, self.gid))
        self.assertEqual(value['identity'], self.m.identity(self.data.lstat()))
        self.assertEqual(set(value['ancestry']), {str(self.root), str(self.parent)})
        self.assertFalse(value['contents_inspected']); self.assertFalse(value['write_tested'])
        self.assertEqual(sentinel.read_bytes(), b'opaque original data')

    def test_ownership_modes_missing_and_symbolic_directories_refuse_without_mutation(self):
        for uid, gid in ((self.uid+1, self.gid), (self.uid, self.gid+1), (True, self.gid)):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(self.m.Pending):
                self.m.observe(self.data, uid, gid)
        for mode in (0o755, 0o750, 0o770, 0o600):
            self.data.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(self.m.Pending): self.observe()
        self.data.chmod(0o700)
        saved = self.parent/'saved'; self.data.rename(saved); self.data.symlink_to(saved)
        with self.assertRaises(self.m.Pending): self.observe()
        self.data.unlink()
        with self.assertRaises(FileNotFoundError): self.observe()
        self.assertTrue(saved.is_dir())

    def test_ancestry_search_and_write_permissions_are_actual_separate_requirements(self):
        for mode, message in ((0o600, 'search permission'), (0o770, 'protected root-owned')):
            self.parent.chmod(mode)
            try:
                with self.assertRaisesRegex(self.m.Pending, message): self.observe()
            finally:
                self.parent.chmod(0o755)
        with self.assertRaises(self.m.Pending):
            self.m.observe(self.root, self.uid, self.gid)
        with self.assertRaises(self.m.Pending):
            self.m.observe(self.data, self.uid, self.gid, [self.gid])

    def test_replacement_after_encoding_refuses_and_retires_the_held_descriptor(self):
        canonical, close = self.m.BASE.canonical, self.m.os.close
        descriptors = []
        def replace(value):
            raw = canonical(value)
            self.data.rename(self.parent/'old-data'); self.data.mkdir(mode=0o700)
            return raw
        def closed(fd): descriptors.append(fd); return close(fd)
        with patch.object(self.m.BASE, 'canonical', side_effect=replace), patch.object(self.m.os, 'close', side_effect=closed), self.assertRaises(self.m.Pending):
            self.observe()
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError): os.fstat(descriptors[0])

    def test_body_and_close_failures_keep_both_objects_and_close_once(self):
        original = self.m.Pending('original encoder refusal')
        cleanup = OSError(errno.EIO, 'modeled close failure')
        close = self.m.os.close; descriptors = []
        def failed(fd):
            descriptors.append(fd); close(fd); raise cleanup
        with patch.object(self.m.BASE, 'canonical', side_effect=original), patch.object(self.m.os, 'close', side_effect=failed), self.assertRaises(self.m.CleanupFailure) as caught:
            self.observe()
        self.assertIs(caught.exception.cause, original)
        self.assertIs(caught.exception.__cause__, original)
        self.assertIs(caught.exception.close_error, cleanup)
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError): os.fstat(descriptors[0])
        with patch.object(self.m.os, 'close', side_effect=failed), self.assertRaises(self.m.Pending) as only_close:
            self.observe()
        self.assertIs(only_close.exception.__cause__, cleanup)
        self.assertEqual(len(descriptors), 2)

    def test_sava_storage_join_uses_real_primitive_and_retains_its_distinct_refusal(self):
        service = load('sava_service.py'); service.STORAGE = self.m
        plan = {'required_storage': {'path': str(self.data), 'owner_uid': self.uid, 'owner_gid': self.gid},
                'units': {'application': {'identity': {'shared_groups': {}}}}}
        raw, value = service.storage_observation(plan, service.KERNEL.now()+10, 4711)
        self.assertEqual(value, json.loads(raw))
        self.assertEqual(value['identity'], self.m.identity(self.data.lstat()))
        original = self.m.Pending('real primitive refusal class')
        self.assertIsNot(self.m.Pending, service.Pending)
        with patch.object(self.m, 'observe', side_effect=original), self.assertRaises(service.Pending) as caught:
            service.storage_observation(plan, service.KERNEL.now()+10, 4711)
        self.assertIs(caught.exception.__cause__, original)
        for flag in (0, 1, 'yes', None):
            with patch.object(service, 'prerequisite', side_effect=AssertionError('no inputs')), self.assertRaises(service.Pending):
                service.prepare(require_storage=flag)

    def test_sava_storage_requirement_is_encoded_before_second_observation(self):
        service = load('sava_service.py'); service.KERNEL.namespace = lambda: 4711
        raw = self.observe(); value = json.loads(raw)
        events = []; canonical = service.BASE.canonical
        def storage(*args):
            events.append('storage'); return raw, value
        def encode(result):
            if type(result) is dict and result.get('state') == service.STATE:
                events.append('encode')
            return canonical(result)
        # This control isolates the new orchestration. The preceding control
        # exercises its real directory reader separately; child receipts here
        # are explicitly modeled and are not a fresh complete preparation.
        with patch.object(service, 'prerequisite', return_value=(b'{}\n', {})), \
             patch.object(service, 'application_files', return_value=({}, (b'private',))), \
             patch.object(service, 'render', side_effect=lambda value: {'required_storage': {'observed': False}}), \
             patch.object(service, 'storage_observation', side_effect=storage), \
             patch.object(service.BASE, 'canonical', side_effect=encode):
            result = json.loads(service.prepare(require_storage=True))
            self.assertTrue(result['plan']['required_storage']['observed'])
            self.assertEqual(result['plan']['required_storage']['observation'], value)
            self.assertEqual(events, ['storage', 'encode', 'storage'])
            with patch.object(service, 'storage_observation', side_effect=[(raw, value), (raw+b' ', value)]), self.assertRaisesRegex(service.Pending, 'storage observation changed'):
                service.prepare(require_storage=True)


if __name__ == '__main__':
    unittest.main()
