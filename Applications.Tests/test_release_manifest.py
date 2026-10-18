"""Private release-inventory proposal controls; no app execution or publication."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('private_inventory_'+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.fixture = load(ROOT/'Applications.Tests/test_releases.py').ReleaseTests(methodName='runTest')
        self.addCleanup(self.fixture.doCleanups); self.fixture.setUp()
        self.m = load(ROOT/'Applications/release_manifest.py')
        self.m.RELEASE = self.fixture.m
        self.m.BASE, self.m.KERNEL, self.m.Pending = self.fixture.m.BASE, self.fixture.m.KERNEL, self.fixture.m.Pending
        self.row = self.fixture.value['applications']['mk8.sava']
        self.directory = Path(self.row['directory'])

    def prepare(self):
        return self.m.prepare('mk8.sava', self.directory, 'application/main', 'gateway/main')

    def test_proposal_matches_complete_existing_declaration_and_writes_nothing(self):
        before = {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('no app entry')):
            value = json.loads(self.prepare())
        self.assertEqual(value['state'], 'release-manifest-proposal-only')
        self.assertEqual(value['declaration'], self.row)
        self.assertEqual(value['source_directory'], str(self.directory))
        self.assertEqual(set(value['observed_sources']), set(self.row['files']))
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_links_modes_empty_directories_and_capacity_refuse(self):
        path = self.directory/'application/main'
        path.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.prepare()
        path.chmod(0o755)
        link = self.directory/'extra'; os.link(path, link)
        with self.assertRaises(self.m.Pending): self.prepare()
        link.unlink(); link.mkdir(mode=0o755)
        with self.assertRaises(self.m.Pending): self.prepare()
        link.rmdir()
        with patch.object(self.m.RELEASE, 'MAX_TOTAL_BYTES', 1), patch.object(self.m.BASE, 'read_protected', side_effect=AssertionError('bound before content read')):
            with self.assertRaises(self.m.Pending): self.prepare()

    def test_change_after_encoding_is_rejected_by_complete_final_readback(self):
        canonical = self.m.BASE.canonical
        def encode(value):
            raw = canonical(value)
            if value.get('state') == 'release-manifest-proposal-only':
                (self.directory/'application/main').write_bytes(b'CHANGED APPLICATION\n')
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=encode), self.assertRaises(self.m.Pending):
            self.prepare()


if __name__ == '__main__':
    unittest.main()
