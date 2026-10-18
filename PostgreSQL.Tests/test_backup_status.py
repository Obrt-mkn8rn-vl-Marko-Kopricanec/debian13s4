"""Inspect real private history without reentering protected/native preparation."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class BackupStatusTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('private_backup_status', ROOT/'PostgreSQL/backup_status.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-backup-status.')
        self.addCleanup(self.temp.cleanup)
        self.store = Path(self.temp.name); self.store.chmod(0o700)
        for module in (self.m.LIFECYCLE.ATTEMPT, self.m.LIFECYCLE.MANIFEST, self.m.LIFECYCLE.UNCERTAINTY, self.m.LIFECYCLE.FAILURE):
            module._STORAGE.TRUST_ROOT = self.store
            module._STORAGE.TRUSTED_UID = os.geteuid()

    def test_empty_and_reserved_status_remain_read_only_and_never_permit_retry(self):
        with patch.object(self.m.LIFECYCLE, 'run_once', side_effect=AssertionError('no entry')), patch('subprocess.Popen', side_effect=AssertionError('no native')):
            value = json.loads(self.m.inspect(self.store))
            self.assertEqual(value['state'], 'no-recorded-attempt')
            self.assertEqual(list(self.store.iterdir()), [])
            self.m.LIFECYCLE.ATTEMPT.reserve(self.store, 'mk8.dns', 4711)
            leaf = self.store/self.m.LIFECYCLE.ATTEMPT.LEAF
            before = leaf.read_bytes(), leaf.stat().st_ino
            value = json.loads(self.m.inspect(self.store))
            self.assertEqual(value['state'], 'reserved-outcome-unknown')
            self.assertEqual((leaf.read_bytes(), leaf.stat().st_ino), before)
            self.assertIs(value['retry_authorized'], False)
            self.assertIs(value['backup_complete'], False)

    def test_real_pipeline_history_is_verified_without_listing_or_dump_reentry(self):
        from test_backup_lifecycle import BackupLifecycleTests
        fixture = BackupLifecycleTests(methodName='runTest')
        self.addCleanup(fixture.doCleanups); fixture.setUp()
        fixture.run_once()
        self.m.LIFECYCLE = fixture.m
        before = {p: p.read_bytes() for p in fixture.store.iterdir()}
        with patch.object(fixture.m, 'run_once', side_effect=AssertionError('no lifecycle')), patch.object(fixture.m.SELECTED, 'stage_selected', side_effect=AssertionError('no stage')), patch('subprocess.Popen', side_effect=AssertionError('no native')):
            value = json.loads(self.m.inspect(fixture.store))
        self.assertEqual(value['state'], 'historical-listing-recorded')
        self.assertTrue(value['records']['manifest']['present'])
        self.assertIs(value['backup_complete'], False)
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_corrupt_linked_and_conflicting_records_refuse(self):
        leaf = self.store/self.m.LIFECYCLE.ATTEMPT.LEAF
        leaf.write_bytes(b'not json'); leaf.chmod(0o600)
        with self.assertRaises(ValueError): self.m.inspect(self.store)
        leaf.unlink(); leaf.symlink_to(self.store/'missing')
        with self.assertRaises(ValueError): self.m.inspect(self.store)
        for records in (
            {'reservation': None, 'manifest': {'application': 'mk8.dns'}, 'incomplete': None},
            {'reservation': {'application': 'mk8.dns'}, 'manifest': {'application': 'mk8.email'}, 'incomplete': None},
            {'reservation': {'application': 'mk8.dns'}, 'manifest': {}, 'incomplete': {}},
        ):
            with self.assertRaises(self.m.Pending): self.m.classify(records)

    def test_post_encoding_change_and_output_failure_do_not_become_success(self):
        life = self.m.LIFECYCLE
        life.ATTEMPT.reserve(self.store, 'mk8.dns', 4711)
        leaf = self.store/life.ATTEMPT.LEAF
        encode = life.PREP.canonical
        def encoded(value):
            raw = encode(value)
            if value.get('scope') == 'historical-backup-records-only': leaf.write_bytes(b'corrupt')
            return raw
        with patch.object(life.PREP, 'canonical', side_effect=encoded), self.assertRaises(ValueError):
            self.m.inspect(self.store)
        raw = b'{"schema":1}\n'
        output = types.SimpleNamespace(buffer=types.SimpleNamespace(write=lambda data: True, flush=lambda: self.fail('no flush')))
        with patch.object(self.m, 'inspect', return_value=raw), patch.object(self.m.sys, 'stdout', output), patch.object(self.m.sys, 'stderr', io.StringIO()):
            self.assertEqual(self.m.main(['--directory', str(self.store), '--format', 'json']), 75)

    def test_installed_lowercase_bundle_loads_without_firewall_policy_or_native_entry(self):
        spec = importlib.util.spec_from_file_location('backup_status_pack', ROOT/'Bootstrap/pack.py')
        pack = importlib.util.module_from_spec(spec); spec.loader.exec_module(pack)
        library = self.store/'installed'
        for name, (data, mode) in pack.assets().items():
            path = library/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); path.chmod(int(mode, 8))
        self.assertEqual([p.name for p in (library/'lib/firewall').iterdir()], ['kernel.py'])
        spec = importlib.util.spec_from_file_location('installed_backup_status', library/'lib/postgresql/backup_status.py')
        installed = importlib.util.module_from_spec(spec)
        history = self.store/'history'; history.mkdir(mode=0o700)
        with patch('subprocess.Popen', side_effect=AssertionError('no native entry')):
            spec.loader.exec_module(installed)
            for module in (installed.LIFECYCLE.ATTEMPT, installed.LIFECYCLE.MANIFEST, installed.LIFECYCLE.UNCERTAINTY, installed.LIFECYCLE.FAILURE):
                module._STORAGE.TRUST_ROOT = self.store
                module._STORAGE.TRUSTED_UID = os.geteuid()
                self.assertFalse(hasattr(module._STORAGE, 'AUTO'))
            installed.LIFECYCLE.ATTEMPT.reserve(history, 'mk8.email', 4711)
            value = json.loads(installed.inspect(history))
        self.assertEqual(value['application'], 'mk8.email')
        self.assertEqual(value['state'], 'reserved-outcome-unknown')
        self.assertIs(value['retry_authorized'], False)


if __name__ == '__main__':
    unittest.main()
