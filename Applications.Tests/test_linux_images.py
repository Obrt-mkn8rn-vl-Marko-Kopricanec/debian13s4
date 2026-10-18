"""Synthetic inert ELF-shaped files, never kernel or dynamic-loader execution."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('private_elf_'+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def image(machine=62, interpreter='/lib64/ld-linux-x86-64.so.2'):
    # Zero instruction/data bytes deliberately do not make a runnable application.
    raw = bytearray(512)
    ident = b'\x7fELF\x02\x01\x01'+b'\0'*9
    headers = [(3, 4, 320, 0, 0, len(interpreter)+1, len(interpreter)+1, 1)] if interpreter else []
    headers += [(1, 5, 0, 0x400000, 0, 512, 512, 4096), (0x6474e551, 6, 0, 0, 0, 0, 0, 16)]
    if interpreter: headers.append((2, 4, 368, 0x400170, 0, 16, 16, 8))
    struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, ident, 2, machine, 1, 0x4001e0, 64, 0, 0, 64, 56, len(headers), 0, 0, 0)
    for index, row in enumerate(headers): struct.pack_into('<IIQQQQQQ', raw, 64+56*index, *row)
    if interpreter: raw[320:320+len(interpreter)+1] = interpreter.encode()+b'\0'
    return bytes(raw)


class LinuxImageTests(unittest.TestCase):
    def setUp(self):
        fixture = load(ROOT/'Applications.Tests/test_releases.py')
        self.helper = fixture.ReleaseTests(methodName='runTest'); self.addCleanup(self.helper.doCleanups); self.helper.setUp()
        self.m = load(ROOT/'Applications/linux_images.py'); self.m.RELEASE = self.helper.m
        self.m.BASE, self.m.KERNEL, self.m.Pending = self.helper.m.BASE, self.helper.m.KERNEL, self.helper.m.Pending
        self.m.INPUT = self.helper.root/'images.json'
        self.settings = {'schema': 1, 'architecture': 'x86_64', 'interpreter': '/lib64/ld-linux-x86-64.so.2'}
        self.m.INPUT.write_bytes(self.m.BASE.canonical(self.settings)); self.m.INPUT.chmod(0o600)
        for row in self.helper.value['applications'].values():
            directory = Path(row['directory'])
            for name in row['entry_points'].values():
                data = image(); (directory/name).write_bytes(data)
                row['files'][name].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            marker = self.m.RELEASE.generation(row['entry_points'], row['files'])
            target = directory.with_name(marker); directory.rename(target)
            row.update(generation=marker, directory=str(target))
        self.helper.write()

    def test_eight_protected_entries_match_explicit_architecture_without_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no readelf/loader/application')):
            raw = self.m.prepare()
        value = json.loads(raw)
        self.assertEqual(value['state'], self.m.STATE)
        self.assertEqual(value['configuration']['value'], self.settings)
        self.assertEqual(set(value['applications']), set(self.m.RELEASE.APPLICATIONS))
        for app, roles in value['applications'].items():
            self.assertEqual(set(roles), {'application', 'gateway'})
            for role, row in roles.items():
                self.assertEqual(row['source']['sha256'], hashlib.sha256(image()).hexdigest())
                self.assertEqual(row['source']['path'], str(self.helper.path(app, role+'/main')))
                self.assertEqual(row['image']['architecture'], 'x86_64')
                self.assertEqual(row['image']['entry_address'], 0x4001e0)
                self.assertTrue(row['image']['nonexecutable_stack_declared'])
        # The sibling DLL is still deliberately invalid: this profile does not
        # claim CLR/library validation or a complete native loader proof.
        self.assertIn(b'INVALID CLR', self.helper.path(name='shared/library.dll').read_bytes())
        arm = self.m.inspect(image(183, '/lib/ld-linux-aarch64.so.1'), 'aarch64', '/lib/ld-linux-aarch64.so.1')
        self.assertEqual(arm['architecture'], 'aarch64')
        self.assertIsNone(self.m.inspect(image(interpreter=None), 'x86_64', None)['interpreter'])

    def test_header_architecture_ranges_and_extended_counts_refuse_before_segment_reads(self):
        cases = [b'INVALID ELF', bytearray(image()), image()[:63]]
        for offset, fmt, value in ((4, 'B', 1), (5, 'B', 2), (7, 'B', 9), (8, 'B', 1),
            (16, 'H', 1), (18, 'H', 183), (24, 'Q', 0), (32, 'Q', 2**64-1),
            (52, 'H', 63), (54, 'H', 55), (56, 'H', 65535), (40, 'Q', 500), (60, 'H', 1)):
            raw = bytearray(image()); struct.pack_into('<'+fmt, raw, offset, value); cases.append(bytes(raw))
        for number, raw in enumerate(cases):
            with self.subTest(number=number), self.assertRaises(self.m.Pending):
                self.m.inspect(raw, 'x86_64', self.settings['interpreter'])

    def test_segment_permissions_entry_alignment_interpreter_and_memory_bounds_refuse(self):
        cases = []
        for header, field, value in ((1, 1, 7), (2, 1, 7), (1, 5, 513), (1, 6, 511),
                                     (1, 7, 3), (1, 3, 0x400001), (1, 6, 2**64-1),
                                     (0, 0, 0), (3, 0, 0), (0, 5, 2**64-1)):
            raw = bytearray(image()); row = list(struct.unpack_from('<IIQQQQQQ', raw, 64+56*header))
            row[field] = value; struct.pack_into('<IIQQQQQQ', raw, 64+56*header, *row); cases.append(bytes(raw))
        raw = bytearray(image()); struct.pack_into('<Q', raw, 24, 0x400300); cases.append(bytes(raw))
        raw = bytearray(image()); raw[321] = 0; cases.append(bytes(raw))
        for number, raw in enumerate(cases):
            with self.subTest(number=number), self.assertRaises(self.m.Pending):
                self.m.inspect(raw, 'x86_64', self.settings['interpreter'])
        with self.assertRaises(self.m.Pending): self.m.inspect(image(), 'x86_64', '/lib/other.so')
        with self.assertRaises(self.m.Pending): self.m.inspect(image(), 'x86_64', None)
        with self.assertRaises(self.m.Pending): self.m.inspect(image(interpreter=None), 'x86_64', self.settings['interpreter'])

    def test_profile_is_private_canonical_typed_and_has_no_machine_fallback(self):
        for field, bad in (('schema', True), ('architecture', 'native'), ('architecture', []),
            ('interpreter', '/tmp/loader'), ('interpreter', '/lib/../lib/loader'), ('interpreter', False)):
            value = copy.deepcopy(self.settings); value[field] = bad
            self.m.INPUT.write_bytes(self.m.BASE.canonical(value))
            with self.subTest(field=field, bad=bad), self.assertRaises(self.m.Pending): self.m.prepare()
        raw = self.m.BASE.canonical(self.settings)
        for bad in (raw+b'\n', raw.replace(b'"schema":1', b'"schema":1,"schema":1'), raw.replace(b'"schema":1', b'"schema":1e999')):
            self.m.INPUT.write_bytes(bad)
            with self.subTest(raw=bad), self.assertRaises(self.m.Pending): self.m.prepare()
        self.m.INPUT.write_bytes(raw); self.m.INPUT.chmod(0o644)
        with self.assertRaises(self.m.Pending): self.m.prepare()

    def test_outer_encoding_precedes_final_observations_and_actual_entry_replacement_refuses(self):
        events = []; child, entries, encode = self.m.prerequisite, self.m.entries, self.m.BASE.canonical
        def preparation(*args): events.append('release'); return child(*args)
        def observed(*args): events.append('entries'); return entries(*args)
        def canonical(value):
            raw = encode(value)
            if type(value) is dict and value.get('state') == self.m.STATE: events.append('encode')
            return raw
        with patch.object(self.m, 'prerequisite', side_effect=preparation), patch.object(self.m, 'entries', side_effect=observed), patch.object(self.m.BASE, 'canonical', side_effect=canonical): self.m.prepare()
        self.assertEqual(events, ['release', 'entries', 'encode', 'release', 'entries'])
        target = self.helper.path()
        def replacement(value):
            raw = encode(value)
            if type(value) is dict and value.get('state') == self.m.STATE:
                other = target.with_name('replacement'); other.write_bytes(target.read_bytes()); other.chmod(0o755); other.replace(target)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=replacement), self.assertRaises(self.m.Pending): self.m.prepare()

    def test_original_refusal_cap_final_expiry_and_binary_output_counts(self):
        error = self.m.RELEASE.Pending('original release refusal')
        with patch.object(self.m.RELEASE, 'prepare', side_effect=error), self.assertRaises(self.m.Pending) as caught: self.m.prepare()
        self.assertIs(caught.exception.__cause__, error)
        with patch.object(self.m, 'MAX_OUTPUT', 1), patch.object(self.m, 'prerequisite', wraps=self.m.prerequisite) as child:
            with self.assertRaises(self.m.Pending): self.m.prepare()
            self.assertEqual(child.call_count, 1)
        original = self.m.entries; calls = 0
        with patch.object(self.m.KERNEL, 'now', return_value=10) as clock:
            def expire(*args):
                nonlocal calls
                value = original(*args); calls += 1
                if calls == 2: clock.return_value = 20
                return value
            with patch.object(self.m, 'entries', side_effect=expire), self.assertRaises(self.m.Pending): self.m.prepare(deadline=20)
        self.assertEqual(calls, 2)
        payload = self.m.prepare(); sink = io.BytesIO()
        with patch.object(self.m.sys, 'argv', ['linux_images.py']), patch.object(self.m, 'prepare', return_value=payload), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)):
            self.assertEqual(self.m.main(), 0)
        self.assertEqual(sink.getvalue(), payload)
        sink = types.SimpleNamespace(write=lambda raw: False, flush=lambda: self.fail('no flush'))
        with patch.object(self.m.sys, 'argv', ['linux_images.py']), patch.object(self.m, 'prepare', return_value=payload), patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)), patch.object(self.m.sys, 'stderr', io.StringIO()):
            self.assertEqual(self.m.main(), 75)


if __name__ == '__main__':
    unittest.main()
