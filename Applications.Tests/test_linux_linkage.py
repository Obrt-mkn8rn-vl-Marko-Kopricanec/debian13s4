"""Synthetic dynamic sections and private files; no loader or host probes."""
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
    spec = importlib.util.spec_from_file_location('private_linkage_'+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def image(machine=62, interpreter='/lib64/ld-linux-x86-64.so.2', needed=('libc.so.6', 'libstdc++.so.6'), extra=()):
    raw = bytearray(8192)
    headers = [(3, 4, 320, 0, 0, len(interpreter)+1, len(interpreter)+1, 1)] if interpreter else []
    headers += [(1, 5, 0, 0x400000, 0, len(raw), len(raw), 4096), (0x6474e551, 6, 0, 0, 0, 0, 0, 16)]
    strings, offsets = bytearray(b'\0'), []
    for name in needed:
        offsets.append(len(strings)); strings.extend(name.encode('ascii')+b'\0')
    entries = [(5, 0x401000), (10, len(strings)), *[(1, offset) for offset in offsets],
               (0x6ffffef5, 0), *extra, (0, 0), (0, 0)]
    if interpreter: headers.append((2, 4, 384, 0x400180, 0, len(entries)*16, len(entries)*16, 8))
    struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, b'\x7fELF\x02\x01\x01'+b'\0'*9,
        2, machine, 1, 0x401ff0, 64, 0, 0, 64, 56, len(headers), 0, 0, 0)
    for index, row in enumerate(headers): struct.pack_into('<IIQQQQQQ', raw, 64+56*index, *row)
    if interpreter:
        raw[320:320+len(interpreter)+1] = interpreter.encode()+b'\0'
        for index, row in enumerate(entries): struct.pack_into('<qQ', raw, 384+16*index, *row)
        raw[4096:4096+len(strings)] = strings
    return bytes(raw)


class LinkageStructureTests(unittest.TestCase):
    def setUp(self): self.m = load(ROOT/'Applications/linux_linkage.py')

    def test_ordered_needed_names_are_file_facts_with_uninterpreted_tags_explicit(self):
        for architecture, machine, interpreter in [('x86_64', 62, '/lib64/ld-linux-x86-64.so.2'),
                                                  ('aarch64', 183, '/lib/ld-linux-aarch64.so.1')]:
            with self.subTest(architecture=architecture), patch('subprocess.Popen', side_effect=AssertionError('no loader')):
                value = self.m.inspect(image(machine, interpreter), architecture, interpreter)
            self.assertEqual(value['needed'], ['libc.so.6', 'libstdc++.so.6'])
            self.assertTrue(value['dynamic_segment']); self.assertEqual(value['uninterpreted_tags'], [0x6ffffef5])
            self.assertFalse(value['dependency_resolution_verified']); self.assertFalse(value['relocations_verified'])
            self.assertFalse(value['loader_environment_verified'])
        value = self.m.inspect(image(interpreter=None), 'x86_64', None)
        self.assertFalse(value['dynamic_segment']); self.assertEqual(value['needed'], [])
        value = self.m.inspect(image(extra=[(14, 1)]), 'x86_64', '/lib64/ld-linux-x86-64.so.2')
        self.assertEqual(value['soname'], 'libc.so.6')

    def test_paths_hooks_textrel_offsets_extents_termination_and_duplicate_names_refuse(self):
        interpreter = '/lib64/ld-linux-x86-64.so.2'
        originals = [image(needed=(name,)) for name in ('', '../lib.so', '/lib/lib.so', '$ORIGIN/lib.so', 'lib:other', 'lib\nother')]
        originals += [image(needed=('lib.so', 'lib.so')), image(needed=tuple('lib%d.so'%i for i in range(65))),
                      image(extra=[(5, 0x401000)]), image(extra=[(10, 1)]), image(extra=[(30, 4)])]
        originals += [image(extra=[(tag, 1)]) for tag in self.m.FORBIDDEN]
        # Every mutation is applied to an otherwise admitted synthetic image.
        raw = image(); self.assertEqual(len(self.m.inspect(raw, 'x86_64', interpreter)['needed']), 2)
        for position, fmt, value in ((384+8, 'Q', 0x402000), (400+8, 'Q', self.m.MAX_STRINGS+1),
            (384+8, 'Q', 0x400180), (416+8, 'Q', 99999), (384, 'q', -1),
            (384+5*16, 'q', 1), (384+6*16+8, 'Q', 1),
            (64+3*56+16, 'Q', 0x400181), (64+3*56+32, 'Q', 17),
            (64+3*56+40, 'Q', 1), (4096, 'B', 1)):
            damaged = bytearray(raw); struct.pack_into('<'+fmt, damaged, position, value); originals.append(bytes(damaged))
        damaged = bytearray(raw); damaged[4097] = 255; originals.append(bytes(damaged))
        damaged = bytearray(raw)
        for position in (384+5*16, 384+6*16): struct.pack_into('<qQ', damaged, position, 0x6ffffef5, 0)
        originals.append(bytes(damaged))
        originals += [image(needed=('x'*256,)), bytearray(raw), b'INVALID ELF']
        for number, damaged in enumerate(originals):
            with self.subTest(number=number), self.assertRaises(self.m.Pending): self.m.inspect(damaged, 'x86_64', interpreter)


class ProtectedLinkageTests(unittest.TestCase):
    def setUp(self):
        fixture = load(ROOT/'Applications.Tests/test_linux_images.py')
        self.h = fixture.LinuxImageTests('runTest'); self.addCleanup(self.h.doCleanups); self.h.setUp()
        self.m = load(ROOT/'Applications/linux_linkage.py'); self.m.IMAGE = self.h.m
        self.m.BASE, self.m.KERNEL, self.m.Pending = self.h.m.BASE, self.h.m.KERNEL, self.h.m.Pending
        self.release = self.h.helper
        for row in self.release.value['applications'].values():
            directory = Path(row['directory'])
            for name in row['entry_points'].values():
                raw = image(); (directory/name).write_bytes(raw)
                row['files'][name].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            marker = self.m.IMAGE.RELEASE.generation(row['entry_points'], row['files'])
            target = directory.with_name(marker); directory.rename(target); row.update(generation=marker, directory=str(target))
        self.release.write()

    def test_eight_real_protected_entries_encode_before_reobservations_and_refuse_replacement(self):
        events=[]; child, observe, canonical=self.m.prerequisite, self.m.observations, self.m.BASE.canonical
        def prerequisite(*args): events.append('images'); return child(*args)
        def observed(*args): events.append('linkage'); return observe(*args)
        def encode(value):
            raw=canonical(value)
            if type(value) is dict and value.get('state')==self.m.STATE: events.append('encode')
            return raw
        with patch.object(self.m,'prerequisite',side_effect=prerequisite), patch.object(self.m,'observations',side_effect=observed), \
             patch.object(self.m.BASE,'canonical',side_effect=encode), patch('subprocess.Popen',side_effect=AssertionError('no native loader')):
            raw=self.m.prepare()
        self.assertEqual(events,['images','linkage','encode','images','linkage'])
        value=json.loads(raw); self.assertEqual(value['state'],self.m.STATE)
        self.assertEqual(sum(len(rows) for rows in value['applications'].values()),8)
        for roles in value['applications'].values():
            for row in roles.values():
                self.assertEqual(row['linkage']['needed'],['libc.so.6','libstdc++.so.6'])
                self.assertEqual(row['source']['sha256'],hashlib.sha256(image()).hexdigest())
        target=self.release.path(); reached=[]
        def replace(value):
            raw=canonical(value)
            if type(value) is dict and value.get('state')==self.m.STATE:
                reached.append(True); replacement=target.with_name('replacement')
                replacement.write_bytes(target.read_bytes()); replacement.chmod(0o755); replacement.replace(target)
            return raw
        with patch.object(self.m.BASE,'canonical',side_effect=replace),self.assertRaises(self.m.Pending): self.m.prepare()
        self.assertEqual(reached,[True])

    def test_original_refusal_output_bound_final_time_and_binary_count_are_preserved(self):
        original=self.m.IMAGE.Pending('original image refusal')
        with patch.object(self.m.IMAGE,'prepare',side_effect=original),self.assertRaises(self.m.Pending) as caught: self.m.prepare()
        self.assertIs(caught.exception.__cause__,original)
        with patch.object(self.m,'MAX_OUTPUT',1),patch.object(self.m,'prerequisite',wraps=self.m.prerequisite) as child:
            with self.assertRaisesRegex(self.m.Pending,'output bound'): self.m.prepare()
            self.assertEqual(child.call_count,1)
        actual=self.m.observations; calls=[]
        with patch.object(self.m.KERNEL,'now',return_value=10) as clock:
            def expire(*args):
                value=actual(*args); calls.append(True)
                if len(calls)==2: clock.return_value=20
                return value
            with patch.object(self.m,'observations',side_effect=expire),self.assertRaises(self.m.Pending): self.m.prepare(deadline=20)
        self.assertEqual(len(calls),2)
        raw=self.m.prepare(); sink=io.BytesIO()
        with patch.object(self.m,'prepare',return_value=raw),patch.object(self.m.sys,'argv',['linux_linkage.py']), \
             patch.object(self.m.sys,'stdout',types.SimpleNamespace(buffer=sink)):
            self.assertEqual(self.m.main(),0)
        self.assertEqual(sink.getvalue(),raw)
        bad=types.SimpleNamespace(write=lambda raw:True,flush=lambda:self.fail('no invalid-count flush'))
        with patch.object(self.m,'prepare',return_value=raw),patch.object(self.m.sys,'argv',['linux_linkage.py']), \
             patch.object(self.m.sys,'stdout',types.SimpleNamespace(buffer=bad)),patch.object(self.m.sys,'stderr',io.StringIO()):
            self.assertEqual(self.m.main(),75)


if __name__=='__main__':
    unittest.main()
