"""Synthetic PE/CLI bytes and private files; no CLR or valid-IL certificate."""
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
    spec = importlib.util.spec_from_file_location('private_cli_'+path.stem, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def aligned(raw):
    return raw+b'\0'*((-len(raw)) % 4)


def assembly(machine=0x14c, fat=False):
    """Independent little-endian fixture layout with deliberately invalid IL."""
    strings = aligned(b'\0Fixture.dll\0Program\0Main\0Fixture\0<Module>\0')
    at = lambda name: strings.index(name.encode()+b'\0')
    rows = struct.pack('<HHHHH', 0, at('Fixture.dll'), 1, 0, 0)
    rows += struct.pack('<IHHHHH', 0, at('<Module>'), 0, 0, 1, 1)
    rows += struct.pack('<IHHHHH', 1, at('Program'), 0, 0, 1, 1)
    method_relative = 24+16+len(rows)
    rows += struct.pack('<IHHHHH', 0x2400, 0, 0x10, at('Main'), 1, 1)
    rows += struct.pack('<IHHHHIHHH', 0x8004, 1, 0, 0, 0, 0, 0, at('Fixture'), 0)
    table = struct.pack('<IBBBBQQ', 0, 2, 0, 0, 1, (1 << 0)|(1 << 2)|(1 << 6)|(1 << 32), 0)
    table += struct.pack('<IIII', 1, 2, 1, 1)+rows
    table = aligned(table+b'\0')
    heaps = {'#~': table, '#Strings': strings, '#GUID': b'\x11'*16,
             '#Blob': aligned(b'\0\x03\0\0\x01'), '#US': b'\0'*4}
    version = aligned(b'v4.0.30319\0')
    root = struct.pack('<IHHII', 0x424a5342, 1, 1, 0, len(version))+version+struct.pack('<HH', 0, len(heaps))
    header_size = len(root)+sum(8+len(aligned(name.encode()+b'\0')) for name in heaps)
    headers, body, positions = b'', b'', {}
    for name, raw in heaps.items():
        positions[name] = {'header': 0x280+len(root)+len(headers), 'data': 0x280+header_size+len(body)}
        headers += struct.pack('<II', header_size+len(body), len(raw))+aligned(name.encode()+b'\0')
        body += raw
    metadata = root+headers+body
    image = bytearray(0x800); image[:2] = b'MZ'; struct.pack_into('<I', image, 0x3c, 0x80)
    image[0x80:0x84] = b'PE\0\0'
    optional_size = 224 if machine == 0x14c else 240
    struct.pack_into('<HHIIIHH', image, 0x84, machine, 1, 0, 0, 0, optional_size, 0x22)
    optional = 0x98; struct.pack_into('<H', image, optional, 0x10b if machine == 0x14c else 0x20b)
    struct.pack_into('<II', image, optional+32, 0x2000, 0x200)
    struct.pack_into('<II', image, optional+56, 0x4000, 0x200)
    directory = optional+(96 if machine == 0x14c else 112)
    struct.pack_into('<I', image, directory-4, 16)
    struct.pack_into('<II', image, directory+14*8, 0x2000, 72)
    section = optional+optional_size; image[section:section+8] = b'.text\0\0\0'
    struct.pack_into('<IIII', image, section+8, 0x600, 0x2000, 0x600, 0x200)
    struct.pack_into('<I', image, section+36, 0x60000020)
    struct.pack_into('<IHHIIII', image, 0x200, 72, 2, 5, 0x2080, len(metadata), 1, 0x06000001)
    image[0x280:0x280+len(metadata)] = metadata
    # 0xff is deliberately not a verified valid instruction stream.
    if fat: image[0x600:0x60d] = struct.pack('<HHII', 0x3013, 8, 1, 0)+b'\xff'
    else: image[0x600:0x602] = b'\x06\xff'
    positions.update(method=positions['#~']['data']+method_relative, section=section, directory=directory)
    return bytes(image), positions


class CliStructureTests(unittest.TestCase):
    def setUp(self): self.m = load(ROOT/'Applications/cli_image.py')

    def test_portable_and_explicit_64bit_headers_bind_entry_without_claiming_valid_il(self):
        for machine, architecture in ((0x14c, 'x86_64'), (0x14c, 'aarch64'), (0x8664, 'x86_64'), (0xaa64, 'aarch64')):
            for fat in (False, True):
                raw, _ = assembly(machine, fat)
                with self.subTest(machine=machine, fat=fat):
                    value = self.m.inspect(raw, architecture)
                    self.assertEqual(value['machine'], machine); self.assertEqual(value['entry_code_bytes'], 1)
                    self.assertEqual(value['metadata']['entry_name'], 'Main')
                    self.assertEqual(value['metadata']['assembly_name'], 'Fixture')
                    self.assertEqual(value['metadata']['entry_token'], 0x06000001)
                    self.assertFalse(value['il_validated']); self.assertFalse(value['native_compatibility_validated'])
                    self.assertFalse(value['publisher_authenticated'])
        for raw, architecture in ((assembly(0xaa64)[0], 'x86_64'), (assembly(0x8664)[0], 'aarch64'),
                                  (assembly()[0], True), (bytearray(assembly()[0]), 'x86_64')):
            with self.subTest(architecture=architecture), self.assertRaises(self.m.Pending): self.m.inspect(raw, architecture)

    def test_pe_range_alignment_permissions_cli_and_native_profile_refusals(self):
        raw, p = assembly()
        self.assertEqual(self.m.inspect(raw, 'x86_64')['entry_code_bytes'], 1)
        changes = [(0x3c, 'I', 0xfffffff0), (0x94, 'H', 0), (0x98+32, 'I', 513),
            (p['section']+20, 'I', len(raw)), (p['section']+36, 'I', 0xe0000020),
            (p['section']+8, 'I', 0), (p['section']+8, 'I', 32),
            (p['directory']+14*8+4, 'I', 71), (0x210, 'I', 0), (0x210, 'I', 3),
            (0x210, 'I', 17), (0x210, 'I', 0x20001), (0x240, 'I', 0x2500),
            (0x20c, 'I', self.m.MAX_METADATA+1), (0x214, 'I', 0x02000001), (0x214, 'I', 0x06000002)]
        for offset, fmt, value in changes:
            damaged = bytearray(raw); struct.pack_into('<'+fmt, damaged, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(self.m.Pending): self.m.inspect(bytes(damaged), 'x86_64')
        for damaged in (b'INVALID CLR ASSEMBLY', raw[:511], b'ZZ'+raw[2:], raw[:-513]):
            with self.subTest(size=len(damaged)), self.assertRaises(self.m.Pending): self.m.inspect(damaged, 'x86_64')

    def test_stream_table_heap_and_method_ranges_refuse_before_any_loader(self):
        raw, p = assembly(); table = p['#~']['data']; method = p['method']
        changes = [(0x280, 'I', 0), (p['#Blob']['header'], 'I', p['#GUID']['data']-0x280),
            (table+8, 'Q', 1 << 45), (table+6, 'B', 128),
            (table+32, 'I', self.m.MAX_ROWS+1), (table+28, 'I', 100000),
            (method, 'I', 0x2080), (method+6, 'H', 0), (method+4, 'H', 4),
            (method+8, 'H', 65535), (method+12, 'H', 2),
            (p['#Blob']['data']+1, 'B', 255), (p['#Blob']['data']+4, 'B', 0x0e)]
        for offset, fmt, value in changes:
            damaged = bytearray(raw); struct.pack_into('<'+fmt, damaged, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(self.m.Pending): self.m.inspect(bytes(damaged), 'x86_64')
        damaged = bytearray(raw); damaged[p['#Blob']['header']+8:p['#Blob']['header']+13] = b'#GUID'
        with self.assertRaises(self.m.Pending): self.m.inspect(bytes(damaged), 'x86_64')


class ManagedImageTests(unittest.TestCase):
    def setUp(self):
        runtime_fixture = load(ROOT/'Applications.Tests/test_managed_runtime.py')
        self.h = runtime_fixture.ManagedRuntimeTests('runTest')
        self.addCleanup(self.h.doCleanups); self.h.setUp()
        self.m = load(ROOT/'Applications/managed_images.py')
        self.m.RUNTIME = self.h.m
        self.m.BASE, self.m.KERNEL, self.m.Pending = self.h.m.BASE, self.h.m.KERNEL, self.h.m.Pending
        self.release = self.h.release
        for row in self.release.value['applications'].values():
            for entry in row['entry_points'].values():
                data, _ = assembly(); (Path(row['directory'])/(entry+'.dll')).write_bytes(data)
        self.declare()

    def declare(self):
        for row in self.release.value['applications'].values():
            directory = Path(row['directory'])
            for entry in row['entry_points'].values():
                name = entry+'.dll'; data = (directory/name).read_bytes()
                row['files'][name] = {'mode': '0644', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            marker = self.m.RUNTIME.RELEASE.generation(row['entry_points'], row['files'])
            target = directory.with_name(marker)
            if target != directory: directory.rename(target)
            row.update(directory=str(target), generation=marker)
        self.release.write()

    def test_eight_protected_images_bind_real_runtime_and_release_observations_without_entry(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no CLR/application/native parser')):
            raw = self.m.prepare()
        value = json.loads(raw); self.assertEqual(value['state'], self.m.STATE)
        self.assertEqual(value['image_configuration']['value']['architecture'], 'x86_64')
        self.assertEqual(set(value['applications']), set(self.m.RUNTIME.RELEASE.APPLICATIONS))
        for roles in value['applications'].values():
            for row in roles.values():
                self.assertEqual(row['source']['sha256'], hashlib.sha256(Path(row['source']['path']).read_bytes()).hexdigest())
                self.assertEqual(row['structure']['metadata']['entry_name'], 'Main')
                self.assertFalse(row['structure']['il_validated'])
        output = io.BytesIO()
        with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'argv', ['managed_images.py']), \
             patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=output)):
            self.assertEqual(self.m.main(), 0)
        self.assertEqual(output.getvalue(), raw)
        for count in (True, len(raw)-1, None):
            sink = types.SimpleNamespace(write=lambda data: count, flush=lambda: self.fail('no short-write flush'))
            with patch.object(self.m, 'prepare', return_value=raw), patch.object(self.m.sys, 'argv', ['managed_images.py']), \
                 patch.object(self.m.sys, 'stdout', types.SimpleNamespace(buffer=sink)), patch.object(self.m.sys, 'stderr', io.StringIO()):
                self.assertEqual(self.m.main(), 75)

    def test_actual_opaque_assembly_with_valid_inventory_retains_distinct_parser_refusal(self):
        target = self.release.path(name='application/main.dll'); target.write_bytes(b'INVALID CLR ASSEMBLY')
        self.declare(); refusals = []; inspect = self.m.CLI.inspect
        def checked(*args):
            try: return inspect(*args)
            except self.m.CLI.Pending as error: refusals.append(error); raise
        self.assertIsNot(self.m.Pending, self.m.CLI.Pending)
        with patch.object(self.m.CLI, 'inspect', side_effect=checked), self.assertRaises(self.m.Pending) as caught:
            self.m.prepare()
        self.assertEqual(len(refusals), 1); self.assertIs(caught.exception.__cause__, refusals[0])
        self.assertIs(type(refusals[0]), self.m.CLI.Pending)

    def test_postencoding_same_bytes_replacement_and_early_bounds_withhold_success(self):
        with patch.object(self.m.RUNTIME, 'prepare', side_effect=AssertionError('early fence')):
            for deadline in (True, float('inf'), float('nan'), self.m.KERNEL.now()-1):
                with self.subTest(deadline=str(deadline)), self.assertRaises(self.m.Pending): self.m.prepare(deadline)
        encoded = self.m.BASE.canonical; target = self.release.path(name='application/main.dll')
        def replace(value):
            raw = encoded(value)
            if type(value) is dict and value.get('state') == self.m.STATE:
                other = target.with_name('replacement'); other.write_bytes(target.read_bytes()); other.chmod(0o644); other.replace(target)
            return raw
        with patch.object(self.m.BASE, 'canonical', side_effect=replace), self.assertRaises(self.m.Pending): self.m.prepare()


if __name__ == '__main__':
    unittest.main()
