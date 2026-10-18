#!/usr/bin/python3
"""Read bounded ELF dynamic dependency declarations without invoking a loader.

This optional file profile rejects embedded RPATH/RUNPATH, audit/filter hooks
and declared text relocations. It does not resolve dependencies or verify the
remaining dynamic tags, relocations, symbols, loader environment or ABI.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_linux_linkage_images',
    Path(__file__).resolve().with_name('linux_images.py'))
IMAGE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(IMAGE)
BASE, KERNEL, Pending = IMAGE.BASE, IMAGE.KERNEL, IMAGE.Pending
PROFILE = 'four-app-elf-dynamic-dependency-files-v1'
STATE = 'protected-linux-linkage-declarations-source-only'
ATTEMPT_SECONDS, MAX_OUTPUT = 2 * IMAGE.ATTEMPT_SECONDS + 30, 262145
MAX_DYNAMIC, MAX_STRINGS, MAX_NEEDED = 4096, 1048576, 64
DYNAMIC = struct.Struct('<qQ')
# Standard RPATH, TEXTREL and RUNPATH; GNU audit/dependency-audit and
# auxiliary/filter objects can also introduce distinct loader behavior.
FORBIDDEN = {15, 22, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff}


def mapped(image, address, size):
    matches = []
    for row in image['loads']:
        offset = address-row['address']
        extent = min(row['file_bytes'], row['memory_bytes'])
        if 0 <= offset <= extent and size <= extent-offset:
            matches.append(row['file_offset']+offset)
    if len(matches) != 1:
        raise Pending('dynamic data must fit one unambiguous file-backed load range')
    return matches[0]


def library_name(strings, offset):
    if not 0 < offset < len(strings):
        raise Pending('dependency string offset is outside the declared table')
    end = strings.find(b'\0', offset, min(len(strings), offset+256))
    if end == -1:
        raise Pending('dependency name lacks a bounded terminator')
    try:
        name = strings[offset:end].decode('ascii')
    except UnicodeError as error:
        raise Pending('dependency name is not ASCII') from error
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,254}', name) is None:
        raise Pending('dependency names must be nonempty basenames without paths or substitutions')
    return name


def inspect(raw, architecture, interpreter):
    image = IMAGE.inspect(raw, architecture, interpreter)
    header = IMAGE.ELF_HEADER.unpack_from(raw)
    dynamic = []
    for index in range(header[10]):
        row = IMAGE.PROGRAM_HEADER.unpack_from(raw, header[5]+index*header[9])
        if row[0] == IMAGE.PT_DYNAMIC:
            dynamic.append(row)
    if not dynamic:
        return {'dynamic_segment': False, 'needed': [], 'soname': None,
                'uninterpreted_tags': [], 'dependency_resolution_verified': False,
                'relocations_verified': False, 'loader_environment_verified': False}
    if len(dynamic) != 1:
        raise Pending('dynamic declarations require one segment')
    _, _, offset, address, _, size, memory, _ = dynamic[0]
    if (size == 0 or size % DYNAMIC.size or size > MAX_DYNAMIC*DYNAMIC.size or
        memory < size or mapped(image, address, size) != offset):
        raise Pending('dynamic table extent or file mapping differs')
    entries, terminated = [], False
    for position in range(offset, offset+size, DYNAMIC.size):
        tag, value = DYNAMIC.unpack_from(raw, position)
        if terminated:
            if tag != 0 or value != 0:
                raise Pending('dynamic padding after termination must be zero')
            continue
        if tag == 0:
            if value != 0: raise Pending('dynamic terminator must have zero value')
            terminated = True
        else:
            if not 0 < tag <= 0x7fffffff:
                raise Pending('unsupported dynamic tag range')
            if tag in FORBIDDEN or tag == 30 and value & 4:
                raise Pending('embedded loader path/hook or text-relocation declaration refused')
            entries.append((tag, value))
    if not terminated:
        raise Pending('dynamic table lacks its terminator')
    singleton = {}
    for tag in (5, 10, 14, 30):
        values = [value for kind, value in entries if kind == tag]
        if len(values) > 1:
            raise Pending('duplicate dynamic string/flag declaration')
        if values: singleton[tag] = values[0]
    if 5 not in singleton or 10 not in singleton or not 1 <= singleton[10] <= MAX_STRINGS:
        raise Pending('dynamic declarations require a bounded explicit string table')
    start = mapped(image, singleton[5], singleton[10]); stop = start+singleton[10]
    if start < offset+size and offset < stop:
        raise Pending('dynamic table and its strings overlap')
    strings = raw[start:stop]
    if strings[:1] != b'\0' or strings[-1:] != b'\0':
        raise Pending('dynamic string table requires leading and trailing NUL')
    offsets = [value for tag, value in entries if tag == 1]
    if len(offsets) > MAX_NEEDED:
        raise Pending('dependency names exceed their count bound')
    needed = [library_name(strings, value) for value in offsets]
    if len(set(needed)) != len(needed):
        raise Pending('dependency names are duplicate or exceed their count bound')
    soname = library_name(strings, singleton[14]) if 14 in singleton else None
    return {'dynamic_segment': True, 'dynamic_entries': len(entries),
            'string_table_bytes': len(strings), 'needed': needed, 'soname': soname,
            'uninterpreted_tags': sorted({tag for tag, _ in entries}-{1, 5, 10, 14}),
            'dependency_resolution_verified': False, 'relocations_verified': False,
            'loader_environment_verified': False}


def prerequisite(end, context):
    BASE.fence(end)
    try: raw = IMAGE.prepare(deadline=end)
    except IMAGE.Pending as error: raise Pending('complete Linux image preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > IMAGE.MAX_OUTPUT:
        raise Pending('unsupported complete Linux image receipt')
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
        fields = {'schema', 'profile', 'state', 'namespace', 'configuration', 'release_sha256', 'applications'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or value['profile'] != IMAGE.PROFILE or
            value['state'] != IMAGE.STATE or KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
            raw != BASE.canonical(value)):
            raise Pending('Linux image receipt profile/context/canonical bytes differ')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete Linux image receipt') from error
    BASE.fence(end)
    return raw, value


def observations(images, end):
    settings = images['configuration']['value']
    result = {}
    for app in IMAGE.RELEASE.APPLICATIONS:
        result[app] = {}
        for role in IMAGE.RELEASE.SERVICES:
            expected = images['applications'][app][role]['source']
            raw, source = BASE.read_protected(Path(expected['path']), IMAGE.RELEASE.MAX_FILE_BYTES, False, end)
            if BASE.canonical(source) != BASE.canonical(expected):
                raise Pending('Linux dependency entry differs from the complete image observation')
            BASE.fence(end)
            result[app][role] = {'source': source,
                'linkage': inspect(raw, settings['architecture'], settings['interpreter'])}
            BASE.fence(end)
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Linux linkage window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if not context: raise Pending('missing Linux linkage namespace')
    original, images = prerequisite(end, context)
    observed = observations(images, end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'image_sha256': hashlib.sha256(original).hexdigest(), 'release_sha256': images['release_sha256'],
        'configuration': images['configuration'], 'applications': observed})
    if len(raw) > MAX_OUTPUT: raise Pending('Linux linkage report exceeds its output bound')
    after, final = prerequisite(end, context)
    if after != original or BASE.canonical(observations(final, end)) != BASE.canonical(observed):
        raise Pending('complete Linux image or linkage observations changed after encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('Linux linkage namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('Linux linkage inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete Linux linkage output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
