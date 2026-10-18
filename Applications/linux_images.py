#!/usr/bin/python3
"""Inspect protected Linux entry images without loading or executing them.

This is a bounded ELF64 header/segment profile, not a complete ELF, CLR, linker,
publisher or ABI verifier. The target architecture and interpreter are explicit
protected inputs, not inferred from the machine running this tool.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_linux_image_releases',
    Path(__file__).resolve().with_name('releases.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
BASE, KERNEL, Pending = RELEASE.BASE, RELEASE.KERNEL, RELEASE.Pending
INPUT = Path('/etc/debian13s4/application-images.json')
MACHINES = {'x86_64': 62, 'aarch64': 183}
MAX_INPUT, MAX_OUTPUT, ATTEMPT_SECONDS = 4096, 262145, 150
MAX_PROGRAM_HEADERS, MAX_SECTION_HEADERS, MAX_MAPPED_BYTES = 128, 4096, 1 << 30
PROFILE = 'four-app-linux-elf64-entry-structure-v1'
STATE = 'protected-linux-entry-structure-source-only'
ELF_HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
PROGRAM_HEADER = struct.Struct('<IIQQQQQQ')
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK = 1, 2, 3, 0x6474e551


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite image configuration')))
        fields = {'schema', 'architecture', 'interpreter'}
        KERNEL.known(value, fields, fields)
        if type(value['schema']) is not int or value['schema'] != 1 or value['architecture'] not in MACHINES:
            raise Pending('unsupported explicit Linux image profile')
        interpreter = value['interpreter']
        if interpreter is not None and (type(interpreter) is not str or len(interpreter) > 240 or
            re.fullmatch(r'/(?:usr/)?lib(?:64)?/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', interpreter) is None or
            os.path.normpath(interpreter) != interpreter or any(p in ('.', '..') for p in interpreter.split('/'))):
            raise Pending('interpreter must be an explicit canonical library path or null')
        if raw != BASE.canonical(value): raise Pending('image configuration must be canonical ASCII JSON plus LF')
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected Linux image configuration') from error
    return {'value': value, 'source': source}


def interval(offset, size, limit, description):
    # Python arithmetic does not wrap; subtraction also expresses the serialized
    # unsigned range check without relying on a machine-sized addition.
    if offset > limit or size > limit-offset:
        raise Pending(description+' exceeds its bounded image/range')


def inspect(raw, architecture, interpreter):
    if type(raw) is not bytes or not ELF_HEADER.size <= len(raw) <= RELEASE.MAX_FILE_BYTES:
        raise Pending('ELF entry requires bounded immutable whole bytes')
    if type(architecture) is not str or architecture not in MACHINES:
        raise Pending('unsupported explicit ELF architecture')
    fields = ELF_HEADER.unpack_from(raw)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shnames = fields
    if (ident[:7] != b'\x7fELF\x02\x01\x01' or ident[7] not in (0, 3) or any(ident[8:]) or
        kind not in (2, 3) or machine != MACHINES[architecture] or version != 1 or flags != 0 or
        ehsize != ELF_HEADER.size or phsize != PROGRAM_HEADER.size or not 1 <= phnum <= MAX_PROGRAM_HEADERS or
        phoff < ELF_HEADER.size or entry == 0):
        raise Pending('unsupported ELF64 little-endian executable header or architecture')
    interval(phoff, phnum*phsize, len(raw), 'program header table')
    if shoff == 0:
        if shnum != 0 or shnames != 0: raise Pending('section table is absent but counts are present')
    else:
        if shoff < ELF_HEADER.size or shsize != 64 or not 1 <= shnum <= MAX_SECTION_HEADERS or shnames >= shnum:
            raise Pending('unsupported bounded section table header')
        interval(shoff, shnum*shsize, len(raw), 'section header table')
    loads, segments, interpreters, stacks = [], [], [], []
    mapped = 0; dynamic = 0
    for index in range(phnum):
        tag, permissions, offset, address, physical, size, memory, alignment = PROGRAM_HEADER.unpack_from(raw, phoff+index*phsize)
        interval(offset, size, len(raw), 'segment file data')
        interval(address, memory, (1 << 64)-1, 'segment virtual range')
        if permissions & ~7 or alignment > MAX_MAPPED_BYTES or alignment > 1 and alignment & (alignment-1):
            raise Pending('unsupported segment flags or alignment')
        if tag == PT_LOAD:
            if size > memory or memory > MAX_MAPPED_BYTES or alignment > 1 and address % alignment != offset % alignment:
                raise Pending('invalid load segment size or congruence')
            if permissions & 3 == 3 or not permissions & 4:
                raise Pending('load segment must be readable and cannot request write plus execute')
            if loads and address < loads[-1]['address']+loads[-1]['memory_bytes']:
                raise Pending('load segments overlap or are not ordered')
            mapped += memory
            if mapped > MAX_MAPPED_BYTES: raise Pending('total load segment memory exceeds its profile bound')
            loads.append({'address': address, 'file_offset': offset, 'file_bytes': size,
                          'memory_bytes': memory, 'flags': permissions, 'alignment': alignment})
        elif tag == PT_INTERP:
            if loads or interpreters or not 2 <= size <= 241:
                raise Pending('interpreter must occur once before load segments')
            data = raw[offset:offset+size]
            try: text = data[:-1].decode('ascii')
            except UnicodeError as error: raise Pending('invalid interpreter encoding') from error
            if data[-1:] != b'\0' or b'\0' in data[:-1]: raise Pending('interpreter must have one final NUL')
            interpreters.append(text)
        elif tag == PT_GNU_STACK:
            if stacks or permissions & 1: raise Pending('an explicit single nonexecutable stack declaration is required')
            stacks.append(permissions)
        elif tag == PT_DYNAMIC:
            dynamic += 1
        elif tag == 5:
            raise Pending('reserved PT_SHLIB segment is unsupported')
        segments.append(tag)
    if not loads or not any(row['flags'] & 1 and row['address'] <= entry < row['address']+row['file_bytes'] for row in loads):
        raise Pending('ELF entry must fall inside a file-backed executable load segment')
    if len(stacks) != 1 or interpreters != ([] if interpreter is None else [interpreter]):
        raise Pending('ELF stack/interpreter differs from the explicit Linux profile')
    if dynamic > 1 or interpreters and dynamic != 1:
        raise Pending('dynamic executable requires one dynamic segment')
    return {'format': 'ELF64-LSB', 'architecture': architecture, 'elf_type': kind,
            'entry_address': entry, 'interpreter': interpreter, 'program_headers': len(segments),
            'section_headers': shnum, 'declared_mapped_bytes': mapped,
            'nonexecutable_stack_declared': True, 'loads': loads}


def prerequisite(end, context):
    BASE.fence(end)
    try: raw = RELEASE.prepare(deadline=end)
    except RELEASE.Pending as error: raise Pending('complete protected release preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > RELEASE.MAX_OUTPUT:
        raise Pending('unsupported complete release observation')
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
        fields = {'schema', 'profile', 'state', 'namespace', 'configuration', 'applications'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or
            value['profile'] != 'four-app-complete-release-files-v1' or
            value['state'] != 'protected-preinstalled-release-source-only' or
            KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or raw != BASE.canonical(value)):
            raise Pending('release observation profile or context differs')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete release observation') from error
    BASE.fence(end)
    return raw, value


def entries(releases, settings, end):
    result = {}
    for app in RELEASE.APPLICATIONS:
        observed = releases['applications'][app]
        declared = releases['configuration']['value']['applications'][app]
        result[app] = {}
        for role in RELEASE.SERVICES:
            relative = declared['entry_points'][role]
            filename = Path(declared['directory'])/relative
            if observed['entry_points'][role] != str(filename): raise Pending('admitted release entry path differs')
            raw, source = BASE.read_protected(filename, declared['files'][relative]['bytes'], False, end)
            if BASE.canonical(source) != BASE.canonical(observed['files'][relative]):
                raise Pending('whole ELF entry differs from its complete protected release')
            result[app][role] = {'source': source, 'image': inspect(raw, settings['architecture'], settings['interpreter'])}
            BASE.fence(end)
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Linux image window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing Linux image namespace')
    settings = configuration(end)
    child_raw, releases = prerequisite(end, context)
    images = entries(releases, settings['value'], end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'configuration': settings, 'release_sha256': hashlib.sha256(child_raw).hexdigest(), 'applications': images})
    if len(raw) > MAX_OUTPUT: raise Pending('complete Linux entry report exceeds its output bound')
    if configuration(end) != settings: raise Pending('Linux image profile changed')
    after, observed = prerequisite(end, context)
    if after != child_raw or entries(observed, settings['value'], end) != images:
        raise Pending('complete releases or entry images changed after encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('Linux image namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('Linux image inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete Linux image report output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
