"""Bounded PE/CLI entry structure; never load, verify IL, or authenticate code.

The selected profile is optimized ECMA metadata in an IL-only, framework-
dependent executable assembly. ReadyToRun, mixed/native entry points, deltas,
portable PDB metadata and uncommon table extensions are outside this profile.
"""
import hashlib
import struct

MAX_BYTES = 64 * 1024 * 1024
MAX_METADATA = 16 * 1024 * 1024
MAX_ROWS = 1048576
MAX_CODE = 1048576


class Pending(ValueError):
    pass


def span(start, size, limit):
    if start < 0 or size < 0 or start > limit or size > limit-start:
        raise Pending('PE/CLI range exceeds its containing bytes')
    return start+size


def number(raw, start, size):
    span(start, size, len(raw))
    return int.from_bytes(raw[start:start+size], 'little')


def unpack(raw, start, pattern):
    span(start, struct.calcsize('<'+pattern), len(raw))
    return struct.unpack_from('<'+pattern, raw, start)


def disjoint(ranges):
    last = 0
    for start, end in sorted(ranges):
        if start < last: raise Pending('overlapping PE/CLI ranges')
        last = end


def heap_string(heap, index):
    if not 0 < index < len(heap): raise Pending('missing managed metadata string')
    end = heap.find(b'\0', index, min(len(heap), index+513))
    if end == -1: raise Pending('unbounded managed metadata string')
    try: value = heap[index:end].decode('utf-8')
    except UnicodeError as error: raise Pending('invalid managed metadata UTF-8') from error
    if not value or any(ord(c) < 32 for c in value): raise Pending('invalid managed metadata name')
    return value


def heap_blob(heap, index):
    if not 0 < index < len(heap): raise Pending('missing managed signature blob')
    lead = heap[index]
    if lead < 0x80:
        size, width = lead, 1
    elif lead < 0xc0:
        span(index, 2, len(heap)); size, width = ((lead & 0x3f) << 8) | heap[index+1], 2
        if size < 0x80: raise Pending('nonminimal managed blob length')
    elif lead < 0xe0:
        span(index, 4, len(heap)); size, width = int.from_bytes(heap[index:index+4], 'big') & 0x1fffffff, 4
        if size < 0x4000: raise Pending('nonminimal managed blob length')
    else: raise Pending('invalid managed blob length')
    if not 1 <= size <= 4096: raise Pending('managed entry signature exceeds its bound')
    end = span(index+width, size, len(heap))
    return heap[index+width:end]


def tables(raw, heaps, token):
    reserved, major, minor, flags, one, present, sorted_mask = unpack(raw, 0, 'IBBBBQQ')
    excluded = (3, 5, 7, 19, 22, 30, 31, 33, 34, 36, 37)
    if (reserved != 0 or (major, minor, one) != (2, 0, 1) or flags & ~7 or
        present >> 45 or sorted_mask >> 45 or any(present & (1 << n) for n in excluded)):
        raise Pending('unsupported optimized managed table profile')
    rows, position = [0]*45, 24
    for table in range(45):
        if present & (1 << table):
            rows[table] = number(raw, position, 4); position += 4
            if not 1 <= rows[table] <= MAX_ROWS: raise Pending('unsupported managed table row count')
    if sum(rows) > MAX_ROWS or rows[0] != 1 or rows[32] != 1 or not rows[2] or not rows[6]:
        raise Pending('managed entry requires bounded module/type/method/assembly tables')
    widths = [4 if flags & (1 << bit) else 2 for bit in range(3)]
    strings, guids, blobs = widths
    for heap, width in zip(('#Strings', '#GUID', '#Blob'), widths):
        if width == 2 and len(heaps[heap]) > 65535: raise Pending('managed heap exceeds its index width')
    def index(table): return 2 if rows[table] < 65536 else 4
    def coded(bits, *targets): return 2 if max(rows[n] for n in targets) < (1 << (16-bits)) else 4
    type_ref = coded(2, 2, 1, 27); method_ref = coded(1, 6, 10)
    implementation = coded(2, 38, 35, 39)
    sizes = {
        0: 2+strings+3*guids, 1: coded(2, 0, 26, 35, 1)+2*strings,
        2: 4+2*strings+type_ref+index(4)+index(6), 4: 2+strings+blobs,
        6: 8+strings+blobs+index(8), 8: 4+strings, 9: index(2)+type_ref,
        10: coded(3, 2, 1, 26, 6, 27)+strings+blobs, 11: 2+coded(2, 4, 8, 23)+blobs,
        12: coded(5, 6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43)+coded(3, 6, 10)+blobs,
        13: coded(1, 4, 8)+blobs, 14: 2+coded(2, 2, 6, 32)+blobs,
        15: 6+index(2), 16: 4+index(4), 17: blobs, 18: index(2)+index(20),
        20: 2+strings+type_ref, 21: index(2)+index(23), 23: 2+strings+blobs,
        24: 2+index(6)+coded(1, 20, 23), 25: index(2)+2*method_ref,
        26: strings, 27: blobs, 28: 2+coded(1, 4, 6)+strings+index(26),
        29: 4+index(4), 32: 16+blobs+2*strings, 35: 12+2*blobs+2*strings,
        38: 4+strings+blobs, 39: 8+2*strings+implementation,
        40: 8+strings+implementation, 41: 2*index(2),
        42: 4+coded(1, 2, 6)+strings, 43: method_ref+blobs, 44: index(42)+type_ref,
    }
    offsets = {}
    for table, count in enumerate(rows):
        if count:
            offsets[table] = position
            position = span(position, sizes[table]*count, len(raw))
    if len(raw)-position > 4 or any(raw[position:]): raise Pending('unexpected managed table suffix')
    if token >> 24 != 6 or not 1 <= (token & 0xffffff) <= rows[6]:
        raise Pending('managed entry must reference an existing MethodDef row')
    module = offsets[0]
    heap_string(heaps['#Strings'], number(raw, module+2, strings))
    mvid = number(raw, module+2+strings, guids)
    if not 1 <= mvid <= len(heaps['#GUID'])//16: raise Pending('missing managed module MVID')
    assembly = offsets[32]
    assembly_name = heap_string(heaps['#Strings'], number(raw, assembly+16+blobs, strings))
    method = offsets[6]+((token & 0xffffff)-1)*sizes[6]
    rva, implementation_flags, attributes = unpack(raw, method, 'IHH')
    if not attributes & 0x10 or attributes & (0x400 | 0x2000) or implementation_flags & ~0x3e8:
        raise Pending('managed entry must be a static managed IL method')
    method_name = heap_string(heaps['#Strings'], number(raw, method+8, strings))
    signature = heap_blob(heaps['#Blob'], number(raw, method+8+strings, blobs))
    if signature not in (b'\0\0\x01', b'\0\0\x08', b'\0\0\x09',
                         b'\0\x01\x01\x1d\x0e', b'\0\x01\x08\x1d\x0e', b'\0\x01\x09\x1d\x0e'):
        raise Pending('unsupported plain managed entry signature')
    parameter = number(raw, method+8+strings+blobs, index(8))
    if not 1 <= parameter <= rows[8]+1: raise Pending('managed entry parameter-list index is out of range')
    return {'rows': {str(n): count for n, count in enumerate(rows) if count},
            'entry_token': token, 'entry_rva': rva, 'entry_name': method_name,
            'assembly_name': assembly_name, 'signature_hex': signature.hex()}


def metadata(raw, token):
    signature, major, minor, reserved, size = unpack(raw, 0, 'IHHII')
    if signature != 0x424a5342 or (major, minor, reserved) != (1, 1, 0) or not 4 <= size <= 256 or size % 4:
        raise Pending('unsupported CLI metadata root')
    position = span(16, size, len(raw)); version = raw[16:position]
    if version.rstrip(b'\0') != b'v4.0.30319' or version[-1] != 0:
        raise Pending('unsupported managed metadata version')
    flags, count = unpack(raw, position, 'HH'); position += 4
    if flags or not 4 <= count <= 5: raise Pending('unsupported managed stream inventory')
    streams = {}
    for _ in range(count):
        offset, size = unpack(raw, position, 'II'); position += 8
        end = raw.find(b'\0', position, min(len(raw), position+32))
        if end == -1: raise Pending('unterminated managed stream name')
        try: name = raw[position:end].decode('ascii')
        except UnicodeError as error: raise Pending('invalid managed stream name') from error
        aligned = (end+4) & ~3
        span(end, aligned-end, len(raw))
        if any(raw[end:aligned]) or name not in ('#~', '#Strings', '#GUID', '#Blob', '#US') or name in streams or offset % 4:
            raise Pending('ambiguous or unsupported managed stream')
        streams[name] = offset, span(offset, size, len(raw)); position = aligned
    if not {'#~', '#Strings', '#GUID', '#Blob'} <= streams.keys(): raise Pending('missing managed metadata streams')
    ranges = [(0, position), *streams.values()]; disjoint(ranges)
    heaps = {name: raw[start:end] for name, (start, end) in streams.items()}
    for name in ('#Strings', '#Blob', '#US'):
        if name in heaps and (not heaps[name] or heaps[name][0] != 0): raise Pending('managed heap lacks its reserved zero')
    if not heaps['#GUID'] or len(heaps['#GUID']) % 16: raise Pending('invalid managed GUID heap extent')
    result = tables(heaps['#~'], heaps, token)
    return result | {'streams': {name: {'offset': start, 'bytes': end-start} for name, (start, end) in streams.items()},
                     'metadata_sha256': hashlib.sha256(raw).hexdigest()}


def inspect(raw, architecture):
    if type(raw) is not bytes or not 512 <= len(raw) <= MAX_BYTES or architecture not in ('x86_64', 'aarch64'):
        raise Pending('unsupported managed image bytes or architecture')
    if raw[:2] != b'MZ': raise Pending('missing managed PE DOS signature')
    pe = number(raw, 60, 4)
    if pe < 64 or pe % 4 or raw[pe:pe+4] != b'PE\0\0': raise Pending('missing managed PE signature')
    machine, count, _, symbol_pointer, symbols, optional_size, characteristics = unpack(raw, pe+4, 'HHIIIHH')
    if not 1 <= count <= 16 or symbol_pointer or symbols or not characteristics & 2:
        raise Pending('unsupported managed COFF image inventory')
    optional = pe+24; magic = number(raw, optional, 2)
    if (machine, magic, optional_size) not in ((0x14c, 0x10b, 224),
        (0x8664 if architecture == 'x86_64' else 0xaa64, 0x20b, 240)):
        raise Pending('managed PE machine/header differs from the explicit target')
    table = span(optional, optional_size, len(raw)); span(table, 40*count, len(raw))
    section_alignment, file_alignment = unpack(raw, optional+32, 'II')
    image_size, headers = unpack(raw, optional+56, 'II')
    if (not 512 <= file_alignment <= 65536 or file_alignment & (file_alignment-1) or
        not file_alignment <= section_alignment <= 65536 or section_alignment & (section_alignment-1) or
        not 0 < image_size <= (1 << 30) or image_size % section_alignment or
        headers < table+40*count or headers > len(raw) or headers % file_alignment):
        raise Pending('unsupported managed PE alignment or image extent')
    sections, file_ranges, virtual_ranges = [], [(0, headers)], []
    for index in range(count):
        offset = table+40*index
        virtual_size, rva, size, pointer = unpack(raw, offset+8, 'IIII')
        flags = number(raw, offset+36, 4)
        extent = max(size, virtual_size)
        if (not virtual_size or rva < headers or rva % section_alignment or
            rva+extent > image_size or size % file_alignment or
            size and (pointer < headers or pointer % file_alignment) or
            not size and pointer or flags & 0x80000000 and flags & 0x20000000):
            raise Pending('unsupported managed PE section range or permissions')
        if size: file_ranges.append((pointer, span(pointer, size, len(raw))))
        virtual_ranges.append((rva, rva+extent)); sections.append((rva, min(size, virtual_size), pointer))
    disjoint(file_ranges); disjoint(virtual_ranges)
    def mapped(rva, size):
        if not rva or not size: raise Pending('missing managed mapped range')
        matches = [pointer+rva-start for start, extent, pointer in sections if start <= rva and rva+size <= start+extent]
        if len(matches) != 1: raise Pending('managed RVA does not map to one whole file-backed section')
        return matches[0]
    directory = optional+(96 if magic == 0x10b else 112)
    if number(raw, directory-4, 4) != 16: raise Pending('unsupported managed PE directory inventory')
    cli_rva, cli_size = unpack(raw, directory+14*8, 'II')
    if cli_size != 72: raise Pending('unsupported CLI header size')
    cli = mapped(cli_rva, cli_size)
    size, major, minor, metadata_rva, metadata_size, flags, token = unpack(raw, cli, 'IHHIIII')
    if size != 72 or (major, minor) != (2, 5) or not flags & 1 or flags & ~0x10009:
        raise Pending('managed profile requires an IL-only executable CLI header')
    for index in range(6):
        rva, size = unpack(raw, cli+24+index*8, 'II')
        if bool(rva) != bool(size) or index >= 2 and (rva or size):
            raise Pending('native/mixed/ReadyToRun CLI directories are outside this profile')
        if rva: mapped(rva, size)
        if index == 1 and flags & 8 and not size: raise Pending('reported strong name has no signature range')
    if not 1 <= metadata_size <= MAX_METADATA: raise Pending('managed metadata exceeds its bounded capacity')
    start = mapped(metadata_rva, metadata_size)
    disjoint(((cli, cli+72), (start, start+metadata_size)))
    result = metadata(raw[start:start+metadata_size], token)
    body = mapped(result['entry_rva'], 1); first = raw[body]
    if first & 3 == 2:
        header, code_size, extra = 1, first >> 2, False
    elif first & 3 == 3:
        header_flags, _, code_size, locals_token = unpack(raw, body, 'HHII')
        header = (header_flags >> 12)*4; extra = bool(header_flags & 8)
        if body % 4 or header != 12 or header_flags & 0xfff & ~0x1b or locals_token and (
            locals_token >> 24 != 17 or not 1 <= (locals_token & 0xffffff) <= result['rows'].get('17', 0)):
            raise Pending('unsupported fat managed entry body header')
    else: raise Pending('missing managed entry IL body header')
    if not 1 <= code_size <= MAX_CODE: raise Pending('managed entry code extent exceeds its bound')
    mapped(result['entry_rva'], header+code_size)
    disjoint(((body, body+header+code_size), (cli, cli+72), (start, start+metadata_size)))
    return {'machine': machine, 'pe_magic': magic, 'sections': count, 'cli_flags': flags,
            'metadata': result, 'entry_code_bytes': code_size,
            'entry_extra_sections_unverified': extra, 'il_validated': False,
            'native_compatibility_validated': False, 'publisher_authenticated': False}
