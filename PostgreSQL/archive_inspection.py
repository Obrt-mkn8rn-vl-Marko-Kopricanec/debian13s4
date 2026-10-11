#!/usr/bin/python3
"""Protected .partial listing SOURCE only, not archive completeness or restore.

The default delivery WOULD execute pg_restore --list against the supplied file.
No database option, dump, restore, mutation, promotion, retry or installer join
is supplied. Listing bytes and public receipts are not native origin attestation.
Path reopening, cooperating locks and repeated reads are sequential, not atomic
or non-ABA guarantees; finite IO/cleanup and honest immutable modules are assumed.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess

SPEC = importlib.util.spec_from_file_location('debian13s4_inspection_stage',
    Path(__file__).with_name('archive_stage.py'))
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)
KERNEL, PREP, Pending = STAGE.KERNEL, STAGE.PREP, STAGE.Pending
RESTORE = Path('/usr/lib/postgresql/17/bin/pg_restore')
MAX_LISTING = 67108864
MAX_OUTPUT = 2 * MAX_LISTING + 16384
ATTEMPT_SECONDS = 60


def checked(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= STAGE.MAX_RECEIPT:
        raise Pending('unsupported archive stage receipt bytes')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda s: (_ for _ in ()).throw(Pending('nonfinite stage receipt')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid archive stage receipt') from error
    fields = {'schema', 'state', 'directory', 'directory_identity', 'leaf',
              'bytes', 'limit_bytes', 'sha256', 'identity'}
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['state'] != 'private-unverified-archive-stage-only' or
        type(value['directory']) is not str or not 1 <= len(value['directory']) <= 512 or
        any(ord(c) < 32 or ord(c) > 126 for c in value['directory']) or
        not Path(value['directory']).is_absolute() or os.path.normpath(value['directory']) != value['directory'] or
        type(value['leaf']) is not str or
        re.fullmatch(r'[0-9a-f]{64}-mk8\.(dns|email)\.dump\.partial', value['leaf']) is None or
        value['leaf'].startswith('0' * 64 + '-') or
        type(value['bytes']) is not int or type(value['limit_bytes']) is not int or
        not 1 <= value['bytes'] <= value['limit_bytes'] <= STAGE.MAX_BYTES or
        type(value['sha256']) is not str or re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is None):
        raise Pending('unsupported archive stage receipt fields')
    for field, width in (('directory_identity', 5), ('identity', 9)):
        row = value[field]
        if type(row) is not list or len(row) != width or any(type(n) is not int for n in row):
            raise Pending('untyped archive stage identity')
    directory, leaf = value['directory_identity'], value['identity']
    if (any(n < 0 for n in directory) or any(leaf[n] < 0 for n in (0, 1, 2, 3, 4, 5, 8)) or
        directory[2] != stat.S_IFDIR | 0o700 or directory[3] != STAGE.TRUSTED_UID or
        leaf[0] != directory[0] or leaf[2] != stat.S_IFREG | 0o600 or
        leaf[3] != STAGE.TRUSTED_UID or leaf[5] != value['bytes'] or leaf[8] != 1):
        raise Pending('unsupported archive stage identity facts')
    if raw != PREP.canonical(value):
        raise Pending('noncanonical archive stage receipt')
    return value


def native(path, maximum, end):
    """Fixed read-only listing primitive; calling real host tools needs authority."""
    STAGE.admission(end)
    if type(maximum) is not int or not 1 <= maximum <= MAX_LISTING:
        raise Pending('unsupported archive listing bound')
    if (type(path) is not type(RESTORE) or not path.is_absolute() or
        os.path.normpath(str(path)) != str(path) or len(str(path)) > 1024 or
        any(ord(c) < 32 or ord(c) > 126 for c in str(path)) or
        re.fullmatch(r'[0-9a-f]{64}-mk8\.(dns|email)\.dump\.partial', path.name) is None or
        path.name.startswith('0' * 64 + '-')):
        raise Pending('unsupported archive listing input pathname')
    before = KERNEL.trusted_binary(RESTORE)
    context = KERNEL.uint(KERNEL.namespace(), 2**64 - 1)
    if context == 0:
        raise Pending('invalid archive listing namespace')
    until = min(end, KERNEL.now() + KERNEL.QUERY_SECONDS)
    STAGE.admission(until)
    child = subprocess.Popen([str(RESTORE), '--list', str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                STAGE.admission(until)
                remaining = until - KERNEL.now()
                if remaining <= 0:
                    raise Pending('archive listing capture window expired')
                for key, _ in selector.select(remaining):
                    part = os.read(key.fileobj.fileno(), min(65536, maximum + 1 - len(buffers[key.data])))
                    if not part:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(part) > maximum:
                        raise Pending('archive listing channel exceeds bound')
                    buffer.extend(part)
            STAGE.admission(until)
            remaining = until - KERNEL.now()
            if remaining <= 0:
                raise Pending('archive listing completion window expired')
            code = child.wait(timeout=remaining)
            if type(code) is not int or code != 0 or buffers['stderr']:
                raise Pending('archive listing failed or warned')
        if KERNEL.trusted_binary(RESTORE) != before or KERNEL.uint(KERNEL.namespace(), 2**64 - 1) != context:
            raise Pending('archive listing executable or context changed')
        STAGE.admission(until)
        return bytes(buffers['stdout'])
    finally:
        try:
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            try:
                child.stdout.close()
            finally:
                child.stderr.close()


def inspect_stage(raw, maximum, read=None, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid archive inspection inherited deadline')
    end = min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS
    if type(maximum) is not int or not 1 <= maximum <= MAX_LISTING or read is not None and not callable(read):
        raise Pending('unsupported archive inspection delivery or bound')
    record = checked(raw)
    context = KERNEL.uint(KERNEL.namespace(), 2**64 - 1)
    if context == 0:
        raise Pending('invalid archive inspection namespace')
    path = Path(record['directory'])
    STAGE.admission(end)
    before = STAGE.directory_identity(path)
    if list(before) != record['directory_identity']:
        raise Pending('archive staging directory differs from receipt')
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        STAGE.directory_matches(path, directory, before)
        fcntl.flock(directory, fcntl.LOCK_SH | fcntl.LOCK_NB)
        identity = tuple(record['identity'])
        STAGE.readback(directory, record['leaf'], identity, record['bytes'], record['sha256'], end)
        STAGE.directory_matches(path, directory, before)
        executable = KERNEL.trusted_binary(RESTORE)
        STAGE.admission(end)
        if KERNEL.uint(KERNEL.namespace(), 2**64 - 1) != context:
            raise Pending('archive inspection pre-entry context changed')
        listing = (native if read is None else read)(path / record['leaf'], maximum, end)
        STAGE.admission(end)
        if type(listing) is not bytes or not 1 <= len(listing) <= maximum:
            raise Pending('unsupported or oversized archive listing bytes')
        payload = PREP.canonical({'schema': 1, 'state': 'private-archive-listing-source-only',
            'stage': record, 'stage_sha256': hashlib.sha256(raw).hexdigest(), 'namespace': context,
            'argv': [str(RESTORE), '--list', str(path / record['leaf'])],
            'executable': list(executable), 'listing_limit_bytes': maximum,
            'listing_bytes': len(listing), 'listing_sha256': hashlib.sha256(listing).hexdigest(),
            'listing_hex': listing.hex()})
        if len(payload) > MAX_OUTPUT:
            raise Pending('archive inspection receipt exceeds bound')
        STAGE.readback(directory, record['leaf'], identity, record['bytes'], record['sha256'], end)
        STAGE.directory_matches(path, directory, before)
        if KERNEL.trusted_binary(RESTORE) != executable or KERNEL.uint(KERNEL.namespace(), 2**64 - 1) != context:
            raise Pending('archive inspection final executable or context changed')
        STAGE.admission(end)
        return payload
    finally:
        closing, directory = directory, None
        os.close(closing)
