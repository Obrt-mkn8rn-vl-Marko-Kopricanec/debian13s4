#!/usr/bin/python3
"""Observe empty registered IPv4/IPv6/ARP legacy x_tables views, read-only.

All three genuine procfs views must exist. Missing reporting is pending, never
absence. This does not cover legacy bridge tables, tc, eBPF, or future changes;
it is not an installer, a complete coexistence check, or policy delivery.
"""

import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import stat
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_kernel', Path(__file__).with_name('kernel.py'))
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending

PROC = Path('/proc')
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
FILES = ('ip_tables_names', 'ip6_tables_names', 'arp_tables_names')
PROC_MAGIC = 0x9FA0
MAX_BYTES = 65536
ATTEMPT_SECONDS = 10
EMPTY_HASH = hashlib.sha256(b'').hexdigest()


class StatFS(ctypes.Structure):
    # Linux/glibc LP64 ABI used by supported Debian amd64 and arm64 hosts.
    _fields_ = ([(name, ctypes.c_long) for name in
                 ('type', 'bsize', 'blocks', 'bfree', 'bavail', 'files', 'ffree')] +
                [('fsid', ctypes.c_int * 2)] +
                [(name, ctypes.c_long) for name in ('namelen', 'frsize', 'flags')] +
                [('spare', ctypes.c_long * 4)])


def filesystem(fd):
    if sys.platform != 'linux' or platform.machine() not in ('x86_64', 'aarch64') or \
            ctypes.sizeof(ctypes.c_long) != 8 or ctypes.sizeof(StatFS) != 120:
        raise Pending('unsupported procfs observation ABI')
    native = ctypes.CDLL(None, use_errno=True).fstatfs
    native.argtypes = (ctypes.c_int, ctypes.POINTER(StatFS))
    native.restype = ctypes.c_int
    info = StatFS()
    if native(fd, ctypes.byref(info)) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
    if info.type != PROC_MAGIC:
        raise Pending('legacy view is not on procfs')


def deadline_admission(deadline):
    if type(deadline) not in (int, float):
        raise Pending('invalid legacy observation deadline')
    try:
        valid = math.isfinite(deadline) and deadline > KERNEL.now()
    except (OverflowError, ValueError):
        valid = False
    if not valid:
        raise Pending('legacy observation window expired or invalid')


def trusted(info, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
        raise Pending('untrusted legacy view kind, owner or mode')
    if not directory and stat.S_IMODE(info.st_mode) != 0o440:
        raise Pending('unexpected legacy procfs view mode')
    return KERNEL.signature(info)


def directory_identity(path):
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending('noncanonical legacy procfs path')
    try:
        path.relative_to(TRUST_ROOT)
    except ValueError as error:
        raise Pending('legacy procfs path outside trusted root') from error
    current = path
    leaf = None
    while True:
        value = trusted(current.lstat(), directory=True)
        if current == path:
            leaf = value
        if current == TRUST_ROOT:
            return leaf
        current = current.parent


def read_views(deadline):
    deadline_admission(deadline)
    path = PROC / str(os.getpid()) / 'net'
    before = directory_identity(path)
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if trusted(os.fstat(directory), directory=True) != before:
            raise Pending('legacy directory descriptor changed')
        filesystem(directory)
        sources = {}
        for name in FILES:
            deadline_admission(deadline)
            initial = trusted(os.stat(name, dir_fd=directory, follow_symlinks=False))
            if initial[0] != before[0]:
                raise Pending('legacy view is on a different procfs device')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            try:
                if trusted(os.fstat(fd)) != initial:
                    raise Pending('legacy view descriptor changed')
                filesystem(fd)
                data = bytearray()
                while True:
                    deadline_admission(deadline)
                    part = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
                    if not part:
                        break
                    data.extend(part)
                    if len(data) > MAX_BYTES:
                        raise Pending('legacy view byte limit exceeded')
                filesystem(fd)
                if trusted(os.fstat(fd)) != initial or \
                        trusted(os.stat(name, dir_fd=directory, follow_symlinks=False)) != initial:
                    raise Pending('legacy view changed during read')
            finally:
                os.close(fd)
            deadline_admission(deadline)
            if data:
                raise Pending('registered or unverifiable legacy table state exists')
            sources[name] = {'identity': list(initial), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        filesystem(directory)
        if trusted(os.fstat(directory), directory=True) != before or directory_identity(path) != before:
            raise Pending('legacy directory changed during read')
        return {'path': str(path), 'identity': list(before), 'files': sources}
    finally:
        os.close(directory)


def copy_identity(value, directory=False):
    if type(value) is not list or len(value) != 8 or any(type(item) is not int or item < 0 for item in value):
        raise Pending('unverifiable legacy identity')
    mode, owner = value[2:4]
    if owner != TRUSTED_UID or mode & 0o022 or not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)) or \
            not directory and stat.S_IMODE(mode) != 0o440:
        raise Pending('untrusted delivered legacy identity')
    return value.copy()


def empty_views(value):
    if type(value) is not dict or set(value) != {'path', 'identity', 'files'} or \
            value['path'] != str(PROC / str(os.getpid()) / 'net') or \
            type(value['files']) is not dict or set(value['files']) != set(FILES):
        raise Pending('incomplete legacy view delivery')
    sources = {}
    for name in FILES:
        row = value['files'][name]
        if type(row) is not dict or set(row) != {'identity', 'bytes', 'sha256'} or \
                type(row['bytes']) is not int or row['bytes'] != 0 or row['sha256'] != EMPTY_HASH:
            raise Pending('nonempty or unverifiable legacy view delivery')
        sources[name] = {'identity': copy_identity(row['identity']), 'bytes': 0, 'sha256': EMPTY_HASH}
    return {'path': value['path'], 'identity': copy_identity(value['identity'], directory=True), 'files': sources}


def observe(read=read_views, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is None:
        deadline = start + ATTEMPT_SECONDS
    deadline_admission(deadline)
    end = min(deadline, start + ATTEMPT_SECONDS)
    deadline_admission(end)
    namespace = scope()
    if type(namespace) is not int or not 0 < namespace < 2 ** 64:
        raise Pending('unverifiable legacy network namespace')
    first = empty_views(read(end))
    deadline_admission(end)
    second = empty_views(read(end))
    deadline_admission(end)
    final_namespace = scope()
    if second != first or type(final_namespace) is not int or final_namespace != namespace:
        raise Pending('legacy views or network namespace changed')
    deadline_admission(end)
    return {'schema': 'debian13s4-legacy-ip-ip6-arp-empty-1', 'namespace': namespace,
            'empty': True, 'source': second}


def main():
    if len(sys.argv) != 1:
        print('legacy observer takes no arguments', file=sys.stderr)
        return 64
    try:
        result = observe()
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0
    except (Pending, OSError, UnicodeError) as error:
        print(f'legacy observation pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
