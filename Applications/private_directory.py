"""Read-only admission of an existing application-owned private directory.

This observes POSIX file metadata for explicitly supplied numeric identities.
It does not authenticate NSS credentials, inspect data contents, acquire a
service lease, test writes, reserve capacity or prove mount/physical durability.
"""
import importlib.util
import os
from pathlib import Path
import re
import stat

SPEC = importlib.util.spec_from_file_location('debian13s4_directory_reader',
    Path(__file__).resolve().parents[1]/'PostgreSQL/prepare.py')
if not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_directory_reader',
        Path(__file__).resolve().parents[1]/'postgresql/prepare.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
KERNEL, Pending = BASE.KERNEL, BASE.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = 32768
STATE = 'private-application-directory-file-observation-only'


class CleanupFailure(Pending):
    """Keep a body refusal and its separate descriptor cleanup failure."""
    def __init__(self, cause, close_error):
        super().__init__('private directory observation and descriptor close both failed')
        self.cause = cause
        self.close_error = close_error


def identity(info):
    # Directory contents may change: this is ownership/path identity, not an
    # inventory or a snapshot of the application's stored data.
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def searchable(info, uid, groups):
    permission = 0o100 if info.st_uid == uid else 0o010 if info.st_gid in groups else 0o001
    return bool(info.st_mode & permission)


def ancestry(path, uid, groups, end):
    try:
        relative = path.relative_to(BASE.TRUST_ROOT)
    except ValueError as error:
        raise Pending('private application directory is outside the trusted root') from error
    if not relative.parts:
        raise Pending('application data cannot be the trusted ancestry root')
    current = BASE.TRUST_ROOT
    result = {}
    for part in ('', *relative.parts[:-1]):
        if part:
            current /= part
        BASE.fence(end)
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != BASE.TRUSTED_UID or
            info.st_mode & 0o022):
            raise Pending('private application data requires protected root-owned ancestry')
        if not searchable(info, uid, groups):
            raise Pending('application identity lacks an ancestry search permission')
        result[str(current)] = identity(info)
    return result


def leaf(info, uid, gid):
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or
        info.st_uid != uid or info.st_gid != gid):
        raise Pending('application data requires its declared UID/GID and directory mode 0700')
    return identity(info)


def observe(path, uid, gid, supplementary_groups=(), deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited private directory window')
    end = min(start+ATTEMPT_SECONDS, deadline) if deadline is not None else start+ATTEMPT_SECONDS
    BASE.fence(end)
    if (type(path) is not type(BASE.TRUST_ROOT) or not path.is_absolute() or
        not 1 < len(str(path)) <= 512 or os.path.normpath(str(path)) != str(path) or
        re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', str(path)) is None or
        any(part in ('.', '..') for part in path.parts)):
        raise Pending('unsupported canonical private directory path')
    if (type(uid) is not int or not 1 <= uid <= 0x7fffffff or
        type(gid) is not int or not 1 <= gid <= 0x7fffffff or
        type(supplementary_groups) not in (tuple, list) or len(supplementary_groups) > 8):
        raise Pending('unsupported explicit private directory identity')
    groups = {gid}
    for group in supplementary_groups:
        if type(group) is not int or not 1 <= group <= 0x7fffffff or group in groups:
            raise Pending('unsupported or duplicate supplementary group')
        groups.add(group)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing private directory namespace')
    parents = ancestry(path, uid, groups, end)
    before = leaf(path.lstat(), uid, gid)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    error = close_error = None
    try:
        if leaf(os.fstat(descriptor), uid, gid) != before:
            raise Pending('private directory descriptor differs from its path')
        payload = BASE.canonical({'schema': 1, 'state': STATE, 'namespace': context,
            'path': str(path), 'owner_uid': uid, 'owner_gid': gid,
            'supplementary_groups': sorted(groups-{gid}), 'identity': before,
            'ancestry': parents, 'contents_inspected': False, 'write_tested': False})
        if len(payload) > MAX_OUTPUT:
            raise Pending('private directory observation exceeds its output bound')
        if (leaf(os.fstat(descriptor), uid, gid) != before or
            leaf(path.lstat(), uid, gid) != before or ancestry(path, uid, groups, end) != parents):
            raise Pending('private directory or ancestry changed after encoding')
        if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
            raise Pending('private directory namespace changed')
        BASE.fence(end)
    except BaseException as caught:
        error = caught
    finally:
        closing, descriptor = descriptor, None
        try:
            os.close(closing)
        except OSError as caught:
            close_error = caught
    if error is not None:
        if close_error is not None:
            raise CleanupFailure(error, close_error) from error
        raise error
    if close_error is not None:
        raise Pending('private directory close did not complete successfully') from close_error
    BASE.fence(end)
    return payload
