#!/usr/bin/python3
"""Create-only OPAQUE private .partial bytes, never a valid or published backup.

No pg_dump/pg_restore/process/connection/CLI/auto-directory/reset/adoption/retry
is provided. Any existing target blocks; failed acquired targets remain closed.
Caller streams/receipts are not native archive attestation. Honest ancestry,
cooperating locks and finite IO are required; fsync is not power-loss proof.
"""
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat

SPEC = importlib.util.spec_from_file_location('debian13s4_archive_inputs',
    Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
MAX_BYTES = 1 << 40
CHUNK = 65536
MAX_RECEIPT = 4096
ATTEMPT_SECONDS = 3600


class Blocked(RuntimeError):
    """An existing or acquired .partial target is not automatically retryable."""


def admission(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('private archive staging window expired')


def window(deadline):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid archive staging inherited deadline')
    return min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS


def directory_identity(path):
    if (type(path) is not type(TRUST_ROOT) or not path.is_absolute() or
        len(str(path)) > 512 or os.path.normpath(str(path)) != str(path)):
        raise Pending('noncanonical private archive directory')
    path.relative_to(TRUST_ROOT)
    current = path; leaf = None
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending('untrusted private archive ancestry')
        value = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        if current == path:
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise Pending('archive staging directory is not private')
            leaf = value
        if current == TRUST_ROOT:
            return leaf
        current = current.parent


def directory_matches(path, fd, before):
    info = os.fstat(fd)
    value = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    if value != before or directory_identity(path) != before:
        raise Pending('private archive directory descriptor or path changed')


def file_identity(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID or
        stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise Pending('untrusted private archive stage')
    return KERNEL.signature(info) + (info.st_nlink,)


def file_matches(directory, name, fd):
    value = file_identity(os.fstat(fd))
    if value[0] != os.fstat(directory).st_dev or value != file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)):
        raise Pending('private archive stage descriptor or name changed')
    return value


def readback(directory, name, identity, count, digest, end):
    admission(end)
    if file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != identity:
        raise Pending('private archive readback identity changed')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        if file_matches(directory, name, fd) != identity:
            raise Pending('private archive readback descriptor changed')
        total = 0; hashed = hashlib.sha256()
        while True:
            admission(end)
            part = os.read(fd, min(CHUNK, count - total + 1))
            admission(end)
            if not part:
                break
            total += len(part)
            if total > count:
                raise Pending('private archive readback exceeds committed size')
            hashed.update(part)
        if total != count or hashed.hexdigest() != digest or file_matches(directory, name, fd) != identity:
            raise Pending('private archive bytes or identity changed during readback')
        admission(end)
    finally:
        closing, fd = fd, None
        os.close(closing)


def stage(path, name, stream, limit, deadline=None):
    end = window(deadline)
    if (type(name) is not str or
        re.fullmatch(r'[0-9a-f]{64}-mk8\.(dns|email)\.dump\.partial', name) is None or
        name.startswith('0' * 64 + '-')):
        raise Pending('unsupported private archive staging leaf')
    if type(limit) is not int or not 1 <= limit <= MAX_BYTES or not callable(getattr(stream, 'read', None)):
        raise Pending('unsupported private archive stream or bound')
    admission(end); before = directory_identity(path)
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    fd = None; acquired = False
    try:
        directory_matches(path, directory, before)
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory_matches(path, directory, before); admission(end)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        acquired = True
        os.fchmod(fd, 0o600)
        file_matches(directory, name, fd)
        total = 0; hashed = hashlib.sha256()
        while True:
            admission(end)
            requested = min(CHUNK, limit - total + 1)
            part = stream.read(requested)
            admission(end)
            if type(part) is not bytes or len(part) > requested:
                raise Pending('untyped or oversized private archive stream delivery')
            if not part:
                break
            if total + len(part) > limit:
                raise Pending('private archive stream exceeds byte bound')
            offset = 0
            while offset < len(part):
                admission(end)
                count = os.write(fd, part[offset:])
                if type(count) is not int or not 0 < count <= len(part) - offset:
                    raise Pending('private archive write did not advance')
                offset += count
            total += len(part); hashed.update(part)
        if total == 0:
            raise Pending('empty private archive staging stream')
        os.fsync(fd)
        identity = file_matches(directory, name, fd)
        if identity[5] != total:
            raise Pending('private archive stage size disagrees')
        receipt = PREP.canonical({'schema':1, 'state':'private-unverified-archive-stage-only',
            'directory':str(path), 'directory_identity':list(before), 'leaf':name,
            'bytes':total, 'limit_bytes':limit, 'sha256':hashed.hexdigest(), 'identity':list(identity)})
        if len(receipt) > MAX_RECEIPT:
            raise Pending('private archive staging receipt exceeds bound')
        if file_matches(directory, name, fd) != identity:
            raise Pending('private archive stage changed after encoding')
        directory_matches(path, directory, before); admission(end)
        closing, fd = fd, None
        os.close(closing)
        os.fsync(directory)
        readback(directory, name, identity, total, hashed.hexdigest(), end)
        directory_matches(path, directory, before); admission(end)
        return receipt
    except BaseException as error:
        if acquired or isinstance(error, FileExistsError):
            raise Blocked('archive staging target exists or may be visible; no automatic retry') from error
        raise
    finally:
        try:
            if fd is not None:
                closing, fd = fd, None
                os.close(closing)
        finally:
            closing, directory = directory, None
            os.close(closing)
