#!/usr/bin/python3
"""Persist one historical compiler-intent proposal in an existing private store.

This library has no CLI, host directory creation, native observer or policy
operation. Stored data is historical: it grants no freshness, ownership,
application or reconciliation authority. Honest private ancestry/finite IO and
cooperating directory locks are required; sync success is not power-loss proof.
"""

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat

SPEC = importlib.util.spec_from_file_location('debian13s4_proposal_auto', Path(__file__).with_name('auto_intent.py'))
AUTO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTO)
MANIFEST, ASSEMBLY = AUTO.MANIFEST, AUTO.ASSEMBLY
KERNEL, Pending = ASSEMBLY.KERNEL, ASSEMBLY.Pending
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
LEAF = 'proposal.json'
MAX_BYTES = 2 * AUTO.MAX_OUTPUT + 4096
ATTEMPT_SECONDS = 10


def admission(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('proposal storage window expired or invalid')


def window(deadline):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid proposal storage deadline')
    return min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS


def decoded(raw, limit):
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise Pending('invalid proposal byte delivery')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
                           parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite proposal JSON')))
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid proposal JSON') from error


def intent(raw):
    value = ASSEMBLY.snapshot(decoded(raw, AUTO.MAX_OUTPUT))
    fields = {'schema', 'namespace', 'profile', 'admission_profile', 'topology', 'intention'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-automatic-nft-intent-1' or \
            value['profile'] != 'automatic-empty-source-compiler-intent-1' or value['admission_profile'] != AUTO.ADMISSION or \
            type(value['namespace']) is not int or not 0 < value['namespace'] < 2 ** 64:
        raise Pending('unsupported historical intention profile')
    topology = MANIFEST.STATE.encoded(value['topology'])
    expected = MANIFEST.expected(topology)
    if MANIFEST.STATE.encoded(value['intention']) != MANIFEST.STATE.encoded(expected):
        raise Pending('historical intention disagrees with the real compiler')
    if raw != MANIFEST.STATE.encoded(value) + b'\n':
        raise Pending('historical intention is not canonical UTF8 plus LF')
    return value


def envelope(payload):
    value = intent(payload)
    raw = MANIFEST.STATE.encoded({'schema': 'debian13s4-nft-intent-history-1', 'state': 'historical-proposal',
                                  'payload': payload.decode('utf-8'), 'sha256': hashlib.sha256(payload).hexdigest()}) + b'\n'
    if len(raw) > MAX_BYTES:
        raise Pending('historical proposal exceeds storage limit')
    return raw


def checked(raw):
    value = decoded(raw, MAX_BYTES)
    fields = {'schema', 'state', 'payload', 'sha256'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-nft-intent-history-1' or value['state'] != 'historical-proposal':
        raise Pending('unsupported stored proposal state')
    if type(value['payload']) is not str:raise Pending('untyped stored proposal payload')
    payload = value['payload'].encode('utf-8')
    intent(payload)
    if type(value['sha256']) is not str or value['sha256'] != hashlib.sha256(payload).hexdigest() or \
            raw != MANIFEST.STATE.encoded(value) + b'\n':
        raise Pending('stored proposal identity or encoding changed')
    return payload


def directory_identity(path):
    if not isinstance(path, Path) or not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending('noncanonical proposal directory')
    path.relative_to(TRUST_ROOT)
    current, leaf = path, None
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending('untrusted proposal directory or ancestry')
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        if current == path:
            if stat.S_IMODE(info.st_mode) != 0o700:raise Pending('proposal directory is not private')
            leaf = identity
        if current == TRUST_ROOT:return leaf
        current = current.parent


def directory_matches(path, fd, before):
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) != before or directory_identity(path) != before:
        raise Pending('proposal directory descriptor or path changed')


def file_identity(info, links=1):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID or \
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != links:
        raise Pending('untrusted proposal leaf kind, owner, mode or links')
    return KERNEL.signature(info) + (info.st_nlink,)


def read_at(directory, end, sync=False, links=1):
    admission(end)
    before = file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False), links)
    if before[0] != os.fstat(directory).st_dev:raise Pending('proposal leaf device disagrees')
    fd = os.open(LEAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        if file_identity(os.fstat(fd), links) != before:raise Pending('proposal leaf descriptor changed')
        data = bytearray()
        while True:
            admission(end)
            part = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
            if not part:break
            data.extend(part)
            if len(data) > MAX_BYTES:raise Pending('proposal leaf exceeds bound')
        if sync:os.fsync(fd)
        if file_identity(os.fstat(fd), links) != before or \
                file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False), links) != before:
            raise Pending('proposal leaf changed during read')
        admission(end)
        return bytes(data)
    finally:
        os.close(fd)


def locked(path, end):
    admission(end)
    before = directory_identity(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        directory_matches(path, fd, before)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory_matches(path, fd, before);admission(end)
        return fd, before
    except BaseException:
        os.close(fd);raise


def load(path, deadline=None):
    end = window(deadline)
    directory, before = locked(path, end)
    try:
        payload = checked(read_at(directory, end))
        directory_matches(path, directory, before);admission(end)
        return payload
    finally:
        os.close(directory)


def reconcile_link(path, directory, before, payload, end):
    try:
        info = os.stat(LEAF, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:return
    if info.st_nlink != 2:return
    identity = file_identity(info, 2)
    if checked(read_at(directory, end, sync=True, links=2)) != payload:
        raise Pending('linked history belongs to a different proposal')
    matches = []
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries, 1):
            admission(end)
            if count > 32:raise Pending('proposal staging inventory exceeds recovery bound')
            if re.fullmatch(r'\.proposal-[0-9a-f]{32}', entry.name):
                stage = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                if (stage.st_dev, stage.st_ino) == identity[:2]:
                    if file_identity(stage, 2) != identity:raise Pending('proposal staging link changed')
                    matches.append(entry.name)
    if len(matches) != 1:raise Pending('linked proposal lacks one positively identified private staging name')
    directory_matches(path, directory, before);admission(end)
    if file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False), 2) != identity or \
            file_identity(os.stat(matches[0], dir_fd=directory, follow_symlinks=False), 2) != identity:
        raise Pending('proposal links changed before reconciliation')
    os.unlink(matches[0], dir_fd=directory)
    os.fsync(directory)
    directory_matches(path, directory, before);admission(end)


def staging_identity(info):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID:
        raise Pending('untrusted acquired staging descriptor or path')
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid


def create(path, payload, deadline=None):
    end = window(deadline)
    raw = envelope(payload);admission(end)
    directory, before = locked(path, end)
    temporary, owned, fd = None, None, None
    try:
        reconcile_link(path, directory, before, payload, end)
        try:
            current = read_at(directory, end, sync=True)
        except FileNotFoundError:
            current = None
        if current is not None:
            if checked(current) != payload:raise Pending('a different historical proposal already exists')
            os.fsync(directory);directory_matches(path, directory, before);admission(end)
            return payload
        candidate = '.proposal-' + secrets.token_hex(16)
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        owned = staging_identity(os.fstat(fd))
        if owned[0] != before[0]:raise Pending('acquired staging device disagrees')
        temporary = candidate
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            admission(end)
            count = os.write(fd, raw[offset:])
            if type(count) is not int or not 0 < count <= len(raw) - offset:
                raise Pending('proposal write did not advance')
            offset += count
        os.fsync(fd)
        identity = file_identity(os.fstat(fd))
        if identity != file_identity(os.stat(temporary, dir_fd=directory, follow_symlinks=False)):
            raise Pending('proposal staging descriptor or path changed')
        directory_matches(path, directory, before);admission(end)
        os.link(temporary, LEAF, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory);temporary = None
        closing, fd = fd, None
        os.close(closing)
        os.fsync(directory)
        result = checked(read_at(directory, end))
        if result != payload:raise Pending('published proposal differs from the intended bytes')
        directory_matches(path, directory, before);admission(end)
        return result
    finally:
        try:
            if temporary is not None:
                directory_matches(path, directory, before)
                if staging_identity(os.fstat(fd)) != owned or \
                        staging_identity(os.stat(temporary, dir_fd=directory, follow_symlinks=False)) != owned:
                    raise Pending('owned staging identity changed before cleanup')
                os.unlink(temporary, dir_fd=directory)
        finally:
            try:
                if fd is not None:
                    closing, fd = fd, None
                    os.close(closing)
            finally:
                os.close(directory)
