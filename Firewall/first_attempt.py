#!/usr/bin/python3
"""Reserve exactly one submission slot in an existing protected directory.

Any existing leaf, including incomplete data, blocks another reservation. The
leaf is deliberately never removed or overwritten, even after failed writes,
sync or close. This is cooperating-process crash conservatism, not physical
durability, authenticated ownership or hostile-root/path/mount containment.
No CLI, directory creation, native observer, reset or submission is provided.
"""

import hashlib
import importlib.util
import os
from pathlib import Path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


MATCH = module('debian13s4_attempt_match', 'first_match.py')
_STORAGE = module('debian13s4_attempt_storage', 'proposal_store.py')
KERNEL, STATE, Pending = _STORAGE.KERNEL, MATCH.STATE, _STORAGE.Pending
LEAF = 'first-attempt.json'
MAX_BYTES = 2 * MATCH.PLAN.MAX_OUTPUT + 4096


class Blocked(RuntimeError):
    """A reserved or unverifiable slot must not be automatically retried."""


def envelope(payload):
    plan = MATCH.checked(payload)
    raw = STATE.encoded({'schema': 'debian13s4-first-create-attempt-1',
        'state': 'submission-reserved-no-retry', 'namespace': plan['namespace'],
        'correlation_id': plan['correlation_id'], 'proposal_sha256': hashlib.sha256(payload).hexdigest(),
        'transaction_sha256': plan['transaction_sha256'], 'proposal': payload.decode('utf-8')}) + b'\n'
    if len(raw) > MAX_BYTES:raise Pending('first-create reservation exceeds byte bound')
    return raw


def checked(raw):
    value = _STORAGE.decoded(raw, MAX_BYTES)
    fields = {'schema', 'state', 'namespace', 'correlation_id', 'proposal_sha256', 'transaction_sha256', 'proposal'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-first-create-attempt-1' or \
            value['state'] != 'submission-reserved-no-retry' or type(value['proposal']) is not str:
        raise Pending('unsupported first-create reservation')
    payload = value['proposal'].encode('utf-8')
    # Recompute the whole plan and every commitment; an outer hash is insufficient.
    if type(value['namespace']) is not int or raw != envelope(payload):
        raise Pending('first-create reservation identity or canonical bytes disagree')
    return raw


_STORAGE.LEAF, _STORAGE.MAX_BYTES, _STORAGE.checked = LEAF, MAX_BYTES, checked


def reserve(path, payload, deadline=None):
    """Exclusive reservation; NEVER treat an identical existing record as success."""
    end = _STORAGE.window(deadline)
    raw = envelope(payload)
    _STORAGE.admission(end)
    directory, before = _STORAGE.locked(path, end)
    fd, acquired = None, False
    try:
        try:
            fd = os.open(LEAF, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            acquired = True
            os.fchmod(fd, 0o600)
            identity = _STORAGE.file_identity(os.fstat(fd))
            if identity[0] != before[0] or identity != _STORAGE.file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False)):
                raise Pending('first-create reservation descriptor or path disagrees')
            offset = 0
            while offset < len(raw):
                _STORAGE.admission(end)
                count = os.write(fd, raw[offset:])
                if type(count) is not int or not 0 < count <= len(raw) - offset:
                    raise Pending('first-create reservation write did not advance')
                offset += count
            os.fsync(fd)
            identity = _STORAGE.file_identity(os.fstat(fd))
            if identity != _STORAGE.file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False)):
                raise Pending('first-create reservation changed during write')
            _STORAGE.directory_matches(path, directory, before)
            _STORAGE.admission(end)
            closing, fd = fd, None
            os.close(closing)  # retire ownership before its ONE checked close
            os.fsync(directory)
            if checked(_STORAGE.read_at(directory, end)) != raw or \
                    _STORAGE.file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False)) != identity:
                raise Pending('first-create reservation readback or identity disagrees')
            _STORAGE.directory_matches(path, directory, before)
            _STORAGE.admission(end)
            return raw
        finally:
            try:
                if fd is not None:
                    closing, fd = fd, None
                    os.close(closing)
            finally:
                os.close(directory)
    except FileExistsError as error:
        raise Blocked('first-create submission slot already exists; no automatic retry') from error
    except BaseException as error:
        if acquired:
            raise Blocked('first-create reservation may be visible; no automatic retry') from error
        raise


def load(path, deadline=None):
    """Check historical reservation bytes without granting another submission."""
    return _STORAGE.load(path, deadline=deadline)
