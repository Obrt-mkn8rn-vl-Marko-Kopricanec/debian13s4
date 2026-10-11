#!/usr/bin/python3
"""One create-only private backup-attempt slot; no reset or retry authority.

Every existing target blocks, including identical or partially written data.
Acquired files remain on failures. Public random correlation is not a credential,
registration/globaldedup/ownership/native completion or physical persistence.
Honest modules/private ancestry/cooperating locks/finite IO are required.
"""
import importlib.util
import os
from pathlib import Path
import re
import secrets

SPEC=importlib.util.spec_from_file_location('debian13s4_backup_attempt_storage',Path(__file__).parent.parent/'Firewall/proposal_store.py')
_STORAGE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(_STORAGE)
KERNEL,Pending=_STORAGE.KERNEL,_STORAGE.Pending
LEAF='selected-backup-attempt.json'
MAX_BYTES=4096
APPLICATIONS=('mk8.dns','mk8.email')


class Blocked(RuntimeError):
    """The attempt slot remains closed even if acquisition or sync failed."""


def encoded(value):return _STORAGE.MANIFEST.STATE.encoded(value)+b'\n'


def checked(raw):
    value=_STORAGE.decoded(raw,MAX_BYTES)
    fields={'schema','state','namespace','application','correlation_id'}
    KERNEL.known(value,fields,fields)
    if value['schema']!='debian13s4-selected-backup-attempt-1' or value['state']!='backup-attempt-reserved-no-retry' or type(value['namespace']) is not int or not 0<value['namespace']<2**64 or type(value['application']) is not str or value['application'] not in APPLICATIONS or type(value['correlation_id']) is not str or re.fullmatch('[0-9a-f]{64}',value['correlation_id']) is None or value['correlation_id']=='0'*64 or raw!=encoded(value):
        raise Pending('unsupported historical backup attempt slot')
    return raw


def envelope(application,namespace):
    if type(application) is not str or application not in APPLICATIONS or type(namespace) is not int or not 0<namespace<2**64:raise Pending('unsupported backup attempt selector/context')
    marker=secrets.token_hex(32)
    raw=encoded({'schema':'debian13s4-selected-backup-attempt-1','state':'backup-attempt-reserved-no-retry','namespace':namespace,'application':application,'correlation_id':marker})
    checked(raw);return raw


_STORAGE.LEAF,_STORAGE.MAX_BYTES,_STORAGE.checked=LEAF,MAX_BYTES,checked


def reserve(path, application, namespace, deadline=None):
    """Exclusive reservation; NEVER treat an identical existing record as success."""
    end = _STORAGE.window(deadline)
    raw = envelope(application, namespace)
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
                raise Pending('backup reservation descriptor or path disagrees')
            offset = 0
            while offset < len(raw):
                _STORAGE.admission(end)
                count = os.write(fd, raw[offset:])
                if type(count) is not int or not 0 < count <= len(raw) - offset:
                    raise Pending('backup reservation write did not advance')
                offset += count
            os.fsync(fd)
            identity = _STORAGE.file_identity(os.fstat(fd))
            if identity != _STORAGE.file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False)):
                raise Pending('backup reservation changed during write')
            _STORAGE.directory_matches(path, directory, before)
            _STORAGE.admission(end)
            closing, fd = fd, None
            os.close(closing)  # retire ownership before its ONE checked close
            os.fsync(directory)
            if checked(_STORAGE.read_at(directory, end)) != raw or \
                    _STORAGE.file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False)) != identity:
                raise Pending('backup reservation readback or identity disagrees')
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
        raise Blocked('backup attempt slot already exists; no automatic retry') from error
    except BaseException as error:
        if acquired:
            raise Blocked('backup reservation may be visible; no automatic retry') from error
        raise


def load(path,deadline=None):return _STORAGE.load(path,deadline=deadline)
