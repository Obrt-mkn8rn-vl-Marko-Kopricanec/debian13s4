#!/usr/bin/python3
"""Retain a reserved lifecycle failure without discharging its original error.

Known returned receipts are opaque historical bytes, not archive validation or
native completion. Recording can itself fail or leave visible data without
success. Neither outcome authorizes a second attempt, reset or publication.
"""
import hashlib
import importlib.util
from pathlib import Path


def module(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


MANIFEST = module('debian13s4_attempt_failure_manifest', 'stage_manifest.py')
ATTEMPT = module('debian13s4_attempt_failure_reservation', 'backup_attempt.py')
_STORAGE = module('debian13s4_attempt_failure_storage', 'private_storage.py')
HISTORY, PREP, Pending = MANIFEST.HISTORY, MANIFEST.PREP, MANIFEST.Pending
LEAF = 'selected-backup-incomplete.json'
STATE = 'historical-backup-attempt-incomplete-no-retry'
PHASES = ('pre-stage', 'stage', 'pre-listing', 'listing', 'manifest', 'final-validation')
LIMITS = {'selection': HISTORY.SELECTED.MAX_OUTPUT,
          'listing': MANIFEST.LISTING.MAX_OUTPUT, 'manifest': MANIFEST.MAX_RECORD}
MAX_RECORD = 2 * sum(LIMITS.values()) + 2 * ATTEMPT.MAX_BYTES + 131072
MAX_BYTES = 2 * MAX_RECORD + 4096


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def opaque(raw, maximum):
    if raw is None:
        return None
    if type(raw) is not bytes or len(raw) > maximum:
        raise Pending('known backup outcome is not bounded immutable bytes')
    return {'bytes': len(raw), 'sha256': digest(raw), 'hex': raw.hex()}


def checked(raw):
    value = HISTORY.BACKUP.ACCESS.decoded(raw, MAX_RECORD)
    HISTORY.fields(value, 'schema state application reservation reservation_sha256 phase cause known history_error cleanup')
    if value['schema'] != 'debian13s4-backup-attempt-incomplete-1' or value['state'] != STATE or \
            type(value['reservation']) is not str or type(value['phase']) is not str or value['phase'] not in PHASES:
        raise Pending('unsupported backup attempt failure profile')
    reservation = value['reservation'].encode('utf-8')
    ATTEMPT.checked(reservation)
    slot = HISTORY.BACKUP.ACCESS.decoded(reservation, ATTEMPT.MAX_BYTES)
    if type(value['application']) is not str or value['application'] != slot['application'] or \
            value['reservation_sha256'] != digest(reservation):
        raise Pending('backup failure and reserved attempt differ')
    HISTORY.diagnostics(value['cause'])
    HISTORY.diagnostics(value['cleanup'])
    if not value['cause']:
        raise Pending('missing original backup failure')
    if value['history_error'] is not None:
        HISTORY.diagnostics(value['history_error'])
        if not value['history_error']:
            raise Pending('missing separate history failure')
    HISTORY.fields(value['known'], 'selection listing manifest')
    for tag, maximum in LIMITS.items():
        row = value['known'][tag]
        if row is not None:
            HISTORY.fields(row, 'bytes sha256 hex')
            data = HISTORY.hex_bytes(row['hex'], maximum)
            if type(row['bytes']) is not int or row['bytes'] != len(data) or row['sha256'] != digest(data):
                raise Pending('known opaque backup outcome commitment differs')
    if raw != PREP.canonical(value):
        raise Pending('backup attempt failure is not canonical')
    return value


def capture(reservation, phase, cause, known, history_error, cleanup):
    ATTEMPT.checked(reservation)
    slot = HISTORY.BACKUP.ACCESS.decoded(reservation, ATTEMPT.MAX_BYTES)
    if type(phase) is not str or phase not in PHASES or type(cleanup) is not tuple or len(cleanup) > 16:
        raise Pending('unsupported backup failure phase or cleanup inventory')
    HISTORY.fields(known, 'selection listing manifest')
    # Known receipts are never parsed into a fabricated successful outcome here.
    outcomes = {tag: opaque(known[tag], maximum) for tag, maximum in LIMITS.items()}
    raw = PREP.canonical({'schema': 'debian13s4-backup-attempt-incomplete-1', 'state': STATE,
        'application': slot['application'], 'reservation': reservation.decode('utf-8'),
        'reservation_sha256': digest(reservation), 'phase': phase, 'cause': HISTORY.chain(cause),
        'known': outcomes, 'history_error': None if history_error is None else HISTORY.chain(history_error),
        'cleanup': [HISTORY.describe(error) for error in cleanup]})
    checked(raw)
    return raw


def envelope(payload):
    checked(payload)
    raw = PREP.canonical({'schema': 'debian13s4-backup-attempt-failure-history-1', 'state': STATE,
                          'payload': payload.decode('utf-8'), 'payload_sha256': digest(payload)})
    if len(raw) > MAX_BYTES:
        raise Pending('backup failure history exceeds its storage bound')
    return raw


def stored(raw):
    value = HISTORY.BACKUP.ACCESS.decoded(raw, MAX_BYTES)
    HISTORY.fields(value, 'schema state payload payload_sha256')
    if value['schema'] != 'debian13s4-backup-attempt-failure-history-1' or value['state'] != STATE or type(value['payload']) is not str:
        raise Pending('unsupported backup failure history envelope')
    payload = value['payload'].encode('utf-8')
    checked(payload)
    if value['payload_sha256'] != digest(payload) or raw != PREP.canonical(value):
        raise Pending('backup failure envelope changed')
    return payload


_STORAGE.LEAF, _STORAGE.MAX_BYTES, _STORAGE.envelope, _STORAGE.checked = LEAF, MAX_BYTES, envelope, stored


def record(path, reservation, phase, cause, known, history_error, cleanup, deadline=None):
    end = _STORAGE.window(deadline)
    payload = capture(reservation, phase, cause, known, history_error, cleanup)
    _STORAGE.admission(end)
    return _STORAGE.create(path, payload, deadline=end)


def load(path, deadline=None):
    return _STORAGE.load(path, deadline=deadline)
