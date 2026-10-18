#!/usr/bin/python3
"""Inspect one existing private backup history directory without native work.

All states describe retained history only. No state authorizes retry, proves a
valid/completed backup, inspects a database/archive, or promotes/deletes a file.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_backup_status_lifecycle',
    Path(__file__).resolve().with_name('backup_lifecycle.py'))
LIFECYCLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFECYCLE)
Pending = LIFECYCLE.Pending
MAX_OUTPUT = 16384


def snapshot(directory, end):
    """Check each whole envelope; only an initially absent leaf is absent."""
    raw, records = {}, {}
    for tag, module in (('reservation', LIFECYCLE.ATTEMPT),
                        ('manifest', LIFECYCLE.MANIFEST),
                        ('incomplete', LIFECYCLE.UNCERTAINTY)):
        storage = module._STORAGE
        until = storage.window(end)
        try:
            os.stat(storage.LEAF, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            raw[tag], records[tag] = None, None
            continue
        data = storage.read_at(directory, until)
        payload = storage.checked(data)
        value = LIFECYCLE.BACKUP.ACCESS.decoded(payload, storage.MAX_BYTES)
        raw[tag], records[tag] = data, value
    return raw, records


def classify(records):
    reservation, manifest, incomplete = (records[tag] for tag in ('reservation', 'manifest', 'incomplete'))
    if manifest is not None and incomplete is not None:
        raise Pending('conflicting backup outcome records; preserve history and investigate')
    if reservation is None:
        if manifest is not None or incomplete is not None:
            raise Pending('backup outcome exists without its reservation; preserve history')
        return 'no-recorded-attempt', None
    for outcome in (manifest, incomplete):
        if outcome is not None and outcome['application'] != reservation['application']:
            raise Pending('backup reservation and outcome applications differ')
    state = ('historical-listing-recorded' if manifest is not None else
             'historical-incomplete-recorded' if incomplete is not None else
             'reserved-outcome-unknown')
    return state, reservation['application']


def inspect(path, deadline=None):
    storage = LIFECYCLE.ATTEMPT._STORAGE
    end = storage.window(deadline)
    directory, before = storage.locked(path, end)
    try:
        raw, records = snapshot(directory, end)
        state, application = classify(records)
        observed = {}
        for tag, data in raw.items():
            observed[tag] = {'present': data is not None}
            if data is not None:
                observed[tag].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                     state=records[tag]['state'])
        payload = LIFECYCLE.PREP.canonical({'schema': 1, 'state': state,
            'scope': 'historical-backup-records-only', 'directory': str(path),
            'application': application, 'records': observed,
            'retry_authorized': False, 'backup_complete': False})
        if len(payload) > MAX_OUTPUT:
            raise Pending('backup history summary exceeds its output bound')
        if snapshot(directory, end)[0] != raw:
            raise Pending('backup history changed after summary encoding')
        storage.directory_matches(path, directory, before)
        storage.admission(end)
    finally:
        closing, directory = directory, None
        os.close(closing)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True,
                        help='existing private directory containing one reserved attempt')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    args = parser.parse_args(argv)
    try:
        raw = inspect(args.directory)
        if args.format == 'text':
            value = LIFECYCLE.BACKUP.ACCESS.decoded(raw, MAX_OUTPUT)
            lines = ['Backup history: '+value['state'], 'Directory: '+value['directory']]
            if value['application'] is not None:
                lines.append('Application: '+value['application'])
            lines.extend(tag+': '+('present' if row['present'] else 'absent')
                         for tag, row in value['records'].items())
            lines.append('Historical records do not establish a completed backup or authorize retry.')
            raw = ('\n'.join(lines)+'\n').encode('utf-8')
        count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw):
            raise Pending('incomplete backup status output')
        sys.stdout.buffer.flush()
        return 0
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
