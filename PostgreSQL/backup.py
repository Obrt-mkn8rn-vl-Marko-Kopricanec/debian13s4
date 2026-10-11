#!/usr/bin/python3
"""Protected logical-backup intentions for the two configured local databases.

This does not dump, open/create an archive, inspect one, restore, publish, delete
or schedule anything. Default preparation WOULD connect through the accepted
read-only access checker; real-host calling is unauthorized here. Selected
access is not complete object/RLS/extension safety or restore compatibility.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_backup_access',
    Path(__file__).with_name('access.py'))
ACCESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCESS)
PREP, KERNEL, Pending = ACCESS.PREP, ACCESS.KERNEL, ACCESS.Pending
INPUT = Path('/etc/debian13s4/postgresql-backup.json')
DUMP = '/usr/lib/postgresql/17/bin/pg_dump'
RESTORE = '/usr/lib/postgresql/17/bin/pg_restore'
RUNUSER = '/usr/sbin/runuser'
MAX_INPUT = 4096
MAX_OUTPUT = ACCESS.MAX_OUTPUT + PREP.MAX_OUTPUT + 16384
ATTEMPT_SECONDS = 60


def checked(value):
    fields = {'schema', 'directory', 'generation', 'archive_limit_bytes',
              'inventory_limit_bytes', 'dump_timeout_seconds', 'lock_wait_ms'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported PostgreSQL backup intention schema')
    path = value['directory']
    if (type(path) is not str or not 6 <= len(path) <= 240 or
        re.fullmatch(r'/[A-Za-z0-9_./-]+', path) is None or
        os.path.normpath(path) != path or
        any(part in ('', '.', '..') for part in path.split('/')[1:]) or
        not any(path.startswith(root + '/') for root in ('/srv', '/var/backups'))):
        raise Pending('unsupported explicit PostgreSQL backup directory intention')
    generation = value['generation']
    if (type(generation) is not str or re.fullmatch(r'[0-9a-f]{64}', generation) is None or
        generation == '0' * 64):
        raise Pending('unsupported explicit PostgreSQL backup generation')
    for field, minimum, maximum in (
        ('archive_limit_bytes', 1024, 1 << 40),
        ('inventory_limit_bytes', 1024, 1 << 26),
        ('dump_timeout_seconds', 1, 3600), ('lock_wait_ms', 1, 60000)):
        number = value[field]
        if type(number) is not int or not minimum <= number <= maximum:
            raise Pending('unsupported explicit PostgreSQL backup bound')
    return json.loads(PREP.canonical(value))


def configuration(end):
    raw, source = PREP.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite backup input')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid PostgreSQL backup input') from error
    if raw != PREP.canonical(value):
        raise Pending('backup input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def render(settings, record):
    settings = checked(settings)
    deployment = PREP.checked(record['configuration']['value'])
    jobs = {}
    for app in PREP.APPLICATIONS:
        item = deployment['applications'][app]
        archive = settings['directory'] + '/' + settings['generation'] + '-' + app + '.dump'
        jobs[app] = {
            'role': item['role'], 'database': item['database'], 'archive': archive,
            # Binary stdout goes to a future independently protected writer;
            # runuser's application identity does not own the archive directory.
            'dump_argv': [RUNUSER, '-u', item['role'], '--', DUMP,
                '--format=custom', '--no-password', '--host', PREP.SOCKET_DIRECTORY,
                '--port', '5432', '--username', item['role'], '--dbname', item['database'],
                '--lock-wait-timeout=' + str(settings['lock_wait_ms'])],
            'dump_environment': {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'},
            'dump_stdout': 'custom-archive-bytes-for-protected-writer',
            'archive_limit_bytes': settings['archive_limit_bytes'],
            'dump_timeout_seconds': settings['dump_timeout_seconds'],
            'inspection_argv': [RESTORE, '--list', archive],
            'inspection_environment': {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'},
            'inventory_limit_bytes': settings['inventory_limit_bytes']}
    return jobs


def prepare(read=None, deadline=None):
    if read is None:
        read = ACCESS.LIVE.native
    if not callable(read):
        raise Pending('unsupported PostgreSQL backup access delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited PostgreSQL backup window')
    end = min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS
    PREP.fence(end)
    namespace = KERNEL.uint(KERNEL.namespace(), (1 << 64) - 1)
    if not namespace:
        raise Pending('missing PostgreSQL backup context')
    def capture(kind, window):
        if not KERNEL.finite_deadline(window) or window > end:
            raise Pending('PostgreSQL backup query exceeds inherited window')
        PREP.fence(end)
        PREP.fence(window)
        raw = read(kind, window)
        PREP.fence(window)
        PREP.fence(end)
        return raw

    settings = configuration(end)
    record, enrolled = ACCESS.LIVE.intention(end)
    before = ACCESS.check(read=capture, deadline=end)
    access = ACCESS.decoded(before, ACCESS.MAX_OUTPUT)
    if (access['namespace'] != namespace or record['namespace'] != namespace or
        access['admin']['enrollment'] != enrolled or access['admin']['accounts'] != record['accounts']):
        raise Pending('PostgreSQL backup and access source identities differ')
    for app in PREP.APPLICATIONS:
        item = record['configuration']['value']['applications'][app]
        if (access['applications'][app]['user'] != item['role'] or
            access['applications'][app]['database'] != item['database']):
            raise Pending('PostgreSQL backup application source differs')
    payload = PREP.canonical({'schema': 1, 'profile': 'postgresql17-selected-logical-backup-intention-v1',
        'state': 'postgresql-logical-backup-intention-only', 'namespace': namespace,
        'configuration': settings, 'source_intention': record, 'enrollment': enrolled,
        'access': access, 'jobs': render(settings['value'], record)})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete PostgreSQL backup intention exceeds bound')
    # Complete immutable encoding precedes every final real input/access read.
    if configuration(end) != settings:
        raise Pending('PostgreSQL backup configuration changed')
    if ACCESS.check(read=capture, deadline=end) != before:
        raise Pending('PostgreSQL backup access source changed')
    final_record, final_enrolled = ACCESS.LIVE.intention(end)
    if final_record != record or final_enrolled != enrolled:
        raise Pending('PostgreSQL backup protected source changed')
    final = KERNEL.namespace()
    if type(final) is not int or final != namespace:
        raise Pending('PostgreSQL backup context changed')
    PREP.fence(end)
    return payload


def main():
    try:
        if sys.argv[1:] != ['--prepare']:
            raise Pending('unsupported PostgreSQL backup action')
        sink = getattr(sys.stdout, 'buffer', None)
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('PostgreSQL backup preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete PostgreSQL backup intention output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError,
            RecursionError, subprocess.TimeoutExpired) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
