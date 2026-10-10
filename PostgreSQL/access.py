#!/usr/bin/python3
"""Require reported local peer access for BOTH configured application identities.

Read-only SOURCE admission, not migration/CRUD/Npgsql, NSS/origin authentication,
complete object safety or physical readiness. Default check WOULD read protected
host files and connect to PostgreSQL; host calling is unauthorized here. No role,
account, SQL mutation, provisioning, adoption or retry operation is supplied.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_postgresql_access_live', Path(__file__).with_name('live.py'))
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)
PREP, KERNEL, Pending = LIVE.PREP, LIVE.KERNEL, LIVE.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = 2 * PREP.MAX_OUTPUT + 8192


def decoded(raw, limit):
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise Pending('invalid PostgreSQL access byte delivery')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(Pending('nonfinite PostgreSQL access JSON')),
            parse_float=lambda value: (_ for _ in ()).throw(Pending('noninteger PostgreSQL access JSON')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid PostgreSQL access JSON') from error


def peer(value, app, record, admin):
    """Complete selected reported facts, never a caller health/hash verdict."""
    if type(app) is not str or app not in PREP.APPLICATIONS:
        raise Pending('unsupported PostgreSQL application identity')
    item = record['configuration']['value']['applications'][app]
    fields = {'version', 'user', 'database', 'client', 'authentication', 'start',
              'recovery', 'read_only', 'role', 'database_access', 'schema_access'}
    KERNEL.known(value, fields, fields)
    if (type(value['version']) is not int or value['version'] != admin['version'] or
        value['user'] != item['role'] or value['database'] != item['database'] or
        value['client'] is not None or value['authentication'] != 'peer:' + item['role'] or
        value['start'] != admin['start'] or value['recovery'] is not False or value['read_only'] is not False):
        raise Pending('PostgreSQL application session differs from enrolled server/peer intention')
    flags = {'super', 'inherit', 'createdb', 'createrole', 'login', 'replication', 'bypass'}
    KERNEL.known(value['role'], flags, flags)
    for flag in flags:
        if value['role'][flag] is not (flag == 'login'):
            raise Pending('PostgreSQL application peer role privileges differ')
    database = value['database_access']
    names = {'owner', 'encoding', 'connect', 'create', 'temp', 'public_access'}
    KERNEL.known(database, names, names)
    if (database['owner'] != item['role'] or database['encoding'] != 'UTF8' or
        any(database[name] is not True for name in ('connect', 'create', 'temp')) or
        database['public_access'] is not False):
        raise Pending('PostgreSQL application database ownership/access differs')
    schema = value['schema_access']
    names = {'owner', 'usage', 'create', 'public_create'}
    KERNEL.known(schema, names, names)
    if (schema['owner'] not in (item['role'], 'pg_database_owner') or
        schema['usage'] is not True or schema['create'] is not True or schema['public_create'] is not False):
        raise Pending('PostgreSQL application public schema ownership/access differs')
    return decoded(PREP.canonical(value), LIVE.MAX_BYTES)


def check(read=None, deadline=None):
    """Real admin admission plus two complete application rounds and final inputs."""
    if read is None:
        read = LIVE.native
    if not callable(read):
        raise Pending('unsupported PostgreSQL access delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid PostgreSQL access inherited deadline')
    end = min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(KERNEL.namespace(), 2 ** 64 - 1)
    if not namespace:
        raise Pending('missing PostgreSQL access context')
    PREP.fence(end)
    before = LIVE.check(read=read, deadline=end)
    admin = decoded(before, PREP.MAX_OUTPUT)
    record, registered = LIVE.intention(end)
    if (admin['namespace'] != namespace or record['namespace'] != namespace or
        admin['enrollment'] != registered or admin['accounts'] != record['accounts']):
        raise Pending('PostgreSQL access and real preparation identities differ')
    rounds = []
    for _ in range(2):
        observed = {}
        for app in PREP.APPLICATIONS:
            PREP.fence(end)
            observed[app] = peer(decoded(read('peer:' + app, end), LIVE.MAX_BYTES), app, record, admin['catalog'])
            PREP.fence(end)
        rounds.append(observed)
    if PREP.canonical(rounds[0]) != PREP.canonical(rounds[1]):
        raise Pending('complete PostgreSQL application peer SOURCE changed')
    # The real admin checker, not a supplied health flag, fences selected server,
    # roles/databases/settings/config/enrollment again AFTER all peer reads.
    if LIVE.check(read=read, deadline=end) != before:
        raise Pending('complete PostgreSQL admin SOURCE changed around application access')
    payload = PREP.canonical({'schema': 1, 'state': 'enrolled-local-postgresql-peer-source-only',
        'profile': 'postgresql17-dns-email-local-peer-owner-access-v1', 'namespace': namespace,
        'admin': admin, 'applications': rounds[-1]})
    if len(payload) > MAX_OUTPUT:
        raise Pending('PostgreSQL application access receipt exceeds bound')
    # All output encoding precedes these real complete protected input reads and
    # the final typed scope/time fence. Equal reads are sequential, not atomic.
    final_record, final_registered = LIVE.intention(end)
    if final_record != record or final_registered != registered:
        raise Pending('PostgreSQL application access protected inputs changed')
    final = KERNEL.namespace()
    if type(final) is not int or final != namespace:
        raise Pending('PostgreSQL application access context changed')
    PREP.fence(end)
    return payload


def main():
    try:
        if sys.argv[1:] != ['--access']:
            raise Pending('unsupported PostgreSQL application access action')
        sink = getattr(sys.stdout, 'buffer', None)
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('PostgreSQL application access requires binary output')
        payload = check()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('short PostgreSQL application access output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError,
            RecursionError, subprocess.TimeoutExpired) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
