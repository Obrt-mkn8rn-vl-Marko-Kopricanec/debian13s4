#!/usr/bin/python3
"""Prepare local PostgreSQL intentions; never install, connect or execute SQL.

Only mk8.dns and mk8.email use this PostgreSQL profile. The other two
applications keep their separate storage contracts. Inputs are explicit private
configuration, not site defaults or authenticated deployment authority.
The ordered SQL requires a NEW cluster: it does not adopt existing objects,
make all steps atomic, supply migrations or authorize retry after an error.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_postgresql_kernel',
    Path(__file__).resolve().parents[1] / 'firewall/kernel.py')
if not SPEC.origin or not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_postgresql_kernel',
        Path(__file__).resolve().parents[1] / 'Firewall/kernel.py')
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
INPUT = Path('/etc/debian13s4/postgresql.json')
PASSWD = Path('/etc/passwd')
CONFIG_DIRECTORY = '/etc/debian13s4-postgresql'
DATA_DIRECTORY = '/var/lib/debian13s4-postgresql'
SOCKET_DIRECTORY = '/run/debian13s4-postgresql'
APPLICATIONS = ('mk8.dns', 'mk8.email')
IDENTIFIER = re.compile(r'[a-z][a-z0-9_]{0,30}\Z')
MAX_INPUT = 4096
MAX_ACCOUNTS = 262144
MAX_OUTPUT = 262145
ATTEMPT_SECONDS = 10


def fence(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('PostgreSQL preparation window expired')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def read_protected(path, limit, private, end):
    fence(end)
    if (type(path) is not type(INPUT) or not path.is_absolute() or
        os.path.normpath(str(path)) != str(path)):
        raise Pending('noncanonical PostgreSQL input path')
    path.relative_to(TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        kind = stat.S_ISREG if current == path else stat.S_ISDIR
        if not kind(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending('unprotected PostgreSQL input or ancestry')
        if current == TRUST_ROOT:
            break
        current = current.parent
    before = path.lstat()
    if (before.st_nlink != 1 or before.st_size > limit or
        private and stat.S_IMODE(before.st_mode) != 0o600):
        raise Pending('nonunique, oversized or nonprivate PostgreSQL input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before):
            raise Pending('PostgreSQL input descriptor differs')
        data = bytearray()
        while True:
            fence(end)
            part = os.read(descriptor, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
            if len(data) > limit:
                raise Pending('PostgreSQL input exceeds its byte bound')
        if (KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before) or
            KERNEL.signature(path.lstat()) != KERNEL.signature(before) or len(data) != before.st_size):
            raise Pending('PostgreSQL input changed during read')
    finally:
        # One close only. Linux may retire/reuse the number before an error.
        os.close(descriptor)
    fence(end)
    raw = bytes(data)
    return raw, {'path': str(path), 'identity': list(KERNEL.signature(before)),
                 'sha256': hashlib.sha256(raw).hexdigest()}


def identifier(value):
    if (type(value) is not str or IDENTIFIER.fullmatch(value) is None or
        value.startswith('pg_') or value in {'postgres', 'template0', 'template1', 'root'}):
        raise Pending('unsupported PostgreSQL role or database identifier')
    return value


def checked(value):
    fields = {'schema', 'applications', 'max_connections', 'shared_buffers_mb'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported PostgreSQL input schema')
    for field, minimum, maximum in (('max_connections', 16, 512), ('shared_buffers_mb', 16, 16384)):
        if type(value[field]) is not int or not minimum <= value[field] <= maximum:
            raise Pending('unsupported explicit PostgreSQL capacity')
    KERNEL.known(value['applications'], set(APPLICATIONS), set(APPLICATIONS))
    roles, databases, total = set(), set(), 0
    for app in APPLICATIONS:
        item = value['applications'][app]
        names = {'role', 'database', 'connection_limit'}
        KERNEL.known(item, names, names)
        role, database = identifier(item['role']), identifier(item['database'])
        limit = item['connection_limit']
        if type(limit) is not int or not 1 <= limit <= 64:
            raise Pending('unsupported PostgreSQL application connection limit')
        if role in roles or database in databases:
            raise Pending('shared PostgreSQL application identity')
        roles.add(role); databases.add(database); total += limit
    if total + 8 > value['max_connections']:
        raise Pending('PostgreSQL application limits consume reserved connection capacity')
    # A plain new private object; callers cannot rewrite admitted input later.
    return json.loads(canonical(value))


def configuration(end):
    raw, source = read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite PostgreSQL input')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid PostgreSQL configuration JSON') from error
    value = checked(value)
    if raw != canonical(value):
        raise Pending('PostgreSQL input is not canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def accounts(raw, settings):
    settings = checked(settings)
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('unsupported local account encoding') from error
    if (not text.endswith('\n') or
        any(character != '\n' and not 32 <= ord(character) <= 126 for character in text)):
        raise Pending('unsupported local account inventory')
    # passwd records are delimited ONLY by LF. Other ASCII control bytes
    # cannot manufacture apparent accounts inside a malformed LF record.
    records = text[:-1].split('\n')
    if len(records) > 4096:
        raise Pending('unsupported local account inventory')
    inventory, uids = {}, set()
    for line in records:
        fields = line.split(':')
        if (len(fields) != 7 or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', fields[0]) is None or
            fields[0] in inventory or any(re.fullmatch(r'0|[1-9][0-9]{0,9}', fields[i]) is None for i in (2, 3))):
            raise Pending('malformed or duplicate local account')
        uid, gid = (KERNEL.uint(int(fields[i]), 0x7fffffff) for i in (2, 3))
        if uid in uids:
            raise Pending('ambiguous local peer account UID')
        uids.add(uid); inventory[fields[0]] = (fields, uid, gid)
    selected = {}
    for app in APPLICATIONS:
        role = settings['applications'][app]['role']
        if role not in inventory:
            raise Pending('PostgreSQL application service account is missing')
        fields, uid, gid = inventory[role]
        if (not 100 <= uid <= 999 or gid == 0 or fields[1] not in ('x', '!', '*') or
            fields[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false')):
            raise Pending('unsupported PostgreSQL local service account')
        selected[app] = {'name': role, 'uid': uid, 'gid': gid, 'shell': fields[6]}
    return selected


def render(settings):
    settings = checked(settings)
    config = (f"data_directory = '{DATA_DIRECTORY}'\n"
              f"hba_file = '{CONFIG_DIRECTORY}/pg_hba.conf'\n"
              f"ident_file = '{CONFIG_DIRECTORY}/pg_ident.conf'\n"
              "listen_addresses = ''\nport = 5432\n"
              f"unix_socket_directories = '{SOCKET_DIRECTORY}'\n"
              "unix_socket_permissions = 0777\nssl = off\n"
              "password_encryption = 'scram-sha-256'\n"
              "fsync = on\nfull_page_writes = on\nsynchronous_commit = on\n"
              f"max_connections = {settings['max_connections']}\n"
              f"shared_buffers = '{settings['shared_buffers_mb']}MB'\n")
    hba = 'local all postgres peer\n'
    roles = []
    steps = []
    connections = {}
    for app in APPLICATIONS:
        item = settings['applications'][app]
        role, database, limit = item['role'], item['database'], item['connection_limit']
        # The grammar excludes quote/backslash/metacharacters. Quotes also
        # prevent HBA keywords and SQL keywords from changing identifier meaning.
        hba += f'local "{database}" "{role}" peer\n'
        roles.append(f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                     f'NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {limit} PASSWORD NULL;\n')
        steps.append({'database': 'postgres', 'transaction': False,
            'sql': f'CREATE DATABASE "{database}" OWNER "{role}" TEMPLATE template0 '
                   f"ENCODING 'UTF8' CONNECTION LIMIT {limit};\n"})
        steps.append({'database': database, 'transaction': True,
            'sql': f'BEGIN;\nREVOKE ALL ON DATABASE "{database}" FROM PUBLIC;\n'
                   'REVOKE CREATE ON SCHEMA public FROM PUBLIC;\nCOMMIT;\n'})
        connections[app] = (f'Host={SOCKET_DIRECTORY};Port=5432;Database={database};'
                            f'Username={role};SSL Mode=Disable;Include Error Detail=false')
    hba += ('local replication all reject\nlocal all all reject\n'
            'host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n'
            'host replication all 0.0.0.0/0 reject\nhost replication all ::/0 reject\n')
    steps.insert(0, {'database': 'postgres', 'transaction': True,
                    'sql': 'BEGIN;\n' + ''.join(roles) + 'COMMIT;\n'})
    files = {'postgresql.conf': config, 'pg_hba.conf': hba,
             'pg_ident.conf': '# No peer identity remapping is admitted.\n'}
    return {'files': files, 'sql_steps': steps, 'connections': connections,
            'initdb_argv': ['/usr/lib/postgresql/17/bin/initdb', '--pgdata', DATA_DIRECTORY,
                '--username=postgres', '--auth-local=peer', '--auth-host=reject',
                '--encoding=UTF8', '--locale=C.UTF-8', '--data-checksums', '--no-instructions']}


def prepare(deadline=None, scope=KERNEL.namespace):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited PostgreSQL deadline')
        end = min(end, deadline)
    fence(end)
    context = KERNEL.uint(scope(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing PostgreSQL caller namespace')
    settings = configuration(end)
    raw, account_source = read_protected(PASSWD, MAX_ACCOUNTS, False, end)
    selected = accounts(raw, settings['value'])
    plan = render(settings['value'])
    record = {'schema': 1, 'profile': 'postgresql17-local-peer-new-cluster-intention-v1',
        'state': 'local-peer-provisioning-intention-only', 'namespace': context,
        'configuration': settings, 'account_source': account_source, 'accounts': selected, 'plan': plan}
    payload = canonical(record)
    if len(payload) > MAX_OUTPUT:
        raise Pending('PostgreSQL intention exceeds its complete output byte bound')
    # Everything above is encoded before the repeated protected input reads
    # and final context/time admission. Only these exact prepared bytes return.
    if configuration(end) != settings:
        raise Pending('PostgreSQL configuration changed during preparation')
    after_raw, after_source = read_protected(PASSWD, MAX_ACCOUNTS, False, end)
    if after_raw != raw or after_source != account_source:
        raise Pending('PostgreSQL local account inventory changed')
    final_context = KERNEL.uint(scope(), 0xffffffffffffffff)
    if final_context != context:
        raise Pending('PostgreSQL caller namespace changed')
    fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('PostgreSQL preparation has no input/configuration overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('PostgreSQL preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete PostgreSQL intention publication')
        sink.flush()
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == '__main__':
    sys.exit(main())
