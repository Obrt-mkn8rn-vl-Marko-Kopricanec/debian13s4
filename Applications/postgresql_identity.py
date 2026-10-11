#!/usr/bin/python3
"""Join protected application-role FILE intentions to local-peer PG intentions.

Only the selected DNS and Email application roles are joined. This does not
authenticate NSS/PAM, grant Gateway database access, validate application
configuration/ABI, enroll services, connect, execute SQL or authorize retry.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_pg_application_identities',
    Path(__file__).resolve().with_name('identities.py'))
IDENTITIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITIES)
PG = IDENTITIES.BASE
KERNEL, Pending = PG.KERNEL, PG.Pending
MAX_OUTPUT = 4194305
ATTEMPT_SECONDS = 290
IDENTITY_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration',
    'passwd_source', 'group_source', 'releases', 'release_sha256', 'execution_bindings'}
PG_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration',
    'account_source', 'accounts', 'plan'}


def prepared_bytes(module, end):
    """Owned real preparations only; every complete return is bounded first."""
    PG.fence(end)
    raw = (PG.prepare(deadline=end, scope=KERNEL.namespace) if module is PG else
           IDENTITIES.prepare(deadline=end))
    if type(raw) is not bytes or len(raw) > module.MAX_OUTPUT:
        raise Pending('unsupported whole application/PG preparation bytes')
    PG.fence(end)
    return raw


def prepared(module, end, context):
    raw = prepared_bytes(module, end)
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite preparation')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid application/PG preparation JSON') from error
    fields, profile, state = ((PG_FIELDS, 'postgresql17-local-peer-new-cluster-intention-v1',
        'local-peer-provisioning-intention-only') if module is PG else
        (IDENTITY_FIELDS, 'four-app-release-account-intention-v1',
         'protected-application-execution-identity-source-only'))
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['profile'] != profile or value['state'] != state or
        KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
        raw != PG.canonical(value)):
        raise Pending('application/PG preparation schema, scope or canonical bytes differ')
    PG.fence(end)
    return raw, value


def bindings(identities, postgres):
    """Reported correspondence only; public hashes do not authenticate origin."""
    if PG.canonical(identities['passwd_source']) != PG.canonical(postgres['account_source']):
        raise Pending('application and PostgreSQL account source observations differ')
    settings = PG.checked(postgres['configuration']['value'])
    plan = PG.render(settings)
    if PG.canonical(postgres['plan']) != PG.canonical(plan):
        raise Pending('complete PostgreSQL intention differs from the real renderer')
    KERNEL.known(identities['execution_bindings'], set(IDENTITIES.RELEASE.APPLICATIONS),
        set(IDENTITIES.RELEASE.APPLICATIONS))
    KERNEL.known(postgres['accounts'], set(PG.APPLICATIONS), set(PG.APPLICATIONS))
    result = {}
    for app in PG.APPLICATIONS:
        pair = identities['execution_bindings'][app]
        KERNEL.known(pair, {'application', 'gateway'}, {'application', 'gateway'})
        role = pair['application']
        fields = {'name', 'uid', 'primary_group', 'primary_gid', 'shell', 'shared_groups', 'entry_point'}
        KERNEL.known(role, fields, fields)
        selected = settings['applications'][app]
        expected = {'name': role['name'], 'uid': role['uid'], 'gid': role['primary_gid'], 'shell': role['shell']}
        if (role['name'] != selected['role'] or role['primary_group'] != selected['role'] or
            not 100 <= KERNEL.uint(role['uid'], 0x7fffffff) <= 999 or
            not 100 <= KERNEL.uint(role['primary_gid'], 0x7fffffff) <= 999 or
            role['shell'] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false') or
            PG.canonical(postgres['accounts'][app]) != PG.canonical(expected) or
            role['entry_point'] != identities['releases']['applications'][app]['entry_points']['application']):
            raise Pending('PostgreSQL peer role differs from the admitted application execution identity')
        result[app] = {'execution_role': 'application', 'user': role['name'],
            'uid': role['uid'], 'primary_gid': role['primary_gid'], 'shell': role['shell'],
            'entry_point': role['entry_point'], 'database': selected['database'],
            'connection_limit': selected['connection_limit'],
            'connection_intention': plan['connections'][app]}
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited application/PG join window')
        end = min(end, deadline)
    PG.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing application/PG caller namespace')
    identity_raw, identities = prepared(IDENTITIES, end, context)
    pg_raw, postgres = prepared(PG, end, context)
    selected = bindings(identities, postgres)
    payload = PG.canonical({'schema': 1, 'profile': 'application-postgresql-peer-role-files-v1',
        'state': 'protected-application-postgresql-role-intention-only', 'namespace': context,
        'identities': identities, 'postgresql': postgres, 'role_bindings': selected,
        'identity_sha256': hashlib.sha256(identity_raw).hexdigest(),
        'postgresql_sha256': hashlib.sha256(pg_raw).hexdigest()})
    if len(payload) > MAX_OUTPUT:
        raise Pending('whole application/PG join exceeds its output bound')
    if prepared_bytes(IDENTITIES, end) != identity_raw:
        raise Pending('complete protected application execution identities changed')
    if prepared_bytes(PG, end) != pg_raw:
        raise Pending('complete protected PostgreSQL intentions changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('application/PG caller namespace changed')
    PG.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('application/PG preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('application/PG preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete application/PG intention output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
