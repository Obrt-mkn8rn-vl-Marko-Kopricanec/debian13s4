#!/usr/bin/python3
"""Join protected release/account FILE intentions with the existing DNS profile.

No unit, account, binary, signed zone, process or socket is installed, adopted,
executed or authenticated. This preprovisioned replica SOURCE join supplies no
catalog, publisher, enrollment, native ownership, enforcement or readiness proof.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_dns_service_identities',
    Path(__file__).resolve().with_name('identities.py'))
IDENTITIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITIES)
SPEC = importlib.util.spec_from_file_location('debian13s4_dns_service_profile',
    Path(__file__).resolve().parents[1]/'DNS/prepare.py')
if not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_dns_service_profile',
        Path(__file__).resolve().parents[1]/'dns/prepare.py')
DNS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)
BASE, KERNEL, Pending = IDENTITIES.BASE, IDENTITIES.KERNEL, IDENTITIES.Pending
MAX_OUTPUT = 4194305
ATTEMPT_SECONDS = 290
PROFILE_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration',
    'user_source', 'group_source', 'accounts', 'plan', 'unit_sha256'}
IDENTITY_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration',
    'passwd_source', 'group_source', 'releases', 'release_sha256', 'execution_bindings'}


def prepared_bytes(module, end):
    if module is not IDENTITIES and module is not DNS:
        raise Pending('unsupported DNS service dependency')
    BASE.fence(end)
    try:
        raw = (module.prepare(deadline=end) if module is IDENTITIES else
            module.prepare(deadline=end, scope=module.KERNEL.namespace))
    except (IDENTITIES.Pending, DNS.Pending) as error:
        raise Pending('protected DNS service dependency refused') from error
    if type(raw) is not bytes or len(raw) > module.MAX_OUTPUT:
        raise Pending('unsupported complete service dependency bytes')
    BASE.fence(end)
    return raw


def prepared(module, end, context):
    raw = prepared_bytes(module, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite dependency JSON')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid service dependency JSON') from error
    fields, profile, state = ((IDENTITY_FIELDS, 'four-app-release-account-intention-v1',
        'protected-application-execution-identity-source-only') if module is IDENTITIES else
        (PROFILE_FIELDS, 'mk8-dns-preprovisioned-static-replica-intention-v1', 'dns-service-intention-only'))
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['profile'] != profile or value['state'] != state or
        KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
        raw != BASE.canonical(value)):
        raise Pending('service dependency schema, scope or canonical bytes differ')
    BASE.fence(end)
    return raw, value


def bindings(identities, service):
    """Cross-component correspondence; reported facts are not authentication."""
    for left, right in (('passwd_source', 'user_source'), ('group_source', 'group_source')):
        if BASE.canonical(identities[left]) != BASE.canonical(service[right]):
            raise Pending('DNS and application identities observed different account sources')
    settings = DNS.checked(service['configuration']['value'])
    KERNEL.known(identities['execution_bindings'], set(IDENTITIES.RELEASE.APPLICATIONS),
        set(IDENTITIES.RELEASE.APPLICATIONS))
    roles = identities['execution_bindings']['mk8.dns']
    KERNEL.known(roles, {'application', 'gateway'}, {'application', 'gateway'})
    KERNEL.known(service['accounts'], {'users', 'ipc_group'}, {'users', 'ipc_group'})
    pair = {settings['application_user'], settings['gateway_user']}
    KERNEL.known(service['accounts']['users'], pair, pair)
    ipc = service['accounts']['ipc_group']
    KERNEL.known(ipc, {'name', 'gid'}, {'name', 'gid'})
    if ipc['name'] != settings['ipc_group']:
        raise Pending('DNS IPC intention differs from its selected group')
    shared = {ipc['name']: KERNEL.uint(ipc['gid'], 0x7fffffff)}
    for role in ('application', 'gateway'):
        row = roles[role]
        fields = {'name', 'uid', 'primary_group', 'primary_gid', 'shell', 'shared_groups', 'entry_point'}
        KERNEL.known(row, fields, fields)
        if (not 100 <= KERNEL.uint(row['uid'], 0x7fffffff) <= 999 or
            not 100 <= KERNEL.uint(row['primary_gid'], 0x7fffffff) <= 999):
            raise Pending('unsupported admitted DNS role numeric identity')
        account = settings[role+'_user']
        reported = service['accounts']['users'][account]
        expected = {'uid': row['uid'], 'primary_gid': row['primary_gid'], 'shell': row['shell']}
        if (row['name'] != account or row['primary_group'] != account or
            row['entry_point'] != settings[role+'_binary'] or
            BASE.canonical(row['shared_groups']) != BASE.canonical(shared) or
            BASE.canonical(reported) != BASE.canonical(expected)):
            raise Pending('DNS unit role, executable or account/group facts differ from admitted release identities')
    plan = DNS.render(settings)
    hashes = {unit: hashlib.sha256(text.encode('ascii')).hexdigest() for unit, text in plan['units'].items()}
    if (BASE.canonical(service['plan']) != BASE.canonical(plan) or
        BASE.canonical(service['unit_sha256']) != BASE.canonical(hashes)):
        raise Pending('complete DNS unit intentions differ from the real profile renderer')
    result = {}
    for unit, argv in plan['argv'].items():
        role = 'application' if unit == DNS.APP_UNIT else 'gateway'
        row = roles[role]
        if argv[0] != row['entry_point']:
            raise Pending('DNS unit invocation differs from the admitted role entry')
        result[unit] = {'role': role, 'user': row['name'], 'uid': row['uid'],
            'account_primary_gid': row['primary_gid'], 'unit_group': ipc['name'],
            'unit_gid': ipc['gid'], 'entry_point': argv[0]}
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited DNS service preparation window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing DNS service caller namespace')
    identity_raw, identities = prepared(IDENTITIES, end, context)
    dns_raw, service = prepared(DNS, end, context)
    selected = bindings(identities, service)
    payload = BASE.canonical({'schema': 1, 'profile': 'protected-dns-release-service-intention-v1',
        'state': 'protected-dns-release-service-intention-only', 'namespace': context,
        'identities': identities, 'dns_service': service, 'unit_bindings': selected,
        'identity_sha256': hashlib.sha256(identity_raw).hexdigest(),
        'dns_service_sha256': hashlib.sha256(dns_raw).hexdigest()})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete DNS release/service intention exceeds its output bound')
    if prepared_bytes(IDENTITIES, end) != identity_raw:
        raise Pending('complete protected release/account identities changed')
    if prepared_bytes(DNS, end) != dns_raw:
        raise Pending('complete protected DNS service intentions changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('DNS release/service caller namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('DNS service preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('DNS service preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete DNS service intention publication')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
