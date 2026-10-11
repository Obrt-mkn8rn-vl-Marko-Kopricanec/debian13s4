#!/usr/bin/python3
"""Compose known protected application FILE prerequisites, never app readiness.

Four-role release/account files, selected DNS unit and PG role intentions, and
selected Sava policy/key files are checked. Drava/Email runtime settings, native
credentials, runnable binaries, health, enrollment and installation stay open.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def owned(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DNS = owned('debian13s4_application_dns_files', 'dns_service.py')
PG = owned('debian13s4_application_pg_files', 'postgresql_identity.py')
SAVA = owned('debian13s4_application_sava_files', 'sava_transport.py')
BASE, KERNEL, Pending = DNS.BASE, DNS.KERNEL, DNS.Pending
MAX_OUTPUT = 16777217
ATTEMPT_SECONDS = 1760
CHILDREN = (
    ('dns', DNS, {'schema', 'profile', 'state', 'namespace', 'identities', 'dns_service',
        'unit_bindings', 'identity_sha256', 'dns_service_sha256'},
     'protected-dns-release-service-intention-v1', 'protected-dns-release-service-intention-only'),
    ('postgresql', PG, {'schema', 'profile', 'state', 'namespace', 'identities', 'postgresql',
        'role_bindings', 'identity_sha256', 'postgresql_sha256'},
     'application-postgresql-peer-role-files-v1', 'protected-application-postgresql-role-intention-only'),
    ('sava', SAVA, {'schema', 'profile', 'state', 'namespace', 'identities', 'identity_sha256', 'settings'},
     'sava-paired-transport-policy-files-v1', 'sava-split-transport-policy-source-only'))


def prepared_bytes(module, end):
    BASE.fence(end)
    try:
        raw = module.prepare(deadline=end)
    except module.Pending as error:
        raise Pending('application file prerequisite refused') from error
    if type(raw) is not bytes or len(raw) > module.MAX_OUTPUT:
        raise Pending('unsupported complete application file prerequisite bytes')
    BASE.fence(end)
    return raw


def prepared(child, end, context):
    tag, module, fields, profile, state = child
    raw = prepared_bytes(module, end)
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite prerequisite')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid application file prerequisite JSON') from error
    KERNEL.known(value, fields, fields)
    identity = value['identities']
    KERNEL.known(identity, DNS.IDENTITY_FIELDS, DNS.IDENTITY_FIELDS)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['profile'] != profile or value['state'] != state or
        KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
        type(identity['schema']) is not int or identity['schema'] != 1 or
        identity['profile'] != 'four-app-release-account-intention-v1' or
        identity['state'] != 'protected-application-execution-identity-source-only' or
        KERNEL.uint(identity['namespace'], 0xffffffffffffffff) != context or
        value['identity_sha256'] != hashlib.sha256(BASE.canonical(identity)).hexdigest() or
        raw != BASE.canonical(value)):
        raise Pending('application file prerequisite schema, identity, scope or canonical bytes differ')
    BASE.fence(end)
    return raw, value


def correspondence(values):
    """Whole reported identity correspondence, not native provenance or access."""
    identity = BASE.canonical(values['dns']['identities'])
    if any(BASE.canonical(values[tag]['identities']) != identity for tag in ('postgresql', 'sava')):
        raise Pending('complete application release/account prerequisites differ')
    dns = values['dns']; pg = values['postgresql']
    try:
        dns_roles = DNS.bindings(dns['identities'], dns['dns_service'])
        pg_roles = PG.bindings(pg['identities'], pg['postgresql'])
    except (DNS.Pending, PG.Pending, DNS.DNS.Pending) as error:
        raise Pending('application role prerequisite refused') from error
    if (BASE.canonical(dns['unit_bindings']) != BASE.canonical(dns_roles) or
        BASE.canonical(pg['role_bindings']) != BASE.canonical(pg_roles)):
        raise Pending('whole DNS or PostgreSQL role correspondence differs from its real renderer')
    unit, peer = dns['unit_bindings'][DNS.DNS.APP_UNIT], pg['role_bindings']['mk8.dns']
    left = {'user': unit['user'], 'uid': unit['uid'], 'primary_gid': unit['account_primary_gid'], 'entry_point': unit['entry_point']}
    right = {key: peer[key] for key in left}
    if BASE.canonical(left) != BASE.canonical(right):
        raise Pending('DNS application unit identity differs from the reserved PostgreSQL role intention')
    return {'dns_application_identity': left, 'dns_unit_group': unit['unit_group'],
        'dns_unit_gid': unit['unit_gid'], 'identity_sha256': hashlib.sha256(identity).hexdigest()}


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited application prerequisite window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing application prerequisite namespace')
    original, values = {}, {}
    for child in CHILDREN:
        raw, value = prepared(child, end, context)
        original[child[0]], values[child[0]] = raw, value
    joined = correspondence(values)
    payload = BASE.canonical({'schema': 1, 'profile': 'application-file-prerequisites-v1',
        'state': 'application-file-prerequisites-source-only', 'namespace': context,
        'components': values, 'component_sha256': {tag: hashlib.sha256(raw).hexdigest() for tag, raw in original.items()},
        'correspondence': joined})
    if len(payload) > MAX_OUTPUT:
        raise Pending('whole application file prerequisites exceed their output bound')
    for tag, module, _, _, _ in CHILDREN:
        if prepared_bytes(module, end) != original[tag]:
            raise Pending('complete application file prerequisite changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('application prerequisite namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('application file prerequisites accept no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('application file prerequisites require binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete application prerequisite output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
