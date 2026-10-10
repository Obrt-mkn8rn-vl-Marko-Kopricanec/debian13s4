"""Check historical DNS first-create bytes and compare whole marked nft SOURCE.

Hash/marker/context/file-account claims are forgeable historical data, not
native origin, ownership, current configuration/coexistence or delivery/retry
permission. Complete passwd/group bytes are NOT retained by the source plan;
this checker validates reported selected facts/units, not the full inventory.
No CLI, store, mutation, adoption or installer join. Default verification WOULD
make native READS elsewhere; only private delivery models are authorized here.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PLAN = module('debian13s4_dns_first_match_plan', 'dns_first_create.py')
MARKED = module('debian13s4_dns_first_match_projector', 'first_match.py')
PREPARE = PLAN.PREPARE
MANIFEST, DNS = PREPARE.MANIFEST, PREPARE.DNS
COMPILER, STATE, KERNEL = MANIFEST.COMPILER, MANIFEST.STATE, MANIFEST.KERNEL
Pending = KERNEL.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = PLAN.MAX_OUTPUT
HEX = re.compile(r'[0-9a-f]{64}\Z')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return DNS.BASE.canonical(value)


def canonical(raw, maximum):
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise Pending('historical DNS record exceeds its immutable byte profile')
    value = COMPILER.decode(raw, maximum)
    if raw != encoded(value):
        raise Pending('DNS historical record requires canonical ASCII JSON plus LF')
    return value


def source_identity(value, maximum, private=False):
    """Validate reported identity shape only; never stat/read its claimed path."""
    KERNEL.known(value, {'path', 'identity', 'sha256'}, {'path', 'identity', 'sha256'})
    path, identity, sha = value['path'], value['identity'], value['sha256']
    if (type(path) is not str or not 1 <= len(path) <= 4096 or not path.startswith('/') or
        os.path.normpath(path) != path or any(not 32 <= ord(c) <= 126 for c in path) or
        type(sha) is not str or HEX.fullmatch(sha) is None or
        type(identity) is not list or len(identity) != 8):
        raise Pending('unsupported reported historical DNS source identity')
    for i, maximum_value in ((0, (1<<64)-1), (1, (1<<64)-1), (2, 0xffff),
        (3, 0xffffffff), (4, 0xffffffff), (5, maximum)):
        KERNEL.uint(identity[i], maximum_value)
    if (not identity[1] or not stat.S_ISREG(identity[2]) or identity[2] & 0o022 or
        private and stat.S_IMODE(identity[2]) != 0o600):
        raise Pending('unsupported reported historical DNS file shape')
    for timestamp in identity[6:]:
        if type(timestamp) is not int or not -(1<<63) <= timestamp < (1<<63):
            raise Pending('unsupported reported historical DNS timestamp')


def service_intention(raw, raw_dns, namespace):
    service = canonical(raw, DNS.MAX_OUTPUT)
    fields = {'schema', 'profile', 'state', 'namespace', 'configuration',
        'user_source', 'group_source', 'accounts', 'plan', 'unit_sha256'}
    KERNEL.known(service, fields, fields)
    if (type(service['schema']) is not int or service['schema'] != 1 or
        service['profile'] != 'mk8-dns-preprovisioned-static-replica-intention-v1' or
        service['state'] != 'dns-service-intention-only' or
        type(service['namespace']) is not int or service['namespace'] != namespace):
        raise Pending('unsupported historical DNS service profile or context')
    configuration = service['configuration']
    KERNEL.known(configuration, {'value', 'source'}, {'value', 'source'})
    settings = DNS.checked(configuration['value'])
    if encoded(settings) != raw_dns:
        raise Pending('historical DNS settings differ from compiler input')
    source_identity(configuration['source'], DNS.MAX_INPUT, True)
    if (configuration['source']['sha256'] != digest(raw_dns) or
        configuration['source']['identity'][5] != len(raw_dns)):
        raise Pending('reported configuration bytes disagree with historical intention')
    for key in ('user_source', 'group_source'):
        source_identity(service[key], DNS.MAX_INVENTORY)
    selected = service['accounts']
    KERNEL.known(selected, {'users', 'ipc_group'}, {'users', 'ipc_group'})
    names = {settings['application_user'], settings['gateway_user']}
    KERNEL.known(selected['users'], names, names)
    uids, primary = set(), set()
    for row in selected['users'].values():
        KERNEL.known(row, {'uid', 'primary_gid', 'shell'}, {'uid', 'primary_gid', 'shell'})
        uid, gid = KERNEL.uint(row['uid'], 999), KERNEL.uint(row['primary_gid'], 0x7fffffff)
        if (uid < 100 or not gid or uid in uids or gid in primary or
            row['shell'] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false')):
            raise Pending('unsupported reported historical DNS service account')
        uids.add(uid); primary.add(gid)
    ipc = selected['ipc_group']
    KERNEL.known(ipc, {'name', 'gid'}, {'name', 'gid'})
    gid = KERNEL.uint(ipc['gid'], 0x7fffffff)
    if ipc['name'] != settings['ipc_group'] or not gid or gid in primary:
        raise Pending('unsupported reported historical DNS IPC group')
    plan = DNS.render(settings)
    hashes = {name: digest(text.encode('ascii')) for name, text in plan['units'].items()}
    if encoded(service['plan']) != encoded(plan) or encoded(service['unit_sha256']) != encoded(hashes):
        raise Pending('whole historical DNS unit/argv intention differs from real rendering')
    return service


def _checked(raw):
    value = canonical(raw, PLAN.MAX_OUTPUT)
    fields = {'schema', 'profile', 'state', 'namespace', 'correlation_id',
        'source_intention', 'source_sha256', 'transaction', 'transaction_sha256'}
    KERNEL.known(value, fields, fields)
    if (value['schema'] != 'debian13s4-dns-first-create-1' or
        value['profile'] != 'protected-dns-empty-first-create-intention-v1' or
        value['state'] != 'prepared-dns-first-create-intention-only'):
        raise Pending('unsupported historical DNS first-create profile')
    namespace = STATE.uint(value['namespace'])
    identifier = value['correlation_id']
    if type(identifier) is not str or HEX.fullmatch(identifier) is None or type(value['source_intention']) is not str:
        raise Pending('unsupported historical DNS first-create correlation or source bytes')
    source_raw = value['source_intention'].encode('ascii')
    source = canonical(source_raw, PREPARE.MAX_OUTPUT)
    names = {'schema', 'profile', 'state', 'namespace', 'admission_profile',
        'service_intention', 'service_sha256', 'topology', 'dns_configuration', 'kernel_snapshot', 'intention'}
    KERNEL.known(source, names, names)
    if (type(source['schema']) is not int or source['schema'] != 1 or
        source['profile'] != 'protected-static-public-dns-empty-source-preparation-v1' or
        source['state'] != 'prepared-public-dns-empty-source-intention-only' or
        source['admission_profile'] != PREPARE.ADMISSION or
        type(source['namespace']) is not int or source['namespace'] != namespace or
        any(type(source[k]) is not str for k in ('service_intention', 'topology', 'dns_configuration', 'kernel_snapshot'))):
        raise Pending('unsupported complete historical DNS SOURCE preparation')
    raw_topology = source['topology'].encode('utf-8')
    raw_dns, raw_kernel = source['dns_configuration'].encode('ascii'), source['kernel_snapshot'].encode('ascii')
    topology = COMPILER.decode(raw_topology, COMPILER.POLICY.MAX_INPUT)
    if raw_topology != encoded(topology)[:-1] or raw_kernel != encoded(COMPILER.decode(raw_kernel, COMPILER.MAX_KERNEL)):
        raise Pending('historical DNS topology/kernel frames are not canonical')
    service_raw = source['service_intention'].encode('ascii')
    service_intention(service_raw, raw_dns, namespace)
    expected = MANIFEST.expected(raw_topology, raw_dns, raw_kernel)
    if expected['compiler']['namespace'] != namespace or encoded(source['intention']) != encoded(expected):
        raise Pending('whole historical DNS intention differs from real compiler/translator')
    original = expected['compiler']['policy']
    prefix = 'destroy table inet debian13s4\ntable inet debian13s4 {\n'
    if not original.startswith(prefix) or not original.endswith('}\n'):
        raise Pending('unsupported historical DNS compiler frame')
    transaction = 'create table inet debian13s4 {\n    comment "'+PLAN.COMMENT_PREFIX+identifier+'"\n'+original[len(prefix):]
    data = transaction.encode('utf-8')
    if (len(data) > PREPARE.ASSEMBLY.POLICY.MAX_OUTPUT or value['transaction'] != transaction or
        value['transaction_sha256'] != digest(data) or value['source_sha256'] != digest(source_raw) or
        source['service_sha256'] != digest(service_raw)):
        raise Pending('historical DNS first-create complete byte commitments disagree')
    return value, source


def checked(raw):
    """Pure complete historical shape/compiler checks, never fresh admission."""
    return _checked(raw)[0]


def verify(raw, query=STATE.NFT.native_query, scope=KERNEL.namespace, deadline=None):
    if not callable(query) or not callable(scope):
        raise Pending('unsupported DNS marked SOURCE delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited DNS marked comparison deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = STATE.uint(scope())
    plan, source = _checked(raw)
    if namespace != plan['namespace'] or KERNEL.now() >= end:
        raise Pending('historical DNS plan context differs or comparison expired')
    observations = []
    for _ in range(2):
        if KERNEL.now() >= end:
            raise Pending('DNS marked comparison expired before query')
        observation = MARKED.project(query(end), PLAN.COMMENT_PREFIX+plan['correlation_id'])
        policy = MANIFEST.BASE.canonical_policy(observation['policy'])
        if STATE.encoded(policy) != STATE.encoded(source['intention']['nft_policy']):
            raise Pending('whole marked nft SOURCE differs from complete DNS intention')
        if KERNEL.now() >= end:
            raise Pending('DNS marked comparison expired after query')
        observations.append(observation)
    stable = lambda row: STATE.encoded({k:v for k,v in row.items() if k != 'statistics'})
    if stable(observations[0]) != stable(observations[1]):
        raise Pending('complete nonstatistical DNS marked SOURCE facts changed')
    payload = encoded({'schema': 'debian13s4-dns-first-match-1',
        'profile': 'historical-protected-dns-first-create-marked-source-v1',
        'state': 'dns-first-create-source-correspondence-only', 'namespace': namespace,
        'correlation_id': plan['correlation_id'], 'proposal_sha256': digest(raw),
        'source_sha256': plan['source_sha256'], 'transaction_sha256': plan['transaction_sha256'],
        'intention': source['intention'], 'observation': observations[-1]})
    if len(payload) > MAX_OUTPUT:
        raise Pending('whole DNS marked comparison receipt exceeds byte bound')
    last = scope()
    if type(last) is not int or last != namespace or KERNEL.now() >= end:
        raise Pending('DNS marked comparison final context changed or expired')
    return payload
