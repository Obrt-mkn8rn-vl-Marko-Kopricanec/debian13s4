#!/usr/bin/python3
"""Compare a historical first-create intention with marked nft SOURCE data.

This library has no CLI, store, executor or installer path. A matching public
comment and complete representation do not authenticate origin or ownership,
freshen the stored topology, or grant policy delivery/reconciliation authority.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re

SPEC = importlib.util.spec_from_file_location('debian13s4_first_match_plan', Path(__file__).with_name('first_create.py'))
PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLAN)
MANIFEST, STATE = PLAN.MANIFEST, PLAN.MANIFEST.STATE
KERNEL, Pending = STATE.KERNEL, STATE.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = PLAN.MAX_OUTPUT


def checked(raw):
    """Recompute the entire canonical intention; hashes alone are not admission."""
    if type(raw) is not bytes or not raw or len(raw) > PLAN.MAX_OUTPUT:
        raise Pending('invalid first-create intention byte delivery')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
                           parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite first-create JSON')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid first-create intention JSON') from error
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop();count += 1
        if depth > 16 or count > STATE.MAX_NODES:
            raise Pending('first-create intention exceeds structure bounds')
        if type(item) is dict:
            if any(type(key) is not str for key in item):raise Pending('nonstring first-create intention key')
            stack.extend((child, depth + 1) for child in (*item.keys(), *item.values()))
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            try:
                if '\0' in item or len(item.encode('utf-8')) > PLAN.MAX_OUTPUT:raise Pending('invalid first-create string')
            except UnicodeError as error:raise Pending('invalid first-create encoding') from error
        elif type(item) is int:
            if item.bit_length() > 64:raise Pending('oversized first-create integer')
        elif item is not None and type(item) is not bool:
            raise Pending('unsupported first-create scalar')
    fields = {'schema', 'state', 'namespace', 'profile', 'admission_profile', 'correlation_id',
              'topology', 'intention', 'transaction', 'transaction_sha256'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-automatic-nft-first-create-1' or \
            value['state'] != 'prepared-first-create-intention' or \
            value['profile'] != 'automatic-empty-source-first-create-intention-1' or value['admission_profile'] != PLAN.AUTO.ADMISSION:
        raise Pending('unsupported first-create intention profile')
    STATE.uint(value['namespace'])
    identifier = value['correlation_id']
    if type(identifier) is not str or re.fullmatch(r'[0-9a-f]{64}', identifier) is None:
        raise Pending('invalid first-create correlation identifier')
    topology = STATE.encoded(value['topology'])
    expected = MANIFEST.expected(topology)
    original = PLAN.ASSEMBLY.POLICY.compile_policy(topology)
    prefix = 'destroy table inet debian13s4\ntable inet debian13s4 {\n'
    if not original.startswith(prefix) or not original.endswith('}\n') or \
            expected['compiler_sha256'] != hashlib.sha256(original.encode('utf-8')).hexdigest():
        raise Pending('unsupported first-create compiler frame or identity')
    transaction = 'create table inet debian13s4 {\n    comment "' + PLAN.COMMENT_PREFIX + identifier + '"\n' + original[len(prefix):]
    data = transaction.encode('utf-8')
    if len(data) > PLAN.ASSEMBLY.POLICY.MAX_OUTPUT or value['transaction'] != transaction or \
            value['transaction_sha256'] != hashlib.sha256(data).hexdigest() or \
            STATE.encoded(value['intention']) != STATE.encoded(expected):
        raise Pending('first-create intention disagrees with the complete real compiler output')
    if raw != STATE.encoded(value) + b'\n':raise Pending('first-create intention is not canonical UTF8 plus LF')
    return value


def project(value, comment):
    # Copy/bound the ENTIRE native delivery, including the comment, before
    # adapting just that positively checked field to the old closed projection.
    value = STATE.private(value)
    KERNEL.known(value, {'nftables'}, {'nftables'})
    tables = []
    for entry in KERNEL.rows(value['nftables'], STATE.MAX_OBJECTS):
        if 'table' in entry:
            row = entry['table']
            fields = {'family', 'name', 'handle', 'flags', 'comment'}
            KERNEL.known(row, fields, {'family', 'name', 'handle', 'comment'})
            if row['family'] != 'inet' or row['name'] != STATE.TABLE or type(row['comment']) is not str or row['comment'] != comment:
                raise Pending('foreign or mismatching first-create table comment')
            tables.append(row)
    if len(tables) != 1:raise Pending('missing or duplicate first-create table')
    del tables[0]['comment']
    return {'comment': comment, **STATE.project(value)}


def verify(payload, query=STATE.NFT.native_query, scope=KERNEL.namespace, deadline=None):
    if not callable(query) or not callable(scope):raise Pending('unsupported first-create source reader')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid first-create comparison deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    plan = checked(payload)
    namespace = STATE.uint(scope())
    if namespace != plan['namespace'] or KERNEL.now() >= end:
        raise Pending('first-create intention context differs or preparation expired')
    comment = PLAN.COMMENT_PREFIX + plan['correlation_id']
    observations = []
    for _ in range(2):
        if KERNEL.now() >= end:raise Pending('first-create comparison expired before read')
        observation = project(query(end), comment)
        intended = MANIFEST.canonical_policy(observation['policy'])
        if STATE.encoded(intended) != STATE.encoded(plan['intention']['policy']):
            raise Pending('marked nft SOURCE differs from the complete compiler intention')
        if KERNEL.now() >= end:raise Pending('first-create comparison expired after read')
        observations.append(observation)
    stable = lambda row: STATE.encoded({key: item for key, item in row.items() if key != 'statistics'})
    if stable(observations[0]) != stable(observations[1]):raise Pending('marked nft SOURCE facts changed')
    # Encode/hash before final context/time fences. Only immutable bytes return
    # after them; no claim of continuous identity, fresh lease or future stdout.
    receipt = STATE.encoded({'schema': 'debian13s4-first-create-source-match-1', 'state': 'source-correspondence-only',
        'profile': 'historical-first-create-intention-marked-source-1', 'namespace': namespace,
        'correlation_id': plan['correlation_id'], 'proposal_sha256': hashlib.sha256(payload).hexdigest(),
        'transaction_sha256': plan['transaction_sha256'], 'intention': plan['intention'], 'observation': observations[-1]}) + b'\n'
    if len(receipt) > MAX_OUTPUT:raise Pending('first-create comparison receipt exceeds byte bound')
    last = scope()
    if type(last) is not int or last != namespace or KERNEL.now() >= end:
        raise Pending('first-create comparison context changed or expired')
    return receipt
