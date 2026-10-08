#!/usr/bin/python3
"""Compare checked historical first-create registration with marked nft SOURCE.

There is no CLI, default path, registration creation or policy operation. Public
comment and complete representation correspondence do not prove ownership,
fresh admission or delivery. Separate locked loads and byte equality cannot
prove continuous inode identity, atomicity, or exclude ABA/future changes.
"""

import hashlib
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('debian13s4_first_audit_registration', Path(__file__).with_name('first_register.py'))
REGISTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGISTER)
MATCH, KERNEL, Pending = REGISTER.MATCH, REGISTER.KERNEL, REGISTER.Pending
STATE = MATCH.STATE
ATTEMPT_SECONDS = 10
MAX_OUTPUT = MATCH.MAX_OUTPUT + 4096


def admission(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('registered first-create SOURCE audit window expired or invalid')


def audit(path, query=STATE.NFT.native_query, scope=KERNEL.namespace, deadline=None):
    if not callable(query) or not callable(scope):
        raise Pending('unsupported registered first-create SOURCE reader')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid registered first-create SOURCE audit deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(scope(), (1 << 64) - 1)
    if not namespace:raise Pending('invalid registered first-create SOURCE caller context')
    admission(end)
    payload = REGISTER.load(path, deadline=end)
    plan = MATCH.checked(payload)
    if plan['namespace'] != namespace:
        raise Pending('historical first-create registration belongs to another caller context')
    admission(end)
    raw = MATCH.verify(payload, query=query, scope=scope, deadline=end)
    comparison = REGISTER._STORAGE.decoded(raw, MATCH.MAX_OUTPUT)
    fields = {'schema', 'state', 'profile', 'namespace', 'correlation_id', 'proposal_sha256',
              'transaction_sha256', 'intention', 'observation'}
    KERNEL.known(comparison, fields, fields)
    digest = hashlib.sha256(payload).hexdigest()
    if comparison['schema'] != 'debian13s4-first-create-source-match-1' or \
            comparison['state'] != 'source-correspondence-only' or \
            comparison['profile'] != 'historical-first-create-intention-marked-source-1' or \
            type(comparison['namespace']) is not int or comparison['namespace'] != namespace or \
            comparison['correlation_id'] != plan['correlation_id'] or comparison['proposal_sha256'] != digest or \
            comparison['transaction_sha256'] != plan['transaction_sha256'] or \
            STATE.encoded(comparison['intention']) != STATE.encoded(plan['intention']) or raw != STATE.encoded(comparison) + b'\n':
        raise Pending('registered first-create SOURCE comparison identity disagrees')
    # Complete immutable receipt preparation precedes the second REAL checked
    # registration load and final caller/time barriers. No work follows them.
    output = STATE.encoded({'schema': 'debian13s4-registered-first-create-source-audit-1',
        'state': 'historical-source-correspondence', 'profile': 'historical-registration-marked-source-correspondence-1',
        'namespace': namespace, 'correlation_id': plan['correlation_id'], 'proposal_sha256': digest,
        'transaction_sha256': plan['transaction_sha256'], 'historical_admission_profile': plan['admission_profile'],
        'comparison': comparison}) + b'\n'
    if len(output) > MAX_OUTPUT:raise Pending('registered first-create SOURCE audit receipt exceeds bound')
    admission(end)
    if REGISTER.load(path, deadline=end) != payload:
        raise Pending('historical first-create registration bytes changed during SOURCE audit')
    last = scope()
    if type(last) is not int or last != namespace:
        raise Pending('registered first-create SOURCE caller context changed')
    admission(end)
    return output
