#!/usr/bin/python3
"""Reprepare registered first-create intent under automatic empty SOURCE admission.

This library has no CLI, default path, registration mutation or policy executor.
Public correlation remains unauthenticated. Equal history at two read points and
sequential SOURCE observations do not establish ownership, atomicity, future
freshness, full coexistence or permission to deliver the prepared transaction.
"""

import hashlib
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('debian13s4_first_refresh_registration', Path(__file__).with_name('first_register.py'))
REGISTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGISTER)
MATCH = REGISTER.MATCH
PLAN, STATE = MATCH.PLAN, MATCH.STATE
ASSEMBLY, MANIFEST = PLAN.ASSEMBLY, PLAN.MANIFEST
ATTEMPT_SECONDS = 60
MAX_OUTPUT = 2 * PLAN.MAX_OUTPUT + 4096


def prepare(path, deadline=None, **readers):
    if set(readers) - PLAN.AUTO.READERS or any(not callable(reader) for reader in readers.values()):
        raise ASSEMBLY.Pending('unsupported registered first-create preparation reader')
    kernel = ASSEMBLY.KERNEL
    start = kernel.now()
    if deadline is not None and (not kernel.finite_deadline(deadline) or deadline <= start):
        raise ASSEMBLY.Pending('invalid registered first-create preparation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = kernel.uint(kernel.namespace(), (1 << 64) - 1)
    if not namespace or kernel.now() >= end:
        raise ASSEMBLY.Pending('invalid or expired registered first-create preparation context')
    original = REGISTER.load(path, deadline=end)
    plan = MATCH.checked(original)
    if plan['namespace'] != namespace or kernel.now() >= end:
        raise ASSEMBLY.Pending('historical registration context differs or preparation expired')
    payload, transaction = None, None

    def compile_intention(raw):
        nonlocal payload, transaction
        if payload is not None or kernel.now() >= end:
            raise ASSEMBLY.Pending('repeated or expired registered first-create compiler turn')
        intention = MANIFEST.expected(raw)
        text = ASSEMBLY.POLICY.compile_policy(raw)
        if raw != STATE.encoded(plan['topology']) or STATE.encoded(intention) != STATE.encoded(plan['intention']) or \
                intention['compiler_sha256'] != hashlib.sha256(text.encode('utf-8')).hexdigest() or \
                intention['topology_sha256'] != hashlib.sha256(raw).hexdigest():
            raise ASSEMBLY.Pending('current automatic input or compiler intention differs from registration')
        prefix = 'destroy table inet debian13s4\ntable inet debian13s4 {\n'
        if not text.startswith(prefix) or not text.endswith('}\n'):
            raise ASSEMBLY.Pending('unsupported registered first-create compiler frame')
        transaction = 'create table inet debian13s4 {\n    comment "' + PLAN.COMMENT_PREFIX + plan['correlation_id'] + '"\n' + text[len(prefix):]
        data = transaction.encode('utf-8')
        if len(data) > ASSEMBLY.POLICY.MAX_OUTPUT or transaction != plan['transaction'] or \
                hashlib.sha256(data).hexdigest() != plan['transaction_sha256']:
            raise ASSEMBLY.Pending('current first-create transaction differs from registration')
        payload = STATE.encoded({'schema': 'debian13s4-registered-first-create-reprepare-1',
            'state': 'reprepared-source-intention', 'profile': 'registered-first-create-empty-source-repreparation-1',
            'namespace': namespace, 'correlation_id': plan['correlation_id'],
            'proposal_sha256': hashlib.sha256(original).hexdigest(), 'transaction_sha256': plan['transaction_sha256'],
            'admission_profile': PLAN.AUTO.ADMISSION, 'proposal': original.decode('utf-8')}) + b'\n'
        if len(payload) > MAX_OUTPUT or kernel.now() >= end:
            raise ASSEMBLY.Pending('registered first-create receipt is oversized or expired')
        # The second REAL load is inside the compiler turn: its validation/IO
        # must precede ASSEMBLY's unchanged FINAL lease/source/context fences.
        if REGISTER.load(path, deadline=end) != original or kernel.now() >= end:
            raise ASSEMBLY.Pending('registered first-create bytes changed or preparation expired')
        return transaction

    prepared = ASSEMBLY.observe(compiler=compile_intention, deadline=end, **readers)
    if payload is None or prepared['schema'] != 'debian13s4-assembled-policy-1' or prepared['profile'] != PLAN.AUTO.ADMISSION:
        raise ASSEMBLY.Pending('registered first-create lacks complete empty SOURCE preparation')
    if type(prepared['namespace']) is not int or prepared['namespace'] != namespace or prepared['policy'] is not transaction:
        raise ASSEMBLY.Pending('registered first-create preparation identity changed')
    last = kernel.namespace()
    if type(last) is not int or last != namespace or kernel.now() >= end:
        raise ASSEMBLY.Pending('registered first-create preparation context changed or expired')
    return payload
