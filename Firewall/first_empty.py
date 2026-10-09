#!/usr/bin/python3
"""Recheck registered uncertainty under automatic EMPTY SOURCE preparation.

Library only: no CLI, storage mutation, submission or recovery decision.
Empty point-in-time SOURCE cannot resolve an uncertain attempt, prove no
effects, ownership or full coexistence, or grant permission to resubmit.
Separate historical locks/reads remain non-atomic and future/ABA limited.
"""

import hashlib
import importlib.util
from pathlib import Path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


HISTORY = module('debian13s4_empty_uncertainty', 'first_uncertainty.py')
REGISTER = module('debian13s4_empty_registration', 'first_register.py')
MATCH = REGISTER.MATCH
PLAN, STATE = MATCH.PLAN, MATCH.STATE
ASSEMBLY, MANIFEST = PLAN.ASSEMBLY, PLAN.MANIFEST
ATTEMPT_SECONDS = 60
MAX_OUTPUT = 2 * (HISTORY.MAX_RECORD + PLAN.MAX_OUTPUT) + 8192


def prepare(registration, uncertainty, deadline=None, **readers):
    """Return checked EMPTY SOURCE intention bytes, never resolved/retry status."""
    if set(readers) - PLAN.AUTO.READERS or any(not callable(reader) for reader in readers.values()):
        raise ASSEMBLY.Pending('unsupported uncertain empty SOURCE preparation reader')
    kernel = ASSEMBLY.KERNEL
    start = kernel.now()
    if deadline is not None and (not kernel.finite_deadline(deadline) or deadline <= start):
        raise ASSEMBLY.Pending('invalid uncertain empty SOURCE preparation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = kernel.uint(kernel.namespace(), (1 << 64) - 1)
    if not namespace or kernel.now() >= end:
        raise ASSEMBLY.Pending('invalid or expired uncertain empty SOURCE caller context')
    original = HISTORY.load(uncertainty, deadline=end)
    history = HISTORY.checked(original)
    if kernel.now() >= end:raise ASSEMBLY.Pending('uncertain history preparation expired')
    proposal = REGISTER.load(registration, deadline=end)
    plan = MATCH.checked(proposal)
    if history['proposal'].encode('utf-8') != proposal or plan['namespace'] != namespace or kernel.now() >= end:
        raise ASSEMBLY.Pending('registered uncertainty input/context differs or preparation expired')
    payload, transaction = None, None

    def compile_intention(raw):
        nonlocal payload, transaction
        if payload is not None or kernel.now() >= end:
            raise ASSEMBLY.Pending('repeated or expired uncertain empty SOURCE compiler turn')
        intention = MANIFEST.expected(raw)
        text = ASSEMBLY.POLICY.compile_policy(raw)
        if raw != STATE.encoded(plan['topology']) or STATE.encoded(intention) != STATE.encoded(plan['intention']) or \
                intention['compiler_sha256'] != hashlib.sha256(text.encode('utf-8')).hexdigest() or \
                intention['topology_sha256'] != hashlib.sha256(raw).hexdigest():
            raise ASSEMBLY.Pending('current automatic input/intention differs from registered uncertainty')
        prefix = 'destroy table inet debian13s4\ntable inet debian13s4 {\n'
        if not text.startswith(prefix) or not text.endswith('}\n'):
            raise ASSEMBLY.Pending('unsupported uncertain empty SOURCE compiler frame')
        transaction = 'create table inet debian13s4 {\n    comment "' + PLAN.COMMENT_PREFIX + plan['correlation_id'] + '"\n' + text[len(prefix):]
        data = transaction.encode('utf-8')
        if len(data) > ASSEMBLY.POLICY.MAX_OUTPUT or transaction != plan['transaction'] or \
                hashlib.sha256(data).hexdigest() != plan['transaction_sha256']:
            raise ASSEMBLY.Pending('current transaction differs from registered uncertain input')
        payload = STATE.encoded({'schema': 'debian13s4-registered-uncertainty-empty-source-1',
            'state': 'uncertain-empty-source-intention-only', 'profile': 'registered-uncertainty-empty-source-repreparation-1',
            'namespace': namespace, 'correlation_id': plan['correlation_id'], 'admission_profile': PLAN.AUTO.ADMISSION,
            'proposal_sha256': hashlib.sha256(proposal).hexdigest(), 'transaction_sha256': plan['transaction_sha256'],
            'uncertainty_sha256': hashlib.sha256(original).hexdigest(),
            'proposal': proposal.decode('utf-8'), 'uncertainty': original.decode('utf-8')}) + b'\n'
        if len(payload) > MAX_OUTPUT or kernel.now() >= end:
            raise ASSEMBLY.Pending('uncertain empty SOURCE receipt oversized or expired')
        # Both second REAL loads must precede ASSEMBLY's final lease/source
        # fences. Their IO/compiler work cannot occur after preparer return.
        if HISTORY.load(uncertainty, deadline=end) != original or kernel.now() >= end:
            raise ASSEMBLY.Pending('uncertainty bytes changed or empty SOURCE preparation expired')
        if REGISTER.load(registration, deadline=end) != proposal or kernel.now() >= end:
            raise ASSEMBLY.Pending('registration bytes changed or empty SOURCE preparation expired')
        return transaction

    prepared = ASSEMBLY.observe(compiler=compile_intention, deadline=end, **readers)
    if payload is None or prepared['schema'] != 'debian13s4-assembled-policy-1' or prepared['profile'] != PLAN.AUTO.ADMISSION:
        raise ASSEMBLY.Pending('uncertain input lacks complete empty SOURCE preparation')
    if type(prepared['namespace']) is not int or prepared['namespace'] != namespace or prepared['policy'] is not transaction:
        raise ASSEMBLY.Pending('uncertain empty SOURCE preparation identity changed')
    last = kernel.namespace()
    if type(last) is not int or last != namespace or kernel.now() >= end:
        raise ASSEMBLY.Pending('uncertain empty SOURCE caller context changed or expired')
    return payload
