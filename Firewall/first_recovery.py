#!/usr/bin/python3
"""Inspect registered uncertainty against marked nft SOURCE without resolving it.

Library only: no CLI, default paths, submission, storage mutation or controller.
Correspondence remains uncertain; it proves neither ownership nor causation,
fresh coexistence, enforcement or retry authority. Separate locked reads and
equal bytes do not establish continuous identity, atomicity or future state.
"""

import hashlib
import importlib.util
from pathlib import Path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


HISTORY = module('debian13s4_recovery_uncertainty', 'first_uncertainty.py')
AUDIT = module('debian13s4_recovery_registration_audit', 'first_audit.py')
REGISTER, MATCH, STATE = AUDIT.REGISTER, AUDIT.MATCH, AUDIT.STATE
KERNEL, Pending = AUDIT.KERNEL, AUDIT.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = 2 * (HISTORY.MAX_RECORD + AUDIT.MAX_OUTPUT) + 4096


def admission(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('uncertain first-create SOURCE inspection window expired or invalid')


def inspect(registration, uncertainty, query=STATE.NFT.native_query, scope=KERNEL.namespace, deadline=None):
    """Return historical correspondence bytes, NEVER resolved/retryable status."""
    if not callable(query) or not callable(scope):
        raise Pending('unsupported uncertain first-create SOURCE reader')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid uncertain first-create SOURCE inspection deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(scope(), (1 << 64) - 1)
    if not namespace:raise Pending('invalid uncertain first-create caller context')
    admission(end)
    original = HISTORY.load(uncertainty, deadline=end)
    history = HISTORY.checked(original)
    admission(end)
    payload = REGISTER.load(registration, deadline=end)
    plan = MATCH.checked(payload)
    if history['proposal'].encode('utf-8') != payload or plan['namespace'] != namespace:
        raise Pending('registered plan, uncertain input or current context disagree')
    admission(end)
    # The accepted audit owns two complete SOURCE comparisons and its own two
    # checked registration loads. No caller verifier/hash/health shortcut.
    raw = AUDIT.audit(registration, query=query, scope=scope, deadline=end)
    comparison = REGISTER._STORAGE.decoded(raw, AUDIT.MAX_OUTPUT)
    fields = {'schema', 'state', 'profile', 'namespace', 'correlation_id', 'proposal_sha256',
              'transaction_sha256', 'historical_admission_profile', 'comparison'}
    KERNEL.known(comparison, fields, fields)
    digest = hashlib.sha256(payload).hexdigest()
    if comparison['schema'] != 'debian13s4-registered-first-create-source-audit-1' or \
            comparison['state'] != 'historical-source-correspondence' or \
            comparison['profile'] != 'historical-registration-marked-source-correspondence-1' or \
            type(comparison['namespace']) is not int or comparison['namespace'] != namespace or \
            comparison['correlation_id'] != plan['correlation_id'] or comparison['proposal_sha256'] != digest or \
            comparison['transaction_sha256'] != plan['transaction_sha256'] or \
            comparison['historical_admission_profile'] != plan['admission_profile'] or \
            STATE.encoded(comparison['comparison']['intention']) != STATE.encoded(plan['intention']) or \
            raw != STATE.encoded(comparison) + b'\n':
        raise Pending('uncertain first-create registered SOURCE comparison identity disagrees')
    # Preserve WHOLE canonical uncertainty and audit bytes BEFORE the final
    # real loads/context/window. Native exit zero still does not resolve it.
    output = STATE.encoded({'schema': 'debian13s4-first-create-uncertain-source-inspection-1',
        'state': 'uncertain-source-correspondence-only', 'profile': 'registered-uncertain-attempt-marked-source-1',
        'namespace': namespace, 'correlation_id': plan['correlation_id'], 'proposal_sha256': digest,
        'transaction_sha256': plan['transaction_sha256'], 'uncertainty_sha256': hashlib.sha256(original).hexdigest(),
        'uncertainty': original.decode('utf-8'), 'audit': raw.decode('utf-8')}) + b'\n'
    if len(output) > MAX_OUTPUT:raise Pending('uncertain first-create SOURCE receipt exceeds bound')
    admission(end)
    if HISTORY.load(uncertainty, deadline=end) != original:
        raise Pending('historical uncertainty bytes changed during SOURCE inspection')
    admission(end)
    if REGISTER.load(registration, deadline=end) != payload:
        raise Pending('historical registration bytes changed during SOURCE inspection')
    last = scope()
    if type(last) is not int or last != namespace:
        raise Pending('uncertain first-create caller context changed')
    admission(end)
    return output
