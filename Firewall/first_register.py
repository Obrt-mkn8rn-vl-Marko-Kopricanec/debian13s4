#!/usr/bin/python3
"""Register exact historical first-create intention bytes in private storage.

There is no CLI, default path, directory creation, observer or policy operation.
This records a public correlation and intention, not authenticated ownership,
fresh admission, delivery or power-loss proof. Honest private ancestry, finite
IO and cooperating directory locks are the inherited storage assumptions.
"""

import hashlib
import importlib.util
from pathlib import Path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


MATCH = module('debian13s4_first_registration_match', 'first_match.py')
# This instance has its OWN globals. Configure its closed storage primitives
# once at import; never patch another caller's store or switch a live policy.
_STORAGE = module('debian13s4_first_registration_storage', 'proposal_store.py')
KERNEL, Pending = _STORAGE.KERNEL, _STORAGE.Pending
LEAF = 'first-create.json'
MAX_BYTES = 2 * MATCH.PLAN.MAX_OUTPUT + 4096
ATTEMPT_SECONDS = _STORAGE.ATTEMPT_SECONDS


def envelope(payload):
    plan = MATCH.checked(payload)
    raw = MATCH.STATE.encoded({'schema': 'debian13s4-first-create-registration-1',
        'state': 'historical-first-create-intention', 'namespace': plan['namespace'],
        'correlation_id': plan['correlation_id'], 'transaction_sha256': plan['transaction_sha256'],
        'payload': payload.decode('utf-8'), 'payload_sha256': hashlib.sha256(payload).hexdigest()}) + b'\n'
    if len(raw) > MAX_BYTES:raise Pending('first-create registration exceeds byte bound')
    return raw


def checked(raw):
    value = _STORAGE.decoded(raw, MAX_BYTES)
    fields = {'schema', 'state', 'namespace', 'correlation_id', 'transaction_sha256', 'payload', 'payload_sha256'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-first-create-registration-1' or value['state'] != 'historical-first-create-intention':
        raise Pending('unsupported first-create registration state')
    if type(value['payload']) is not str:raise Pending('untyped first-create registration payload')
    payload = value['payload'].encode('utf-8')
    plan = MATCH.checked(payload)
    if type(value['namespace']) is not int or value['namespace'] != plan['namespace'] or \
            value['correlation_id'] != plan['correlation_id'] or value['transaction_sha256'] != plan['transaction_sha256'] or \
            value['payload_sha256'] != hashlib.sha256(payload).hexdigest() or raw != MATCH.STATE.encoded(value) + b'\n':
        raise Pending('first-create registration identity or canonical bytes disagree')
    return payload


_STORAGE.LEAF, _STORAGE.MAX_BYTES = LEAF, MAX_BYTES
_STORAGE.envelope, _STORAGE.checked = envelope, checked


def create(path, payload, deadline=None):
    """No-replace historical registration; success does not apply the transaction."""
    return _STORAGE.create(path, payload, deadline=deadline)


def load(path, deadline=None):
    """Return checked historical bytes without obtaining fresh source admission."""
    return _STORAGE.load(path, deadline=deadline)
