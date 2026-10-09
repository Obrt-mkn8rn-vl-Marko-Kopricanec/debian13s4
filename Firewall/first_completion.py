#!/usr/bin/python3
"""Preserve a checked first-create transport receipt as historical data.

Library only: no CLI, current observer, submission, retry or installer path.
A caller can forge receipt bytes: structure and integrity do not attest native
origin, application, enforcement, ownership, freshness or physical persistence.
Recording failure may leave visible history and never authorizes resubmission.
"""

import hashlib
import importlib.util
from pathlib import Path
import stat


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


TRANSPORT = module('debian13s4_completion_transport', 'first_transport.py')
_STORAGE = module('debian13s4_completion_storage', 'proposal_store.py')
MATCH, STATE, KERNEL, Pending = TRANSPORT.MATCH, TRANSPORT.STATE, TRANSPORT.KERNEL, TRANSPORT.Pending
LEAF = 'first-completion.json'
MAX_RECORD = 2 * (MATCH.PLAN.MAX_OUTPUT + TRANSPORT.MAX_RECEIPT) + 4096
MAX_BYTES = 2 * MAX_RECORD + 4096
ATTEMPT_SECONDS = _STORAGE.ATTEMPT_SECONDS


def encoded(value):
    try:return STATE.encoded(value) + b'\n'
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid historical completion encoding') from error


def receipt(payload, raw):
    """Validate a supplied canonical receipt without querying current state."""
    value = _STORAGE.decoded(raw, TRANSPORT.MAX_RECEIPT)
    fields = {'schema', 'state', 'profile', 'namespace', 'proposal_sha256',
              'correlation_id', 'transaction_sha256', 'input_bytes', 'source'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-first-create-native-transport-1' or \
            value['state'] != 'native-zero-exit-empty-capture' or \
            value['profile'] != 'checked-historical-first-create-batch-1':
        raise Pending('unsupported historical transport completion receipt')
    plan = MATCH.checked(payload)
    if type(value['namespace']) is not int or value['namespace'] != plan['namespace'] or \
            value['proposal_sha256'] != hashlib.sha256(payload).hexdigest() or \
            value['correlation_id'] != plan['correlation_id'] or \
            value['transaction_sha256'] != plan['transaction_sha256'] or \
            type(value['input_bytes']) is not int or value['input_bytes'] != len(plan['transaction'].encode('utf-8')):
        raise Pending('historical completion disagrees with the complete original intention')
    source = value['source']
    KERNEL.known(source, {'binary', 'argv', 'identity'}, {'binary', 'argv', 'identity'})
    if source['binary'] != str(TRANSPORT.BINARY) or type(source['argv']) is not list or \
            source['argv'] != list(TRANSPORT.COMMAND):
        raise Pending('unsupported historical completion command')
    identity = source['identity']
    if type(identity) is not list or len(identity) != 8:
        raise Pending('unsupported historical executable identity')
    for item, bits in zip(identity[:6], (64, 64, 32, 32, 32, 63)):
        KERNEL.uint(item, (1 << bits) - 1)
    for item in identity[6:]:
        if type(item) is not int or not -(1 << 63) <= item < (1 << 63):
            raise Pending('unsupported historical executable timestamp')
    if not identity[1] or not stat.S_ISREG(identity[2]) or not identity[2] & 0o100 or \
            identity[2] & 0o022 or identity[3] != KERNEL.TRUSTED_UID:
        raise Pending('unsupported historical executable kind, owner or permissions')
    if raw != encoded(value):raise Pending('historical completion receipt is not canonical UTF8 plus LF')
    return value


def capture(payload, completion):
    """Keep the WHOLE original immutable bytes; no native-origin attestation."""
    receipt(payload, completion)
    raw = encoded({'schema': 'debian13s4-first-create-completion-1',
        'state': 'historical-transport-receipt-only', 'proposal': payload.decode('utf-8'),
        'proposal_sha256': hashlib.sha256(payload).hexdigest(), 'receipt': completion.decode('utf-8'),
        'receipt_sha256': hashlib.sha256(completion).hexdigest()})
    checked(raw)
    return raw


def checked(raw):
    value = _STORAGE.decoded(raw, MAX_RECORD)
    fields = {'schema', 'state', 'proposal', 'proposal_sha256', 'receipt', 'receipt_sha256'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-first-create-completion-1' or \
            value['state'] != 'historical-transport-receipt-only' or \
            type(value['proposal']) is not str or type(value['receipt']) is not str:
        raise Pending('unsupported historical completion record')
    try:payload, completion = value['proposal'].encode('utf-8'), value['receipt'].encode('utf-8')
    except UnicodeError as error:raise Pending('invalid historical completion bytes') from error
    receipt(payload, completion)
    if value['proposal_sha256'] != hashlib.sha256(payload).hexdigest() or \
            value['receipt_sha256'] != hashlib.sha256(completion).hexdigest() or raw != encoded(value):
        raise Pending('historical completion integrity or canonical bytes disagree')
    return value


def envelope(payload):
    checked(payload)
    raw = encoded({'schema': 'debian13s4-first-create-completion-history-1',
        'state': 'historical-transport-receipt-only', 'payload': payload.decode('utf-8'),
        'payload_sha256': hashlib.sha256(payload).hexdigest()})
    if len(raw) > MAX_BYTES:raise Pending('historical completion envelope exceeds bound')
    return raw


def stored(raw):
    value = _STORAGE.decoded(raw, MAX_BYTES)
    fields = {'schema', 'state', 'payload', 'payload_sha256'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-first-create-completion-history-1' or \
            value['state'] != 'historical-transport-receipt-only' or type(value['payload']) is not str:
        raise Pending('unsupported stored completion history')
    try:payload = value['payload'].encode('utf-8')
    except UnicodeError as error:raise Pending('invalid stored completion encoding') from error
    checked(payload)
    if value['payload_sha256'] != hashlib.sha256(payload).hexdigest() or raw != encoded(value):
        raise Pending('stored completion integrity or canonical bytes disagree')
    return payload


_STORAGE.LEAF, _STORAGE.MAX_BYTES = LEAF, MAX_BYTES
_STORAGE.envelope, _STORAGE.checked = envelope, stored


def record(path, payload, completion, deadline=None):
    """No-replace historical data; failure is never a reason to submit again."""
    end = _STORAGE.window(deadline)
    raw = capture(payload, completion)
    _STORAGE.admission(end)
    return _STORAGE.create(path, raw, deadline=end)


def load(path, deadline=None):
    """Load historical bytes without native observation or delivery permission."""
    return _STORAGE.load(path, deadline=deadline)
