#!/usr/bin/python3
"""Preserve checked historical uncertain first-create evidence in private storage.

No CLI, default path, transport call, registration mutation, source observation
or recovery operation exists here. Loading even a zero-exit record NEVER grants
retry, ownership, application or delivery authority. Sync/readback retains the
existing honest-ancestry/finite-IO assumptions, not physical power-loss proof.
"""

import hashlib
import importlib.util
from pathlib import Path
import re


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


TRANSPORT = module('debian13s4_uncertainty_transport', 'first_transport.py')
_STORAGE = module('debian13s4_uncertainty_storage', 'proposal_store.py')
MATCH, STATE = TRANSPORT.MATCH, TRANSPORT.STATE
KERNEL, Pending = TRANSPORT.KERNEL, TRANSPORT.Pending
LEAF = 'first-uncertain.json'
MAX_RECORD = 2 * MATCH.PLAN.MAX_OUTPUT + 6 * TRANSPORT.MAX_BYTES + 8192
MAX_BYTES = 2 * MAX_RECORD + 4096
ATTEMPT_SECONDS = _STORAGE.ATTEMPT_SECONDS


def encoded(value):
    try:return STATE.encoded(value) + b'\n'
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid historical uncertainty encoding') from error


def diagnostic(value):
    if type(value) is not list or len(value) != 2 or type(value[0]) is not str or \
            re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', value[0]) is None or \
            type(value[1]) is not str or len(value[1]) > 1024:
        raise Pending('unsupported historical uncertainty diagnostic')
    try:value[1].encode('utf-8')
    except UnicodeError as error:raise Pending('invalid uncertainty diagnostic UTF8') from error


def raw_hex(value, limit):
    if type(value) is not str or len(value) > 2 * limit or len(value) % 2 or \
            re.fullmatch(r'[0-9a-f]*', value) is None:
        raise Pending('invalid canonical uncertainty binary encoding')
    return bytes.fromhex(value)


def checked(raw):
    value = _STORAGE.decoded(raw, MAX_RECORD)
    fields = {'schema', 'state', 'proposal', 'cause', 'evidence'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-first-create-uncertainty-1' or \
            value['state'] != 'historical-uncertain-no-retry' or type(value['proposal']) is not str:
        raise Pending('unsupported historical uncertainty record')
    try:payload = value['proposal'].encode('utf-8')
    except UnicodeError as error:raise Pending('invalid historical uncertainty proposal encoding') from error
    plan = MATCH.checked(payload)
    diagnostic(value['cause'])
    row = value['evidence']
    fields = {'command', 'namespace', 'deadline', 'proposal_sha256', 'correlation_id', 'transaction_sha256',
              'input_hex', 'input_written', 'stdout_hex', 'stderr_hex', 'received', 'returncode', 'cleanup_errors'}
    KERNEL.known(row, fields, fields)
    if type(row['command']) is not list or row['command'] != [str(TRANSPORT.BINARY), *TRANSPORT.COMMAND] or \
            type(row['namespace']) is not int or row['namespace'] != plan['namespace'] or \
            not KERNEL.finite_deadline(row['deadline']) or row['deadline'] <= 0 or \
            row['proposal_sha256'] != hashlib.sha256(payload).hexdigest() or \
            row['correlation_id'] != plan['correlation_id'] or row['transaction_sha256'] != plan['transaction_sha256']:
        raise Pending('historical uncertainty context or complete intention disagrees')
    data = raw_hex(row['input_hex'], MATCH.PLAN.ASSEMBLY.POLICY.MAX_OUTPUT)
    if data != plan['transaction'].encode('utf-8') or type(row['input_written']) is not int or \
            not 0 <= row['input_written'] <= len(data):
        raise Pending('historical uncertainty input or reported count disagrees')
    KERNEL.known(row['received'], {'stdout', 'stderr'}, {'stdout', 'stderr'})
    for label in ('stdout', 'stderr'):
        capture = raw_hex(row[label + '_hex'], TRANSPORT.MAX_BYTES)
        count = row['received'][label]
        if type(count) is not int or not len(capture) <= count <= TRANSPORT.MAX_BYTES + 65536 or \
                (len(capture) < TRANSPORT.MAX_BYTES and count != len(capture)):
            raise Pending('historical uncertainty capture prefix or received count disagrees')
    if row['returncode'] is not None and (type(row['returncode']) is not int or not -(1 << 31) <= row['returncode'] < (1 << 31)):
        raise Pending('untyped historical uncertainty exit')
    if type(row['cleanup_errors']) is not list or len(row['cleanup_errors']) > 4:
        raise Pending('unsupported historical uncertainty cleanup inventory')
    for item in row['cleanup_errors']:diagnostic(item)
    if raw != encoded(value):raise Pending('historical uncertainty bytes are not canonical UTF8 plus LF')
    return value


def capture(payload, error):
    """Privately encode evidence; the exception and its facts are not attested."""
    if type(error) is not TRANSPORT.Uncertain or not isinstance(error.__cause__, BaseException):
        raise Pending('a transport uncertainty with an original cause is required')
    row = error.evidence
    fields = {'command', 'namespace', 'deadline', 'proposal_sha256', 'correlation_id', 'transaction_sha256',
              'input', 'input_written', 'stdout', 'stderr', 'received', 'returncode', 'cleanup_errors'}
    KERNEL.known(row, fields, fields)
    if type(payload) is not bytes or type(row['command']) is not tuple or type(row['cleanup_errors']) is not tuple or \
            any(type(row[label]) is not bytes for label in ('input', 'stdout', 'stderr')) or \
            any(type(item) is not tuple for item in row['cleanup_errors']):
        raise Pending('unsupported transport uncertainty delivery types')
    MATCH.checked(payload)
    if row['command'] != (str(TRANSPORT.BINARY), *TRANSPORT.COMMAND) or \
            len(row['input']) > MATCH.PLAN.ASSEMBLY.POLICY.MAX_OUTPUT or \
            any(len(row[label]) > TRANSPORT.MAX_BYTES for label in ('stdout', 'stderr')) or len(row['cleanup_errors']) > 4:
        raise Pending('transport uncertainty source or raw delivery exceeds bounds')
    cause = [type(error.__cause__).__name__, str(error.__cause__)[:1024]]
    diagnostic(cause)
    for item in row['cleanup_errors']:diagnostic(list(item))
    copied = {key: item for key, item in row.items() if key not in ('command', 'input', 'stdout', 'stderr', 'cleanup_errors')}
    copied.update(command=list(row['command']), input_hex=row['input'].hex(), stdout_hex=row['stdout'].hex(),
                  stderr_hex=row['stderr'].hex(), cleanup_errors=[list(item) for item in row['cleanup_errors']])
    try:proposal = payload.decode('utf-8')
    except UnicodeError as cause:raise Pending('invalid uncertainty proposal UTF8') from cause
    raw = encoded({'schema': 'debian13s4-first-create-uncertainty-1', 'state': 'historical-uncertain-no-retry',
        'proposal': proposal, 'cause': cause, 'evidence': copied})
    checked(raw)
    return raw


def envelope(payload):
    checked(payload)
    raw = encoded({'schema': 'debian13s4-first-create-uncertainty-history-1', 'state': 'historical-uncertain-no-retry',
        'payload': payload.decode('utf-8'), 'payload_sha256': hashlib.sha256(payload).hexdigest()})
    if len(raw) > MAX_BYTES:raise Pending('historical uncertainty envelope exceeds bound')
    return raw


def stored(raw):
    value = _STORAGE.decoded(raw, MAX_BYTES)
    fields = {'schema', 'state', 'payload', 'payload_sha256'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-first-create-uncertainty-history-1' or \
            value['state'] != 'historical-uncertain-no-retry' or type(value['payload']) is not str:
        raise Pending('unsupported stored historical uncertainty')
    try:payload = value['payload'].encode('utf-8')
    except UnicodeError as error:raise Pending('invalid stored historical uncertainty encoding') from error
    checked(payload)
    if value['payload_sha256'] != hashlib.sha256(payload).hexdigest() or raw != encoded(value):
        raise Pending('stored uncertainty integrity or canonical bytes disagree')
    return payload


_STORAGE.LEAF, _STORAGE.MAX_BYTES = LEAF, MAX_BYTES
_STORAGE.envelope, _STORAGE.checked = envelope, stored


def record(path, payload, error, deadline=None):
    """No-replace history; failure may leave visible data but never retry authority."""
    end = _STORAGE.window(deadline)
    raw = capture(payload, error)
    _STORAGE.admission(end)
    return _STORAGE.create(path, raw, deadline=end)


def load(path, deadline=None):
    """Return checked historical uncertainty without querying or resubmitting."""
    return _STORAGE.load(path, deadline=deadline)
