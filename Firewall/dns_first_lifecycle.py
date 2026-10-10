#!/usr/bin/python3
"""Join a durable reservation, fresh empty admission and ONE DNS first submission.

Calling submit_once is explicitly MUTATING. This standalone library has no CLI,
default path, installer/controller join, reset or retry. Its partial admission
profile is unchanged; legitimate unsupported coexistence refuses. Public hashes,
markers, namespace and honest native delivery do not authenticate ownership.
The final result is SOURCE correspondence, not effective enforcement or readiness.
"""

import hashlib
import importlib.util
import os
from pathlib import Path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


REFRESH = module('debian13s4_dns_lifecycle_refresh', 'dns_first_refresh.py')
ATTEMPT = module('debian13s4_dns_lifecycle_attempt', 'dns_first_attempt.py')
UNCERTAINTY = module('debian13s4_dns_lifecycle_uncertainty', 'dns_first_uncertainty.py')
COMPLETION = module('debian13s4_dns_lifecycle_completion', 'dns_first_completion.py')
TRANSPORT = UNCERTAINTY.TRANSPORT  # preserve the EXACT class consumed by record()
REGISTER, MATCH, STATE = REFRESH.REGISTER, REFRESH.MATCH, REFRESH.MATCH.STATE
KERNEL, Pending = REFRESH.KERNEL, REFRESH.Pending
ATTEMPT_SECONDS = 90
MAX_OUTPUT = REFRESH.MAX_OUTPUT + MATCH.MAX_OUTPUT + TRANSPORT.MAX_RECEIPT + 4096


class Blocked(RuntimeError):
    """The reserved slot remains closed even when history recording fails."""

    def __init__(self, reason, proposal, reservation, completion=None, history_error=None):
        super().__init__(reason)
        self.proposal, self.reservation = proposal, reservation
        self.completion, self.history_error = completion, history_error


def admission(end, namespace):
    current = KERNEL.namespace()
    if type(current) is not int or current != namespace or not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('first-create lifecycle caller context or window changed')


def fresh_receipt(raw, payload, plan):
    value = REGISTER._STORAGE.decoded(raw, REFRESH.MAX_OUTPUT)
    fields = {'schema', 'state', 'profile', 'namespace', 'correlation_id', 'proposal_sha256',
              'transaction_sha256', 'source_sha256', 'admission_profile', 'proposal'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-dns-first-refresh-1' or \
            value['state'] != 'reprepared-dns-empty-source-intention-only' or \
            value['profile'] != 'registered-public-dns-first-create-empty-source-repreparation-v1' or \
            type(value['namespace']) is not int or value['namespace'] != plan['namespace'] or \
            value['correlation_id'] != plan['correlation_id'] or \
            value['proposal_sha256'] != hashlib.sha256(payload).hexdigest() or \
            value['transaction_sha256'] != plan['transaction_sha256'] or \
            value['source_sha256'] != plan['source_sha256'] or \
            value['admission_profile'] != REFRESH.PREPARE.ADMISSION or \
            value['proposal'] != payload.decode('utf-8') or raw != STATE.encoded(value) + b'\n':
        raise Pending('first-create lifecycle fresh admission disagrees with registration')
    return value


def outcomes_absent(path, deadline):
    """Existing outcome leaves forbid entry, even without a reservation slot.

    The protected cooperating-directory lock is shared with history storage.
    ENOENT is an honest-base observation, not proof of no previous effects.
    """
    backend = ATTEMPT._STORAGE
    end = backend.window(deadline)
    directory, before = backend.locked(path, end)
    try:
        for leaf in (UNCERTAINTY.LEAF, COMPLETION.LEAF):
            backend.admission(end)
            try:os.stat(leaf, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:continue
            raise Pending('existing DNS outcome history forbids another submission')
        backend.directory_matches(path, directory, before)
        backend.admission(end)
    finally:
        os.close(directory)


def submit_once(path, deadline=None, query=MATCH.STATE.NFT.native_query, **readers):
    """Reserve before admission; persist outcomes; never submit a second command."""
    if not callable(query) or set(readers) - REFRESH.PREPARE.READERS or any(not callable(reader) for reader in readers.values()):
        raise Pending('unsupported first-create lifecycle delivery adapter')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid first-create lifecycle deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(KERNEL.namespace(), (1 << 64) - 1)
    if not namespace:raise Pending('invalid first-create lifecycle context')
    admission(end, namespace)
    payload = REGISTER.load(path, deadline=end)
    plan = MATCH.checked(payload)
    if plan['namespace'] != namespace:raise Pending('registered first-create context differs')
    admission(end, namespace)
    # Even a pre-entry crash/refusal leaves this slot closed. No idempotent
    # create/recovery path can convert existing reservation bytes into permission.
    reservation = ATTEMPT.reserve(path, payload, deadline=end)
    completion = None
    try:
        outcomes_absent(path, end)
        admitted = fresh_receipt(REFRESH.prepare(path, deadline=end, **readers), payload, plan)
        outcomes_absent(path, end)
        admission(end, namespace)
        completion = TRANSPORT.transmit(payload, deadline=end)
        # Preserve the reported zero-exit receipt BEFORE post-entry queries.
        # Failed recording never promotes the transport result to success/retry.
        COMPLETION.record(path, payload, completion, deadline=end)
        transport = COMPLETION.receipt(payload, completion)
        admission(end, namespace)
        comparison = MATCH.verify(payload, query=query, scope=KERNEL.namespace, deadline=end)
        post = REGISTER._STORAGE.decoded(comparison, MATCH.MAX_OUTPUT)
        # MATCH.verify is the real closed whole-ruleset comparator, not a caller
        # health function. Keep its whole canonical output alongside the input.
        result = STATE.encoded({'schema': 'debian13s4-dns-first-create-lifecycle-1',
            'state': 'single-submission-source-correspondence-no-retry',
            'profile': 'registered-public-dns-first-create-single-submission-v1',
            'namespace': namespace, 'correlation_id': plan['correlation_id'],
            'proposal_sha256': hashlib.sha256(payload).hexdigest(),
            'transaction_sha256': plan['transaction_sha256'], 'source_sha256': plan['source_sha256'],
            'admission': admitted, 'transport': transport, 'comparison': post}) + b'\n'
        if len(result) > MAX_OUTPUT:raise Pending('first-create lifecycle result exceeds bound')
        # Finish all encoding before the final REAL checked reservation/history
        # loads and typed caller/window fence. These reads are sequential only.
        if ATTEMPT.load(path, deadline=end) != reservation or REGISTER.load(path, deadline=end) != payload:
            raise Pending('first-create lifecycle reservation or registration changed')
        admission(end, namespace)
        return result
    except TRANSPORT.Uncertain as error:
        history_error = None
        try:UNCERTAINTY.record(path, payload, error, deadline=end)
        except BaseException as failure:history_error = failure
        raise Blocked('first-create native outcome uncertain; reserved slot forbids automatic retry',
                      payload, reservation, history_error=history_error) from error
    except BaseException as error:
        raise Blocked('first-create lifecycle incomplete; reserved slot forbids automatic retry',
                      payload, reservation, completion=completion) from error
