#!/usr/bin/python3
"""Compare an existing historical proposal with current nft SOURCE records.

This library has no CLI, default store, directory creation or policy operation.
A match means representation correspondence to checked history, not ownership,
fresh topology/lease admission, safe enforcement or permission to reconcile.
Sequential reads and byte equality do not prove atomicity or prevent ABA.
"""

import hashlib
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('debian13s4_audit_store', Path(__file__).with_name('proposal_store.py'))
STORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORE)
MANIFEST = STORE.MANIFEST
STATE, KERNEL, Pending = MANIFEST.STATE, MANIFEST.KERNEL, MANIFEST.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = STORE.AUTO.MAX_OUTPUT


def admission(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('historical SOURCE audit window expired or invalid')


def audit(path, query=STATE.NFT.native_query, scope=KERNEL.namespace, deadline=None):
    if not callable(query) or not callable(scope):
        raise Pending('unsupported historical SOURCE audit delivery adapter')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid historical SOURCE audit deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(scope(), (1 << 64) - 1)
    if not namespace:raise Pending('invalid historical SOURCE audit namespace')
    admission(end)
    # The real store loader checks canonical bytes and recomputes the complete
    # intention with the real compiler. No caller supplies an expected hash.
    payload = STORE.load(path, deadline=end)
    record = STORE.decoded(payload, STORE.AUTO.MAX_OUTPUT)
    if type(record['namespace']) is not int or record['namespace'] != namespace:
        raise Pending('historical proposal belongs to a different caller context')
    admission(end)
    topology = STATE.encoded(record['topology'])
    comparison = MANIFEST.verify(topology, query=query, scope=scope, deadline=end)
    if comparison['schema'] != 'debian13s4-nft-compiler-match-1' or \
            comparison['profile'] != 'numeric-static-compiler-source-1' or \
            type(comparison['namespace']) is not int or comparison['namespace'] != namespace:
        raise Pending('historical SOURCE comparison context disagrees')
    intended = {key: comparison[key] for key in record['intention']}
    if STATE.encoded(intended) != STATE.encoded(record['intention']):
        raise Pending('historical SOURCE comparison disagrees with checked intention')
    result = {'schema': 'debian13s4-historical-nft-source-audit-1',
              'profile': 'historical-proposal-compiler-source-correspondence-1',
              'state': 'historical-source-correspondence', 'namespace': namespace,
              'proposal_sha256': hashlib.sha256(payload).hexdigest(),
              'historical_admission_profile': record['admission_profile'], 'comparison': comparison}
    # Prepare the entire immutable receipt before the final store/context/time
    # fences. No post-fence hashing, compilation, copying or serialization.
    output = STATE.encoded(result) + b'\n'
    if len(output) > MAX_OUTPUT:raise Pending('historical SOURCE audit receipt exceeds bound')
    admission(end)
    if STORE.load(path, deadline=end) != payload:
        raise Pending('historical proposal bytes changed during SOURCE audit')
    last = scope()
    if type(last) is not int or last != namespace:
        raise Pending('historical SOURCE audit caller context changed')
    admission(end)
    return output
