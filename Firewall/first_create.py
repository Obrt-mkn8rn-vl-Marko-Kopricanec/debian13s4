#!/usr/bin/python3
"""Prepare a first-create nft transaction inside automatic empty admission.

This library has no CLI, store, executor or policy operation. Its opaque table
comment is a proposed correlation identifier, not authentication or retained
ownership. Native compatibility, persistence and delivery remain separate gates.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets

SPEC = importlib.util.spec_from_file_location('debian13s4_first_create_auto', Path(__file__).with_name('auto_intent.py'))
AUTO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTO)
ASSEMBLY, MANIFEST = AUTO.ASSEMBLY, AUTO.MANIFEST
ATTEMPT_SECONDS = 60
MAX_OUTPUT = 2 * AUTO.MAX_OUTPUT + 4096
COMMENT_PREFIX = 'debian13s4-first-create-v1-'


def prepare(deadline=None, **readers):
    if set(readers) - AUTO.READERS or any(not callable(reader) for reader in readers.values()):
        raise ASSEMBLY.Pending('unsupported first-create intention reader')
    kernel = ASSEMBLY.KERNEL
    start = kernel.now()
    if deadline is not None and (not kernel.finite_deadline(deadline) or deadline <= start):
        raise ASSEMBLY.Pending('invalid first-create intention deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = kernel.uint(kernel.namespace(), (1 << 64) - 1)
    if not namespace:raise ASSEMBLY.Pending('invalid first-create intention namespace')
    identifier = secrets.token_hex(32)
    if type(identifier) is not str or re.fullmatch(r'[0-9a-f]{64}', identifier) is None:
        raise ASSEMBLY.Pending('invalid generated first-create correlation identifier')
    if kernel.now() >= end:raise ASSEMBLY.Pending('first-create identifier preparation expired')
    payload, transaction = None, None

    def compile_intention(raw):
        nonlocal payload, transaction
        if payload is not None or kernel.now() >= end:
            raise ASSEMBLY.Pending('repeated or expired first-create intention preparation')
        intention = MANIFEST.expected(raw)
        text = ASSEMBLY.POLICY.compile_policy(raw)
        if intention['compiler_sha256'] != hashlib.sha256(text.encode('utf-8')).hexdigest() or \
                intention['topology_sha256'] != hashlib.sha256(raw).hexdigest():
            raise ASSEMBLY.Pending('first-create compiler intention identity disagrees')
        prefix = 'destroy table inet debian13s4\ntable inet debian13s4 {\n'
        if not text.startswith(prefix) or not text.endswith('}\n'):
            raise ASSEMBLY.Pending('unsupported first-create compiler transaction frame')
        # Keep the complete compiler body verbatim. Only the destructive outer
        # frame becomes an exclusive create, plus one grammar-bounded comment.
        transaction = 'create table inet debian13s4 {\n    comment "' + COMMENT_PREFIX + identifier + '"\n' + text[len(prefix):]
        if len(transaction.encode('utf-8')) > ASSEMBLY.POLICY.MAX_OUTPUT:
            raise ASSEMBLY.Pending('first-create transaction exceeds compiler output bound')
        record = {'schema': 'debian13s4-automatic-nft-first-create-1',
                  'state': 'prepared-first-create-intention', 'namespace': namespace,
                  'profile': 'automatic-empty-source-first-create-intention-1', 'admission_profile': AUTO.ADMISSION,
                  'correlation_id': identifier, 'topology': json.loads(raw), 'intention': intention,
                  'transaction': transaction, 'transaction_sha256': hashlib.sha256(transaction.encode('utf-8')).hexdigest()}
        # The entire immutable plan precedes unchanged final source/lease/time
        # barriers. A future caller must not treat these bytes as live authority.
        payload = MANIFEST.STATE.encoded(record) + b'\n'
        if len(payload) > MAX_OUTPUT or kernel.now() >= end:
            raise ASSEMBLY.Pending('first-create intention payload is oversized or expired')
        return transaction

    prepared = ASSEMBLY.observe(compiler=compile_intention, deadline=end, **readers)
    if payload is None or prepared['schema'] != 'debian13s4-assembled-policy-1' or prepared['profile'] != AUTO.ADMISSION:
        raise ASSEMBLY.Pending('first-create intention lacks the complete empty preparation profile')
    if type(prepared['namespace']) is not int or prepared['namespace'] != namespace or prepared['policy'] is not transaction:
        raise ASSEMBLY.Pending('first-create preparation identity changed')
    last = kernel.namespace()
    if type(last) is not int or last != namespace or kernel.now() >= end:
        raise ASSEMBLY.Pending('first-create intention context changed or expired')
    return payload
