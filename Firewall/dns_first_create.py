"""Prepare a PARTIAL public-DNS exclusive-create transaction intention.

Library only: no CLI, registration, storage, executor or installer join. The
public random marker is correlation data, not a credential, uniqueness proof,
ownership, delivery or retry authority. Native create/comment compatibility and
effective policy remain unverified. Default preparation would perform native
READS elsewhere; this checkpoint authorizes only private delivery models.
"""

import hashlib
import importlib.util
from pathlib import Path
import re
import secrets

SPEC = importlib.util.spec_from_file_location('debian13s4_dns_first_preparation',
    Path(__file__).with_name('dns_prepare.py'))
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)
KERNEL, Pending = PREPARE.KERNEL, PREPARE.Pending
MAX_OUTPUT = PREPARE.MAX_OUTPUT
COMMENT_PREFIX = 'debian13s4-dns-first-create-v1-'


def prepare(deadline=None, **readers):
    if set(readers) - PREPARE.READERS or any(not callable(reader) for reader in readers.values()):
        raise Pending('unsupported DNS first-create delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited DNS first-create deadline')
    end = min(deadline, start + PREPARE.ATTEMPT_SECONDS) if deadline is not None else start + PREPARE.ATTEMPT_SECONDS
    namespace = KERNEL.uint(KERNEL.namespace(), (1 << 64) - 1)
    if not namespace:
        raise Pending('missing DNS first-create namespace')
    identifier = secrets.token_hex(32)
    if type(identifier) is not str or re.fullmatch(r'[0-9a-f]{64}', identifier) is None:
        raise Pending('invalid generated DNS first-create correlation')
    PREPARE.fence(end, namespace)

    def build(record):
        if type(record['namespace']) is not int or record['namespace'] != namespace:
            raise Pending('DNS first-create preparation context disagrees')
        source = PREPARE.DNS.BASE.canonical(record)
        if len(source) > PREPARE.MAX_OUTPUT:
            raise Pending('DNS first-create source intention exceeds byte bound')
        original = record['intention']['compiler']['policy']
        prefix = 'destroy table inet debian13s4\ntable inet debian13s4 {\n'
        if type(original) is not str or not original.startswith(prefix) or not original.endswith('}\n'):
            raise Pending('unsupported public-DNS compiler transaction frame')
        transaction = ('create table inet debian13s4 {\n    comment "'+
            COMMENT_PREFIX+identifier+'"\n'+original[len(prefix):])
        data = transaction.encode('utf-8')
        if len(data) > PREPARE.ASSEMBLY.POLICY.MAX_OUTPUT:
            raise Pending('DNS first-create transaction exceeds compiler byte bound')
        payload = PREPARE.DNS.BASE.canonical({'schema': 'debian13s4-dns-first-create-1',
            'profile': 'protected-dns-empty-first-create-intention-v1',
            'state': 'prepared-dns-first-create-intention-only', 'namespace': namespace,
            'correlation_id': identifier, 'source_intention': source.decode('ascii'),
            'source_sha256': hashlib.sha256(source).hexdigest(),
            'transaction': transaction, 'transaction_sha256': hashlib.sha256(data).hexdigest()})
        if len(payload) > MAX_OUTPUT:
            raise Pending('complete DNS first-create intention exceeds byte bound')
        # This owned framing/encoding finishes BEFORE the second protected service
        # preparation and all unchanged final assembly lease/source/time fences.
        return payload, transaction

    return PREPARE._prepare(build, deadline=end, **readers)
