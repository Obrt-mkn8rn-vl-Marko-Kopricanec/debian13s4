"""Reprepare historical registered DNS intent under real protected EMPTY SOURCE.

Library only: no CLI/default directory, store mutation, entropy, executor or
installer join. Public correlation/hashes/context remain unauthenticated. Equal
separately locked history and sequential source reads do not prove ownership,
atomicity, future freshness/full coexistence or native delivery/retry authority.
Default readers WOULD perform native READS elsewhere, unauthorized here.
"""
import hashlib
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('debian13s4_dns_refresh_registration',
    Path(__file__).with_name('dns_first_register.py'))
REGISTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGISTER)
MATCH, PLAN = REGISTER.MATCH, REGISTER.MATCH.PLAN
PREPARE, KERNEL = PLAN.PREPARE, PLAN.PREPARE.KERNEL
Pending = PREPARE.Pending
ATTEMPT_SECONDS = PREPARE.ATTEMPT_SECONDS
MAX_OUTPUT = PREPARE.MAX_OUTPUT


def prepare(path, deadline=None, **readers):
    if set(readers) - PREPARE.READERS or any(not callable(reader) for reader in readers.values()):
        raise Pending('unsupported registered DNS preparation delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited registered DNS preparation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(KERNEL.namespace(), (1 << 64) - 1)
    if not namespace:
        raise Pending('missing registered DNS preparation context')
    PREPARE.fence(end, namespace)
    original = REGISTER.load(path, deadline=end)
    plan = MATCH.checked(original)
    if plan['namespace'] != namespace or KERNEL.now() >= end:
        raise Pending('historical DNS registration context differs or preparation expired')
    payload, transaction = None, None

    def build(record):
        nonlocal payload, transaction
        if payload is not None or KERNEL.now() >= end:
            raise Pending('repeated or expired registered DNS compiler turn')
        source = MATCH.encoded(record)
        if source != plan['source_intention'].encode('ascii'):
            raise Pending('whole current protected DNS source intention differs from registration')
        text = record['intention']['compiler']['policy']
        prefix = 'destroy table inet debian13s4\ntable inet debian13s4 {\n'
        if type(text) is not str or not text.startswith(prefix) or not text.endswith('}\n'):
            raise Pending('unsupported registered DNS compiler frame')
        transaction = ('create table inet debian13s4 {\n    comment "'+
            PLAN.COMMENT_PREFIX+plan['correlation_id']+'"\n'+text[len(prefix):])
        data = transaction.encode('utf-8')
        if (len(data) > PREPARE.ASSEMBLY.POLICY.MAX_OUTPUT or transaction != plan['transaction'] or
            hashlib.sha256(data).hexdigest() != plan['transaction_sha256'] or
            hashlib.sha256(source).hexdigest() != plan['source_sha256']):
            raise Pending('whole current DNS transaction or source bytes differ from registration')
        payload = MATCH.encoded({'schema': 'debian13s4-dns-first-refresh-1',
            'profile': 'registered-public-dns-first-create-empty-source-repreparation-v1',
            'state': 'reprepared-dns-empty-source-intention-only', 'namespace': namespace,
            'correlation_id': plan['correlation_id'], 'proposal': original.decode('ascii'),
            'proposal_sha256': hashlib.sha256(original).hexdigest(),
            'source_sha256': plan['source_sha256'], 'transaction_sha256': plan['transaction_sha256'],
            'admission_profile': PREPARE.ADMISSION})
        if len(payload) > MAX_OUTPUT or KERNEL.now() >= end:
            raise Pending('registered DNS receipt exceeds its byte or admission bound')
        # REAL locked/checksummed/recompiled history read finishes BEFORE the
        # second protected service preparation and all existing final fences.
        if REGISTER.load(path, deadline=end) != original or KERNEL.now() >= end:
            raise Pending('registered DNS bytes changed or preparation expired')
        return payload, transaction

    result = PREPARE._prepare(build, deadline=end, **readers)
    if payload is None or result is not payload:
        raise Pending('registered DNS preparation returned a different receipt object')
    PREPARE.fence(end, namespace)
    return payload
