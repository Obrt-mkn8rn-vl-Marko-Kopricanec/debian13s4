"""Compare a PARTIAL public-DNS intention with complete nft SOURCE data.

Matching unmarked reserved objects may be FOREIGN. This library supplies no
ownership, current topology/configuration/account/lease/coexistence admission,
registration, installation, delivery, retry, CLI or controller authority. The
default query would make native READS if invoked elsewhere; none is authorized
here. Trusted immutable modules and callable deliveries are not authentication
or hostile in-process isolation. Supplied kernel/context facts may be historical.
"""

import hashlib
import importlib.util
import json
from pathlib import Path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


COMPILER = module('debian13s4_dns_manifest_compiler', 'dns_policy.py')
BASE = module('debian13s4_dns_manifest_base', 'nft_manifest.py')
STATE, KERNEL, Pending = BASE.STATE, BASE.KERNEL, BASE.KERNEL.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = 2097153


def expected(raw_topology, raw_dns, raw_kernel):
    """Recompute the whole real compiler before using the closed translator."""
    payload = COMPILER.compile_intention(raw_topology, raw_dns, raw_kernel)
    intention = json.loads(payload)
    # Private independently loaded translator instance: the original BASE and
    # every accepted global/function remain untouched, including on exceptions.
    translator = module('debian13s4_dns_manifest_owned_translator', 'nft_manifest.py')
    text = intention['policy']

    def owned_compiler(raw):
        if type(raw) is not bytes or raw != raw_topology:
            raise Pending('DNS translator received a different topology')
        return text

    # This is an internally owned text-delivery adapter, not a caller compiler
    # or verdict/hash shortcut. It returns ONLY the real recomputed same text.
    translator.POLICY.compile_policy = owned_compiler
    translated = translator.expected(raw_topology)
    if (translated['compiler_sha256'] != intention['compiler_sha256'] or
        translated['topology_sha256'] != intention['topology_sha256'] or
        translated['compiler_sha256'] != hashlib.sha256(text.encode('utf-8')).hexdigest()):
        raise Pending('DNS compiler and complete translator identities disagree')
    return {'compiler': intention, 'nft_policy': translated['policy'],
        'nft_fingerprint': translated['fingerprint']}


def verify(raw_topology, raw_dns, raw_kernel, query=STATE.NFT.native_query,
           scope=KERNEL.namespace, deadline=None):
    if not callable(query) or not callable(scope):
        raise Pending('unsupported DNS SOURCE delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited DNS SOURCE deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = STATE.uint(scope())
    intention = expected(raw_topology, raw_dns, raw_kernel)
    if namespace != intention['compiler']['namespace'] or KERNEL.now() >= end:
        raise Pending('DNS intention caller context differs or preparation expired')
    observations = []
    for _ in range(2):
        if KERNEL.now() >= end:
            raise Pending('DNS SOURCE window expired before query')
        observation = STATE.project(query(end))
        policy = BASE.canonical_policy(observation['policy'])
        if STATE.encoded(policy) != STATE.encoded(intention['nft_policy']):
            raise Pending('whole nft SOURCE differs from the complete DNS intention')
        if KERNEL.now() >= end:
            raise Pending('DNS SOURCE window expired after query')
        observations.append(observation)
    stable = lambda row: STATE.encoded({key: value for key, value in row.items() if key != 'statistics'})
    if stable(observations[0]) != stable(observations[1]):
        raise Pending('complete nonstatistical DNS SOURCE facts changed')
    # All preparation/hashes/copy/encoding precede the FINAL real caller/time
    # fence. Only these immutable bytes return; no future/atomic stdout claim.
    payload = STATE.encoded({'schema': 'debian13s4-dns-source-match-1',
        'profile': 'static-reported-public-dns-intention-source-1',
        'state': 'dns-intention-source-correspondence-only', 'namespace': namespace,
        'intention': intention, 'observation': observations[-1]}) + b'\n'
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete DNS comparison receipt exceeds byte bound')
    last = scope()
    if type(last) is not int or last != namespace or KERNEL.now() >= end:
        raise Pending('DNS SOURCE caller context changed or window expired')
    return payload
