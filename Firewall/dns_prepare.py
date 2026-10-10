"""Prepare PARTIAL public-DNS intentions under automatic EMPTY SOURCE admission.

Protected settings/account files, reported static addresses and complete supported
infrastructure are sequential honest-base observations, not authenticated native
ownership, usable catalogs/listeners, full coexistence or delivery authority.
There is no CLI, publication, registration, executor, reset or retry path here.
Default readers WOULD perform native READS if invoked elsewhere; this checkpoint
authorizes only private delivery models. Admissions do not interrupt blocked work.
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


ASSEMBLY = module('debian13s4_dns_prepare_assembly', 'assemble.py')
MANIFEST = module('debian13s4_dns_prepare_manifest', 'dns_manifest.py')
COMPILER, KERNEL = MANIFEST.COMPILER, ASSEMBLY.KERNEL
DNS, Pending = COMPILER.DNS, KERNEL.Pending
READERS = {'dhcp', 'dns', 'ntp', 'nft', 'legacy', 'classifiers', 'bpf', 'bpf_links', 'kernel'}
ADMISSION = 'nft-legacy-proc-tc-fq-bpf-program-link-id-empty-networkd-classic-timesyncd-no-dhcp6-1'
ATTEMPT_SECONDS = 60
KERNEL_SECONDS = 10
MAX_OUTPUT = 4194305


def fence(end, namespace):
    current = KERNEL.namespace()
    if type(current) is not int or current != namespace or KERNEL.now() >= end:
        raise Pending('DNS preparation context changed or admission expired')


def kernel_pair(query, end, namespace):
    """Retain two complete byte-equal raw inventories, including ancillary facts.

This deliberately strict profile may refuse changing unrelated lifetimes or
metadata. Equal samples do not exclude ABA, concurrent changes or future drift.
"""
    limit = min(end, KERNEL.now() + KERNEL_SECONDS)
    frames = []
    for _ in range(2):
        data = {}
        for name in KERNEL.COMMANDS:
            fence(limit, namespace)
            data[name] = ASSEMBLY.snapshot(query(name, deadline=limit))
            fence(limit, namespace)
        raw = DNS.BASE.canonical({'schema': 1, 'namespace': namespace, 'snapshot': data})
        if len(raw) > COMPILER.MAX_KERNEL:
            raise Pending('complete DNS kernel frame exceeds its byte bound')
        # Validate both complete ten-query inventories through the real parser.
        COMPILER.KERNEL.normalize(data)
        fence(limit, namespace)
        frames.append(raw)
    if frames[0] != frames[1]:
        raise Pending('complete DNS kernel inventories changed between samples')
    return frames[1]


def _intention(record):
    return DNS.BASE.canonical(record), record['intention']['compiler']['policy']


def _prepare(builder, deadline=None, **readers):
    """Internal receipt/framing join; public entries own their builders.

This is trusted in-process reuse, not isolation from arbitrary Python callers.
The public prepare interface admits only the declared reader deliveries.
"""
    if not callable(builder):
        raise Pending('unsupported internal public-DNS intention builder')
    if set(readers) - READERS or any(not callable(reader) for reader in readers.values()):
        raise Pending('unsupported public-DNS preparation delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited public-DNS preparation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(KERNEL.namespace(), (1 << 64) - 1)
    if not namespace:
        raise Pending('missing public-DNS preparation namespace')
    fence(end, namespace)
    original = DNS.prepare(deadline=end, scope=KERNEL.namespace)
    service = json.loads(original)
    if type(service['namespace']) is not int or service['namespace'] != namespace:
        raise Pending('DNS service and preparation contexts disagree')
    raw_dns = DNS.BASE.canonical(service['configuration']['value'])
    fence(end, namespace)
    query = readers.pop('kernel', KERNEL.native_query)
    payload, text = None, None

    def compile_intention(raw_topology):
        nonlocal payload, text
        if payload is not None:
            raise Pending('repeated public-DNS compiler turn')
        fence(end, namespace)
        raw_kernel = kernel_pair(query, end, namespace)
        expected = MANIFEST.expected(raw_topology, raw_dns, raw_kernel)
        record = {'schema': 1,
            'profile': 'protected-static-public-dns-empty-source-preparation-v1',
            'state': 'prepared-public-dns-empty-source-intention-only',
            'namespace': namespace, 'admission_profile': ADMISSION,
            'service_intention': original.decode('ascii'),
            'service_sha256': hashlib.sha256(original).hexdigest(),
            'topology': raw_topology.decode('utf-8'),
            'dns_configuration': raw_dns.decode('ascii'),
            'kernel_snapshot': raw_kernel.decode('ascii'), 'intention': expected}
        payload, text = builder(record)
        if (type(payload) is not bytes or not payload or len(payload) > MAX_OUTPUT or
            type(text) is not str or not text or len(text.encode('utf-8')) > ASSEMBLY.POLICY.MAX_OUTPUT):
            raise Pending('complete public-DNS preparation receipt exceeds its immutable byte profile')
        fence(end, namespace)
        # All encoding/hashing and this second REAL protected service preparation
        # precede ASSEMBLY's unchanged final lease/NFT/Legacy/TC/program/link fences.
        if DNS.prepare(deadline=end, scope=KERNEL.namespace) != original:
            raise Pending('protected DNS service intention changed during preparation')
        fence(end, namespace)
        return text

    prepared = ASSEMBLY.observe(compiler=compile_intention, deadline=end, **readers)
    if (payload is None or prepared['schema'] != 'debian13s4-assembled-policy-1' or
        prepared['profile'] != ADMISSION or type(prepared['namespace']) is not int or
        prepared['namespace'] != namespace or prepared['policy'] is not text):
        raise Pending('public-DNS preparation lacks the same complete EMPTY SOURCE intention')
    fence(end, namespace)
    return payload


def prepare(deadline=None, **readers):
    if set(readers) - READERS or any(not callable(reader) for reader in readers.values()):
        raise Pending('unsupported public-DNS preparation delivery')
    return _prepare(_intention, deadline=deadline, **readers)
