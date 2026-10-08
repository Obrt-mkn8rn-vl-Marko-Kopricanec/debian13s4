#!/usr/bin/python3
"""Prepare expected nft SOURCE intent from the accepted automatic empty profile.

No topology/configuration or expected fingerprint is accepted from stdin/argv.
Intention is serialized inside the real preparer's compiler turn, before its
final source, lease and namespace checks. Empty nft admission remains mandatory;
this establishes neither ownership nor delivery/native enforcement authority.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


ASSEMBLY = module('debian13s4_auto_intent_assembly', 'assemble.py')
MANIFEST = module('debian13s4_auto_intent_manifest', 'nft_manifest.py')
ATTEMPT_SECONDS = 60
MAX_OUTPUT = 1048576
ADMISSION = 'nft-legacy-proc-tc-fq-bpf-program-link-id-empty-networkd-classic-timesyncd-no-dhcp6-1'
READERS = frozenset(('dhcp', 'dns', 'ntp', 'nft', 'legacy', 'classifiers', 'bpf', 'bpf_links'))


def prepare(deadline=None, **readers):
    if set(readers) - READERS or any(not callable(reader) for reader in readers.values()):
        raise ASSEMBLY.Pending('unsupported automatic intention reader')
    kernel = ASSEMBLY.KERNEL
    start = kernel.now()
    if deadline is not None and (not kernel.finite_deadline(deadline) or deadline <= start):
        raise ASSEMBLY.Pending('invalid automatic intention deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = kernel.uint(kernel.namespace(), (1 << 64) - 1)
    if not namespace:raise ASSEMBLY.Pending('invalid automatic intention namespace')
    payload, text = None, None

    def compile_intention(raw):
        nonlocal payload, text
        if payload is not None or kernel.now() >= end:
            raise ASSEMBLY.Pending('repeated or expired automatic intention preparation')
        intention = MANIFEST.expected(raw)
        text = ASSEMBLY.POLICY.compile_policy(raw)
        if intention['compiler_sha256'] != hashlib.sha256(text.encode('utf-8')).hexdigest() or \
                intention['topology_sha256'] != hashlib.sha256(raw).hexdigest():
            raise ASSEMBLY.Pending('automatic compiler intention identity disagrees')
        record = {'schema': 'debian13s4-automatic-nft-intent-1', 'namespace': namespace,
                  'profile': 'automatic-empty-source-compiler-intent-1', 'admission_profile': ADMISSION,
                  'topology': json.loads(raw), 'intention': intention}
        # All expensive preparation/publication encoding precedes ASSEMBLY's
        # unchanged postcompiler lease/source/namespace/time fences.
        payload = MANIFEST.STATE.encoded(record) + b'\n'
        if len(payload) > MAX_OUTPUT or kernel.now() >= end:
            raise ASSEMBLY.Pending('automatic intention payload is oversized or expired')
        return text

    prepared = ASSEMBLY.observe(compiler=compile_intention, deadline=end, **readers)
    if payload is None or prepared['schema'] != 'debian13s4-assembled-policy-1' or prepared['profile'] != ADMISSION:
        raise ASSEMBLY.Pending('automatic intention lacks the complete preparation profile')
    # The trusted unchanged preparer returns this exact immutable compiler
    # object. No hashing, copying or serialization follows its final fences.
    if type(prepared['namespace']) is not int or prepared['namespace'] != namespace or prepared['policy'] is not text:
        raise ASSEMBLY.Pending('automatic intention preparation identity changed')
    last = kernel.namespace()
    if type(last) is not int or last != namespace or kernel.now() >= end:
        raise ASSEMBLY.Pending('automatic intention context changed or expired')
    return payload


def main():
    if len(sys.argv) != 1:return 64
    try:
        sink = getattr(sys.stdout, 'buffer', None)
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise ASSEMBLY.Pending('automatic intention requires a binary output sink')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise ASSEMBLY.Pending('automatic intention output was not fully written')
        sink.flush();return 0
    except (OSError, ValueError, AttributeError, ASSEMBLY.KERNEL.subprocess.TimeoutExpired) as error:
        print(f'debian13s4 automatic nft intention pending: {error}', file=sys.stderr);return 75


if __name__ == '__main__':raise SystemExit(main())
