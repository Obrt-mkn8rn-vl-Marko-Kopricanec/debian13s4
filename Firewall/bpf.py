#!/usr/bin/python3
"""Observe the partial empty global registered BPF program-ID profile.

Only a zero-start BPF_PROG_GET_NEXT_ID lookup is issued; no program, map, link,
iterator, socket or mount is created. Registered legitimate programs also refuse.
This is neither all-BPF absence nor coexistence, packet or delivery authority.
The namespace is caller context, not a registry filter. Deadline checks cannot
interrupt a blocked in-process syscall; finite honest kernel IO is assumed.
"""

import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_bpf_kernel', Path(__file__).with_name('kernel.py'))
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending
COMMAND = 11  # Linux UAPI BPF_PROG_GET_NEXT_ID; no caller command or ID.
ATTR_BYTES = 12  # Through open_flags, matching the libbpf zeroed ID lookup.
ATTEMPT_SECONDS = 10
MAX_BYTES = 4096
SYSCALLS = {'x86_64': 321, 'aarch64': 280}


class IdFields(ctypes.Structure):
    _fields_ = [('start_id', ctypes.c_uint32), ('next_id', ctypes.c_uint32), ('open_flags', ctypes.c_uint32)]


class IdAttr(ctypes.Union):
    # union bpf_attr is eight-byte aligned. Only its first twelve bytes are sent.
    _fields_ = [('ids', IdFields), ('alignment', ctypes.c_uint64)]


def abi():
    machine = os.uname().machine
    if sys.platform != 'linux' or sys.byteorder != 'little' or machine not in SYSCALLS or \
            ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8 or \
            ctypes.sizeof(ctypes.c_int) != 4 or ctypes.sizeof(ctypes.c_uint32) != 4 or \
            ctypes.sizeof(IdFields) != ATTR_BYTES or ctypes.sizeof(IdAttr) != 16 or \
            ctypes.alignment(IdAttr) != 8 or \
            [getattr(IdFields, name).offset for name in ('start_id', 'next_id', 'open_flags')] != [0, 4, 8]:
        raise Pending('unsupported BPF ID syscall ABI')
    return {'interface': 'bpf-syscall', 'machine': machine, 'syscall': SYSCALLS[machine],
            'command': COMMAND, 'start_id': 0, 'attr_bytes': ATTR_BYTES}


def native_query(deadline):
    if not KERNEL.finite_deadline(deadline) or deadline <= KERNEL.now():
        raise Pending('invalid or expired BPF ID deadline')
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    source = abi()
    library = ctypes.CDLL(None, use_errno=True)
    lookup = library.syscall
    lookup.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    lookup.restype = ctypes.c_long
    attr = IdAttr()
    if ctypes.addressof(attr) % 8 or bytes(attr) != bytes(ctypes.sizeof(attr)):
        raise Pending('invalid zeroed BPF ID attribute')
    if KERNEL.now() >= end:
        raise Pending('BPF ID admission expired')
    ctypes.set_errno(0)
    result = lookup(ctypes.c_long(source['syscall']), ctypes.c_int(COMMAND),
                    ctypes.byref(attr), ctypes.c_uint(ATTR_BYTES))
    error = ctypes.get_errno()
    if KERNEL.now() >= end or abi() != source:
        raise Pending('BPF ID delivery expired or ABI changed')
    if type(result) is not int:
        raise Pending('unverifiable BPF ID result')
    if result == 0:
        # Even an unattached or legitimate program requires a different profile.
        raise Pending('registered BPF program or unverifiable successful ID lookup')
    if result != -1 or error != errno.ENOENT or bytes(attr) != bytes(ctypes.sizeof(attr)):
        # EPERM/ENOSYS/EINVAL/EINTR and every other error are NOT empty receipts.
        raise Pending('BPF ID lookup did not positively observe an empty registry')
    return {'source': source, 'result': -1, 'errno': errno.ENOENT, 'next_id': 0}


def checked_lookup(value):
    fields = {'source', 'result', 'errno', 'next_id'}
    KERNEL.known(value, fields, fields)
    source = value['source']
    KERNEL.known(source, {'interface', 'machine', 'syscall', 'command', 'start_id', 'attr_bytes'},
                 {'interface', 'machine', 'syscall', 'command', 'start_id', 'attr_bytes'})
    if source != abi() or any(type(source[key]) is not int for key in ('syscall', 'command', 'start_id', 'attr_bytes')) or \
            any(type(value[key]) is not int for key in ('result', 'errno', 'next_id')) or \
            value['result'] != -1 or value['errno'] != errno.ENOENT or value['next_id'] != 0:
        raise Pending('unverifiable empty BPF ID observation')
    return {'source': dict(source), 'result': -1, 'errno': errno.ENOENT, 'next_id': 0}


def validate_receipt(value):
    fields = {'schema', 'namespace', 'profile', 'lookup'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-bpf-program-id-empty-1' or \
            value['profile'] != 'global-program-id-zero-start-enoent-1' or \
            not KERNEL.uint(value['namespace'], (1 << 64) - 1):
        raise Pending('invalid BPF ID receipt')
    return {'schema': value['schema'], 'namespace': value['namespace'], 'profile': value['profile'],
            'lookup': checked_lookup(value['lookup'])}


def observe(query=native_query, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid BPF ID observation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = scope()
    if not KERNEL.uint(namespace, (1 << 64) - 1):
        raise Pending('invalid BPF ID observer namespace')
    records = []
    for _ in range(2):
        if KERNEL.now() >= end:
            raise Pending('BPF ID observation expired before lookup')
        records.append(checked_lookup(query(end)))
        if KERNEL.now() >= end:
            raise Pending('BPF ID observation expired after lookup')
    final_namespace = scope()
    if type(final_namespace) is not int or final_namespace != namespace or \
            records[0] != records[1] or KERNEL.now() >= end:
        raise Pending('BPF ID observations changed or expired')
    return validate_receipt({'schema': 'debian13s4-bpf-program-id-empty-1', 'namespace': namespace,
        'profile': 'global-program-id-zero-start-enoent-1', 'lookup': records[-1]})


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        sink = getattr(sys.stdout, 'buffer', None)
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('BPF ID receipt requires a binary output sink')
        payload = (json.dumps(observe(), sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')
        if len(payload) > MAX_BYTES:
            raise Pending('BPF ID output limit exceeded')
        written = sink.write(payload)
        if type(written) is not int or written != len(payload):
            raise Pending('BPF ID output was not fully written')
        sink.flush()
        return 0
    except (OSError, ValueError, AttributeError) as error:
        print(f'debian13s4 BPF program-ID preflight pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
