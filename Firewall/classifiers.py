#!/usr/bin/python3
"""Observe only noqueue/fq_codel roots and empty fq_codel classifier dumps.

This is a partial source profile, not all-TC/eBPF absence or firewall authority.
It neither configures schedulers nor installs policy. Other layouts stay pending.
"""

import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_classifier_tc', Path(__file__).with_name('tc.py'))
TC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TC)
KERNEL = TC.KERNEL
Pending = KERNEL.Pending
BINARY = Path('/usr/sbin/tc')
QDISCS = ('-json', 'qdisc', 'show', 'invisible')
MAX_BYTES = TC.MAX_BYTES
LOCAL_SECONDS = 30
# Each of two rounds admits links, qdiscs and at most MAX_LINKS filter dumps.
# Include native failure cleanup; an inherited deadline is never extended.
ATTEMPT_SECONDS = 2 * (KERNEL.MAX_LINKS + 2) * (KERNEL.QUERY_SECONDS + KERNEL.CLEANUP_SECONDS) + LOCAL_SECONDS
HANDLE = re.compile(r'(?:0|[1-9a-f][0-9a-f]{0,3}):\Z')
FQ_REQUIRED = {'limit', 'flows', 'quantum', 'target', 'interval', 'memory_limit'}
FQ_OPTIONAL = {'ecn', 'drop_batch', 'ce_threshold', 'ce_threshold_selector', 'ce_threshold_mask'}


def native_query(operation, deadline, interface=None):
    if type(operation) is not str or operation not in ('qdiscs', 'filters'):
        raise Pending('unsupported classifier read operation')
    if operation == 'qdiscs':
        if interface is not None:
            raise Pending('qdisc dump must be unfiltered')
        command = QDISCS
    else:
        if type(interface) is not str or KERNEL.NAME.fullmatch(interface) is None:
            raise Pending('invalid classifier device name')
        # Deliberately omit root/parent/chain/protocol/preference/handle selectors.
        # With tcm_parent=0, Linux tc_dump_tfilter selects dev->qdisc and walks
        # every chain/protocol. An explicit root can miss a zero-handle root.
        command = ('-json', 'filter', 'show', 'dev', interface)
    if not KERNEL.finite_deadline(deadline) or deadline <= KERNEL.now():
        raise Pending('invalid or expired classifier read deadline')
    identity = KERNEL.trusted_binary(BINARY)
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    if KERNEL.now() >= end:
        raise Pending('classifier read admission expired')
    process = subprocess.Popen([str(BINARY), *command], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = end - KERNEL.now()
                if remaining <= 0:
                    raise Pending('classifier read timed out')
                for key, _ in selector.select(remaining):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending('classifier read output limit exceeded')
                    buffer.extend(data)
            remaining = end - KERNEL.now()
            if remaining <= 0 or process.wait(timeout=remaining) != 0 or buffers['stderr']:
                raise Pending('classifier read failed or warned')
        if KERNEL.trusted_binary(BINARY) != identity:
            raise Pending('classifier binary changed during read')
        if KERNEL.now() >= end:
            raise Pending('classifier read completed after its deadline')
        try:
            return json.loads(buffers['stdout'].decode('utf-8'), object_pairs_hook=KERNEL.unique_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Pending('invalid classifier read JSON') from error
    except subprocess.TimeoutExpired as error:
        raise Pending('classifier read timed out after pipe closure') from error
    finally:
        try:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            process.stdout.close()
            process.stderr.close()


def link_inventory(value):
    rows = KERNEL.rows(TC.snapshot(value), KERNEL.MAX_LINKS)
    if not rows:
        raise Pending('missing classifier link inventory')
    names, indexes = set(), set()
    for row in rows:
        KERNEL.known(row, KERNEL.LINK_KEYS, ('ifindex', 'ifname', 'flags', 'qdisc', 'link_type'))
        name, index = row['ifname'], KERNEL.uint(row['ifindex'], 0x7fffffff)
        if type(name) is not str or KERNEL.NAME.fullmatch(name) is None or name in names or not index or index in indexes:
            raise Pending('ambiguous classifier link identity')
        flags, kind = KERNEL.flags(row['flags']), KERNEL.link_type(row['link_type'])
        if not flags.issubset(KERNEL.LINK_FLAGS) or row['qdisc'] not in ('noqueue', 'fq_codel'):
            raise Pending('unsupported classifier link profile')
        if (name == 'lo') != (kind == 'loopback') or ('LOOPBACK' in flags) != (name == 'lo'):
            raise Pending('inconsistent classifier loopback identity')
        if name == 'lo' and row['qdisc'] != 'noqueue':
            raise Pending('unsupported loopback scheduler')
        names.add(name)
        indexes.add(index)
    if 'lo' not in names:
        raise Pending('incomplete classifier loopback inventory')
    return rows


def fq_options(value):
    KERNEL.known(value, FQ_REQUIRED | FQ_OPTIONAL, FQ_REQUIRED)
    for key in FQ_REQUIRED:
        KERNEL.uint(value[key])
    if not 1 <= value['flows'] <= 65536:
        raise Pending('invalid fq_codel flow count')
    if 'ecn' in value and value['ecn'] is not True:
        # Native formatting omits disabled ECN instead of printing false.
        raise Pending('invalid native fq_codel ECN flag')
    for key in ('drop_batch', 'ce_threshold'):
        if key in value:
            KERNEL.uint(value[key])
    if 'drop_batch' in value and not value['drop_batch']:
        raise Pending('invalid native fq_codel drop batch')
    pair = {'ce_threshold_selector', 'ce_threshold_mask'} & set(value)
    if pair:
        if pair != {'ce_threshold_selector', 'ce_threshold_mask'} or 'ce_threshold' not in value:
            raise Pending('incomplete fq_codel CE selector')
        for key in pair:
            KERNEL.uint(value[key], 255)
        if not (value['ce_threshold_selector'] or value['ce_threshold_mask']):
            raise Pending('non-native empty fq_codel CE selector')


def root_inventory(value, links):
    schedulers = {row['ifname']: row['qdisc'] for row in links}
    rows = KERNEL.rows(TC.snapshot(value), KERNEL.MAX_ITEMS)
    seen = set()
    for row in rows:
        required = {'kind', 'handle', 'dev', 'root', 'options'}
        KERNEL.known(row, required | {'refcnt'}, required)
        name = row['dev']
        if type(name) is not str or name not in schedulers or name in seen:
            raise Pending('foreign or duplicate classifier root')
        if row['root'] is not True or row['kind'] != schedulers[name]:
            raise Pending('unsupported or mismatched classifier root')
        if type(row['handle']) is not str or HANDLE.fullmatch(row['handle']) is None or row['handle'] == 'ffff:':
            raise Pending('unsupported classifier root handle')
        if row['kind'] == 'noqueue':
            if row['handle'] != '0:' or type(row['options']) is not dict or row['options']:
                raise Pending('unsupported noqueue root')
        else:
            fq_options(row['options'])
        if 'refcnt' in row and not KERNEL.uint(row['refcnt']):
            raise Pending('invalid classifier root reference count')
        seen.add(name)
    if seen != set(schedulers):
        raise Pending('incomplete positive classifier root inventory')
    return rows


def observe(query=native_query, links=KERNEL.native_query, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid classifier observation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = scope()
    if not KERNEL.uint(namespace, (1 << 64) - 1):
        raise Pending('invalid classifier network namespace')

    def fresh():
        if KERNEL.now() >= end:
            raise Pending('classifier observation expired')

    records = []
    for _ in range(2):
        fresh()
        interfaces = link_inventory(links('links', end))
        fresh()
        roots = root_inventory(query('qdiscs', end), interfaces)
        filters = {}
        for root in roots:
            if root['kind'] != 'fq_codel':
                continue
            fresh()
            rows = TC.snapshot(query('filters', end, interface=root['dev']))
            if type(rows) is not list or rows:
                raise Pending('fq_codel classifier dump is not positively empty')
            filters[root['dev']] = rows
        fresh()
        records.append({'links': interfaces, 'qdiscs': roots, 'fq_codel_filters': filters})
    final_namespace = scope()
    fresh()
    if records[0] != records[1] or type(final_namespace) is not int or final_namespace != namespace:
        raise Pending('classifier link/root/filter/namespace observations changed')
    return TC.snapshot({'schema': 'debian13s4-tc-fq-codel-classifiers-1', 'namespace': namespace,
        'profile': 'all-links-noqueue-or-fq-codel-roots-empty-filters-1',
        'source': {'tc': str(BINARY), 'ip': str(KERNEL.IP_BINARY)}, **records[-1]})


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        sink = getattr(sys.stdout, 'buffer', None)
        if sink is None or not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('binary stdout is unavailable')
        payload = (json.dumps(observe(), sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
        if len(payload) > MAX_BYTES + 1:
            raise Pending('serialized classifier observation exceeds its byte limit')
        written = sink.write(payload)
        if type(written) is not int or written != len(payload):
            raise Pending('classifier stdout write was incomplete')
        sink.flush()
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'debian13s4 classifier observation pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
