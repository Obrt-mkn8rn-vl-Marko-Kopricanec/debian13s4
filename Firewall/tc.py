#!/usr/bin/python3
"""Observe the partial all-links zero-handle noqueue-only qdisc profile.

This does not inspect TCX/XDP/cgroup/other eBPF or legacy bridge filtering, and
is not whole coexistence or delivery authority. Other qdiscs remain pending.
"""

import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_tc_kernel', Path(__file__).with_name('kernel.py'))
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending
BINARY = Path('/usr/sbin/tc')
COMMAND = ('-json', 'qdisc', 'show', 'invisible')
MAX_BYTES = 262144
ATTEMPT_SECONDS = 15
MAX_NODES = 16384


def native_query(deadline):
    if not KERNEL.finite_deadline(deadline) or deadline <= KERNEL.now():
        raise Pending('invalid or expired tc read deadline')
    identity = KERNEL.trusted_binary(BINARY)
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    if KERNEL.now() >= end:
        raise Pending('tc read admission expired')
    process = subprocess.Popen([str(BINARY), *COMMAND], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = end - KERNEL.now()
                if remaining <= 0:
                    raise Pending('tc read timed out')
                for key, _ in selector.select(remaining):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending('tc read output limit exceeded')
                    buffer.extend(data)
            remaining = end - KERNEL.now()
            if remaining <= 0 or process.wait(timeout=remaining) != 0 or buffers['stderr']:
                raise Pending('tc read failed or warned')
        if KERNEL.trusted_binary(BINARY) != identity:
            raise Pending('tc binary changed during read')
        if KERNEL.now() >= end:
            raise Pending('tc read completed after its deadline')
        try:
            return json.loads(buffers['stdout'].decode('utf-8'), object_pairs_hook=KERNEL.unique_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Pending('invalid tc read JSON') from error
    except subprocess.TimeoutExpired as error:
        raise Pending('tc read timed out after pipe closure') from error
    finally:
        try:
            # Retain the leader PID until its owned group is terminated on a
            # capture error; trusted native tools must stay in this session.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            process.stdout.close()
            process.stderr.close()


def snapshot(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop();count += 1
        if count > MAX_NODES or depth > 16:
            raise Pending('tc observation structure limit exceeded')
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise Pending('nonstring tc observation key')
            stack.extend((entry, depth + 1) for entry in (*item.keys(), *item.values()))
        elif type(item) is list:
            stack.extend((entry, depth + 1) for entry in item)
        elif type(item) is str:
            try:
                if '\x00' in item or len(item.encode('utf-8')) > MAX_BYTES:
                    raise Pending('invalid tc observation string')
            except UnicodeError as error:
                raise Pending('invalid tc observation encoding') from error
        elif item is not None and type(item) not in (bool, int):
            raise Pending('unsupported tc observation scalar')
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid tc observation JSON') from error
    if len(raw) > MAX_BYTES:
        raise Pending('tc observation byte limit exceeded')
    return json.loads(raw)


def link_inventory(value):
    rows = KERNEL.rows(value, KERNEL.MAX_LINKS)
    if not rows:
        raise Pending('missing tc link inventory')
    names, indexes = set(), set()
    for row in rows:
        KERNEL.known(row, KERNEL.LINK_KEYS, ('ifindex', 'ifname', 'flags', 'qdisc', 'link_type'))
        name, index = row['ifname'], KERNEL.uint(row['ifindex'], 0x7fffffff)
        if type(name) is not str or KERNEL.NAME.fullmatch(name) is None or name in names or not index or index in indexes:
            raise Pending('ambiguous tc link identity')
        flags = KERNEL.flags(row['flags'])
        if not flags.issubset(KERNEL.LINK_FLAGS) or row['qdisc'] != 'noqueue' or row['link_type'] not in ('ether', 'loopback'):
            raise Pending('unsupported tc link profile')
        if (name == 'lo') != (row['link_type'] == 'loopback') or ('LOOPBACK' in flags) != (name == 'lo'):
            raise Pending('inconsistent tc loopback identity')
        names.add(name);indexes.add(index)
    if 'lo' not in names:
        raise Pending('incomplete tc loopback inventory')
    return snapshot(rows)


def noqueue_roots(value, links):
    names = {row['ifname'] for row in links}
    seen = set()
    rows = KERNEL.rows(value, KERNEL.MAX_ITEMS)
    for row in rows:
        required = {'kind', 'handle', 'dev', 'root', 'options'}
        KERNEL.known(row, required | {'refcnt'}, required)
        name = row['dev']
        if type(name) is not str or name not in names or name in seen:
            raise Pending('foreign or duplicate tc qdisc device')
        if row['kind'] != 'noqueue' or row['handle'] != '0:' or row['root'] is not True or                 type(row['options']) is not dict or row['options']:
            raise Pending('qdisc requires a separate classifier/coexistence adapter')
        if 'refcnt' in row and not KERNEL.uint(row['refcnt']):
            raise Pending('invalid tc reference count')
        seen.add(name)
    if seen != names:
        # A builtin/omitted/down-device root is not inferred from an empty dump.
        raise Pending('incomplete positive tc root inventory')
    return snapshot(rows)


def observe(query=native_query, links=KERNEL.native_query, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid tc observation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = scope()
    if not KERNEL.uint(namespace, (1 << 64) - 1):
        raise Pending('invalid tc network namespace')
    records = []
    for _ in range(2):
        if KERNEL.now() >= end:
            raise Pending('tc observation expired before links')
        interfaces = link_inventory(links('links', end))
        if KERNEL.now() >= end:
            raise Pending('tc observation expired before qdisc query')
        qdiscs = noqueue_roots(query(end), interfaces)
        records.append({'links': interfaces, 'qdiscs': qdiscs})
        if KERNEL.now() >= end:
            raise Pending('tc observation expired after delivery')
    final_namespace = scope()
    if records[0] != records[1] or type(final_namespace) is not int or final_namespace != namespace or KERNEL.now() >= end:
        raise Pending('tc link/qdisc/namespace observations changed or expired')
    return {'schema': 'debian13s4-tc-noqueue-roots-1', 'namespace': namespace,
            'profile': 'all-links-zero-handle-noqueue-only-1', 'source': {'tc': str(BINARY), 'ip': str(KERNEL.IP_BINARY)},
            **records[-1]}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        payload = json.dumps(observe(), sort_keys=True, separators=(',', ':')) + '\n'
        sys.stdout.write(payload);sys.stdout.flush()
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'debian13s4 tc observation pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
