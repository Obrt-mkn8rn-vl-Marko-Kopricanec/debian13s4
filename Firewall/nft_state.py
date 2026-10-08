#!/usr/bin/python3
"""Observe a reserved-name nft candidate, without claiming ownership or health.

The complete global dump must contain only this restricted inet table shape.
Every admitted match/element is retained as opaque SOURCE data, not interpreted
as safe policy or proven compiler/kernel semantics. A future trusted manifest
comparison and durable ownership transaction remain necessary before delivery.
Only checked anonymous counter statistics are excluded from the fingerprint;
handles and statistics remain separately observable. No object is changed.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_nft_state_reader', Path(__file__).with_name('nft.py'))
NFT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NFT)
KERNEL = NFT.KERNEL
Pending = KERNEL.Pending
TABLE = 'debian13s4'
ATTEMPT_SECONDS = 10
MAX_NODES = 65536
MAX_OBJECTS = 4096
MAX_OUTPUT = 1048576
CHAINS = ('input', 'forward', 'output')
SET_TYPES = {'onlink6': 'ipv6_addr', 'dhcp4_links': 'ifname', 'dhcp6_links': 'ifname'}
for _version in (4, 6):
    _address = f'ipv{_version}_addr'
    SET_TYPES[f'blocked{_version}'] = _address
    SET_TYPES[f'ssh{_version}'] = ['ifname', _address, 'ether_addr']
    SET_TYPES[f'ssh_reply{_version}'] = ['ifname', _address]
    for _service in ('dns', 'ntp', 'dhcp4', 'dhcp6'):
        SET_TYPES[f'{_service}_{_version}'] = ['ifname', _address]


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def private(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop();count += 1
        if count > MAX_NODES or depth > 16:
            raise Pending('nft candidate exceeds structure bounds')
        if type(item) is dict:
            if any(type(key) is not str for key in item):raise Pending('nonstring nft candidate key')
            stack.extend((child, depth + 1) for child in (*item.keys(), *item.values()))
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            try:
                if '\0' in item or len(item.encode('utf-8')) > NFT.MAX_BYTES:raise Pending('invalid nft candidate string')
            except UnicodeError as error:raise Pending('invalid nft candidate encoding') from error
        elif type(item) is int:
            if item.bit_length() > 64:raise Pending('oversized nft candidate integer')
        elif item is not None and type(item) is not bool:
            raise Pending('unsupported nft candidate scalar')
    try:
        data = encoded(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid nft candidate serialization') from error
    if len(data) > NFT.MAX_BYTES:raise Pending('nft candidate exceeds byte bound')
    return json.loads(data)


def uint(value, zero=False):
    if type(value) is not int or value < (0 if zero else 1) or value > (1 << 64) - 1:
        raise Pending('invalid nft candidate integer')
    return value


def object_identity(row):
    if row['family'] != 'inet' or row.get('table', TABLE) != TABLE:
        raise Pending('foreign nft candidate family or table')
    return uint(row['handle'])


def project(value):
    value = private(value)
    KERNEL.known(value, {'nftables'}, {'nftables'})
    objects = KERNEL.rows(value['nftables'], MAX_OBJECTS)
    if not objects or set(objects[0]) != {'metainfo'}:raise Pending('missing first nft candidate metainfo')
    info = NFT.metadata(objects[0]['metainfo'])
    table, chains, sets = None, {}, {}
    rules = {name: [] for name in CHAINS}
    handles = {'table': None, 'chains': {}, 'sets': {}, 'rules': {name: [] for name in CHAINS}}
    statistics = []
    for entry in objects[1:]:
        if type(entry) is not dict or len(entry) != 1:raise Pending('invalid nft candidate object envelope')
        kind, row = next(iter(entry.items()))
        if kind == 'table':
            KERNEL.known(row, {'family', 'name', 'handle', 'flags'}, {'family', 'name', 'handle'})
            if table is not None or row['name'] != TABLE:raise Pending('foreign or duplicate nft candidate table')
            if 'flags' in row and (type(row['flags']) is not list or row['flags']):raise Pending('unsupported nft candidate table flags')
            handles['table'] = object_identity(row)
            table = {key: item for key, item in row.items() if key != 'handle'}
        elif kind == 'chain':
            fields = {'family', 'table', 'name', 'handle', 'type', 'hook', 'prio', 'policy'}
            KERNEL.known(row, fields, fields)
            name = row['name']
            if type(name) is not str or name not in CHAINS or name in chains or row['type'] != 'filter' or \
                    row['hook'] != name or type(row['prio']) is not int or row['prio'] != 0 or row['policy'] != 'drop':
                raise Pending('unsupported nft candidate base chain')
            handles['chains'][name] = object_identity(row)
            chains[name] = {key: item for key, item in row.items() if key != 'handle'}
        elif kind == 'set':
            required = {'family', 'table', 'name', 'handle', 'type', 'flags'}
            KERNEL.known(row, required | {'elem', 'policy', 'size', 'auto-merge'}, required)
            name = row['name']
            if type(name) is not str or name not in SET_TYPES or name in sets or row['type'] != SET_TYPES[name]:
                raise Pending('unsupported nft candidate set identity or type')
            flags = row['flags']
            interval = name in ('blocked4', 'blocked6', 'onlink6')
            if type(flags) is not list or any(type(flag) is not str for flag in flags) or \
                    len(flags) != len(set(flags)) or set(flags) != ({'constant', 'interval'} if interval else {'constant'}):
                raise Pending('unsupported nft candidate set flags')
            if 'policy' in row and row['policy'] not in ('performance', 'memory'):raise Pending('invalid nft candidate set policy')
            if 'size' in row:uint(row['size'], True)
            if 'auto-merge' in row and (type(row['auto-merge']) is not bool or not interval):raise Pending('invalid nft candidate merge flag')
            if 'elem' in row and (row['elem'] is None or type(row['elem']) is list and len(row['elem']) > KERNEL.MAX_ITEMS):
                raise Pending('unsupported nft candidate element delivery')
            handles['sets'][name] = object_identity(row)
            sets[name] = {key: item for key, item in row.items() if key != 'handle'}
            sets[name]['flags'] = sorted(flags)
        elif kind == 'rule':
            fields = {'family', 'table', 'chain', 'handle', 'expr'}
            KERNEL.known(row, fields, fields)
            name = row['chain']
            if type(name) is not str or name not in ('input', 'output'):raise Pending('unsupported nft candidate rule chain')
            handle = object_identity(row)
            if handle in handles['rules'][name]:raise Pending('duplicate nft candidate rule handle')
            expressions = KERNEL.rows(row['expr'])
            if len(expressions) < 2 or len(expressions[-1]) != 1 or next(iter(expressions[-1])) not in ('accept', 'drop') or next(iter(expressions[-1].values())) is not None:
                raise Pending('unsupported nft candidate terminal verdict')
            counters = 0
            for position, statement in enumerate(expressions[:-1]):
                if type(statement) is not dict or len(statement) != 1:raise Pending('unsupported nft candidate statement')
                if 'counter' in statement:
                    data = statement['counter'];KERNEL.known(data, {'packets', 'bytes'}, {'packets', 'bytes'})
                    statistics.append({'chain': name, 'rule_handle': handle, 'position': position,
                                       'packets': uint(data['packets'], True), 'bytes': uint(data['bytes'], True)})
                    statement['counter'] = {};counters += 1
                elif 'match' in statement:
                    match = statement['match'];KERNEL.known(match, {'op', 'left', 'right'}, {'op', 'left', 'right'})
                    if match['op'] not in ('==', '!=', 'in', '<', '>', '<=', '>='):raise Pending('unsupported nft candidate match operator')
                else:raise Pending('unsupported nft candidate rule statement')
            if counters != 1:raise Pending('missing or duplicate nft candidate anonymous counter')
            handles['rules'][name].append(handle)
            rules[name].append({key: item for key, item in row.items() if key != 'handle'})
        else:
            raise Pending('foreign or unsupported nft candidate object kind')
    if table is None or set(chains) != set(CHAINS) or set(sets) != set(SET_TYPES) or not rules['input'] or not rules['output']:
        raise Pending('incomplete nft candidate table inventory')
    policy = {'table': table, 'chains': chains, 'sets': sets, 'rules': rules}
    return {'source': {'binary': str(NFT.BINARY), **info}, 'policy': policy, 'identity': handles,
            'statistics': statistics, 'fingerprint': hashlib.sha256(encoded(policy)).hexdigest()}


def observe(query=NFT.native_query, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):raise Pending('invalid nft candidate deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = uint(scope())
    observations = []
    for _ in range(2):
        if KERNEL.now() >= end:raise Pending('nft candidate window expired before read')
        observations.append(project(query(end)))
        if KERNEL.now() >= end:raise Pending('nft candidate window expired after read')
    stable = lambda row: {key: value for key, value in row.items() if key != 'statistics'}
    last = scope()
    if type(last) is not int or last != namespace or stable(observations[0]) != stable(observations[1]) or KERNEL.now() >= end:
        raise Pending('nft candidate facts changed or expired')
    return {'schema': 'debian13s4-nft-candidate-1', 'profile': 'reserved-inet-static-root-shape-source-1',
            'namespace': namespace, **observations[-1]}


def main():
    if len(sys.argv) != 1:return 64
    try:
        sink = getattr(sys.stdout, 'buffer', None)
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('nft candidate requires a binary output sink')
        payload = encoded(observe()) + b'\n'
        if len(payload) > MAX_OUTPUT:raise Pending('nft candidate publication exceeds bound')
        written = sink.write(payload)
        if type(written) is not int or written != len(payload):raise Pending('nft candidate output was not fully written')
        sink.flush();return 0
    except (OSError, ValueError, AttributeError, KERNEL.subprocess.TimeoutExpired) as error:
        print(f'debian13s4 nft candidate pending: {error}', file=sys.stderr);return 75


if __name__ == '__main__':raise SystemExit(main())
