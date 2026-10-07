#!/usr/bin/python3
"""Prepare compiler input from agreeing supported automatic observations.

Empty nftables space, classic external DNS, selected timesyncd and managed
networkd without an instantiated DHCPv6 client form this limited profile. No policy is installed;
coexistence, native nft verification and controller ownership remain separate.
"""

import importlib.util
import json
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_servers', Path(__file__).with_name('dhcp_servers.py'))
SERVERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVERS)
DHCP, KERNEL = SERVERS.DHCP, SERVERS.KERNEL
TIMESYNC, RESOLVER = DHCP.TIMESYNC, SERVERS.RESOLVER
SPEC = importlib.util.spec_from_file_location('debian13s4_policy', Path(__file__).with_name('policy.py'))
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
SPEC = importlib.util.spec_from_file_location('debian13s4_nft', Path(__file__).with_name('nft.py'))
NFT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NFT)
Pending = KERNEL.Pending
ATTEMPT_SECONDS = 60
MAX_NODES = 65536
SHAPES = {'dhcp4': ('debian13s4-networkd-dhcp4-servers-1', {'schema', 'kernel', 'source', 'interfaces', 'dhcp4', 'attributions'}),
          'dns': ('debian13s4-resolver-1', {'schema', 'kernel', 'source', 'dns'}),
          'ntp': ('debian13s4-timesync-1', {'schema', 'kernel', 'source', 'ntp'})}


def snapshot(value):
    """Bound and privately copy results before later readers can mutate them."""
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > 16:
            raise Pending('assembled observer record exceeds structure limits')
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise Pending('observer record has nonstring keys')
            stack.extend((entry, depth + 1) for entry in (*item.keys(), *item.values()))
        elif type(item) is list:
            stack.extend((entry, depth + 1) for entry in item)
        elif type(item) is str:
            try:
                if '\x00' in item or len(item.encode('utf-8')) > KERNEL.MAX_BYTES:
                    raise Pending('invalid assembled record string')
            except UnicodeError as error:
                raise Pending('invalid assembled record encoding') from error
        elif item is not None and type(item) not in (bool, int):
            raise Pending('unsupported assembled record scalar')
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid assembled record') from error
    if len(raw) > KERNEL.MAX_BYTES:
        raise Pending('assembled observer record too large')
    return json.loads(raw)


def kernel_base(record, extra):
    names = {'schema', 'namespace', 'interfaces'} | extra
    KERNEL.known(record, names, names)
    if record['schema'] != 'debian13s4-kernel-1' or KERNEL.uint(record['namespace'], (1 << 64) - 1) == 0:
        raise Pending('invalid assembled kernel identity')
    seen, indexes = set(), set()
    for row in KERNEL.rows(record['interfaces'], POLICY.MAX_INTERFACES):
        fields = {'name', 'index', 'mac', 'up', 'kind', 'flags', 'parent', 'vlan', 'prefixes', 'gateways', 'neighbors'}
        KERNEL.known(row, fields, fields)
        name, index = row['name'], KERNEL.uint(row['index'], 0x7fffffff)
        if type(name) is not str or KERNEL.NAME.fullmatch(name) is None or name == 'lo' or name in seen or not index or index in indexes:
            raise Pending('invalid assembled interface identity')
        seen.add(name); indexes.add(index)
        KERNEL.ethernet(row['mac'])
        flags = KERNEL.flags(row['flags'])
        if row['kind'] != 'ether' or type(row['up']) is not bool or not flags.issubset(KERNEL.LINK_FLAGS) or row['up'] != {'UP', 'LOWER_UP'}.issubset(flags):
            raise Pending('inconsistent assembled interface usability')
    return {key: record[key] for key in ('schema', 'namespace', 'interfaces')}


def validate_record(service, record):
    schema, fields = SHAPES[service]
    KERNEL.known(record, fields, fields)
    if record['schema'] != schema:
        raise Pending('unsupported assembled observer schema')
    kernel = kernel_base(record['kernel'], {'assigned4'} if service == 'dhcp4' else {'scope_names'} if service == 'dns' else set())
    source = record['source']
    if service == 'dns':
        KERNEL.known(source, {'path', 'sha256'}, ('path', 'sha256'))
        if type(source['path']) is not str or not source['path'].startswith('/') or type(source['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', source['sha256']) is None:
            raise Pending('invalid assembled resolver source')
    else:
        names = {'service', 'owner', 'pid'} | ({'name'} if service == 'ntp' else set())
        KERNEL.known(source, names, names)
        if source['service'] != (DHCP.SERVICE if service == 'dhcp4' else TIMESYNC.SERVICE) or not KERNEL.uint(source['pid']):
            raise Pending('invalid assembled manager identity')
        TIMESYNC.owner_name(source['owner'])
        if service == 'ntp':
            TIMESYNC.text(source['name'], empty=False)
    if service == 'dhcp4':
        assignments = set()
        for row in KERNEL.rows(record['kernel']['assigned4']):
            fields = {'interface', 'address', 'prefixlen', 'scope', 'usable'}
            KERNEL.known(row, fields, fields)
            if type(row['interface']) is not str or row['interface'] not in {link['name'] for link in kernel['interfaces']} or type(row['scope']) is not str or row['scope'] not in ('global', 'link', 'host') or type(row['usable']) is not bool:
                raise Pending('invalid assembled kernel assignment')
            KERNEL.address(row['address'], 4)
            if not KERNEL.uint(row['prefixlen'], 32):
                raise Pending('invalid assembled assignment mask')
            identity = (row['interface'], row['address'], row['prefixlen'])
            if identity in assignments:
                raise Pending('duplicate assembled kernel assignment')
            assignments.add(identity)
        clients = KERNEL.rows(record['interfaces'], POLICY.MAX_INTERFACES)
        seen = set()
        for row in clients:
            fields = {'name', 'index', 'path', 'administrative', 'dhcp4', 'state4', 'dhcp6', 'state6'}
            KERNEL.known(row, fields, fields)
            if type(row['name']) is not str or row['name'] in seen:
                raise Pending('duplicate or invalid assembled client name')
            seen.add(row['name'])
            if row['path'] != DHCP.link_path(row['index']) or row['administrative'] not in ('configured', 'configuring'):
                raise Pending('invalid assembled client identity')
            for family in (4, 6):
                enabled, state = row['dhcp' + str(family)], row['state' + str(family)]
                if type(enabled) is not bool or enabled and (type(state) is not str or state not in DHCP.STATES[family]) or not enabled and state is not None:
                    raise Pending('inconsistent assembled client state')
            if row['dhcp6']:
                raise Pending('DHCPv6 reply compatibility is not admitted by this assembly profile')
        DHCP.bind_inventory({'namespace': kernel['namespace'], 'interfaces': clients}, kernel)
    else:
        count = len(KERNEL.rows(record[service], 256))
        if not count or service == 'ntp' and count != 1:
            raise Pending('missing or ambiguous assembled infrastructure endpoint')
    return kernel


def input_from(records, kernel):
    clients = {row['name']: row for row in records['dhcp4']['interfaces']}
    interfaces = []
    for link in kernel['interfaces']:
        row = {key: link[key] for key in ('name', 'kind', 'prefixes', 'gateways', 'neighbors')}
        # Keep down-link prefixes blocked, while withholding their cached peers.
        if not link['up']:
            row['neighbors'] = []
        row.update(dhcp4=clients[link['name']]['dhcp4'], dhcp6=False)
        interfaces.append(row)
    value = {'schema': 1, 'interfaces': interfaces, 'dns': records['dns']['dns'], 'ntp': records['ntp']['ntp'], 'dhcp4': records['dhcp4']['dhcp4'], 'dhcp6': []}
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')
    POLICY.decode(raw)
    active = {row['name'] for row in kernel['interfaces'] if row['up']}
    if any(row['interface'] not in active for service in ('dns', 'ntp', 'dhcp4') for row in value[service]):
        raise Pending('infrastructure endpoint lacks an active common interface')
    expected = {(row['interface'], row['address']) for row in records['dhcp4']['dhcp4']}
    actual = set()
    for row in KERNEL.rows(records['dhcp4']['attributions'], 256):
        fields = {'interface', 'address', 'assigned', 'prefixlen', 'preferred_until', 'valid_until'}
        KERNEL.known(row, fields, fields)
        if type(row['interface']) is not str or row['interface'] not in clients or not clients[row['interface']]['dhcp4'] or clients[row['interface']]['state4'] not in SERVERS.LIVE_STATES:
            raise Pending('DHCP endpoint lacks a live observed client attribution')
        KERNEL.address(row['address'], 4); KERNEL.address(row['assigned'], 4)
        if not KERNEL.uint(row['prefixlen'], 32):
            raise Pending('invalid assembled assigned prefix')
        matches = [item for item in KERNEL.rows(records['dhcp4']['kernel']['assigned4'])
                   if item['interface'] == row['interface'] and item['address'] == row['assigned'] and item['prefixlen'] == row['prefixlen']]
        if len(matches) != 1 or matches[0]['scope'] != 'global' or matches[0]['usable'] is not True:
            raise Pending('assembled attribution lacks an exact usable kernel assignment')
        for name in ('preferred_until', 'valid_until'):
            if row[name] is not None:
                KERNEL.uint(row[name], (1 << 64) - 2)
        actual.add((row['interface'], row['address']))
    if expected != actual:
        raise Pending('DHCP endpoints and attribution inventory disagree')
    live = {name for name, row in clients.items() if row['dhcp4'] and row['state4'] in SERVERS.LIVE_STATES}
    if {row['interface'] for row in records['dhcp4']['attributions']} != live:
        raise Pending('live DHCP clients lack complete server attributions')
    SERVERS.fresh(records['dhcp4']['attributions'])
    return value, raw


def observe(dhcp=SERVERS.observe, dns=RESOLVER.observe, ntp=TIMESYNC.observe, compiler=POLICY.compile_policy, deadline=None, nft=NFT.observe):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid assembly deadline')
    deadline = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    rounds, common = [], None
    for _ in range(2):
        if KERNEL.now() >= deadline:
            raise Pending('assembly deadline expired before nft admission')
        records = {'nft': snapshot(NFT.validate_receipt(nft(deadline=deadline)))}
        for service, reader in (('dhcp4', dhcp), ('dns', dns), ('ntp', ntp)):
            if KERNEL.now() >= deadline:
                raise Pending('assembly deadline expired before observer admission')
            record = snapshot(reader(deadline=deadline))
            kernel = validate_record(service, record)
            if common is None:
                common = kernel
            if kernel != common:
                raise Pending('independent observer kernel inventories disagree')
            if records['nft']['namespace'] != common['namespace']:
                raise Pending('nft and infrastructure namespaces disagree')
            records[service] = record
        if rounds and records != rounds[0]:
            raise Pending('complete infrastructure observations changed between rounds')
        rounds.append(records)
    value, raw = input_from(rounds[-1], common)
    text = compiler(raw)
    if type(text) is not str or not text or len(text.encode('utf-8')) > POLICY.MAX_OUTPUT:
        raise Pending('invalid assembled compiler output')
    SERVERS.fresh(rounds[-1]['dhcp4']['attributions'])
    if KERNEL.now() >= deadline:
        raise Pending('assembly changed or expired before publication')
    if snapshot(NFT.validate_receipt(nft(deadline=deadline))) != rounds[-1]['nft']:
        raise Pending('nft facts changed before preparation publication')
    SERVERS.fresh(rounds[-1]['dhcp4']['attributions'])
    if KERNEL.namespace() != common['namespace'] or KERNEL.now() >= deadline:
        raise Pending('assembly changed or expired before publication')
    return {'schema': 'debian13s4-assembled-policy-1', 'namespace': common['namespace'], 'topology': value, 'policy': text,
            'profile': 'nft-empty-networkd-classic-timesyncd-no-dhcp6-1', 'sources': {service: row['source'] for service, row in rounds[-1].items()}}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        result = observe()
        sys.stdout.write(result['policy'])
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, KERNEL.subprocess.TimeoutExpired) as error:
        print(f'debian13s4 firewall preparation pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
