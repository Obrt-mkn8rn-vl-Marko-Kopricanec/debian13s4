#!/usr/bin/python3
"""Observe networkd's current DHCPv4 server attribution and kernel egress.

This partial record is not complete firewall input, DHCPv6 discovery, endpoint
reachability/authentication, an installed controller or absence of other clients.
"""

import importlib.util
import ipaddress
import json
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_dhcp', Path(__file__).with_name('dhcp.py'))
DHCP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DHCP)
KERNEL = DHCP.KERNEL
RESOLVER = DHCP.TIMESYNC.RESOLVER
Pending = KERNEL.Pending
ATTEMPT_SECONDS = 60
MAX_ITEMS = 4096
LIVE_STATES = {'bound', 'renewing', 'rebinding'}
SOURCES = {'foreign', 'static', 'IPv4LL', 'DHCPv4', 'DHCPv6', 'DHCP-PD', 'NDisc', 'runtime'}
LINK_KEYS = set('Index Name AlternativeNames MasterInterfaceIndex Kind Type Driver Flags FlagsString KernelOperationalState KernelOperationalStateString MTU MinimumMTU MaximumMTU HardwareAddress PermanentHardwareAddress BroadcastAddress IPv6LinkLocalAddress WirelessLanInterfaceType WirelessLanInterfaceTypeString SSID BSSID AdministrativeState OperationalState CarrierState AddressState IPv4AddressState IPv6AddressState OnlineState NetworkFile NetworkFileDropins RequiredForOnline RequiredOperationalStateForOnline RequiredFamilyForOnline ActivationPolicy LinkFile LinkFileDropins Path Vendor Model DNS DNR NTP SIP SearchDomains RouteDomains DNSSECNegativeTrustAnchors DNSSettings CaptivePortal NDisc Addresses Neighbors NextHops Routes DHCPServer DHCPv4Client DHCPv6Client'.split())
ADDRESS_KEYS = set('Family Address Peer PrefixLength ConfigSource ConfigProvider Broadcast Scope ScopeString Flags FlagsString Label PreferredLifetimeUSec PreferredLifetimeUsec ValidLifetimeUSec ValidLifetimeUsec ConfigState'.split())


def byte_array(value, size=None, limit=255):
    if type(value) is not list or not value or len(value) > limit or size is not None and len(value) != size:
        raise Pending('invalid native DHCP byte array')
    return bytes(KERNEL.uint(item, 255) for item in value)


def bounded_json(message):
    text = DHCP.TIMESYNC.reply(message, 's')
    try:
        if type(text) is not str or len(text.encode('utf-8')) > DHCP.MAX_BYTES:
            raise Pending('invalid DHCP description size or type')
        value = json.loads(text, object_pairs_hook=KERNEL.unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid DHCP description JSON') from error
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_ITEMS or depth > 12:
            raise Pending('DHCP description structure exceeds bounds')
        if type(item) is dict:
            stack.extend((key, depth + 1) for key in item)
            stack.extend((entry, depth + 1) for entry in item.values())
        elif type(item) is list:
            stack.extend((entry, depth + 1) for entry in item)
        elif type(item) is str:
            if len(item.encode('utf-8')) > DHCP.MAX_BYTES or '\x00' in item:
                raise Pending('invalid DHCP description scalar')
        elif item is not None and type(item) not in (int, bool):
            raise Pending('unsupported DHCP description scalar')
    return value


def lifetime(row, name):
    # v257 emits both spellings for compatibility, and omits each only for
    # USEC_INFINITY. Omission is native infinity, not a file-reader default.
    modern, legacy = name + 'USec', name + 'Usec'
    if (modern in row) != (legacy in row):
        raise Pending('incomplete DHCP lifetime aliases')
    if modern not in row:
        return None
    result = KERNEL.uint(row[modern], (1 << 64) - 2)
    if row[legacy] != result or type(row[legacy]) is not int:
        raise Pending('inconsistent DHCP lifetime aliases')
    return result


def fresh(records):
    instant = int(KERNEL.now() * 1000000)
    for row in records:
        for name in ('preferred_until', 'valid_until'):
            if row[name] is not None and row[name] <= instant:
                raise Pending('DHCP address attribution expired')


def descriptions(message, client, topology):
    node = bounded_json(message)
    KERNEL.known(node, LINK_KEYS, ('Index', 'Name', 'HardwareAddress', 'Type', 'AdministrativeState', 'Flags'))
    KERNEL.uint(node['Index'], 0x7fffffff)
    if node['Index'] != client['index'] or node['Name'] != client['name'] or node['AdministrativeState'] != client['administrative']:
        raise Pending('DHCP description and client identities differ')
    links = [item for item in topology['interfaces'] if item['name'] == client['name']]
    if len(links) != 1 or links[0]['index'] != client['index']:
        raise Pending('DHCP description lacks a kernel interface')
    link = links[0]
    mac = ':'.join(f'{item:02x}' for item in byte_array(node['HardwareAddress'], 6))
    if KERNEL.ethernet(mac) != link['mac'] or node['Type'] != 'ether' or not link['up']:
        raise Pending('DHCP description and kernel Ethernet identities differ')
    if node.get('Kind') != ('vlan' if link['vlan'] is not None else None) or 'MasterInterfaceIndex' in node or 'DHCPServer' in node:
        raise Pending('unsupported DHCP link kind or server role')
    flags = KERNEL.uint(node['Flags'])
    if flags & (1 | 65536) != (1 | 65536):
        raise Pending('DHCP description interface is inactive')
    payload = node.get('DHCPv4Client')
    KERNEL.known(payload, {'ClientIdentifier', 'Lease', 'PrivateOptions', '6rdPrefix'}, ('ClientIdentifier', 'Lease'))
    byte_array(payload['ClientIdentifier'])
    if '6rdPrefix' in payload:
        raise Pending('DHCP 6rd requires a separate supported profile')
    lease = payload['Lease']
    KERNEL.known(lease, {'LeaseTimestampUSec', 'Timeout1USec', 'Timeout2USec'}, ('LeaseTimestampUSec',))
    instant = int(KERNEL.now() * 1000000)
    timestamp = KERNEL.uint(lease['LeaseTimestampUSec'], (1 << 64) - 2)
    if timestamp > instant:
        raise Pending('DHCP lease timestamp is in the future')
    deadlines = []
    for name in ('Timeout1USec', 'Timeout2USec'):
        if name in lease:
            deadline = KERNEL.uint(lease[name], (1 << 64) - 2)
            if deadline < timestamp:
                raise Pending('DHCP lease timeout precedes its timestamp')
            deadlines.append(deadline)
    if deadlines != sorted(deadlines):
        raise Pending('DHCP lease timeouts are reversed')
    result, identities = [], set()
    for row in KERNEL.rows(node.get('Addresses', [])):
        KERNEL.known(row, ADDRESS_KEYS, ('Family', 'Address', 'PrefixLength', 'ConfigSource', 'ConfigState', 'Flags', 'Scope'))
        family = KERNEL.uint(row['Family'])
        if family not in (2, 10) or type(row['ConfigSource']) is not str or row['ConfigSource'] not in SOURCES:
            raise Pending('unsupported DHCP description address family or source')
        version = 4 if family == 2 else 6
        assigned = str(ipaddress.ip_address(byte_array(row['Address'], 4 if version == 4 else 16)))
        KERNEL.address(assigned, version)
        length = KERNEL.uint(row['PrefixLength'], 32 if version == 4 else 128)
        if not length:
            raise Pending('default assigned DHCP prefix')
        KERNEL.uint(row['Flags'])
        KERNEL.uint(row['Scope'], 255)
        if type(row['ConfigState']) is not str:
            raise Pending('invalid DHCP address state')
        if row['ConfigSource'] != 'DHCPv4':
            continue
        if version != 4 or row['ConfigState'] != 'configured' or row['Flags'] & (8 | 32 | 64) or row['Scope'] != 0 or 'Peer' in row:
            raise Pending('DHCPv4 address is not positively configured and usable')
        if (assigned, length) in identities:
            raise Pending('duplicate DHCPv4 address attribution')
        identities.add((assigned, length))
        preferred, valid = lifetime(row, 'PreferredLifetime'), lifetime(row, 'ValidLifetime')
        if preferred is None and valid is not None or preferred is not None and valid is not None and preferred > valid:
            raise Pending('inconsistent DHCP address lifetime ordering')
        provider = str(ipaddress.ip_address(byte_array(row.get('ConfigProvider'), 4)))
        KERNEL.address(provider, 4)
        network = ipaddress.ip_network(f'{assigned}/{length}', strict=False)
        if provider == assigned or network.prefixlen < 31 and ipaddress.ip_address(provider) in (network.network_address, network.broadcast_address):
            raise Pending('DHCP server identifier is a local or subnet endpoint')
        matches = [item for item in topology['assigned4'] if item['interface'] == client['name'] and item['address'] == assigned and item['prefixlen'] == length]
        if len(matches) != 1 or matches[0]['scope'] != 'global' or not matches[0]['usable']:
            raise Pending('DHCPv4 attribution lacks a usable exact kernel assignment')
        result.append({'interface': client['name'], 'address': provider, 'assigned': assigned,
                       'prefixlen': length, 'preferred_until': preferred, 'valid_until': valid})
    if not result or len({row['address'] for row in result}) != 1:
        raise Pending('missing or conflicting DHCPv4 server attribution')
    fresh(result)
    return sorted(result, key=lambda row: (row['assigned'], row['prefixlen']))


def assigned_topology(deadline, query=None):
    query = KERNEL.native_query if query is None else query
    deliveries = []
    def checked(name, window):
        value = query(name, window)
        if name == 'addresses':
            deliveries.append(value)
        return value
    topology = KERNEL.observe(query=checked, deadline=deadline)
    rounds = []
    for delivery in deliveries:
        result = []
        for link in KERNEL.rows(delivery, KERNEL.MAX_LINKS):
            if link['ifname'] == 'lo':
                continue
            for row in KERNEL.rows(link['addr_info']):
                if row['family'] != 'inet':
                    continue
                usable = True
                for flag in ('tentative', 'dadfailed', 'deprecated'):
                    if flag in row and type(row[flag]) is not bool:
                        raise Pending('invalid kernel address usability flag')
                    usable &= not row.get(flag, False)
                if 'valid_life_time' not in row or KERNEL.uint(row['valid_life_time']) == 0:
                    usable = False
                if type(row.get('scope')) is not str:
                    raise Pending('kernel IPv4 address scope is not a native string')
                scope = {'global': 'global', '0': 'global', 'link': 'link', '253': 'link', 'host': 'host', '254': 'host'}.get(row['scope'])
                if scope is None:
                    raise Pending('unverifiable kernel IPv4 address scope')
                result.append({'interface': link['ifname'], 'address': row['local'], 'prefixlen': row['prefixlen'], 'scope': scope, 'usable': usable})
        rounds.append(sorted(result, key=lambda row: (row['interface'], row['address'], row['prefixlen'])))
    if len(rounds) != 2 or rounds[0] != rounds[1]:
        raise Pending('kernel DHCP address assignments changed')
    return topology | {'assigned4': rounds[1]}


def read_attributions(inventory, topology, deadline, query=DHCP.native_query):
    DHCP.bind_inventory(inventory, topology)
    result = []
    for client in inventory['interfaces']:
        if client['dhcp4'] and client['state4'] in LIVE_STATES:
            result.extend(descriptions(query('describe', deadline, owner=inventory['owner'], index=client['index']), client, topology))
    if len(result) > 256:
        raise Pending('too many DHCP server attributions')
    fresh(result)
    return result


def bindings(records, topology, deadline, route=KERNEL.native_route):
    endpoints, observations = [], []
    for name, destination in sorted({(row['interface'], row['address']) for row in records}):
        rows = route(destination, None, deadline)
        endpoint = RESOLVER.bind_route(destination, None, rows, topology['interfaces'])
        if endpoint['interface'] != name:
            raise Pending('DHCP server route differs from its client interface')
        endpoints.append(endpoint)
        observations.append(rows)
    return endpoints, observations


def observe(read=DHCP.read_inventory, topology=assigned_topology, query=DHCP.native_query, route=KERNEL.native_route, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid DHCP server attempt deadline')
    deadline = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    first = read(deadline)
    kernel = topology(deadline=deadline)
    attributions = read_attributions(first, kernel, deadline, query)
    endpoints, routes = bindings(attributions, kernel, deadline, route)
    if read(deadline) != first:
        raise Pending('DHCP client facts changed during server observation')
    second = topology(deadline=deadline)
    if second != kernel or read_attributions(first, second, deadline, query) != attributions:
        raise Pending('kernel assignments or DHCP server attributions changed')
    if bindings(attributions, second, deadline, route) != (endpoints, routes):
        raise Pending('DHCP server route changed')
    if read(deadline) != first or KERNEL.namespace() != kernel['namespace'] or KERNEL.now() >= deadline:
        raise Pending('DHCP server facts changed or expired before publication')
    fresh(attributions)
    return {'schema': 'debian13s4-networkd-dhcp4-servers-1', 'kernel': second,
            'source': {'service': DHCP.SERVICE, 'owner': first['owner'], 'pid': first['pid']},
            'interfaces': first['interfaces'], 'dhcp4': endpoints, 'attributions': attributions}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        payload = json.dumps(observe(), sort_keys=True, separators=(',', ':')) + '\n'
        if len(payload.encode()) > KERNEL.MAX_BYTES:
            raise Pending('DHCP server observation too large')
        sys.stdout.write(payload)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, KERNEL.subprocess.TimeoutExpired) as error:
        print(f'debian13s4 DHCP server observation pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
