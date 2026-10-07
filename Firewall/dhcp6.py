#!/usr/bin/python3
"""Observe the local substrate for networkd's pinned DHCPv6 multicast profile.

No unicast server is inferred. This is a partial point-in-time record, not a
socket/daemon compatibility, reply/lease health or complete firewall verdict.
"""

import hashlib
import importlib.util
import ipaddress
from pathlib import Path
import json
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_dhcp_servers', Path(__file__).with_name('dhcp_servers.py'))
SERVERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVERS)
DHCP, KERNEL = SERVERS.DHCP, SERVERS.KERNEL
Pending = KERNEL.Pending
DESTINATION = ipaddress.ip_address('ff02::1:2')
ATTEMPT_SECONDS = 60
SCOPES = {'global': 'global', '0': 'global', 'link': 'link', '253': 'link', 'host': 'host', '254': 'host'}


def extended_topology(deadline, query=None):
    query = KERNEL.native_query if query is None else query
    addresses, routes = [], []
    def checked(name, window):
        value = query(name, window)
        if name == 'addresses':
            addresses.append(value)
        elif name == 'routes6':
            routes.append(value)
        return value
    topology = KERNEL.observe(query=checked, deadline=deadline)
    rounds = []
    for delivery in addresses:
        records = []
        for link in KERNEL.rows(delivery, KERNEL.MAX_LINKS):
            if link['ifname'] == 'lo':
                continue
            for row in KERNEL.rows(link['addr_info']):
                if row['family'] != 'inet6':
                    continue
                if type(row.get('scope')) is not str or row['scope'] not in SCOPES:
                    raise Pending('unverifiable kernel IPv6 address scope')
                usable = True
                for name in ('tentative', 'dadfailed', 'deprecated'):
                    if name in row and type(row[name]) is not bool:
                        raise Pending('invalid kernel IPv6 usability flag')
                    usable &= not row.get(name, False)
                for name in ('valid_life_time', 'preferred_life_time'):
                    if name not in row or KERNEL.uint(row[name]) == 0:
                        usable = False
                records.append({'interface': link['ifname'], 'address': row['local'],
                                'prefixlen': row['prefixlen'], 'scope': SCOPES[row['scope']], 'usable': usable})
        rounds.append(sorted(records, key=lambda item: (item['interface'], item['address'], item['prefixlen'])))
    if len(rounds) != 2 or rounds[0] != rounds[1] or len(routes) != 2:
        raise Pending('DHCPv6 kernel assignments changed or observation was incomplete')
    multicast = []
    for delivery in routes:
        rows = []
        for row in KERNEL.rows(delivery):
            if KERNEL.route_type(row.get('type', 'unicast')) != 'multicast':
                continue
            network = KERNEL.prefix(row['dst'], 6)
            if network.prefixlen >= 8 and network.network_address.is_multicast and DESTINATION in network:
                rows.append(row)
        # Native inventories are unordered. Preserve complete relevant rows,
        # including metric and preferred source, before semantic selection.
        multicast.append(sorted(rows, key=lambda item: json.dumps(item, sort_keys=True)))
    if multicast[0] != multicast[1]:
        raise Pending('DHCPv6 multicast route inventory changed')
    return topology | {'assigned6': rounds[1], 'multicast6': multicast[1]}


def multicast_route(interface, local, topology):
    candidates = []
    for row in topology['multicast6']:
        if row['dev'] != interface:
            continue
        KERNEL.known(row, KERNEL.ROUTE_KEYS, ('dst', 'dev', 'type'))
        network = KERNEL.prefix(row['dst'], 6)
        if KERNEL.route_type(row['type']) != 'multicast' or network.prefixlen < 8 or not network.network_address.is_multicast or DESTINATION not in network:
            raise Pending('DHCPv6 route does not cover the multicast destination')
        if KERNEL.table(row.get('table', 254)) != 255 or KERNEL.flags(row.get('flags', [])) or 'gateway' in row:
            raise Pending('DHCPv6 multicast route is not a direct active local route')
        if 'scope' in row and (type(row['scope']) is not str or row['scope'] not in ('global', '0', 'link', '253')):
            raise Pending('unsupported DHCPv6 multicast route scope')
        metric = KERNEL.uint(row.get('metric', 0))
        if 'prefsrc' in row and KERNEL.address(row['prefsrc'], 6) != ipaddress.ip_address(local):
            raise Pending('DHCPv6 multicast route preferred source differs')
        candidates.append((network.prefixlen, metric, row))
    if not candidates:
        raise Pending('DHCPv6 client lacks a matching native multicast route')
    length = max(row[0] for row in candidates)
    metric = min(row[1] for row in candidates if row[0] == length)
    selected = [row[2] for row in candidates if row[:2] == (length, metric)]
    if len(selected) != 1:
        raise Pending('ambiguous DHCPv6 multicast route')
    return selected[0]


def local_client(message, client, topology):
    node = SERVERS.bounded_json(message)
    KERNEL.known(node, SERVERS.LINK_KEYS, ('Index', 'Name', 'HardwareAddress', 'Type', 'AdministrativeState', 'Flags', 'IPv6LinkLocalAddress', 'DHCPv6Client'))
    KERNEL.uint(node['Index'], 0x7fffffff)
    if node['Index'] != client['index'] or node['Name'] != client['name'] or node['AdministrativeState'] != client['administrative']:
        raise Pending('DHCPv6 description and client identities differ')
    matches = [row for row in topology['interfaces'] if row['name'] == client['name'] and row['index'] == client['index']]
    if len(matches) != 1 or not matches[0]['up']:
        raise Pending('DHCPv6 client lacks an active kernel interface')
    interface = matches[0]
    mac = ':'.join(f'{byte:02x}' for byte in SERVERS.byte_array(node['HardwareAddress'], 6))
    if KERNEL.ethernet(mac) != interface['mac'] or node['Type'] != 'ether' or node.get('Kind') != ('vlan' if interface['vlan'] is not None else None):
        raise Pending('DHCPv6 Ethernet/kernel description differs')
    if 'MasterInterfaceIndex' in node or 'DHCPServer' in node:
        raise Pending('unsupported DHCPv6 master or server profile')
    flags = KERNEL.uint(node['Flags'])
    if flags & (1 | 65536) != (1 | 65536):
        raise Pending('DHCPv6 description is inactive')
    local = str(ipaddress.ip_address(SERVERS.byte_array(node['IPv6LinkLocalAddress'], 16)))
    if not KERNEL.address(local, 6).is_link_local:
        raise Pending('DHCPv6 local description is not link-local')
    assigned = [row for row in topology['assigned6'] if row['interface'] == client['name'] and row['address'] == local]
    if len(assigned) != 1 or assigned[0]['scope'] != 'link' or not assigned[0]['usable']:
        raise Pending('DHCPv6 link-local address lacks an exact usable kernel assignment')
    payload = node['DHCPv6Client']
    KERNEL.known(payload, {'DUID', 'Lease', 'Prefixes', 'VendorSpecificOptions'}, ('DUID',))
    if 'Prefixes' in payload:
        raise Pending('DHCPv6 delegated-prefix profile is not admitted')
    # sd-dhcp-duid's raw grammar is a two-byte type plus 1..128 data bytes.
    # This is an opaque local identifier, not authentication or MAC derivation.
    duid = SERVERS.byte_array(payload['DUID'], limit=130)
    if len(duid) < 3:
        raise Pending('DHCPv6 DUID is incomplete')
    route = multicast_route(client['name'], local, topology)
    return {'interface': client['name'], 'index': client['index'], 'local': local,
            'prefixlen': assigned[0]['prefixlen'], 'state': client['state6'],
            'duid_sha256': hashlib.sha256(duid).hexdigest(), 'route': route}


def collect(inventory, topology, deadline, query=DHCP.native_query):
    DHCP.bind_inventory(inventory, topology)
    result = []
    for client in inventory['interfaces']:
        if client['dhcp6']:
            # Include stopped clients: native information-request completion
            # can stop the client while retaining a lease for later refresh.
            result.append(local_client(query('describe', deadline, owner=inventory['owner'], index=client['index']), client, topology))
    return result


def observe(read=DHCP.read_inventory, topology=extended_topology, query=DHCP.native_query, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid DHCPv6 observation deadline')
    deadline = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    first = read(deadline)
    kernel = topology(deadline=deadline)
    clients = collect(first, kernel, deadline, query)
    if read(deadline) != first:
        raise Pending('DHCPv6 client inventory changed')
    second = topology(deadline=deadline)
    if second != kernel or collect(first, second, deadline, query) != clients:
        raise Pending('DHCPv6 local descriptions or topology changed')
    if read(deadline) != first or KERNEL.namespace() != kernel['namespace'] or KERNEL.now() >= deadline:
        raise Pending('DHCPv6 observation changed or expired before publication')
    return {'schema': 'debian13s4-networkd-dhcp6-multicast-1', 'kernel': second,
            'source': {'service': DHCP.SERVICE, 'owner': first['owner'], 'pid': first['pid']},
            'interfaces': first['interfaces'], 'clients': clients,
            'transport': {'basis': 'pinned-networkd-v257-send-path', 'destination': str(DESTINATION),
                          'client_port': 546, 'server_port': 547, 'unicast_servers': []}}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        payload = json.dumps(observe(), sort_keys=True, separators=(',', ':')) + '\n'
        if len(payload.encode()) > KERNEL.MAX_BYTES:
            raise Pending('DHCPv6 observation too large')
        sys.stdout.write(payload)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, KERNEL.subprocess.TimeoutExpired) as error:
        print(f'debian13s4 DHCPv6 observation pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
