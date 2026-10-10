"""Compile a distinct PARTIAL static DNS-server SOURCE policy intention.

Three immutable byte inputs are trusted delivery: complete infrastructure
topology, explicit DNS configuration and a complete reported kernel snapshot.
No current observer, protected file read, registration, CLI, executor, installer
or policy operation exists here. Reported static assignments and caller namespace
are not authenticated/native ownership, freshness or full coexistence authority.
The original compiler/manifest/admission/transport remain unchanged and separate.
"""

import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


POLICY = module('debian13s4_dns_policy_base', Path(__file__).with_name('policy.py'))
DNS = module('debian13s4_dns_policy_settings', Path(__file__).resolve().parents[1] / 'DNS/prepare.py')
KERNEL = DNS.KERNEL
Pending = KERNEL.Pending
MAX_KERNEL = KERNEL.MAX_BYTES
MAX_OUTPUT = POLICY.MAX_OUTPUT
UNSAFE_FLAGS = {'tentative', 'dadfailed', 'deprecated', 'optimistic', 'temporary', 'dynamic'}
ADDRESS_FLAGS = UNSAFE_FLAGS | {'secondary', 'permanent', 'mngtmpaddr', 'noprefixroute'}


def decode(raw, maximum):
    if type(raw) is not bytes or len(raw) > maximum:
        raise Pending('DNS policy input exceeds its immutable byte profile')
    try:
        result = json.loads(raw.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite DNS policy input')),
            parse_float=lambda text: (_ for _ in ()).throw(Pending('noninteger DNS policy input')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid DNS policy input JSON') from error
    stack, count = [(result, 0)], 0
    while stack:
        value, depth = stack.pop(); count += 1
        if count > 65536 or depth > 16:
            raise Pending('DNS policy input exceeds structure bounds')
        if type(value) is dict:
            stack.extend((item, depth+1) for item in (*value.keys(), *value.values()))
        elif type(value) is list:
            stack.extend((item, depth+1) for item in value)
        elif type(value) is str:
            if '\0' in value:
                raise Pending('NUL in DNS policy input')
        elif type(value) is int:
            if value.bit_length() > 64:
                raise Pending('oversized DNS policy integer')
        elif value is not None and type(value) is not bool:
            raise Pending('unsupported DNS policy scalar')
    return result


def infinite(value):
    return value == 'forever' if type(value) is str else type(value) is int and value == 0xffffffff


def inputs(raw_topology, raw_dns, raw_kernel):
    topology = decode(raw_topology, POLICY.MAX_INPUT)
    POLICY.decode(raw_topology)
    settings = DNS.checked(decode(raw_dns, DNS.MAX_INPUT))
    if raw_dns != DNS.BASE.canonical(settings):
        raise Pending('DNS policy configuration is not canonical ASCII JSON plus LF')
    frame = decode(raw_kernel, MAX_KERNEL)
    KERNEL.known(frame, {'schema', 'namespace', 'snapshot'}, {'schema', 'namespace', 'snapshot'})
    if type(frame['schema']) is not int or frame['schema'] != 1 or KERNEL.uint(frame['namespace'], 0xffffffffffffffff) == 0:
        raise Pending('invalid reported DNS kernel context')
    # The real complete normalizer checks link/address/route/rule/neighbor/proxy
    # inventories. Do not replace it with a caller healthy Boolean or prefix guess.
    normalized = KERNEL.normalize(frame['snapshot'])
    links = {row['name']: row for row in normalized}
    if {row['name'] for row in topology['interfaces']} != set(links):
        raise Pending('DNS policy topology and complete kernel interfaces disagree')
    for row in topology['interfaces']:
        link = links[row['name']]
        expected = {key: link[key] for key in ('name', 'kind', 'prefixes', 'gateways', 'neighbors')}
        if not link['up']:
            expected['neighbors'] = []
        if {key: row[key] for key in expected} != expected:
            raise Pending('DNS policy topology and complete kernel facts disagree')
    for service in ('dns', 'ntp', 'dhcp4', 'dhcp6'):
        if any(not links[row['interface']]['up'] for row in topology[service]):
            raise Pending('DNS policy infrastructure endpoint has no active reported link')
    bindings = []
    for listener in settings['listeners']:
        host = ipaddress.ip_address(listener['address'])
        candidates = []
        for row in frame['snapshot']['addresses']:
            for entry in row['addr_info']:
                if entry['local'] == str(host):
                    candidates.append((row, entry))
        if len(candidates) != 1:
            raise Pending('DNS listener lacks one exact reported assignment')
        row, entry = candidates[0]; name = row['ifname']
        if (name not in links or not links[name]['up'] or entry.get('scope') != 'global' or
            entry['family'] != ('inet' if host.version == 4 else 'inet6') or
            not infinite(entry.get('valid_life_time')) or not infinite(entry.get('preferred_life_time'))):
            raise Pending('DNS listener requires an active reported static global-scope assignment')
        for flag in ADDRESS_FLAGS:
            if flag in entry and (type(entry[flag]) is not bool or flag in UNSAFE_FLAGS and entry[flag]):
                raise Pending('unsupported or unusable DNS assignment flag')
        length = KERNEL.uint(entry['prefixlen'], host.max_prefixlen)
        network = ipaddress.ip_network(f'{host}/{length}', strict=False)
        if host.version == 4 and length < 31 and host in (network.network_address, network.broadcast_address):
            raise Pending('DNS listener is a reported IPv4 network or broadcast address')
        if any(gateway['address'] == str(host) for link in normalized for gateway in link['gateways']):
            raise Pending('DNS assignment also names a reported router')
        bindings.append({'interface': name, 'address': str(host), 'family': host.version,
            'prefixlen': length, 'scope': 'global', 'valid_life_time': entry['valid_life_time'],
            'preferred_life_time': entry['preferred_life_time'],
            'flags': {key: entry[key] for key in sorted(ADDRESS_FLAGS) if key in entry}})
    return settings, frame['namespace'], bindings


def rules(bindings):
    inbound, replies = [], []
    for row in bindings:
        protocol = 'ip' if row['family'] == 4 else 'ip6'
        interface, host = POLICY.quote(row['interface']), row['address']
        for transport in ('udp', 'tcp'):
            for state in ('new', 'established'):
                syn = ' tcp flags & (fin | syn | rst | ack) == syn' if transport == 'tcp' and state == 'new' else ''
                inbound.append(f'        iifname {interface} {protocol} daddr {host} ct direction original '
                    f'ct state {state} {transport} dport 53 ct original proto-dst 53{syn} counter accept')
            replies.append(f'        oifname {interface} {protocol} saddr {host} ct direction reply '
                f'ct state established {transport} sport 53 ct original proto-dst 53 counter accept')
    return inbound, replies


def compile_intention(raw_topology, raw_dns, raw_kernel):
    settings, namespace, bindings = inputs(raw_topology, raw_dns, raw_kernel)
    original = POLICY.compile_policy(raw_topology)
    lines = original.split('\n')
    if lines[:2] != ['destroy table inet debian13s4', 'table inet debian13s4 {'] or lines[-2:] != ['}', '']:
        raise Pending('unsupported original compiler frame')
    inbound, replies = rules(bindings)
    result, chain, seen, inserted_input, inserted_output = [], None, set(), False, False
    for line in lines:
        if line.startswith('    chain '):
            if chain is not None:
                raise Pending('nested original compiler chain')
            chain = line.split()[1]
            if chain not in ('input', 'forward', 'output') or chain in seen:
                raise Pending('unsupported original compiler chain identity')
            seen.add(chain)
        if chain == 'output' and line == '        ip daddr @blocked4 counter drop':
            if inserted_output:
                raise Pending('duplicate original compiler isolation anchor')
            result.extend(replies); inserted_output = True
        if line == '    }' and chain is not None:
            if chain == 'input':
                result.extend(inbound); inserted_input = True
            chain = None
        result.append(line)
    if chain is not None or seen != {'input', 'forward', 'output'} or not inserted_input or not inserted_output:
        raise Pending('incomplete original compiler chain or isolation anchor')
    text = '\n'.join(result)
    if len(text.encode('utf-8')) > MAX_OUTPUT:
        raise Pending('DNS compiler intention exceeds text bound')
    record = {'schema': 1, 'profile': 'static-assignment-web-ssh-public-dns-source-intention-v1',
        'state': 'dns-firewall-source-intention-only', 'namespace': namespace,
        'topology_sha256': hashlib.sha256(raw_topology).hexdigest(),
        'dns_configuration_sha256': hashlib.sha256(raw_dns).hexdigest(),
        'kernel_snapshot_sha256': hashlib.sha256(raw_kernel).hexdigest(),
        'original_compiler_sha256': hashlib.sha256(original.encode('utf-8')).hexdigest(),
        'compiler_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
        'bindings': bindings, 'dns_configuration': settings, 'policy': text}
    payload = DNS.BASE.canonical(record)
    if len(payload) > MAX_OUTPUT:
        raise Pending('DNS compiler receipt exceeds complete byte bound')
    return payload
