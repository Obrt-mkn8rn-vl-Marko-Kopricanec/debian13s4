#!/usr/bin/python3
"""Observe systemd-networkd DHCP client instances without changing host state.

This partial record cannot certify absence of other clients, DHCP reachability,
lease/server endpoints or complete firewall input. Other managers need adapters.
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
import xml.etree.ElementTree as ET

SPEC = importlib.util.spec_from_file_location('debian13s4_timesync', Path(__file__).with_name('timesync.py'))
TIMESYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TIMESYNC)
KERNEL = TIMESYNC.KERNEL
Pending = KERNEL.Pending
BUS_BINARY = Path('/usr/bin/busctl')
SERVICE = 'org.freedesktop.network1'
OBJECT = '/org/freedesktop/network1'
MANAGER = SERVICE + '.Manager'
LINK = SERVICE + '.Link'
CLIENTS = {4: SERVICE + '.DHCPv4Client', 6: SERVICE + '.DHCPv6Client'}
PROPERTIES = 'org.freedesktop.DBus.Properties'
INTROSPECT = 'org.freedesktop.DBus.Introspectable'
CORE = {'org.freedesktop.DBus.Peer', PROPERTIES, INTROSPECT, LINK}
BUS = TIMESYNC.BUS
MAX_BYTES = 65536
MAX_XML_ITEMS = 1024
ATTEMPT_SECONDS = 60
DOCTYPE = ('<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"\n'
           '"https://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">\n')
STATES = {
    4: set('stopped initialization selecting init-reboot rebooting requesting bound renewing rebinding'.split()),
    6: set('stopped information-request solicitation request bound renew rebind stopping'.split()),
}


def link_path(index):
    if KERNEL.uint(index, 0x7fffffff) == 0:
        raise Pending('missing DHCP interface index')
    return OBJECT + '/link/_' + str(index)


def native_query(operation, deadline, owner=None, index=None):
    if type(operation) is not str or operation not in ('owner', 'pid', 'namespace', 'links', 'introspect', 'admin', 'state4', 'state6', 'describe'):
        raise Pending('DHCP query is not an admitted read-only operation')
    if operation == 'owner':
        if owner is not None or index is not None:
            raise Pending('DHCP owner query cannot override its service')
        arguments = (*BUS, 'GetNameOwner', 's', SERVICE)
    else:
        TIMESYNC.owner_name(owner)
        if operation in ('pid', 'namespace', 'links'):
            if index is not None:
                raise Pending('manager query cannot override its object')
            if operation == 'pid':
                arguments = (*BUS, 'GetConnectionUnixProcessID', 's', owner)
            elif operation == 'links':
                arguments = (owner, OBJECT, MANAGER, 'ListLinks')
            else:
                arguments = (owner, OBJECT, PROPERTIES, 'Get', 'ss', MANAGER, 'NamespaceId')
        else:
            path = link_path(index)
            if operation == 'describe':
                arguments = (owner, OBJECT, MANAGER, 'DescribeLink', 'i', str(index))
            elif operation == 'introspect':
                arguments = (owner, path, INTROSPECT, 'Introspect')
            else:
                interface = LINK if operation == 'admin' else CLIENTS[int(operation[-1])]
                property_name = 'AdministrativeState' if operation == 'admin' else 'State'
                arguments = (owner, path, PROPERTIES, 'Get', 'ss', interface, property_name)
    if not KERNEL.finite_deadline(deadline):
        raise Pending('invalid DHCP-query deadline')
    identity = KERNEL.trusted_binary(BUS_BINARY)
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    if KERNEL.now() >= end:
        raise Pending('DHCP-query deadline expired')
    command = [str(BUS_BINARY), '--system', '--no-pager', '--json=short',
               '--auto-start=no', '--allow-interactive-authorization=no',
               '--expect-reply=yes', '--timeout=3s', 'call', *arguments]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'},
                               close_fds=True, start_new_session=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = end - KERNEL.now()
                if remaining <= 0:
                    raise Pending('DHCP query timed out')
                for key, _ in selector.select(remaining):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending('DHCP query output limit exceeded')
                    buffer.extend(data)
            remaining = end - KERNEL.now()
            if remaining <= 0 or process.wait(timeout=remaining) != 0 or buffers['stderr']:
                raise Pending('DHCP query failed or warned')
        if KERNEL.trusted_binary(BUS_BINARY) != identity:
            raise Pending('DHCP-query binary changed')
        try:
            return json.loads(buffers['stdout'].decode('utf-8'), object_pairs_hook=KERNEL.unique_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Pending('invalid DHCP-query JSON') from error
    except subprocess.TimeoutExpired as error:
        raise Pending('DHCP query timed out after pipe closure') from error
    finally:
        try:
            # Keep an unreaped leader's PID reserved until its owned group has
            # been terminated. Trusted busctl must remain in this new session.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            process.stdout.close()
            process.stderr.close()


def variant(value, signature):
    entry = TIMESYNC.reply(value, 'v')
    KERNEL.known(entry, {'type', 'data'}, ('type', 'data'))
    if entry['type'] != signature:
        raise Pending('unexpected DHCP property signature')
    return entry['data']


def links(value):
    records = TIMESYNC.reply(value, 'a(iso)')
    if type(records) is not list or not records or len(records) > KERNEL.MAX_LINKS:
        raise Pending('missing or excessive DHCP link inventory')
    indexes, names, result = set(), set(), []
    for row in records:
        if type(row) is not list or len(row) != 3:
            raise Pending('invalid DHCP link structure')
        index, name, path = row
        expected = link_path(index)
        if type(name) is not str or KERNEL.NAME.fullmatch(name) is None or path != expected or index in indexes or name in names:
            raise Pending('unverifiable or duplicate DHCP link identity')
        indexes.add(index)
        names.add(name)
        result.append({'name': name, 'index': index, 'path': path})
    if 'lo' not in names:
        raise Pending('DHCP link inventory lacks loopback')
    return sorted(result, key=lambda row: row['name'])


def client_interfaces(value):
    xml = TIMESYNC.reply(value, 's')
    if type(xml) is not str or len(xml.encode('utf-8')) > MAX_BYTES:
        raise Pending('invalid or excessive DHCP introspection')
    # Strip only sd-bus's exact external declaration. Never resolve a DTD or
    # accept entities, alternate declarations, processing instructions/comments.
    document = xml[len(DOCTYPE):] if xml.startswith(DOCTYPE) else xml
    if '<!' in document or '<?' in document or '&' in document:
        raise Pending('unsupported DHCP XML declaration or entity')
    try:
        root = ET.fromstring(document)
    except (ET.ParseError, ValueError) as error:
        raise Pending('invalid DHCP introspection XML') from error
    if root.tag != 'node' or root.attrib:
        raise Pending('invalid DHCP introspection root')
    grammar = {'node': {'interface'}, 'interface': {'method', 'signal', 'property', 'annotation'},
               'method': {'arg', 'annotation'}, 'signal': {'arg', 'annotation'},
               'property': {'annotation'}, 'arg': {'annotation'}, 'annotation': set()}
    attributes = {'node': set(), 'interface': {'name'}, 'method': {'name'}, 'signal': {'name'},
                  'property': {'name', 'type', 'access'}, 'arg': {'name', 'type', 'direction'},
                  'annotation': {'name', 'value'}}
    stack, count = [(root, 0)], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_XML_ITEMS or depth > 8 or node.tag not in grammar or not set(node.attrib).issubset(attributes[node.tag]):
            raise Pending('unsupported DHCP XML shape or size')
        if node.text and node.text.strip() or node.tail and node.tail.strip():
            raise Pending('unexpected DHCP XML text')
        required = {'interface': {'name'}, 'method': {'name'}, 'signal': {'name'},
                    'property': {'name', 'type', 'access'}, 'arg': {'type'},
                    'annotation': {'name', 'value'}, 'node': set()}
        if not required[node.tag].issubset(node.attrib):
            raise Pending('missing DHCP XML member attributes')
        if node.tag == 'property' and node.attrib['access'] not in ('read', 'write', 'readwrite'):
            raise Pending('invalid DHCP XML property access')
        if node.tag == 'arg' and 'direction' in node.attrib and node.attrib['direction'] not in ('in', 'out'):
            raise Pending('invalid DHCP XML argument direction')
        for item in node.attrib.values():
            if len(item) > 255 or any(not 32 <= ord(char) <= 126 for char in item):
                raise Pending('invalid DHCP XML attribute')
        for child in node:
            if child.tag not in grammar[node.tag]:
                raise Pending('invalid DHCP XML nesting')
            stack.append((child, depth + 1))
    names = set()
    for interface in root:
        if set(interface.attrib) != {'name'}:
            raise Pending('missing DHCP XML interface name')
        name = interface.attrib['name']
        if name in names or name not in CORE | set(CLIENTS.values()):
            raise Pending('duplicate or unsupported DHCP interface')
        names.add(name)
        required_members = {'org.freedesktop.DBus.Peer': {'Ping', 'GetMachineId'},
                            INTROSPECT: {'Introspect'}, PROPERTIES: {'Get', 'GetAll', 'Set'}}
        if name in required_members and not required_members[name].issubset({item.attrib['name'] for item in interface if item.tag == 'method'}):
            raise Pending('incomplete DHCP introspection core methods')
        if name == LINK and not any(item.tag == 'property' and item.attrib == {'name': 'AdministrativeState', 'type': 's', 'access': 'read'} for item in interface):
            raise Pending('incomplete DHCP link introspection')
        if name in CLIENTS.values():
            members = [item for item in interface if item.tag != 'annotation']
            if len(members) != 1 or members[0].tag != 'property' or members[0].attrib != {'name': 'State', 'type': 's', 'access': 'read'}:
                raise Pending('unverifiable DHCP State property')
    if not CORE.issubset(names):
        raise Pending('incomplete DHCP introspection interface inventory')
    return xml, {family for family, name in CLIENTS.items() if name in names}


def read_inventory(deadline, query=native_query, scope=TIMESYNC.process_scope):
    if not KERNEL.finite_deadline(deadline) or deadline <= KERNEL.now():
        raise Pending('invalid or expired DHCP observation deadline')
    owner = TIMESYNC.owner_name(TIMESYNC.reply(query('owner', deadline), 's'))
    pid = TIMESYNC.reply(query('pid', deadline, owner=owner), 'u')
    if KERNEL.uint(pid) == 0:
        raise Pending('missing DHCP manager PID')
    namespace = variant(query('namespace', deadline, owner=owner), 't')
    if KERNEL.uint(namespace, (1 << 64) - 1) == 0 or namespace != scope(pid) or namespace != KERNEL.namespace():
        raise Pending('DHCP manager and observer namespaces differ')
    inventory = links(query('links', deadline, owner=owner))
    records = []
    for item in inventory:
        if item['name'] == 'lo':
            continue
        index = item['index']
        before, families = client_interfaces(query('introspect', deadline, owner=owner, index=index))
        admin = variant(query('admin', deadline, owner=owner, index=index), 's')
        if type(admin) is not str or admin not in ('configured', 'configuring'):
            raise Pending('interface is not managed by the admitted networkd profile')
        record = item | {'administrative': admin}
        for family in (4, 6):
            state = None
            if family in families:
                state = variant(query('state' + str(family), deadline, owner=owner, index=index), 's')
                if type(state) is not str or state not in STATES[family]:
                    raise Pending('unknown or inconsistent DHCP client state')
            # True means instantiated, including stopped clients; it does not
            # claim an active lease, successful packets or absence of others.
            record['dhcp' + str(family)] = family in families
            record['state' + str(family)] = state
        if client_interfaces(query('introspect', deadline, owner=owner, index=index))[0] != before:
            raise Pending('DHCP client interfaces changed during state queries')
        records.append(record)
    if links(query('links', deadline, owner=owner)) != inventory:
        raise Pending('DHCP manager link identities changed')
    if KERNEL.uint(variant(query('namespace', deadline, owner=owner), 't'), (1 << 64) - 1) != namespace or scope(pid) != namespace:
        raise Pending('DHCP manager namespace changed')
    if KERNEL.uint(TIMESYNC.reply(query('pid', deadline, owner=owner), 'u')) != pid:
        raise Pending('DHCP manager PID changed')
    if TIMESYNC.owner_name(TIMESYNC.reply(query('owner', deadline), 's')) != owner or KERNEL.namespace() != namespace or KERNEL.now() >= deadline:
        raise Pending('DHCP manager owner changed or observation expired')
    return {'owner': owner, 'pid': pid, 'namespace': namespace, 'links': inventory, 'interfaces': records}


def bind_inventory(inventory, topology):
    if inventory['namespace'] != topology['namespace']:
        raise Pending('DHCP inventory and topology namespaces differ')
    expected = {row['name']: row for row in topology['interfaces']}
    records = inventory['interfaces']
    if {row['name'] for row in records} != set(expected):
        raise Pending('DHCP manager and kernel interface inventories differ')
    for row in records:
        link = expected[row['name']]
        if row['index'] != link['index'] or (row['dhcp4'] or row['dhcp6']) and not link['up']:
            raise Pending('DHCP interface is changed or inactive')
    return records


def observe(read=read_inventory, topology=KERNEL.observe):
    deadline = KERNEL.now() + ATTEMPT_SECONDS
    first = read(deadline)
    kernel = topology(deadline=deadline)
    bind_inventory(first, kernel)
    if read(deadline) != first:
        raise Pending('DHCP clients changed during observation')
    second = topology(deadline=deadline)
    if second != kernel:
        raise Pending('kernel topology changed during DHCP observation')
    records = bind_inventory(first, second)
    if read(deadline) != first or KERNEL.namespace() != second['namespace'] or KERNEL.now() >= deadline:
        raise Pending('DHCP facts changed or expired before publication')
    return {'schema': 'debian13s4-networkd-dhcp-1', 'kernel': second,
            'source': {'service': SERVICE, 'owner': first['owner'], 'pid': first['pid']},
            'interfaces': records}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        result = observe()
        payload = json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n'
        if len(payload.encode()) > KERNEL.MAX_BYTES:
            raise Pending('DHCP observation too large')
        sys.stdout.write(payload)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'debian13s4 DHCP observation pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
