#!/usr/bin/python3
"""Observe one systemd-timesyncd peer without activating or configuring a service.

This partial record is not a compiler input or an installed firewall controller.
Other time daemons and link-local IPv6 need separate, positively scoped adapters.
"""

import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_resolver', Path(__file__).with_name('resolver.py'))
RESOLVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESOLVER)
KERNEL = RESOLVER.KERNEL
Pending = KERNEL.Pending
BUS_BINARY = Path('/usr/bin/busctl')
SERVICE = 'org.freedesktop.timesync1'
OBJECT = '/org/freedesktop/timesync1'
INTERFACE = SERVICE + '.Manager'
BUS = ('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus')
MAX_BYTES = 65536
MAX_SERVERS = 256
ATTEMPT_SECONDS = 60
PROPERTIES = {
    'LinkNTPServers': 'as', 'SystemNTPServers': 'as', 'RuntimeNTPServers': 'as',
    'FallbackNTPServers': 'as', 'ServerName': 's', 'ServerAddress': '(iay)',
    'RootDistanceMaxUSec': 't', 'PollIntervalMinUSec': 't',
    'PollIntervalMaxUSec': 't', 'PollIntervalUSec': 't',
    'NTPMessage': '(uuuuittayttttbtt)', 'Frequency': 'x',
}


def owner_name(value):
    if type(value) is not str or re.fullmatch(r':[1-9][0-9]{0,9}\.(?:0|[1-9][0-9]{0,9})', value) is None:
        raise Pending('unverifiable time-service bus owner')
    for part in value[1:].split('.'):
        KERNEL.uint(int(part))
    return value


def native_query(operation, deadline, owner=None):
    if type(operation) is not str or operation not in ('owner', 'pid', 'peer'):
        raise Pending('time query is not an admitted read-only operation')
    if operation == 'owner':
        if owner is not None:
            raise Pending('owner query cannot override its service')
        arguments = (*BUS, 'GetNameOwner', 's', SERVICE)
    else:
        owner_name(owner)
        arguments = (*BUS, 'GetConnectionUnixProcessID', 's', owner) if operation == 'pid' else (
            owner, OBJECT, 'org.freedesktop.DBus.Properties', 'GetAll', 's', INTERFACE)
    if not KERNEL.finite_deadline(deadline):
        raise Pending('invalid time-query deadline')
    identity = KERNEL.trusted_binary(BUS_BINARY)
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    if KERNEL.now() >= end:
        raise Pending('time-query deadline expired')
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
                    raise Pending('time query timed out')
                for key, _ in selector.select(remaining):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending('time query output limit exceeded')
                    buffer.extend(data)
            remaining = end - KERNEL.now()
            if remaining <= 0 or process.wait(timeout=remaining) != 0 or buffers['stderr']:
                raise Pending('time query failed or warned')
        if KERNEL.trusted_binary(BUS_BINARY) != identity:
            raise Pending('time-query binary changed')
        try:
            return json.loads(buffers['stdout'].decode('utf-8'), object_pairs_hook=KERNEL.unique_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Pending('invalid time-query JSON') from error
    except subprocess.TimeoutExpired as error:
        raise Pending('time query timed out after pipe closure') from error
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


def reply(value, signature):
    KERNEL.known(value, {'type', 'data'}, ('type', 'data'))
    if value['type'] != signature or type(value['data']) is not list or len(value['data']) != 1:
        raise Pending('unexpected time-query reply signature or arity')
    return value['data'][0]


def text(value, empty=True):
    if type(value) is not str or len(value) > 255 or any(not 32 <= ord(char) <= 126 for char in value) or not empty and not value:
        raise Pending('invalid native time-server name')
    return value


def signed(value, bits):
    if type(value) is not int or not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        raise Pending('invalid signed time value')


def byte_array(value, size):
    if type(value) is not list or len(value) != size:
        raise Pending('invalid time-service address bytes')
    return bytes(KERNEL.uint(item, 255) for item in value)


def properties(value):
    values = reply(value, 'a{sv}')
    KERNEL.known(values, set(PROPERTIES), tuple(PROPERTIES))
    for name, signature in PROPERTIES.items():
        entry = values[name]
        KERNEL.known(entry, {'type', 'data'}, ('type', 'data'))
        if entry['type'] != signature:
            raise Pending('unexpected time-service property signature')
        item = entry['data']
        if signature == 's':
            text(item, empty=False)
        elif signature == 'as':
            if type(item) is not list or len(item) > MAX_SERVERS:
                raise Pending('oversized time-server inventory')
            for server in item:
                text(server, empty=False)
        elif signature == 't':
            KERNEL.uint(item, (1 << 64) - 1)
        elif signature == 'x':
            signed(item, 64)
        elif signature == '(uuuuittayttttbtt)':
            if type(item) is not list or len(item) != 15:
                raise Pending('invalid native NTP message')
            for index in (0, 1, 2, 3):
                KERNEL.uint(item[index])
            signed(item[4], 32)
            byte_array(item[7], 4)
            if type(item[12]) is not bool:
                raise Pending('invalid NTP message boolean')
            for index in (5, 6, 8, 9, 10, 11, 13, 14):
                KERNEL.uint(item[index], (1 << 64) - 1)
    family = values['ServerAddress']['data']
    if type(family) is not list or len(family) != 2 or type(family[0]) is not int or family[0] not in (2, 10):
        raise Pending('no selected IPv4 or IPv6 time-server address')
    ip = ipaddress.ip_address(byte_array(family[1], 4 if family[0] == 2 else 16))
    KERNEL.address(str(ip), ip.version)
    # This API omits sin6_scope_id. A stable forced lookup cannot reconstruct
    # the daemon's configured scope, so no link-local IPv6 permission is made.
    if ip.version == 6 and ip.is_link_local:
        raise Pending('time-service API lacks link-local IPv6 scope')
    return {'name': values['ServerName']['data'], 'address': str(ip)}


def process_scope(pid):
    if KERNEL.uint(pid) == 0:
        raise Pending('missing time-service PID')
    value = os.readlink(f'/proc/{pid}/ns/net')
    match = re.fullmatch(r'net:\[([0-9]+)\]', value)
    if match is None:
        raise Pending('unverifiable time-service network namespace')
    return int(match[1])


def read_peer(deadline, query=native_query, scope=process_scope):
    if not KERNEL.finite_deadline(deadline) or deadline <= KERNEL.now():
        raise Pending('invalid or expired time-peer deadline')
    owner = owner_name(reply(query('owner', deadline), 's'))
    pid = reply(query('pid', deadline, owner=owner), 'u')
    if KERNEL.uint(pid) == 0:
        raise Pending('missing time-service PID')
    first_scope = scope(pid)
    peer = properties(query('peer', deadline, owner=owner))
    if scope(pid) != first_scope or KERNEL.namespace() != first_scope:
        raise Pending('time-service network namespace changed or differs')
    if owner_name(reply(query('owner', deadline), 's')) != owner or KERNEL.now() >= deadline:
        raise Pending('time-service owner changed or observation expired')
    return peer | {'owner': owner, 'pid': pid, 'namespace': first_scope}


def observe(read=read_peer, topology=KERNEL.observe, route=KERNEL.native_route):
    deadline = KERNEL.now() + ATTEMPT_SECONDS
    first = read(deadline)
    first_kernel = topology(deadline=deadline)
    if first['namespace'] != first_kernel['namespace']:
        raise Pending('time peer and kernel namespaces differ')
    first_route = route(first['address'], None, deadline)
    endpoint = RESOLVER.bind_route(first['address'], None, first_route, first_kernel['interfaces'])
    if read(deadline) != first:
        raise Pending('time peer changed during observation')
    second_kernel = topology(deadline=deadline)
    if second_kernel != first_kernel:
        raise Pending('kernel topology changed during time observation')
    second_route = route(first['address'], None, deadline)
    if second_route != first_route or RESOLVER.bind_route(first['address'], None, second_route, second_kernel['interfaces']) != endpoint:
        raise Pending('time-peer route changed during observation')
    if read(deadline) != first or KERNEL.namespace() != first_kernel['namespace'] or KERNEL.now() >= deadline:
        raise Pending('time observation changed or expired before publication')
    return {'schema': 'debian13s4-timesync-1', 'kernel': second_kernel,
            'source': {'service': SERVICE, 'owner': first['owner'], 'pid': first['pid'], 'name': first['name']},
            'ntp': [endpoint]}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        result = observe()
        payload = json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n'
        if len(payload.encode()) > KERNEL.MAX_BYTES:
            raise Pending('time observation too large')
        sys.stdout.write(payload)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'debian13s4 time observation pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
