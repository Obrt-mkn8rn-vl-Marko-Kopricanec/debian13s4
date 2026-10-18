#!/usr/bin/python3
"""Prepare PARTIAL preprovisioned mk8.dns replica service intentions only.

No binaries, accounts, snapshots, directories, units or network are installed,
published, started or queried. Binary paths and zone IDs are explicit caller
intentions, not checked releases or usable signed catalogs. The existing
application must have provisioned active signed snapshots; this profile has
no controller, publication, TSIG, transfer, signing or renewal authority.
"""

import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_dns_inputs',
    Path(__file__).resolve().parents[1] / 'PostgreSQL/prepare.py')
if not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_dns_inputs',
        Path(__file__).resolve().parents[1] / 'postgresql/prepare.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
KERNEL = BASE.KERNEL
Pending = BASE.Pending
INPUT = Path('/etc/debian13s4/dns.json')
PASSWD = Path('/etc/passwd')
GROUP = Path('/etc/group')
MAX_INPUT = 8192
MAX_INVENTORY = 262144
MAX_OUTPUT = 65537
ATTEMPT_SECONDS = 10
SOCKET = '/run/debian13s4-dns/query.sock'
STATE = '/var/lib/debian13s4-dns'
APP_UNIT = 'debian13s4-dns-application.service'
# Product CLI fields and supported capacity bounds, not deployment defaults.
BUDGETS = {'udp-response-rate': (1, 1000000), 'udp-response-burst': (1, 1000000),
    'udp-byte-rate': (1, 1000000000), 'udp-byte-burst': (512, 1000000000),
    'udp-global-response-rate': (1, 1000000), 'udp-global-response-burst': (1, 1000000),
    'udp-global-byte-rate': (1, 1000000000), 'udp-global-byte-burst': (512, 1000000000),
    'udp-prefix-limit': (1, 65536)}
NAME = re.compile(r'[a-z][a-z0-9_]{0,30}\Z')


def name(value):
    if type(value) is not str or NAME.fullmatch(value) is None or value == 'root':
        raise Pending('unsupported explicit DNS service identity')
    return value


def binary_path(value):
    if (type(value) is not str or not 6 <= len(value) <= 240 or
        re.fullmatch(r'/opt/[A-Za-z0-9_./-]+', value) is None or
        any(part in ('', '.', '..') for part in value.split('/')[1:]) or
        os.path.normpath(value) != value):
        raise Pending('unsupported explicit DNS binary path')
    return value


def address(value):
    if type(value) is not str or '%' in value:
        raise Pending('DNS bind address requires a literal without a scope alias')
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise Pending('invalid DNS bind address') from error
    if (str(parsed) != value or parsed.is_unspecified or parsed.is_multicast or
        parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or
        parsed.version == 4 and int(parsed) < 0x01000000 or
        parsed.version == 6 and (parsed.ipv4_mapped is not None or parsed.is_site_local)):
        raise Pending('unsupported explicit unicast DNS bind address')
    return parsed.version


def checked(value):
    fields = {'schema', 'application_user', 'gateway_user', 'ipc_group',
        'application_binary', 'gateway_binary', 'node', 'zones', 'listeners', 'budgets'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported DNS intention schema')
    identities = [name(value[k]) for k in ('application_user', 'gateway_user', 'ipc_group')]
    if len(set(identities)) != 3:
        raise Pending('DNS service accounts and IPC group must be distinct')
    binaries = [binary_path(value[k]) for k in ('application_binary', 'gateway_binary')]
    if binaries[0] == binaries[1]:
        raise Pending('DNS application and gateway binaries must be distinct')
    if (type(value['node']) is not str or
        re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value['node']) is None):
        raise Pending('unsupported explicit DNS node')
    zones = value['zones']
    if (type(zones) is not list or not 1 <= len(zones) <= 64 or
        any(type(z) is not str or re.fullmatch(r'[0-9a-f]{32}', z) is None or
            z == '0'*32 for z in zones) or len(set(zones)) != len(zones)):
        raise Pending('DNS requires distinct nonempty canonical zone IDs')
    listeners = value['listeners']
    if type(listeners) is not list or not 1 <= len(listeners) <= 2:
        raise Pending('DNS requires one or two explicit family listeners')
    families, health = set(), set()
    for row in listeners:
        KERNEL.known(row, {'address', 'health_port'}, {'address', 'health_port'})
        family = address(row['address']); port = row['health_port']
        if type(port) is not int or not 1024 <= port <= 65535 or port == 5432:
            raise Pending('unsupported explicit DNS loopback health port')
        if family in families or port in health:
            raise Pending('DNS listeners share a family or health port')
        families.add(family); health.add(port)
    KERNEL.known(value['budgets'], set(BUDGETS), set(BUDGETS))
    for field, (minimum, maximum) in BUDGETS.items():
        number = value['budgets'][field]
        if type(number) is not int or not minimum <= number <= maximum:
            raise Pending('unsupported explicit DNS response budget')
    return json.loads(BASE.canonical(value))


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite DNS input')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid DNS JSON input') from error
    if raw != BASE.canonical(value):
        raise Pending('DNS input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def records(raw, columns):
    if type(raw) is not bytes or len(raw) > MAX_INVENTORY:
        raise Pending('unsupported DNS account inventory bytes')
    if (not raw.endswith(b'\n') or
        any(c != 10 and not 32 <= c <= 126 for c in raw)):
        raise Pending('DNS inventory requires printable ASCII and exact LF records')
    lines = raw[:-1].decode('ascii').split('\n')
    if len(lines) > 4096:
        raise Pending('DNS account inventory exceeds its row bound')
    rows = {}
    for line in lines:
        fields = line.split(':')
        if (len(fields) != columns or
            re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', fields[0]) is None or
            fields[0] in rows):
            raise Pending('malformed or duplicate DNS account inventory')
        rows[fields[0]] = fields
    return rows


def numeric(text):
    if re.fullmatch(r'0|[1-9][0-9]{0,9}', text) is None:
        raise Pending('noncanonical DNS inventory numeric identity')
    return KERNEL.uint(int(text), 0x7fffffff)


def accounts(passwd, group, settings):
    settings = checked(settings)
    users = records(passwd, 7); groups = records(group, 4)
    primary, uids, gids, membership = {}, set(), set(), {}
    for account, row in users.items():
        uid, gid = numeric(row[2]), numeric(row[3])
        if uid in uids:
            raise Pending('ambiguous DNS account UID')
        uids.add(uid); primary[account] = (uid, gid)
    for group_name, row in groups.items():
        gid = numeric(row[2]); members = row[3].split(',') if row[3] else []
        if (gid in gids or len(members) != len(set(members)) or
            any(member not in users for member in members)):
            raise Pending('ambiguous DNS group identity or membership')
        gids.add(gid); membership[group_name] = (gid, set(members))
    selected = [settings['application_user'], settings['gateway_user']]
    result = {}
    for account in selected:
        if account not in users or account not in groups:
            raise Pending('DNS service account or dedicated primary group is missing')
        row = users[account]; uid, gid = primary[account]
        if (not 100 <= uid <= 999 or gid == 0 or row[1] not in ('x', '!', '*') or
            row[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false') or
            membership[account][0] != gid or membership[account][1] - {account} or
            any(other != account and other_gid == gid for other, (_, other_gid) in primary.items())):
            raise Pending('DNS requires dedicated nonlogin system accounts')
        result[account] = {'uid': uid, 'primary_gid': gid, 'shell': row[6]}
    ipc = settings['ipc_group']
    if (ipc not in membership or membership[ipc][0] == 0 or
        membership[ipc][1] != set(selected) or
        any(gid == membership[ipc][0] for _, gid in primary.values())):
        raise Pending('DNS IPC group must contain only the two explicit supplementary members')
    for group_name, (_, members) in membership.items():
        for account in selected:
            if account in members and group_name not in (account, ipc):
                raise Pending('DNS service account has unsupported supplementary membership')
    return {'users': result, 'ipc_group': {'name': ipc, 'gid': membership[ipc][0]}}


def render(settings):
    settings = checked(settings)
    shared = ('Type=exec\nRestart=no\nUMask=0077\nNoNewPrivileges=yes\n'
        'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
        'RestrictSUIDSGID=yes\nLockPersonality=yes\n'
        'KillMode=control-group\nTimeoutStartSec=30\nTimeoutStopSec=30\n'
        'StandardOutput=journal\nStandardError=journal\n')
    app_argv = [settings['application_binary'], '--socket', SOCKET, '--state', STATE,
        '--node', settings['node'], '--role', 'authoritative-replica',
        '--zones', ','.join(settings['zones'])]
    for field in BUDGETS:
        app_argv.extend(('--'+field, str(settings['budgets'][field])))
    application = ('[Unit]\nDescription=Private mk8.dns preprovisioned replica\n'
        '[Service]\n' + shared + f"User={settings['application_user']}\n"
        f"Group={settings['ipc_group']}\nWorkingDirectory={Path(settings['application_binary']).parent}\n"
        'RuntimeDirectory=debian13s4-dns\nRuntimeDirectoryMode=0710\n'
        'RuntimeDirectoryPreserve=yes\n'
        f'ReadWritePaths={STATE} /run/debian13s4-dns\n'
        'RestrictAddressFamilies=AF_UNIX\nCapabilityBoundingSet=\nAmbientCapabilities=\n'
        'ExecStart='+' '.join(app_argv)+'\n[Install]\nWantedBy=multi-user.target\n')
    units = {APP_UNIT: application}; argv = {APP_UNIT: app_argv}; listeners = []
    for row in settings['listeners']:
        family = address(row['address'])
        unit = f'debian13s4-dns-gateway{family}.service'
        command = [settings['gateway_binary'], '--socket', SOCKET, '--role', 'query',
            '--health-port', str(row['health_port']), '--dns-address', row['address'], '--dns-port', '53']
        units[unit] = ('[Unit]\nDescription=Public mk8.dns query gateway\n'
            f'Requires={APP_UNIT}\nAfter={APP_UNIT} network-online.target\n'
            'Wants=network-online.target\n[Service]\n'+shared+
            f"User={settings['gateway_user']}\nGroup={settings['ipc_group']}\n"
            f"WorkingDirectory={Path(settings['gateway_binary']).parent}\n"
            f'InaccessiblePaths={STATE}\n'
            'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'
            'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'
            'ExecStart='+' '.join(command)+'\n[Install]\nWantedBy=multi-user.target\n')
        argv[unit] = command
        listeners.append({'unit': unit, 'address': row['address'], 'port': 53,
            'transports': ['udp', 'tcp'], 'health_address': '127.0.0.1',
            'health_port': row['health_port']})
    return {'units': units, 'argv': argv, 'listeners': listeners,
        'ipc': {'socket': SOCKET, 'directory_mode': '0710', 'socket_mode': '0660'},
        'state_directory': STATE}


def prepare(deadline=None, scope=KERNEL.namespace):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited DNS deadline')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(scope(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing DNS caller namespace')
    settings = configuration(end)
    passwd, user_source = BASE.read_protected(PASSWD, MAX_INVENTORY, False, end)
    group, group_source = BASE.read_protected(GROUP, MAX_INVENTORY, False, end)
    selected = accounts(passwd, group, settings['value'])
    plan = render(settings['value'])
    record = {'schema': 1, 'profile': 'mk8-dns-preprovisioned-static-replica-intention-v1',
        'state': 'dns-service-intention-only', 'namespace': context, 'configuration': settings,
        'user_source': user_source, 'group_source': group_source, 'accounts': selected,
        'plan': plan, 'unit_sha256': {k: hashlib.sha256(v.encode('ascii')).hexdigest()
            for k, v in plan['units'].items()}}
    payload = BASE.canonical(record)
    if len(payload) > MAX_OUTPUT:
        raise Pending('DNS service intention exceeds its complete output bound')
    if configuration(end) != settings:
        raise Pending('DNS input changed during preparation')
    for path, raw, source in ((PASSWD, passwd, user_source), (GROUP, group, group_source)):
        after, after_source = BASE.read_protected(path, MAX_INVENTORY, False, end)
        if after != raw or after_source != source:
            raise Pending('DNS account or group inventory changed')
    if KERNEL.uint(scope(), 0xffffffffffffffff) != context:
        raise Pending('DNS caller namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('DNS preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('DNS preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete DNS intention publication')
        sink.flush()
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == '__main__':
    sys.exit(main())
