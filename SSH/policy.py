#!/usr/bin/python3
"""Derive and check LAN-bound SSH for one existing local administrator.

This does not create credentials, configure an address or attest client locality.
The IPv6 allocation is used only when a usable assignment is actually reported.
Native delivery and the local account database belong to the trusted-base profile.
"""

import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location('debian13s4_ssh_kernel',
    Path(__file__).resolve().parents[1] / 'firewall/kernel.py')
if not SPEC.origin or not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_ssh_kernel',
        Path(__file__).resolve().parents[1] / 'Firewall/kernel.py')
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending
ETC = Path('/etc')
HOME = Path('/home')
CONFIG = ETC / 'ssh/debian13s4-admin.conf'
HOST_KEY = ETC / 'ssh/ssh_host_ed25519_key'
SSHD = Path('/usr/sbin/sshd')
SS = Path('/usr/bin/ss')
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
ADMIN4 = ipaddress.ip_network('192.168.90.0/24')
ADMIN6 = ipaddress.ip_network('fd51:b089:f5e0:90::/64')
MAX_BYTES = 262144
ATTEMPT_SECONDS = 60
NAME = re.compile(r'[a-z_][a-z0-9_-]{0,31}\Z')
ACCOUNT_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z')


def fence(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('SSH observation window expired')


def trusted_read(path, owners=(0,), private=False):
    """Read a bounded unique leaf through a checked no-follow descriptor."""
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending('noncanonical SSH input path')
    path.relative_to(TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        if not (stat.S_ISREG(info.st_mode) if current == path else stat.S_ISDIR(info.st_mode)):
            raise Pending('symbolic or unsupported SSH input')
        allowed = owners if current == path or HOME in current.parents else (TRUSTED_UID,)
        if info.st_uid not in allowed or info.st_mode & 0o022:
            raise Pending('unprotected SSH input or ancestry')
        if current == TRUST_ROOT:
            break
        current = current.parent
    before = path.lstat()
    if before.st_nlink != 1 or before.st_size > MAX_BYTES or private and before.st_mode & 0o077:
        raise Pending('nonunique, oversized or nonprivate SSH input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before):
            raise Pending('SSH input descriptor differs')
        data = bytearray()
        while True:
            part = os.read(descriptor, min(65536, MAX_BYTES + 1 - len(data)))
            if not part:
                break
            data.extend(part)
            if len(data) > MAX_BYTES:
                raise Pending('SSH input byte bound exceeded')
        if (KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before) or
            KERNEL.signature(path.lstat()) != KERNEL.signature(before) or len(data) != before.st_size):
            raise Pending('SSH input changed during read')
    finally:
        # Linux retires the number even when close reports an error: never retry.
        os.close(descriptor)
    return bytes(data), {'path': str(path), 'identity': list(KERNEL.signature(before)),
                         'sha256': hashlib.sha256(data).hexdigest()}


def database(raw, width):
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('unsupported local account encoding') from error
    if not text.endswith('\n') or '\x00' in text or len(text.splitlines()) > 4096:
        raise Pending('invalid local account database')
    result, names = [], set()
    for line in text.splitlines():
        fields = line.split(':')
        if len(fields) != width or ACCOUNT_NAME.fullmatch(fields[0]) is None or fields[0] in names:
            raise Pending('malformed or duplicate local account row')
        names.add(fields[0]); result.append(fields)
    return result


def number(value, maximum=0x7fffffff):
    if type(value) is not str or re.fullmatch(r'0|[1-9][0-9]{0,9}', value) is None:
        raise Pending('invalid local account number')
    return KERNEL.uint(int(value), maximum)


def public_keys(raw):
    try:
        text = raw.decode('utf-8')
    except UnicodeError as error:
        raise Pending('invalid administrator key encoding') from error
    if not text.endswith('\n') or '\x00' in text or len(text.splitlines()) > 64:
        raise Pending('invalid administrator key inventory')
    seen = set()
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        words = line.split()
        if len(line.encode('utf-8')) > 16384 or len(words) < 2 or words[0] not in ('ssh-ed25519', 'ssh-rsa'):
            # Do not strip options, certificates or constraints to widen a key.
            raise Pending('unsupported administrator key or key options')
        try:
            wire = base64.b64decode(words[1], validate=True)
        except (ValueError, UnicodeError) as error:
            raise Pending('invalid administrator key wire encoding') from error
        if base64.b64encode(wire).decode('ascii') != words[1] or wire in seen:
            raise Pending('noncanonical or duplicate administrator key')
        parts, offset = [], 0
        while offset < len(wire):
            if len(wire) - offset < 4:
                raise Pending('truncated administrator key')
            size = struct.unpack_from('!I', wire, offset)[0]; offset += 4
            if size > 16384 or size > len(wire) - offset:
                raise Pending('invalid administrator key field')
            parts.append(wire[offset:offset + size]); offset += size
        if not parts or parts[0] != words[0].encode('ascii'):
            raise Pending('administrator key type disagreement')
        if words[0] == 'ssh-ed25519':
            if len(parts) != 2 or len(parts[1]) != 32:
                raise Pending('invalid Ed25519 key shape')
        else:
            if len(parts) != 3 or any(not part or part[0] & 128 or
                len(part) > 1 and part[0] == 0 and not part[1] & 128 for part in parts[1:]):
                raise Pending('invalid RSA positive mpint')
            exponent, modulus = (int.from_bytes(part, 'big') for part in parts[1:])
            if exponent < 65537 or not exponent & 1 or not 3072 <= modulus.bit_length() <= 8192 or not modulus & 1:
                raise Pending('unsupported RSA key size or exponent')
        seen.add(wire)
    if not seen:
        raise Pending('no existing supported administrator key')
    return len(seen)


def administrator():
    contents, sources = {}, {}
    for name, width in (('passwd', 7), ('group', 4), ('shadow', 9)):
        raw, sources[name] = trusted_read(ETC / name, (TRUSTED_UID,))
        if name == 'shadow' and sources[name]['identity'][2] & 0o007:
            raise Pending('shadow database is readable by other users')
        contents[name] = database(raw, width)
    groups = {row[0]: row for row in contents['group']}
    if 'sudo' not in groups:
        raise Pending('no existing local sudo administrator group')
    sudo_gid = number(groups['sudo'][2])
    members = groups['sudo'][3].split(',') if groups['sudo'][3] else []
    if len(members) != len(set(members)) or any(NAME.fullmatch(name) is None for name in members):
        raise Pending('invalid local administrator membership')
    eligible, uids = [], set()
    for row in contents['passwd']:
        uid, gid = number(row[2]), number(row[3])
        if uid in uids:
            raise Pending('duplicate local UID')
        uids.add(uid)
        if 1000 <= uid <= 59999 and (row[0] in members or gid == sudo_gid):
            eligible.append(row)
    if len(eligible) != 1:
        raise Pending('administrator discovery is missing or ambiguous')
    user = eligible[0]; name, uid, gid = user[0], number(user[2]), number(user[3])
    if (NAME.fullmatch(name) is None or user[1] != 'x' or user[5] != str(HOME / name) or
        user[6] not in ('/bin/bash', '/usr/bin/bash')):
        raise Pending('unsupported existing administrator account')
    shadows = [row for row in contents['shadow'] if row[0] == name]
    if len(shadows) != 1 or not shadows[0][1].startswith(('$y$', '$6$')) or len(shadows[0][1]) < 32:
        raise Pending('administrator password is absent, locked or unsupported')
    # Password expiry must not silently turn a key-only unattended login into
    # a required password-change dialogue. Native PAM authentication is separate.
    if shadows[0][2] in ('', '0') or shadows[0][6:9] != ['', '', '']:
        raise Pending('expired or restricted existing administrator account')
    last_change = number(shadows[0][2])
    ages = [number(value) if value else None for value in shadows[0][3:6]]
    wall = time.time()
    if not KERNEL.finite_deadline(wall) or wall <= 0:
        raise Pending('invalid trusted account-age clock')
    day = int(wall // 86400)
    if (last_change > day or ages[1] is not None and day - last_change >= ages[1] or
        ages[0] is not None and ages[1] is not None and ages[0] > ages[1]):
        raise Pending('administrator password age requires native recovery')
    key_path = HOME / name / '.ssh/authorized_keys'
    keys, sources['keys'] = trusted_read(key_path, (TRUSTED_UID, uid), True)
    directory = key_path.parent.lstat()
    if directory.st_mode & 0o077:
        raise Pending('administrator key directory is not private')
    return {'name': name, 'uid': uid, 'gid': gid, 'key_file': str(key_path),
            'key_count': public_keys(keys), 'sources': sources}


def copied(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop(); count += 1
        if count > 65536 or depth > 16:
            raise Pending('SSH delivery structure exceeds bounds')
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise Pending('nonstring SSH delivery key')
            stack.extend((entry, depth + 1) for entry in (*item.keys(), *item.values()))
        elif type(item) is list:
            stack.extend((entry, depth + 1) for entry in item)
        elif item is not None and type(item) not in (str, int, bool):
            raise Pending('unsupported SSH delivery scalar')
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(raw) > KERNEL.MAX_BYTES:
        raise Pending('SSH delivery byte bound exceeded')
    return json.loads(raw, object_pairs_hook=KERNEL.unique_object)


def checked_admin(value):
    fields = {'name', 'uid', 'gid', 'key_file', 'key_count', 'sources'}
    KERNEL.known(value, fields, fields)
    name = value['name']
    if type(name) is not str or NAME.fullmatch(name) is None or not 1000 <= KERNEL.uint(value['uid'], 59999):
        raise Pending('invalid SSH administrator identity')
    KERNEL.uint(value['gid'], 0x7fffffff)
    if value['key_file'] != str(HOME / name / '.ssh/authorized_keys') or not 1 <= KERNEL.uint(value['key_count'], 64):
        raise Pending('invalid SSH administrator key identity')
    KERNEL.known(value['sources'], {'passwd', 'group', 'shadow', 'keys'}, {'passwd', 'group', 'shadow', 'keys'})
    for key, source in value['sources'].items():
        KERNEL.known(source, {'path', 'identity', 'sha256'}, {'path', 'identity', 'sha256'})
        expected = value['key_file'] if key == 'keys' else str(ETC / key)
        identity = source['identity']
        if (source['path'] != expected or type(identity) is not list or len(identity) != 8 or
            any(type(part) is not int for part in identity) or
            not stat.S_ISREG(identity[2]) or identity[2] & 0o022 or identity[1] <= 0 or
            not 0 <= identity[0] <= (1 << 64) - 1 or not identity[1] <= (1 << 64) - 1 or
            not 0 <= identity[2] <= 0o177777 or not 0 <= identity[4] <= 0xffffffff or
            any(not -(1 << 63) <= timestamp < (1 << 63) for timestamp in identity[6:]) or
            identity[3] not in ((TRUSTED_UID, value['uid']) if key == 'keys' else (TRUSTED_UID,)) or
            not 0 <= identity[5] <= MAX_BYTES or key == 'keys' and identity[2] & 0o077 or
            key == 'shadow' and identity[2] & 0o007 or type(source['sha256']) is not str or
            re.fullmatch('[0-9a-f]{64}', source['sha256']) is None):
            raise Pending('invalid SSH account delivery source')
    return value


def network(snapshot, observed=0):
    interfaces = KERNEL.normalize(snapshot)
    admitted, loopback, names, expiry = [], [], set(), None
    by_name = {item['name']: item for item in interfaces}
    for row in snapshot['addresses']:
        if row['ifname'] == 'lo':
            if not {'UP', 'LOWER_UP', 'LOOPBACK'}.issubset(KERNEL.flags(row['flags'])):
                raise Pending('loopback is not active')
            for address in row['addr_info']:
                if address['local'] in ('127.0.0.1', '::1'):
                    if (address.get('scope') not in ('host', '254') or
                        any(type(address[flag]) is not bool or address[flag] for flag in
                            ('tentative', 'dadfailed', 'deprecated', 'temporary', 'optimistic') if flag in address) or
                        any(not KERNEL.uint(address.get(key)) for key in ('valid_life_time', 'preferred_life_time')) or
                        address['local'] in loopback):
                        raise Pending('loopback assignment is not positively usable')
                    loopback.append(address['local'])
                    until = observed + min(address[key] for key in ('valid_life_time', 'preferred_life_time'))
                    expiry = min(expiry, until) if expiry is not None else until
            continue
        link = by_name[row['ifname']]
        for address in row['addr_info']:
            version = 4 if address['family'] == 'inet' else 6
            ip = KERNEL.address(address['local'], version)
            prefix = ADMIN4 if version == 4 else ADMIN6
            if ip not in prefix:
                continue
            if not link['up'] or address['prefixlen'] != prefix.prefixlen or address.get('scope') not in ('global', '0'):
                raise Pending('admin address lacks active exact-prefix global assignment')
            for flag in ('dynamic', 'mngtmpaddr', 'noprefixroute', 'tentative', 'dadfailed', 'deprecated',
                         'temporary', 'secondary', 'optimistic', 'permanent'):
                if flag in address and type(address[flag]) is not bool:
                    raise Pending('admin assignment flag is not Boolean')
            if any(address.get(flag, False) for flag in ('tentative', 'dadfailed', 'deprecated', 'temporary', 'optimistic')):
                raise Pending('admin assignment is not usable')
            if any(not KERNEL.uint(address.get(key)) for key in ('valid_life_time', 'preferred_life_time')):
                raise Pending('admin assignment has no positive typed lifetimes')
            until = observed + min(address[key] for key in ('valid_life_time', 'preferred_life_time'))
            expiry = min(expiry, until) if expiry is not None else until
            routes = [entry for entry in snapshot[f'routes{version}']
                      if entry.get('dev') == link['name'] and entry['dst'] == str(prefix)
                      and KERNEL.table(entry.get('table', 254)) == 254
                      and KERNEL.route_type(entry.get('type', 'unicast')) == 'unicast'
                      and 'gateway' not in entry and 'linkdown' not in entry.get('flags', [])
                      and entry.get('scope') in ('link', '253')]
            if (len(routes) != 1 or ip == prefix.network_address or version == 4 and ip == prefix.broadcast_address or
                'prefsrc' in routes[0] and routes[0]['prefsrc'] != str(ip)):
                raise Pending('admin assignment lacks one supported direct route')
            if str(ip) in admitted:
                raise Pending('duplicate admin listener assignment')
            names.add(link['name']); admitted.append(str(ip))
    if len(names) != 1 or '127.0.0.1' not in loopback or not any(ipaddress.ip_address(value).version == 4 for value in admitted):
        raise Pending('one active IPv4 admin interface is required')
    return {'interface': by_name[next(iter(names))], 'listeners': sorted(admitted),
            'loopback': sorted(loopback), 'kernel': interfaces}, expiry


def configuration(admin, binding):
    lines = ['# Generated from checked local administrator and assigned admin addresses.',
        'Port 22', 'AddressFamily any', 'PermitRootLogin no', 'AuthenticationMethods publickey',
        'PubkeyAuthentication yes', 'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
        'PermitEmptyPasswords no', 'HostbasedAuthentication no', 'GSSAPIAuthentication no', 'UsePAM yes',
        'StrictModes yes', 'IgnoreRhosts yes', 'UseDNS no', 'PermitUserEnvironment no',
        'DisableForwarding yes', 'PermitTunnel no', 'X11Forwarding no', 'PermitTTY yes',
        'MaxAuthTries 3', 'MaxSessions 4', 'MaxStartups 10:30:30', 'LoginGraceTime 30',
        'ClientAliveInterval 120', 'ClientAliveCountMax 2', 'LogLevel VERBOSE',
        f'HostKey {HOST_KEY}', 'PidFile /run/debian13s4-admin-ssh.pid',
        'PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
        f'AuthorizedKeysFile {admin["key_file"]}',
        f'AllowUsers {admin["name"]}@127.0.0.1/32 {admin["name"]}@::1/128 '
        f'{admin["name"]}@{ADMIN4} {admin["name"]}@{ADMIN6}']
    for value in [*binding['loopback'], *binding['listeners']]:
        lines.append(f'ListenAddress [{value}]:22' if ':' in value else f'ListenAddress {value}:22')
    return ('\n'.join(lines) + '\n').encode('ascii')


def prepare(query=KERNEL.native_query, account=administrator, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid SSH preparation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = scope()
    if not KERNEL.uint(namespace, (1 << 64) - 1):
        raise Pending('invalid SSH namespace')
    first_admin = checked_admin(copied(account()))
    records = []
    for _ in range(2):
        fence(end)
        raw, observed = {}, None
        for name in KERNEL.COMMANDS:
            fence(end)
            raw[name] = copied(query(name, end))
            if name == 'addresses':
                observed = KERNEL.now()
        raw = copied(raw)
        binding, expiry = network(raw, observed)
        end = min(end, expiry)
        fence(end)
        records.append({'raw': raw, 'binding': binding})
    last_admin = checked_admin(copied(account()))
    if first_admin != last_admin or records[0] != records[1]:
        raise Pending('SSH administrator or network deliveries changed')
    payload = configuration(last_admin, records[1]['binding'])
    if len(payload) > MAX_BYTES:
        raise Pending('SSH configuration exceeds byte bound')
    final_namespace = scope()
    if not KERNEL.uint(final_namespace, (1 << 64) - 1) or final_namespace != namespace:
        raise Pending('SSH namespace changed')
    fence(end)
    return {'namespace': namespace, 'admin': last_admin, 'binding': records[1]['binding'],
            'configuration': payload, 'deadline': end}


def capture(binary, arguments, deadline):
    fence(deadline)
    if type(arguments) is not tuple or any(type(argument) is not str for argument in arguments) or not (
        binary == SSHD and arguments in (('-t', '-f', str(CONFIG)), ('-T', '-f', str(CONFIG))) or
        binary == SS and arguments == ('-H', '-n', '-l', '-t', '-p', 'sport = :22')):
        raise Pending('unapproved SSH native read')
    identity = KERNEL.trusted_binary(binary)
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    fence(end)
    process = subprocess.Popen([str(binary), *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                fence(end)
                for key, _ in selector.select(end - KERNEL.now()):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj); continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending('SSH native channel limit exceeded')
                    buffer.extend(data)
            fence(end)
            code = process.wait(timeout=end - KERNEL.now())
            if type(code) is not int or code != 0 or buffers['stderr']:
                raise Pending('SSH native check failed or warned')
        if KERNEL.trusted_binary(binary) != identity:
            raise Pending('SSH native executable changed')
        fence(end)
        return bytes(buffers['stdout'])
    finally:
        try:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            process.stdout.close(); process.stderr.close()


def effective(raw, plan):
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('invalid effective sshd encoding') from error
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(' ')
        if not separator or not re.fullmatch('[a-z0-9]+', key) or not value or '\x00' in value:
            raise Pending('invalid effective sshd row')
        if key in values and key not in ('listenaddress', 'hostkey', 'allowusers'):
            raise Pending('duplicate effective sshd setting')
        values.setdefault(key, []).append(value)
    required = {'port': '22', 'addressfamily': 'any', 'permitrootlogin': 'no',
        'authenticationmethods': 'publickey', 'pubkeyauthentication': 'yes',
        'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
        'permitemptypasswords': 'no', 'hostbasedauthentication': 'no', 'gssapiauthentication': 'no',
        'usepam': 'yes', 'strictmodes': 'yes', 'usedns': 'no', 'permituserenvironment': 'no',
        'disableforwarding': 'yes', 'permittunnel': 'no', 'x11forwarding': 'no',
        'authorizedkeysfile': plan['admin']['key_file'], 'authorizedkeyscommand': 'none',
        'trustedusercakeys': 'none', 'authorizedprincipalsfile': 'none',
        'pubkeyacceptedalgorithms': 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'}
    for key, value in required.items():
        if values.get(key) != [value]:
            raise Pending(f'effective sshd setting differs: {key}')
    users = f'{plan["admin"]["name"]}@127.0.0.1/32 {plan["admin"]["name"]}@::1/128 '
    users += f'{plan["admin"]["name"]}@{ADMIN4} {plan["admin"]["name"]}@{ADMIN6}'
    admitted_users = [pattern for row in values.get('allowusers', []) for pattern in row.split()]
    if admitted_users != users.split() or values.get('hostkey') != [str(HOST_KEY)]:
        raise Pending('effective sshd user/key authority differs')
    listeners = {f'[{value}]:22' if ':' in value else f'{value}:22'
                 for value in [*plan['binding']['loopback'], *plan['binding']['listeners']]}
    if len(values.get('listenaddress', [])) != len(listeners) or set(values.get('listenaddress', [])) != listeners:
        raise Pending('effective sshd listeners differ')


def sockets(raw, plan, pid):
    if not KERNEL.uint(pid, 0x7fffffff):
        raise Pending('invalid SSH service PID')
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('invalid SSH socket encoding') from error
    expected = {f'[{value}]:22' if ':' in value else f'{value}:22'
                for value in [*plan['binding']['loopback'], *plan['binding']['listeners']]}
    found = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 6 or parts[0] != 'LISTEN' or not all(re.fullmatch('[0-9]+', part) for part in parts[1:3]):
            raise Pending('unsupported SSH listening socket row')
        number(parts[1], 0xffffffff); number(parts[2], 0xffffffff)
        owner = re.fullmatch(r'users:\(\("sshd",pid=([1-9][0-9]*),fd=([0-9]+)\)\)', parts[5])
        if (owner is None or int(owner[1]) != pid or parts[3] not in expected or parts[3] in found or
            parts[4] not in ('0.0.0.0:*', '[::]:*', '*:*')):
            raise Pending('SSH listener is missing, foreign, duplicate or public')
        number(owner[1]); number(owner[2])
        found.add(parts[3])
    if found != expected:
        raise Pending('partial SSH listener inventory')


def check(plan=None, read=capture, live_pid=None):
    plan = prepare() if plan is None else plan
    fence(plan['deadline'])
    config, config_source = trusted_read(CONFIG, (TRUSTED_UID,), True)
    host_key = trusted_read(HOST_KEY, (TRUSTED_UID,), True)
    if config != plan['configuration']:
        raise Pending('installed SSH configuration differs from fresh preparation')
    if read(SSHD, ('-t', '-f', str(CONFIG)), plan['deadline']):
        raise Pending('sshd syntax check produced unexpected output')
    effective(read(SSHD, ('-T', '-f', str(CONFIG)), plan['deadline']), plan)
    if live_pid is not None:
        sockets(read(SS, ('-H', '-n', '-l', '-t', '-p', 'sport = :22'), plan['deadline']), plan, live_pid)
    if trusted_read(CONFIG, (TRUSTED_UID,), True) != (config, config_source) or trusted_read(
        HOST_KEY, (TRUSTED_UID,), True) != host_key:
        raise Pending('SSH configuration or host key changed during native checks')
    namespace = KERNEL.namespace()
    if not KERNEL.uint(namespace, (1 << 64) - 1) or administrator() != plan['admin'] or namespace != plan['namespace']:
        raise Pending('SSH account or namespace changed during native checks')
    fence(plan['deadline'])


def main():
    if sys.argv[1:] not in (['--plan'], ['--check']) and not (
        len(sys.argv) == 3 and sys.argv[1] == '--live' and re.fullmatch('[1-9][0-9]{0,9}', sys.argv[2])):
        return 64
    if sys.argv[1] == '--live' and int(sys.argv[2]) > 0x7fffffff:
        return 64
    try:
        sink = sys.stdout.buffer
        if not callable(sink.write) or not callable(sink.flush):
            raise Pending('SSH CLI requires a binary sink')
        if sys.argv[1] == '--plan':
            payload = prepare()['configuration']
            count = sink.write(payload)
            if type(count) is not int or count != len(payload):
                raise Pending('incomplete SSH configuration publication')
            sink.flush()
        else:
            check(live_pid=int(sys.argv[2]) if sys.argv[1] == '--live' else None)
        return 0
    except (OSError, ValueError, AttributeError, subprocess.TimeoutExpired, RecursionError) as error:
        print(f'debian13s4 SSH pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
