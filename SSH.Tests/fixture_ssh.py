"""Ordinary-UID fixtures; native account, IP, sshd, socket and PID1 deliveries are models."""

import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import struct
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('fixed_private_dispatch', ROOT / 'Firewall.Tests/fixture_dispatch.py')
DISPATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DISPATCH)


def load():
    spec = importlib.util.spec_from_file_location('ssh_policy', ROOT / 'SSH/policy.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def topology(ipv6=True):
    loop = {'ifindex': 1, 'ifname': 'lo', 'flags': ['UP', 'LOWER_UP', 'LOOPBACK'],
            'link_type': '[772]', 'address': '00:00:00:00:00:00'}
    link = {'ifindex': 2, 'ifname': 'enp1s0', 'flags': ['UP', 'LOWER_UP', 'BROADCAST', 'MULTICAST'],
            'link_type': '[1]', 'address': '02:00:00:00:00:90'}
    def address(family, local, length, scope='global'):
        return {'family': family, 'local': local, 'prefixlen': length, 'scope': scope,
                'valid_life_time': 4294967295, 'preferred_life_time': 4294967295}
    loops = [address('inet', '127.0.0.1', 8, 'host')]
    assigned = [address('inet', '192.168.90.10', 24)]
    if ipv6:
        loops.append(address('inet6', '::1', 128, 'host'))
        assigned.append(address('inet6', 'fd51:b089:f5e0:90::10', 64))
    return {'links': [loop, link],
        'addresses': [copy.deepcopy(loop) | {'addr_info': loops}, copy.deepcopy(link) | {'addr_info': assigned}],
        'routes4': [{'dst': '192.168.90.0/24', 'dev': 'enp1s0', 'table': 254, 'scope': 'link',
                     'prefsrc': '192.168.90.10', 'flags': []}],
        'routes6': [{'dst': 'fd51:b089:f5e0:90::/64', 'dev': 'enp1s0', 'table': 254,
                     'scope': 'link', 'flags': []}] if ipv6 else [],
        'rules4': [{'priority': 0, 'src': 'all', 'table': 255}, {'priority': 32766, 'src': 'all', 'table': 254}],
        'rules6': [{'priority': 0, 'src': 'all', 'table': 255}, {'priority': 32766, 'src': 'all', 'table': 254}] if ipv6 else [],
        'neighbors4': [], 'neighbors6': [], 'proxy4': [], 'proxy6': []}


def key():
    wire = b''.join(struct.pack('!I', len(part)) + part for part in (b'ssh-ed25519', b'\x01' * 32))
    return b'ssh-ed25519 ' + base64.b64encode(wire) + b' private fixture\n'


class PrivateSSH:
    def __init__(self):
        if os.geteuid() == 0:
            raise RuntimeError('Run SSH fixtures as an ordinary user.')
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-ssh.', dir='/dev/shm')
        self.root = Path(self.directory.name); self.root.chmod(0o700)
        self.etc = self.root / 'etc'; self.home = self.root / 'home'
        for path in (self.etc, self.home, self.etc / 'ssh', self.home / 'operator', self.home / 'operator/.ssh',
                     self.root / 'native', self.root / 'state', self.root / 'systemd', self.root / 'library',
                     self.root / 'library/ssh', self.root / 'library/firewall', self.root / 'library/maintenance'):
            path.mkdir(mode=0o700)
        uid, gid = os.geteuid(), os.getegid()
        self.write(self.etc / 'passwd',
                   (f'root:x:0:0:root:/root:/bin/bash\noperator:x:{uid}:{gid}::{self.home}/operator:/bin/bash\n').encode())
        self.write(self.etc / 'group', f'root:x:0:\nsudo:x:27:operator\noperator:x:{gid}:\n'.encode())
        self.write(self.etc / 'shadow', b'root:!:20000:0:99999:7:::\noperator:$y$j9T$fixture$'
                   b'0123456789012345678901234567890123456789:20000:0:99999:7:::\n')
        self.write(self.home / 'operator/.ssh/authorized_keys', key())
        self.write(self.etc / 'ssh/ssh_host_ed25519_key', b'PRIVATE HOST KEY DELIVERY MODEL\n')
        self.data = topology()
        self.module = load(); self.configure(self.module)
        self.ledger = self.root / 'native.jsonl'
        self.ip = self.root / 'native/ip'; self.sshd = self.root / 'native/sshd'; self.ss = self.root / 'native/ss'
        for name in ('common.sh', 'policy.py', 'repair.sh', 'debian13s4-admin-ssh.service',
                     'debian13s4-ssh.service', 'debian13s4-ssh.timer'):
            self.write(self.root / 'library/ssh' / name, (ROOT / 'SSH' / name).read_bytes(), 0o700 if name == 'repair.sh' else 0o600)
        self.write(self.root / 'library/firewall/kernel.py', (ROOT / 'Firewall/kernel.py').read_bytes())
        self.write(self.root / 'library/maintenance/common.sh', (ROOT / 'Maintenance/common.sh').read_bytes())
        self.wrapper = self.root / 'policy-driver.py'
        body = f'''import importlib.util, os, pathlib, sys
root = pathlib.Path({str(self.root)!r})
spec = importlib.util.spec_from_file_location('production_ssh', root / 'library/ssh/policy.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.ETC, m.HOME, m.TRUST_ROOT, m.TRUSTED_UID = root/'etc', root/'home', root, os.geteuid()
m.CONFIG, m.HOST_KEY = root/'etc/ssh/debian13s4-admin.conf', root/'etc/ssh/ssh_host_ed25519_key'
m.SSHD, m.SS = root/'native/sshd', root/'native/ss'
m.KERNEL.IP_BINARY, m.KERNEL.TRUST_ROOT, m.KERNEL.TRUSTED_UID = root/'native/ip', root, os.geteuid()
m.KERNEL.namespace = lambda: 4711
m.prepare.__defaults__ = (m.KERNEL.native_query, m.administrator, m.KERNEL.namespace, None)
raise SystemExit(m.main())
'''
        self.write(self.wrapper, body.encode())
        self.database = self.root / 'manager.json'
        self.write(self.database, json.dumps({'active': {}, 'enabled': {}, 'packages': False, 'faults': {}}).encode())
        self.model = self.root / 'manager.py'; self.write(self.model, MODEL.encode())

    def close(self):
        self.directory.cleanup()

    @staticmethod
    def write(path, data, mode=0o600):
        path.write_bytes(data); path.chmod(mode)

    def configure(self, module):
        module.ETC, module.HOME, module.TRUST_ROOT, module.TRUSTED_UID = self.etc, self.home, self.root, os.geteuid()
        module.CONFIG, module.HOST_KEY = self.etc / 'ssh/debian13s4-admin.conf', self.etc / 'ssh/ssh_host_ed25519_key'
        module.KERNEL.TRUST_ROOT, module.KERNEL.TRUSTED_UID = self.root, os.geteuid()
        module.KERNEL.namespace = lambda: 4711
        module.prepare.__defaults__ = (module.KERNEL.native_query, module.administrator, module.KERNEL.namespace, None)

    def query(self, name, deadline):
        return copy.deepcopy(self.data[name])

    def plan(self):
        return self.module.prepare(query=self.query)

    def effective(self, plan):
        entries = {}
        for line in plan['configuration'].decode().splitlines():
            if line.startswith('#'):
                continue
            name, value = line.split(' ', 1)
            entries.setdefault(name.lower(), []).append(value)
        entries.update({'authorizedkeyscommand': ['none'], 'trustedusercakeys': ['none'],
                        'authorizedprincipalsfile': ['none']})
        return ''.join(f'{name} {value}\n' for name, values in entries.items() for value in values).encode()

    def sockets(self, plan, pid=42342):
        values = [*plan['binding']['loopback'], *plan['binding']['listeners']]
        rows = []
        for index, value in enumerate(values):
            local = f'[{value}]:22' if ':' in value else f'{value}:22'
            peer = '[::]:*' if ':' in value else '0.0.0.0:*'
            rows.append(f'LISTEN 0 128 {local} {peer} users:(("sshd",pid={pid},fd={index + 3}))\n')
        return ''.join(rows).encode()

    def install_native(self, effective=None, sockets=None):
        plan = self.plan()
        self.module.KERNEL.IP_BINARY = self.ip
        self.module.SSHD, self.module.SS = self.sshd, self.ss
        replies = {('-j', '-N', *arguments): json.dumps(self.data[name]) + '\n'
                   for name, arguments in self.module.KERNEL.COMMANDS.items()}
        self.write(self.ip, DISPATCH.script(self.ledger, 'ip', replies).encode(), 0o700)
        replies = {('-t', '-f', str(self.module.CONFIG)): '',
                   ('-T', '-f', str(self.module.CONFIG)): (self.effective(plan) if effective is None else effective).decode('ascii')}
        self.write(self.sshd, DISPATCH.script(self.ledger, 'sshd', replies).encode(), 0o700)
        replies = {('-H', '-n', '-l', '-t', '-p', 'sport = :22'): (self.sockets(plan) if sockets is None else sockets).decode('ascii')}
        self.write(self.ss, DISPATCH.script(self.ledger, 'ss', replies).encode(), 0o700)
        return plan

    def controller(self, command):
        q = shlex.quote
        return f'''
set -Eeuo pipefail
umask 077
source {q(str(ROOT / 'Maintenance/common.sh'))}
source /dev/stdin <<'SSH_COMMON'
{(ROOT / 'SSH/common.sh').read_text().replace('. /usr/local/lib/debian13s4/maintenance/common.sh', '# fixture already loaded production maintenance')}
SSH_COMMON
S4M_STATE={q(str(self.root / 'state'))}
S4M_SYSTEMD={q(str(self.root / 'systemd'))}
S4M_LIBRARY={q(str(self.root / 'library/maintenance'))}
S4S_LIBRARY={q(str(self.root / 'library/ssh'))}
S4S_CONFIG={q(str(self.module.CONFIG))}
S4S_HOST_KEY={q(str(self.module.HOST_KEY))}
S4S_SSHD={q(str(self.sshd))}
s4m_trusted() {{
    local path=$1 owner mode
    [[ $path == {q(str(self.root))} || $path == {q(str(self.root))}/* ]] || return 1
    while :; do
        [[ -e $path && ! -L $path ]] || return 1
        read -r owner mode < <(/usr/bin/stat --format='%u %a' -- "$path") || return 1
        [[ $owner == "$EUID" ]] && (( (8#$mode & 8#022) == 0 )) || return 1
        [[ $path == {q(str(self.root))} ]] && return 0
        path=${{path%/*}}
    done
}}
stat() {{
    if [[ $1 == --format=%u && $3 == "$S4M_SYSTEMD"/* ]]; then
        printf '0\\n'
    else
        /usr/bin/stat "$@"
    fi
}}
s4m_systemctl() {{ /usr/bin/python3 -B {q(str(self.model))} {q(str(self.root))} systemctl "$@"; }}
s4m_sync() {{ /usr/bin/python3 -B {q(str(self.model))} {q(str(self.root))} sync "$@"; }}
s4s_policy() {{ /usr/bin/python3 -I -B {q(str(self.wrapper))} "$@"; }}
s4s_packages() {{ return 0; }}
s4p_prepare() {{ return 0; }}
s4p_apply() {{ /usr/bin/python3 -B {q(str(self.model))} {q(str(self.root))} packages; }}
s4p_verify() {{ /usr/bin/python3 -B {q(str(self.model))} {q(str(self.root))} package-verify; }}
{command}
'''


MODEL = r'''
import json, pathlib, sys
root, action, *args = sys.argv[1:]
root = pathlib.Path(root); database = root / 'manager.json'
state = json.loads(database.read_text()); faults = state['faults']; systemd = root / 'systemd'
code, output = 0, ''
if action == 'sync':
    assert args and all(pathlib.Path(arg).exists() for arg in args), args
    if (faults.get('sync') or faults.get('sync_ready') and any('ssh.ready' in arg for arg in args) or
        faults.get('sync_loaded') and any('ssh.loaded' in arg for arg in args)): code = 1
elif action == 'packages':
    assert all((systemd / name).is_symlink() and (systemd / name).readlink() == pathlib.Path('/dev/null')
               for name in ('ssh.service', 'ssh.socket', 'sshd.service'))
    if faults.get('packages'): code = 1
    else: state['packages'] = True
elif action == 'package-verify':
    code = 0 if state['packages'] and not faults.get('package_verify') else 1
elif action == 'systemctl':
    operation, unit = args[0], args[-1]
    if faults.get(operation) or faults.get(operation + '_' + unit): code = 1
    elif operation == 'show':
        if args[:-1] == ['show', '--property=ActiveState', '--property=MainPID', '--property=InvocationID']:
            active = state['active'].get(unit, False)
            output = ('MainPID=' + ('42342' if active else '0') + '\nActiveState=' +
                      ('active' if active else 'inactive') + '\nInvocationID=' +
                      (state.get('invocations', {}).get(unit, '') if active else ''))
            if faults.get('instance_reply'): output = faults['instance_reply']
        else:
            assert len(args) == 4 and args[2] == '--value', args
            prop = args[1].split('=', 1)[1]; path = systemd / unit
            if prop == 'LoadState': output = 'masked' if path.is_symlink() else 'loaded' if path.is_file() else 'not-found'
            elif prop == 'ActiveState': output = 'active' if state['active'].get(unit) else 'inactive'
            elif prop == 'FragmentPath': output = str(path)
            elif prop == 'DropInPaths': output = 'foreign.conf' if faults.get('dropin') else ''
            elif prop == 'MainPID': output = '42342' if state['active'].get(unit) else '0'
            elif prop == 'InvocationID': output = state.get('invocations', {}).get(unit, '') if state['active'].get(unit) else ''
            else: raise AssertionError(prop)
    elif operation == 'stop':
        if not faults.get('stop_incomplete'): state['active'][unit] = False
        if unit == 'debian13s4-admin-ssh.service' and faults.get('damage_after_stop'):
            (root / 'etc/ssh/ssh_host_ed25519_key').chmod(0o644)
    elif operation == 'mask':
        assert unit in ('ssh.service', 'ssh.socket', 'sshd.service')
        path = systemd / unit
        if not path.is_symlink(): path.symlink_to('/dev/null')
    elif operation == 'daemon-reload': pass
    elif operation == 'enable':
        assert unit in ('debian13s4-admin-ssh.service', 'debian13s4-ssh.timer')
        directory = systemd / ('timers.target.wants' if unit.endswith('.timer') else 'multi-user.target.wants')
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / unit
        if not path.is_symlink(): path.symlink_to(systemd / unit)
        state['enabled'][unit] = True
    elif operation == 'is-enabled':
        enabled = state['enabled'].get(unit, False)
        output, code = ('enabled', 0) if enabled else ('disabled', 1)
    elif operation == 'start':
        if not faults.get('start_incomplete') and not state['active'].get(unit):
            state['active'][unit] = True
            if unit == 'debian13s4-admin-ssh.service':
                state['server_starts'] = state.get('server_starts', 0) + 1
                state.setdefault('invocations', {})[unit] = format(state['server_starts'], '032x')
                # These are private daemon-start DELIVERY snapshots. Fresh
                # -t/-T replies remain disk models and cannot update them.
                state['loaded_configuration'] = (root / 'etc/ssh/debian13s4-admin.conf').read_bytes().hex()
                key = root / 'etc/ssh/ssh_host_ed25519_key'
                state['loaded_host_key'] = key.read_bytes().hex()
                if faults.get('damage_after_start'): key.write_bytes(key.read_bytes() + b'changed after start\n')
    else: raise AssertionError(args)
else: raise AssertionError(action)
database.write_text(json.dumps(state))
with (root / 'events.jsonl').open('a') as stream:
    stream.write(json.dumps({'action': action, 'args': args, 'code': code}) + '\n')
if output: print(output)
raise SystemExit(code)
'''
