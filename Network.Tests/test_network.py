import configparser
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


if os.geteuid() == 0:
    raise RuntimeError('Run these disposable fixtures as an ordinary user.')
ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'debian13s4-network.service'
TIMER = 'debian13s4-network.timer'


def load(path=ROOT / 'Network/verify.py'):
    spec = importlib.util.spec_from_file_location('network_policy', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def trust(root, path, kind):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path) or root not in (path, *path.parents):
        raise ValueError('outside private fixture')
    current = path
    while True:
        info = current.lstat()
        if not (kind if current == path else stat.S_ISDIR)(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('untrusted private fixture')
        if current == root:
            return path.lstat()
        current = current.parent


def populate(module, proc, ipv6=True, interface='enp1s0'):
    families = [('ipv4', module.IPV4), ('ipv6', module.IPV6)] if ipv6 else [('ipv4', module.IPV4)]
    for family, settings in families:
        for name in ('all', 'default', 'lo', interface):
            directory = proc / 'net' / family / 'conf' / name
            directory.mkdir(parents=True, exist_ok=True)
            for key, expected in settings.items():
                path = directory / key
                path.write_text(str(expected) + '\n'); path.chmod(0o600)
    for key, expected in module.GLOBALS.items():
        path = proc / 'net/ipv4' / key
        path.write_text(str(expected) + '\n'); path.chmod(0o600)
    for path in proc.rglob('*'):
        if path.is_dir(): path.chmod(0o700)
    proc.chmod(0o700)


# Production predicate and private files/locks/renames are real. Root ancestry,
# procfs location, kernel writes, systemctl and filesystem sync are substituted.
# No writable host /proc/sys path is admitted by this delivery model.
MODEL = r'''
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
root, action, *args = sys.argv[1:]
root = Path(root)
db = root / 'manager.json'
state = json.loads(db.read_text())
fault = state['faults']
code, output = 0, ''
spec = importlib.util.spec_from_file_location('production_predicate', root / 'library/verify.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.PROC = root / 'proc'
def trust(path, kind):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path) or root not in (path, *path.parents):
        raise ValueError('outside private fixture')
    current = path
    while True:
        info = current.lstat()
        if not (kind if current == path else stat.S_ISDIR)(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('untrusted private fixture')
        if current == root: return path.lstat()
        current = current.parent
m.trusted = trust
if action == 'observe':
    sys.argv = [str(root / 'library/verify.py')]
    code = m.main()
elif action == 'kernel':
    assert args == ['--strict', str(root / 'etc/sysctl.d/90-debian13s4-network.conf')], args
    if fault.get('kernel'): code = 1
    elif not fault.get('kernel_noop'):
        for key, value in m.GLOBALS.items():
            (m.PROC / 'net/ipv4' / key).write_text(str(value) + '\n')
        for family, settings in [('ipv4', m.IPV4), ('ipv6', m.IPV6)]:
            base = m.PROC / 'net' / family / 'conf'
            if not base.exists(): continue
            for directory in base.iterdir():
                for key, value in settings.items():
                    if fault.get('kernel_partial') and directory.name == 'enp1s0' and key == 'accept_redirects': continue
                    (directory / key).write_text(str(value) + '\n')
elif action == 'sync':
    assert all(Path(arg).exists() for arg in args), args
    if fault.get('sync') or (fault.get('sync_ready') and any('network.ready' in arg for arg in args)): code = 1
elif action == 'systemctl':
    command, unit = args[0], args[-1]
    if fault.get(command): code = 1
    elif command == 'show':
        prop = args[1].split('=', 1)[1]
        if prop == 'LoadState': output = 'loaded' if (root / 'systemd' / unit).is_file() else 'not-found'
        elif prop == 'ActiveState': output = 'active' if state['active'].get(unit) else 'inactive'
        elif prop == 'FragmentPath': output = str(root / 'systemd' / unit)
        elif prop == 'DropInPaths': output = 'foreign.conf' if fault.get('dropin') else ''
        else: raise AssertionError(prop)
    elif command == 'stop':
        if not fault.get('stop_incomplete'): state['active'][unit] = False
    elif command == 'daemon-reload': pass
    elif command == 'enable':
        assert unit == 'debian13s4-network.timer'
        directory = root / 'systemd/timers.target.wants'; directory.mkdir(mode=0o700, exist_ok=True)
        link = directory / unit
        if not link.is_symlink(): link.symlink_to(root / 'systemd' / unit)
        state['enabled'] = True
    elif command == 'is-enabled':
        output = 'enabled' if state['enabled'] else 'disabled'; code = 0 if state['enabled'] else 1
    elif command == 'start':
        if not fault.get('start_incomplete'): state['active'][unit] = True
    else: raise AssertionError(args)
else: raise AssertionError(action)
db.write_text(json.dumps(state))
with (root / 'events.jsonl').open('a') as stream:
    stream.write(json.dumps({'action': action, 'args': args, 'code': code}) + '\n')
if output: print(output)
sys.exit(code)
'''


class PredicateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-network-predicate.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.proc = self.root / 'proc'
        self.module = load(); self.module.PROC = self.proc
        self.module.trusted = lambda path, kind: trust(self.root, path, kind)
        populate(self.module, self.proc)

    def test_complete_ipv4_and_ipv6_policy_passes(self):
        self.module.verify()

    def test_dotted_vlan_and_literal_glob_interface_names_are_observed(self):
        source = self.proc / 'net/ipv4/conf/enp1s0'; source.rename(source.with_name('enp1s0.123'))
        source = self.proc / 'net/ipv6/conf/enp1s0'; source.rename(source.with_name('test[0]'))
        self.module.verify()

    def test_every_required_scalar_detects_drift(self):
        for path in self.proc.rglob('*'):
            if path.is_file():
                old = path.read_bytes(); path.write_text('9\n')
                with self.subTest(path=path.relative_to(self.proc)), self.assertRaises(ValueError): self.module.verify()
                path.write_bytes(old)
        self.module.verify()

    def test_absent_ipv6_passes_but_partial_namespace_fails(self):
        import shutil
        shutil.rmtree(self.proc / 'net/ipv6'); self.module.verify()
        (self.proc / 'net/ipv6').mkdir(mode=0o700)
        with self.assertRaises(FileNotFoundError): self.module.verify()

    def test_missing_inventory_or_scalar_never_certifies(self):
        path = self.proc / 'net/ipv4/conf/default'; path.rename(path.with_name('renamed'))
        with self.assertRaises(ValueError): self.module.verify()
        path.with_name('renamed').rename(path)
        (self.proc / 'net/ipv6/conf/enp1s0/accept_source_route').unlink()
        with self.assertRaises(FileNotFoundError): self.module.verify()

    def test_fifo_socket_directory_and_symbolic_scalar_are_rejected(self):
        path = self.proc / 'net/ipv4/conf/enp1s0/accept_redirects'
        victim = self.root / 'victim'; victim.write_bytes(b'unchanged\n')
        identity = (victim.stat().st_ino, victim.read_bytes())
        for kind in ('fifo', 'socket', 'directory', 'symbolic'):
            path.unlink(missing_ok=True); handle = None
            if kind == 'fifo': os.mkfifo(path, 0o600)
            elif kind == 'socket':
                handle = socket.socket(socket.AF_UNIX); handle.bind(str(path))
            elif kind == 'directory': path.mkdir(mode=0o700)
            else: path.symlink_to(victim)
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.module.verify()
            self.assertEqual((victim.stat().st_ino, victim.read_bytes()), identity)
            if handle: handle.close()
            if kind == 'directory': path.rmdir()
            else: path.unlink()

    def test_symbolic_namespace_and_untrusted_modes_fail(self):
        path = self.proc / 'net/ipv6'; path.rename(path.with_name('saved-v6')); path.symlink_to(path.with_name('saved-v6'))
        with self.assertRaises(ValueError): self.module.verify()
        path.unlink(); path.with_name('saved-v6').rename(path)
        (path / 'conf/enp1s0/accept_redirects').chmod(0o622)
        with self.assertRaises(ValueError): self.module.verify()

    def test_changed_descriptor_and_read_errors_fail(self):
        path = self.proc / 'net/ipv4/ip_forward'
        with mock.patch.object(self.module.os, 'fstat', side_effect=lambda fd: path.parent.stat()):
            with self.assertRaises(ValueError): self.module.value(path)
        with mock.patch.object(self.module.os, 'read', side_effect=OSError('read failed')):
            with self.assertRaises(OSError): self.module.value(path)
        self.module.verify()

    def test_invalid_or_oversized_scalars_fail(self):
        path = self.proc / 'net/ipv4/ip_forward'
        for data in (b'', b'0 trailing\n', b'0\n1\n', b'0' * 65, b'\xff\n'):
            path.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(ValueError): self.module.value(path)

    def test_changing_inventory_and_excessive_count_fail(self):
        original = self.module.interfaces; count = 0
        def changing(family):
            nonlocal count
            count += 1; names = original(family)
            return names + ['late0'] if count > 2 and names is not None else names
        with mock.patch.object(self.module, 'interfaces', side_effect=changing):
            with self.assertRaisesRegex(ValueError, 'inventory changed'): self.module.verify()
        self.module.MAX_INTERFACES = 1
        with self.assertRaisesRegex(ValueError, 'too many'): self.module.verify()

    def test_native_proc_scalar_is_read_only_and_trusted(self):
        self.assertIn(load().value(Path('/proc/sys/net/ipv4/ip_forward')), (0, 1))

    def test_persisted_policy_covers_predicate_and_forwarding_precedes_reset(self):
        text = (ROOT / 'Network/network.conf').read_text()
        rows = [line.split(' = ') for line in text.splitlines() if line and not line.startswith('#')]
        expected = {f'net/ipv4/{key}': str(value) for key, value in self.module.GLOBALS.items()}
        for family, settings in [('ipv4', self.module.IPV4), ('ipv6', self.module.IPV6)]:
            for interface in ('all', 'default', '*'):
                for key, value in settings.items(): expected[f'net/{family}/conf/{interface}/{key}'] = str(value)
        self.assertEqual(rows[0], ['net/ipv4/ip_forward', '0'])
        self.assertEqual(len(rows), len(expected))
        self.assertEqual({key.lstrip('-'): value for key, value in rows}, expected)
        self.assertLess(text.index('net/ipv4/conf/default/forwarding'), text.index('net/ipv4/conf/*/forwarding'))
        self.assertFalse(any('disable_ipv6' in key or 'accept_ra' in key or 'autoconf' in key or 'ip_no_pmtu_disc' in key for key in expected))


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-network-controller.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.library = self.root / 'library'; self.state = self.root / 'state'
        self.systemd = self.root / 'systemd'; self.shared = self.root / 'shared'; self.etc = self.root / 'etc'
        for path in (self.library, self.state, self.systemd, self.shared, self.etc): path.mkdir(mode=0o700)
        for source in (ROOT / 'Network').iterdir():
            target = self.library / source.name; target.write_bytes(source.read_bytes())
            target.chmod(0o755 if source.name == 'repair.sh' else 0o644)
        target = self.shared / 'common.sh'; target.write_bytes((ROOT / 'Maintenance/common.sh').read_bytes()); target.chmod(0o644)
        self.model = self.root / 'delivery.py'; self.model.write_text(MODEL)
        self.db = self.root / 'manager.json'; self.db.write_text(json.dumps({'enabled': False, 'active': {}, 'faults': {}}))
        self.proc = self.root / 'proc'; populate(load(), self.proc)
        self.config = self.etc / 'sysctl.d/90-debian13s4-network.conf'

    def harness(self):
        q = shlex.quote
        common = (self.library / 'common.sh').read_text().replace('. /usr/local/lib/debian13s4/maintenance/common.sh', '. ' + q(str(self.shared / 'common.sh')))
        return f'''set -Eeuo pipefail
umask 077
{common}
S4M_LIBRARY={q(str(self.shared))}
S4M_STATE={q(str(self.state))}
S4M_SYSTEMD={q(str(self.systemd))}
S4N_LIBRARY={q(str(self.library))}
S4N_CONFIG={q(str(self.config))}
s4m_trusted() {{
    local path=$1 mode
    [[ $path == {q(str(self.root))} || $path == {q(str(self.root))}/* ]] || return 1
    [[ $path != *'/../'* && $path != */.. && $path != *'/./'* && $path != */. && $path != *'//'* ]] || return 1
    while :; do
        [[ -e $path && ! -L $path && -O $path ]] || return 1
        mode=$(stat --format='%a' -- "$path") || return 1
        (( (8#$mode & 8#022) == 0 )) || return 1
        [[ $path == {q(str(self.root))} ]] && return 0
        path=${{path%/*}}
    done
}}
s4m_systemctl() {{ python3 -B {q(str(self.model))} {q(str(self.root))} systemctl "$@"; }}
s4m_sync() {{ python3 -B {q(str(self.model))} {q(str(self.root))} sync "$@"; }}
s4m_control() {{
    if [[ $1 == /usr/lib/systemd/systemd-sysctl ]]; then
        shift; python3 -B {q(str(self.model))} {q(str(self.root))} kernel "$@"
    elif [[ $1 == /usr/bin/python3 && $2 == -I && $3 == -B && $4 == "$S4N_LIBRARY/verify.py" ]]; then
        python3 -B {q(str(self.model))} {q(str(self.root))} observe
    else return 99; fi
}}
'''

    def run_script(self, script, timeout=30):
        return subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', self.harness() + '\n' + script], text=True, capture_output=True, timeout=timeout)

    def faults(self, **faults):
        state = json.loads(self.db.read_text()); state['faults'] = faults; self.db.write_text(json.dumps(state))

    def events(self):
        path = self.root / 'events.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def apply(self):
        self.assert_success(self.run_script('s4n_apply'))

    def test_initial_apply_and_actual_verify_publish_readiness(self):
        self.apply(); self.assert_success(self.run_script('s4n_verify'))
        self.assertEqual(self.config.read_bytes(), (self.library / 'network.conf').read_bytes())
        self.assertTrue((self.state / 'network.ready').exists())
        events = self.events()
        kernel = next(i for i, e in enumerate(events) if e['action'] == 'kernel')
        enable = next(i for i, e in enumerate(events) if e['args'][:1] == ['enable'])
        self.assertLess(kernel, enable)
        self.assertTrue(any(e['action'] == 'sync' and str(self.systemd / 'timers.target.wants') in e['args'] for e in events))

    def test_zero_exit_partial_kernel_application_cannot_certify(self):
        path = self.proc / 'net/ipv4/conf/enp1s0/accept_redirects'; path.write_text('1\n')
        for fault in ('kernel_noop', 'kernel_partial'):
            self.faults(**{fault: True})
            self.assertNotEqual(self.run_script('s4n_apply').returncode, 0)
            self.assertFalse((self.state / 'network.ready').exists())
        self.faults(); self.apply(); self.assertEqual(path.read_text(), '0\n')

    def test_failed_initial_delivery_is_retried(self):
        self.faults(kernel=True); self.assertNotEqual(self.run_script('s4n_apply').returncode, 0)
        self.assertFalse((self.state / 'network.ready').exists())
        self.faults(); self.apply()

    def test_recurring_repair_corrects_drift_and_config_without_network(self):
        self.apply(); path = self.proc / 'net/ipv6/conf/enp1s0/accept_source_route'; path.write_text('0\n')
        self.config.write_text('wrong config\n'); self.assertNotEqual(self.run_script('s4n_verify').returncode, 0)
        self.assert_success(self.run_script('s4n_repair')); self.assert_success(self.run_script('s4n_verify'))
        self.assertEqual(path.read_text(), '-1\n')
        self.assertFalse(any(e['action'] in ('apt-get', 'curl') for e in self.events()))

    def test_recurring_failed_zero_exit_stays_pending_then_recovers(self):
        self.apply(); (self.proc / 'net/ipv4/conf/enp1s0/rp_filter').write_text('0\n')
        self.faults(kernel_noop=True); self.assertEqual(self.run_script('s4n_repair').returncode, 75)
        self.assertNotEqual(self.run_script('s4n_verify').returncode, 0)
        self.faults(); self.assert_success(self.run_script('s4n_repair')); self.assert_success(self.run_script('s4n_verify'))

    def test_late_interface_and_late_ipv6_are_repaired(self):
        import shutil
        shutil.rmtree(self.proc / 'net/ipv6'); self.apply()
        populate(load(), self.proc, interface='usb0')
        (self.proc / 'net/ipv6/conf/usb0/accept_redirects').write_text('1\n')
        self.assertNotEqual(self.run_script('s4n_verify').returncode, 0)
        self.assert_success(self.run_script('s4n_repair')); self.assert_success(self.run_script('s4n_verify'))

    def test_pending_bootstrap_and_lock_contention_precede_any_write(self):
        self.apply(); log = self.root / 'events.jsonl'; log.unlink()
        (self.state / 'bootstrap').mkdir(mode=0o700); (self.state / 'bootstrap/pending').write_text('pending\n')
        self.assertEqual(self.run_script('s4n_repair').returncode, 75); self.assertFalse(log.exists())
        (self.state / 'bootstrap/pending').unlink()
        with (self.state / 'repair.lock').open('a') as stream:
            (self.state / 'repair.lock').chmod(0o600)
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_script('s4n_repair').returncode, 75)
        self.assertFalse(log.exists()); self.assert_success(self.run_script('s4n_repair'))

    def test_unsafe_config_paths_are_rejected_without_following_or_blocking(self):
        self.config.parent.mkdir(mode=0o700)
        victim = self.root / 'victim'; victim.write_bytes(b'untouched\n'); victim.chmod(0o600)
        identity = (victim.stat().st_ino, victim.read_bytes())
        for kind in ('symlink', 'fifo', 'directory', 'socket', 'unsafe-mode'):
            handle = None
            if kind == 'symlink': self.config.symlink_to(victim)
            elif kind == 'fifo': os.mkfifo(self.config, 0o600)
            elif kind == 'directory': self.config.mkdir(mode=0o700)
            elif kind == 'socket':
                handle = socket.socket(socket.AF_UNIX); handle.bind(str(self.config))
            else: self.config.write_text('unsafe\n'); self.config.chmod(0o666)
            with self.subTest(kind=kind):
                self.assertNotEqual(self.run_script('s4n_apply', timeout=10).returncode, 0)
                self.assertEqual((victim.stat().st_ino, victim.read_bytes()), identity)
                self.assertFalse((self.state / 'network.ready').exists())
            if handle: handle.close()
            if kind == 'directory': self.config.rmdir()
            else: self.config.unlink()

    def test_stop_queued_start_enable_or_dropin_errors_cannot_certify(self):
        self.apply()
        for fault in ('stop_incomplete', 'start_incomplete', 'enable', 'dropin'):
            state = json.loads(self.db.read_text()); state['active'][TIMER] = True; self.db.write_text(json.dumps(state))
            self.faults(**{fault: True})
            with self.subTest(fault=fault):
                self.assertNotEqual(self.run_script('s4n_apply').returncode, 0)
                self.assertFalse((self.state / 'network.ready').exists())
            self.faults(); self.apply()

    def test_persistence_failure_cannot_report_success(self):
        self.faults(sync=True); self.assertNotEqual(self.run_script('s4n_apply').returncode, 0)
        self.assertFalse((self.state / 'network.ready').exists())
        self.faults(); self.apply(); self.faults(sync=True)
        self.assertEqual(self.run_script('s4n_repair').returncode, 75)

    def test_changed_code_shared_dependency_and_dropins_block_readiness(self):
        self.apply()
        for path in (self.library / 'verify.py', self.shared / 'common.sh'):
            before = path.read_bytes(); path.write_bytes(before + b'\n# changed\n')
            with self.subTest(path=path):
                self.assertNotEqual(self.run_script('s4n_ready').returncode, 0)
                self.assertEqual(self.run_script('s4n_repair').returncode, 75)
            path.write_bytes(before)
        self.faults(dropin=True); self.assertEqual(self.run_script('s4n_repair').returncode, 75)

    def test_idempotent_repair_keeps_timer_and_file_identity(self):
        self.apply(); before = (self.config.stat().st_ino, self.config.read_bytes())
        ready = (self.state / 'network.ready').read_bytes()
        self.assert_success(self.run_script('s4n_repair'))
        self.assertEqual((self.config.stat().st_ino, self.config.read_bytes()), before)
        self.assertEqual((self.state / 'network.ready').read_bytes(), ready)
        self.assertTrue(json.loads(self.db.read_text())['active'][TIMER])

    def test_unit_retry_and_fixed_deadline_cover_controls(self):
        service = configparser.ConfigParser(interpolation=None); service.read(ROOT / 'Network' / SERVICE)
        self.assertEqual(service['Service']['Restart'], 'on-failure'); self.assertEqual(service['Unit']['StartLimitIntervalSec'], '0')
        self.assertNotIn('PrivateNetwork', service['Service']); self.assertNotIn('ProtectKernelTunables', service['Service'])
        self.assertEqual(service['Service']['ReadOnlyPaths'], '/proc/sys /sys')
        self.assertEqual(service['Service']['ReadWritePaths'], '/etc/sysctl.d /var/lib/debian13s4 /proc/sys/net')
        self.assertEqual(service['Service']['CapabilityBoundingSet'], 'CAP_NET_ADMIN')
        self.assertEqual(service['Service']['TimeoutStartSec'], '180s'); self.assertGreater(180, 10 * 11 + 30)
        timer = configparser.ConfigParser(interpolation=None); timer.read(ROOT / 'Network' / TIMER)
        self.assertEqual(timer['Timer']['Unit'], SERVICE); self.assertEqual(timer['Timer']['OnBootSec'], '10s')
        self.assertEqual(timer['Timer']['OnUnitInactiveSec'], '2min'); self.assertEqual(timer['Install']['WantedBy'], 'timers.target')

    def test_native_control_closes_lock_and_clears_environment(self):
        script = 'fixture_trust=$(declare -f s4m_trusted)\nsource ' + shlex.quote(str(self.shared / 'common.sh')) + f'''
eval "$fixture_trust"
S4M_STATE={shlex.quote(str(self.state))}
s4m_lock
trap s4m_unlock EXIT
export DEBIAN13S4_FOREIGN=unsafe
s4m_control /bin/bash -c '[[ ! -e /proc/self/fd/$1 && -z ${{DEBIAN13S4_FOREIGN+x}} ]]' fixture "$S4M_REPAIR_FD"
'''
        self.assert_success(self.run_script(script))

    def test_native_control_timeout_is_finite(self):
        script = 'source ' + shlex.quote(str(self.shared / 'common.sh')) + '''
S4M_CONTROL_SECONDS=0.05
S4M_CONTROL_GRACE_SECONDS=0.05
s4m_control /bin/bash -c 'trap "" TERM; sleep 5'
'''
        self.assertNotEqual(self.run_script(script, timeout=5).returncode, 0)

    def test_entrypoint_refuses_unprivileged_use_before_source_or_write(self):
        result = subprocess.run(['/bin/bash', '-p', str(ROOT / 'Network/repair.sh')], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 77)

    def test_absent_config_file_is_recreated_by_periodic_repair(self):
        self.apply(); self.config.unlink()
        self.assertNotEqual(self.run_script('s4n_verify').returncode, 0)
        self.assert_success(self.run_script('s4n_repair'))
        self.assert_success(self.run_script('s4n_verify'))

    def test_ready_sync_failure_is_not_reported_as_apply_success(self):
        self.faults(sync_ready=True)
        self.assertNotEqual(self.run_script('s4n_apply').returncode, 0)
        self.faults(); self.apply()

    def test_boot_trigger_rechecks_reset_kernel_state(self):
        self.apply()
        ready = (self.state / 'network.ready').read_bytes()
        # Simulated reboot keeps published bytes/enablement but resets volatile
        # kernel values. This is not a disk-ordering or PID 1 boot simulation.
        (self.proc / 'net/ipv4/ip_forward').write_text('1\n')
        (self.proc / 'net/ipv6/conf/default/accept_source_route').write_text('0\n')
        self.assertNotEqual(self.run_script('s4n_verify').returncode, 0)
        self.assert_success(self.run_script('s4n_repair'))
        self.assert_success(self.run_script('s4n_verify'))
        self.assertEqual((self.state / 'network.ready').read_bytes(), ready)

    def test_production_native_flags_parse_with_every_write_excluded(self):
        self.config.parent.mkdir(mode=0o700)
        self.config.write_bytes((self.library / 'network.conf').read_bytes())
        # Intercept only delivery: the native command and options originate in
        # s4n_kernel. This prefix cannot match any maintained net/... key.
        script = '''
s4m_control() {
    if [[ $1 == /usr/lib/systemd/systemd-sysctl ]]; then
        local executable=$1
        shift
        "$executable" --prefix=/debian13s4-absent-no-match "$@"
    else
        python3 -B ''' + shlex.quote(str(self.model)) + ' ' + shlex.quote(str(self.root)) + ''' observe
    fi
}
s4n_kernel
'''
        self.assert_success(self.run_script(script))


if __name__ == '__main__':
    unittest.main()
