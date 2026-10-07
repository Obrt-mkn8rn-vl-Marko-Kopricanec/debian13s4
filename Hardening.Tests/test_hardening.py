import configparser
import contextlib
import fcntl
import importlib.util
import io
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
SERVICE = 'debian13s4-hardening.service'
TIMER = 'debian13s4-hardening.timer'


def load(path=ROOT / 'Hardening/verify.py'):
    spec = importlib.util.spec_from_file_location('host_policy', path)
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


def populate(module, proc):
    for key, expected in module.POLICY.items():
        path = proc / key
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(str(expected) + '\n'); path.chmod(0o600)
    for path in proc.rglob('*'):
        if path.is_dir(): path.chmod(0o700)
    proc.chmod(0o700)


# The production observer, ordinary-user files, locks and renames are real.
# Root trust, procfs, native kernel writes, manager and sync delivery are
# explicitly substituted. No writable host /proc/sys path is admitted.
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
state = json.loads(db.read_text()); fault = state['faults']
code, output = 0, ''
spec = importlib.util.spec_from_file_location('production_observer', root / 'library/verify.py')
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
try:
    if action == 'observe':
        sys.argv = [str(root / 'library/verify.py')]
        code = m.main()
    elif action == 'plan':
        output = '\n'.join(m.plan())
        if fault.get('plan'): code = 75
        if fault.get('plan_malformed'): output = 'kernel/randomize_va_space\n--prefix=kernel'
    elif action == 'kernel':
        assert args[0] == '--strict' and args[-1] == str(root / 'etc/sysctl.d/90-debian13s4-kernel.conf'), args
        keys = [arg.removeprefix('--prefix=') for arg in args[1:-1]]
        assert keys and keys == m.plan() and all(key in m.POLICY for key in keys), args
        if fault.get('kernel'): code = 1
        elif not fault.get('kernel_noop'):
            for key in keys:
                if fault.get('kernel_partial') and key == 'kernel/dmesg_restrict': continue
                (m.PROC / key).write_text(str(m.POLICY[key]) + '\n')
    elif action == 'sync':
        assert all(Path(arg).exists() for arg in args), args
        if fault.get('sync') or (fault.get('sync_ready') and any('hardening.ready' in arg for arg in args)): code = 1
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
            assert unit == 'debian13s4-hardening.timer'
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
except (OSError, ValueError) as error:
    print(str(error), file=sys.stderr); code = 75
db.write_text(json.dumps(state))
with (root / 'events.jsonl').open('a') as stream:
    stream.write(json.dumps({'action': action, 'args': args, 'code': code}) + '\n')
if output: print(output)
sys.exit(code)
'''


class PredicateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-host-predicate.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.proc = self.root / 'proc'
        self.module = load(); self.module.PROC = self.proc
        self.module.trusted = lambda path, kind: trust(self.root, path, kind)
        populate(self.module, self.proc)

    def test_complete_host_policy_has_no_pending_writes(self):
        self.assertEqual(self.module.plan(), [])

    def test_every_required_scalar_is_in_the_real_write_plan_on_drift(self):
        for key in self.module.POLICY:
            path = self.proc / key; old = path.read_bytes(); path.write_text('-1\n')
            with self.subTest(key=key): self.assertEqual(self.module.plan(), [key])
            path.write_bytes(old)

    def test_stronger_ptrace_and_perf_are_preserved(self):
        (self.proc / 'kernel/yama/ptrace_scope').write_text('3\n')
        (self.proc / 'kernel/perf_event_paranoid').write_text('4\n')
        self.assertEqual(self.module.plan(), [])
        (self.proc / 'kernel/dmesg_restrict').write_text('0\n')
        self.assertEqual(self.module.plan(), ['kernel/dmesg_restrict'])

    def test_invalid_ptrace_scope_is_not_a_stronger_policy(self):
        (self.proc / 'kernel/yama/ptrace_scope').write_text('4\n')
        self.assertEqual(self.module.plan(), ['kernel/yama/ptrace_scope'])

    def test_missing_every_required_control_fails_before_plan_output(self):
        for key in self.module.POLICY:
            path = self.proc / key; old = path.read_bytes(); path.unlink()
            with self.subTest(key=key), self.assertRaises(FileNotFoundError): self.module.plan()
            path.write_bytes(old); path.chmod(0o600)

    def test_fifo_socket_directory_and_symbolic_scalar_are_rejected(self):
        path = self.proc / 'kernel/dmesg_restrict'; path.unlink()
        victim = self.root / 'victim'; victim.write_bytes(b'unchanged\n')
        identity = (victim.stat().st_ino, victim.read_bytes())
        for kind in ('fifo', 'socket', 'directory', 'symbolic'):
            handle = None
            if kind == 'fifo': os.mkfifo(path, 0o600)
            elif kind == 'socket':
                handle = socket.socket(socket.AF_UNIX); handle.bind(str(path))
            elif kind == 'directory': path.mkdir(mode=0o700)
            else: path.symlink_to(victim)
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.module.plan()
            self.assertEqual((victim.stat().st_ino, victim.read_bytes()), identity)
            if handle: handle.close()
            if kind == 'directory': path.rmdir()
            else: path.unlink()

    def test_symbolic_namespace_and_unsafe_modes_fail(self):
        path = self.proc / 'kernel/yama'; path.rename(path.with_name('saved')); path.symlink_to(path.with_name('saved'))
        with self.assertRaises(ValueError): self.module.plan()
        path.unlink(); path.with_name('saved').rename(path)
        (path / 'ptrace_scope').chmod(0o622)
        with self.assertRaises(ValueError): self.module.plan()

    def test_changed_descriptor_read_and_close_errors_fail(self):
        path = self.proc / 'kernel/dmesg_restrict'
        with mock.patch.object(self.module.os, 'fstat', side_effect=lambda fd: path.parent.stat()):
            with self.assertRaises(ValueError): self.module.value(path)
        with mock.patch.object(self.module.os, 'read', side_effect=OSError('read failed')):
            with self.assertRaises(OSError): self.module.value(path)
        close = self.module.os.close
        def failed_close(fd):
            close(fd); raise OSError('close failed')
        with mock.patch.object(self.module.os, 'close', side_effect=failed_close):
            with self.assertRaises(OSError): self.module.value(path)
        self.assertEqual(self.module.plan(), [])

    def test_invalid_oversized_and_out_of_range_scalars_fail(self):
        path = self.proc / 'kernel/dmesg_restrict'
        for data in (b'', b'1 trailing\n', b'1\n2\n', b'1' * 65, b'\xff\n', b'2147483648\n', b'-2147483649\n'):
            path.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(ValueError): self.module.value(path)

    def test_changing_scalar_snapshot_is_pending(self):
        original = self.module.value; calls = 0
        def changing(path):
            nonlocal calls
            calls += 1; number = original(path)
            return number + 1 if calls == len(self.module.POLICY) + 1 else number
        with mock.patch.object(self.module, 'value', side_effect=changing):
            with self.assertRaisesRegex(ValueError, 'changed during'): self.module.plan()

    def test_real_main_has_no_partial_plan_on_late_missing_control(self):
        (self.proc / 'kernel/dmesg_restrict').write_text('0\n')
        (self.proc / 'vm/unprivileged_userfaultfd').unlink()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(self.module.sys, 'argv', ['verify.py', '--plan']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(self.module.main(), 75)
        self.assertEqual(out.getvalue(), '')

    def test_native_proc_scalar_and_native_owner_rejection_are_read_only(self):
        native = load(); path = Path('/proc/sys/kernel/randomize_va_space')
        self.assertIn(native.value(path), (0, 1, 2))
        native.TRUSTED_UID = os.geteuid()
        with self.assertRaises(ValueError): native.value(path)

    def test_config_exactly_covers_policy_and_leaves_namespace_defaults(self):
        lines = (ROOT / 'Hardening/kernel.conf').read_text().splitlines()
        rows = [line.split(' = ') for line in lines if line and not line.startswith('#')]
        self.assertEqual(len(rows), len(self.module.POLICY))
        self.assertEqual(dict(rows), {key: str(value) for key, value in self.module.POLICY.items()})
        self.assertFalse(any('userns_clone' in key or 'max_user_namespaces' in key or 'modules_disabled' in key or 'kexec' in key for key in self.module.POLICY))


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-host-controller.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.library = self.root / 'library'; self.state = self.root / 'state'
        self.systemd = self.root / 'systemd'; self.shared = self.root / 'shared'; self.etc = self.root / 'etc'
        for path in (self.library, self.state, self.systemd, self.shared, self.etc): path.mkdir(mode=0o700)
        for source in (ROOT / 'Hardening').iterdir():
            target = self.library / source.name; target.write_bytes(source.read_bytes())
            target.chmod(0o755 if source.name == 'repair.sh' else 0o644)
        target = self.shared / 'common.sh'; target.write_bytes((ROOT / 'Maintenance/common.sh').read_bytes()); target.chmod(0o644)
        self.model = self.root / 'delivery.py'; self.model.write_text(MODEL)
        self.db = self.root / 'manager.json'; self.db.write_text(json.dumps({'enabled': False, 'active': {}, 'faults': {}}))
        self.proc = self.root / 'proc'; populate(load(), self.proc)
        (self.proc / 'kernel/dmesg_restrict').write_text('0\n')
        self.config = self.etc / 'sysctl.d/90-debian13s4-kernel.conf'

    def harness(self):
        q = shlex.quote
        common = (self.library / 'common.sh').read_text().replace('. /usr/local/lib/debian13s4/maintenance/common.sh', '. ' + q(str(self.shared / 'common.sh')))
        return f'''set -Eeuo pipefail
umask 077
{common}
S4M_LIBRARY={q(str(self.shared))}
S4M_STATE={q(str(self.state))}
S4M_SYSTEMD={q(str(self.systemd))}
S4H_LIBRARY={q(str(self.library))}
S4H_CONFIG={q(str(self.config))}
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
    elif [[ $1 == /usr/bin/python3 && $2 == -I && $3 == -B && $4 == "$S4H_LIBRARY/verify.py" ]]; then
        if [[ ${{5-}} == --plan ]]; then
            python3 -B {q(str(self.model))} {q(str(self.root))} plan
        else python3 -B {q(str(self.model))} {q(str(self.root))} observe; fi
    else return 99; fi
}}
'''

    def run_script(self, script, timeout=120):
        return subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', self.harness() + '\n' + script], text=True, capture_output=True, timeout=timeout)

    def faults(self, **faults):
        state = json.loads(self.db.read_text()); state['faults'] = faults; self.db.write_text(json.dumps(state))

    def events(self):
        path = self.root / 'events.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def apply(self):
        self.assert_success(self.run_script('s4h_apply'))

    def test_initial_apply_and_actual_verify_publish_readiness(self):
        self.apply(); self.assert_success(self.run_script('s4h_verify'))
        self.assertEqual(self.config.read_bytes(), (self.library / 'kernel.conf').read_bytes())
        self.assertTrue((self.state / 'hardening.ready').exists())
        events = self.events()
        kernel = next(i for i, e in enumerate(events) if e['action'] == 'kernel')
        enable = next(i for i, e in enumerate(events) if e['args'][:1] == ['enable'])
        self.assertLess(kernel, enable)
        self.assertTrue(any(e['action'] == 'sync' and str(self.systemd / 'timers.target.wants') in e['args'] for e in events))

    def test_zero_exit_noop_and_partial_delivery_cannot_certify(self):
        for fault in ('kernel_noop', 'kernel_partial'):
            self.faults(**{fault: True})
            self.assertNotEqual(self.run_script('s4h_apply').returncode, 0)
            self.assertFalse((self.state / 'hardening.ready').exists())
        self.faults(); self.apply()

    def test_failed_initial_delivery_is_retried(self):
        self.faults(kernel=True); self.assertNotEqual(self.run_script('s4h_apply').returncode, 0)
        self.assertFalse((self.state / 'hardening.ready').exists())
        self.faults(); self.apply()

    def test_missing_scalar_prevents_every_native_kernel_write(self):
        (self.proc / 'vm/unprivileged_userfaultfd').unlink()
        self.assertNotEqual(self.run_script('s4h_apply').returncode, 0)
        self.assertFalse(any(e['action'] == 'kernel' for e in self.events()))
        self.assertFalse((self.state / 'hardening.ready').exists())

    def test_plan_failure_and_malformed_output_prevent_kernel_write(self):
        for fault in ('plan', 'plan_malformed'):
            self.faults(**{fault: True})
            self.assertNotEqual(self.run_script('s4h_apply').returncode, 0)
        self.assertFalse(any(e['action'] == 'kernel' for e in self.events()))
        self.faults(); self.apply()

    def test_stronger_live_controls_are_not_in_native_write_selection(self):
        (self.proc / 'kernel/yama/ptrace_scope').write_text('3\n')
        (self.proc / 'kernel/perf_event_paranoid').write_text('4\n')
        self.apply()
        event = next(e for e in self.events() if e['action'] == 'kernel')
        self.assertEqual(event['args'][1:-1], ['--prefix=kernel/dmesg_restrict'])
        self.assertEqual((self.proc / 'kernel/yama/ptrace_scope').read_text(), '3\n')
        self.assertEqual((self.proc / 'kernel/perf_event_paranoid').read_text(), '4\n')

    def test_recurring_repair_corrects_drift_and_config_offline(self):
        self.apply(); path = self.proc / 'fs/protected_regular'; path.write_text('0\n')
        self.config.write_text('wrong config\n'); self.assertNotEqual(self.run_script('s4h_verify').returncode, 0)
        self.assert_success(self.run_script('s4h_repair')); self.assert_success(self.run_script('s4h_verify'))
        self.assertEqual(path.read_text(), '2\n')
        self.assertFalse(any(e['action'] in ('apt-get', 'curl') for e in self.events()))

    def test_recurring_zero_exit_failure_stays_pending_then_recovers(self):
        self.apply(); (self.proc / 'kernel/dmesg_restrict').write_text('0\n')
        self.faults(kernel_noop=True); self.assertEqual(self.run_script('s4h_repair').returncode, 75)
        self.assertNotEqual(self.run_script('s4h_verify').returncode, 0)
        self.faults(); self.assert_success(self.run_script('s4h_repair')); self.assert_success(self.run_script('s4h_verify'))

    def test_pending_bootstrap_and_lock_contention_precede_any_write(self):
        self.apply(); log = self.root / 'events.jsonl'; log.unlink()
        (self.state / 'bootstrap').mkdir(mode=0o700); (self.state / 'bootstrap/pending').write_text('pending\n')
        self.assertEqual(self.run_script('s4h_repair').returncode, 75); self.assertFalse(log.exists())
        (self.state / 'bootstrap/pending').unlink()
        with (self.state / 'repair.lock').open('a') as stream:
            (self.state / 'repair.lock').chmod(0o600)
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_script('s4h_repair').returncode, 75)
        self.assertFalse(log.exists()); self.assert_success(self.run_script('s4h_repair'))

    def test_unsafe_config_paths_never_follow_victims_or_block_on_fifo(self):
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
                self.assertNotEqual(self.run_script('s4h_apply', timeout=30).returncode, 0)
                self.assertEqual((victim.stat().st_ino, victim.read_bytes()), identity)
                self.assertFalse((self.state / 'hardening.ready').exists())
            if handle: handle.close()
            if kind == 'directory': self.config.rmdir()
            else: self.config.unlink()

    def test_stop_start_enable_and_dropin_errors_cannot_certify(self):
        self.apply()
        for fault in ('stop_incomplete', 'start_incomplete', 'enable', 'dropin'):
            state = json.loads(self.db.read_text()); state['active'][TIMER] = True; self.db.write_text(json.dumps(state))
            self.faults(**{fault: True})
            with self.subTest(fault=fault):
                self.assertNotEqual(self.run_script('s4h_apply').returncode, 0)
                self.assertFalse((self.state / 'hardening.ready').exists())
            self.faults(); self.apply()

    def test_persistence_failures_remain_pending(self):
        self.faults(sync=True); self.assertNotEqual(self.run_script('s4h_apply').returncode, 0)
        self.assertFalse((self.state / 'hardening.ready').exists())
        self.faults(); self.apply(); self.faults(sync=True)
        self.assertEqual(self.run_script('s4h_repair').returncode, 75)

    def test_code_shared_dependency_and_controller_drift_block_readiness(self):
        self.apply()
        for path in (self.library / 'verify.py', self.shared / 'common.sh', self.systemd / SERVICE):
            before = path.read_bytes(); path.write_bytes(before + b'\n# changed\n')
            with self.subTest(path=path):
                self.assertNotEqual(self.run_script('s4h_ready').returncode, 0)
                self.assertEqual(self.run_script('s4h_repair').returncode, 75)
            path.write_bytes(before)
        self.faults(dropin=True); self.assertEqual(self.run_script('s4h_repair').returncode, 75)

    def test_idempotent_repair_skips_all_native_kernel_writes(self):
        self.apply(); before = (self.config.stat().st_ino, self.config.read_bytes())
        ready = (self.state / 'hardening.ready').read_bytes()
        log = self.root / 'events.jsonl'; log.unlink()
        self.assert_success(self.run_script('s4h_repair'))
        self.assertFalse(any(e['action'] == 'kernel' for e in self.events()))
        self.assertEqual((self.config.stat().st_ino, self.config.read_bytes()), before)
        self.assertEqual((self.state / 'hardening.ready').read_bytes(), ready)
        self.assertTrue(json.loads(self.db.read_text())['active'][TIMER])

    def test_unit_capabilities_retry_and_fixed_control_budget(self):
        service = configparser.ConfigParser(interpolation=None); service.read(ROOT / 'Hardening' / SERVICE)
        self.assertEqual(service['Service']['Restart'], 'on-failure'); self.assertEqual(service['Unit']['StartLimitIntervalSec'], '0')
        self.assertNotIn('PrivateNetwork', service['Service']); self.assertNotIn('ProtectKernelTunables', service['Service'])
        self.assertEqual(service['Service']['ReadOnlyPaths'], '/proc/sys /sys')
        self.assertEqual(service['Service']['ReadWritePaths'], '/etc/sysctl.d /var/lib/debian13s4 /proc/sys/kernel /proc/sys/fs /proc/sys/vm')
        self.assertEqual(service['Service']['CapabilityBoundingSet'], 'CAP_SYS_ADMIN CAP_SYS_PTRACE')
        self.assertEqual(service['Service']['TimeoutStartSec'], '180s'); self.assertGreater(180, 11 * 11 + 30)
        timer = configparser.ConfigParser(interpolation=None); timer.read(ROOT / 'Hardening' / TIMER)
        self.assertEqual(timer['Timer']['Unit'], SERVICE); self.assertEqual(timer['Timer']['OnBootSec'], '10s')
        self.assertEqual(timer['Timer']['OnUnitInactiveSec'], '2min'); self.assertEqual(timer['Install']['WantedBy'], 'timers.target')

    def test_native_control_relinquishes_lock_and_clears_environment(self):
        script = 'fixture_trust=$(declare -f s4m_trusted)\nsource ' + shlex.quote(str(self.shared / 'common.sh')) + f'''
eval "$fixture_trust"
S4M_STATE={shlex.quote(str(self.state))}
s4m_lock
trap s4m_unlock EXIT
export DEBIAN13S4_FOREIGN=unsafe
s4m_control /bin/bash -c '[[ ! -e /proc/self/fd/$1 && -z ${{DEBIAN13S4_FOREIGN+x}} ]]' fixture "$S4M_REPAIR_FD"
'''
        self.assert_success(self.run_script(script))

    def test_native_control_timeout_and_unprivileged_entrypoint_are_finite(self):
        script = 'source ' + shlex.quote(str(self.shared / 'common.sh')) + '''
S4M_CONTROL_SECONDS=0.05
S4M_CONTROL_GRACE_SECONDS=0.05
s4m_control /bin/bash -c 'trap "" TERM; sleep 5'
'''
        self.assertNotEqual(self.run_script(script, timeout=5).returncode, 0)
        result = subprocess.run(['/bin/bash', '-p', str(ROOT / 'Hardening/repair.sh')], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 77)

    def test_absent_config_and_ready_sync_failure_recover(self):
        self.faults(sync_ready=True); self.assertNotEqual(self.run_script('s4h_apply').returncode, 0)
        self.faults(); self.apply(); self.config.unlink()
        self.assertNotEqual(self.run_script('s4h_verify').returncode, 0)
        self.assert_success(self.run_script('s4h_repair')); self.assert_success(self.run_script('s4h_verify'))

    def test_boot_reset_is_reconciled_using_persisted_controller_identity(self):
        self.apply(); ready = (self.state / 'hardening.ready').read_bytes()
        (self.proc / 'kernel/randomize_va_space').write_text('0\n')
        (self.proc / 'kernel/unprivileged_bpf_disabled').write_text('2\n')
        self.assertNotEqual(self.run_script('s4h_verify').returncode, 0)
        self.assert_success(self.run_script('s4h_repair')); self.assert_success(self.run_script('s4h_verify'))
        self.assertEqual((self.state / 'hardening.ready').read_bytes(), ready)

    def test_native_parser_probe_removes_all_matching_prefixes_before_execution(self):
        self.config.parent.mkdir(mode=0o700)
        self.config.write_bytes((self.library / 'kernel.conf').read_bytes())
        populate(load(), self.proc)
        # Prefixes are ORed. Remove EVERY production matching prefix before
        # adding the sole nonmatching prefix. This proves parsing, not writes.
        script = '''
s4m_control() {
    if [[ $1 == /usr/lib/systemd/systemd-sysctl ]]; then
        local executable=$1 argument
        local -a safe=(--prefix=debian13s4-absent-no-match)
        shift
        for argument in "$@"; do
            [[ $argument == --prefix=* ]] || safe+=("$argument")
        done
        [[ ${#safe[@]} == 3 ]] || return 99
        "$executable" "${safe[@]}"
    elif [[ ${5-} == --plan ]]; then
        printf '%s\\n' kernel/randomize_va_space kernel/dmesg_restrict
    else
        python3 -B ''' + shlex.quote(str(self.model)) + ' ' + shlex.quote(str(self.root)) + ''' observe
    fi
}
s4h_kernel
'''
        self.assert_success(self.run_script(script))


if __name__ == '__main__':
    unittest.main()
