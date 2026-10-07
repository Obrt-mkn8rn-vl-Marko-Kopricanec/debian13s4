import configparser
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time
import unittest


if os.geteuid() == 0:
    raise RuntimeError("Run the unprivileged fixture suite as an ordinary user.")


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "setup.sh"
BOOT = "debian13s4-bootstrap.service"
TIMER = "debian13s4-repair.timer"
SERVICE = "debian13s4-repair.service"
RESUME = "debian13s4-resume.service"


# Models independent persistence scopes: state, bootstrap /var files, library
# files, /etc units and enablement directories. This is deliberately not PID 1
# or physical storage. Fixture-owned trust and manager/sync delivery are replaced;
# publication, locks, snapshots, generated code and state transitions are real.
MODEL = r'''
import json
from pathlib import Path
import sys

database, log, action, caller, *args = sys.argv[1:]
database = Path(database)
state = json.loads(database.read_text())
root = database.parent
state_dir = root / "state"
boot = state_dir / "bootstrap"
library = root / "library-parent/library"
systemd = root / "systemd"
boot_unit = "debian13s4-bootstrap.service"
timer = "debian13s4-repair.timer"
service = "debian13s4-repair.service"
resume = "debian13s4-resume.service"
faults = state.get("faults", {})
code = 0
output = ""
stage = None

def content(path):
    return path.read_text() if path.is_file() and not path.is_symlink() else None

def files(directory):
    return {str(path.relative_to(directory)): path.read_text()
            for path in directory.rglob("*")
            if path.is_file() and not path.is_symlink()
            and not any(part.startswith("bundle.") for part in path.parts)}

def durable_guard():
    disk = state["disk"]
    return (disk["boot_enabled"] and disk["boot"].get("pending") is not None
            and disk["boot"].get("setup.sh") is not None
            and disk["units"].get(boot_unit) is not None)

before = json.loads(json.dumps(state))
if action == "sync":
    targets = [Path(value) for value in args]
    assert all(path.exists() for path in targets), targets
    if caller == "s4b_atomic":
        stage = "file_data"
    elif caller == "s4b_arm":
        stage = "arm_data"
    elif caller == "s4b_enablement_paths":
        stage = "arm_enablement" if systemd / boot_unit in targets else "timer_enablement"
    elif state_dir in targets:
        stage = "invalidate"
    elif boot in targets:
        stage = "completion" if (boot / "pending").exists() else "cleanup"
    elif library / "repair.sh" in targets:
        stage = "worker"
    elif library / "tasks.list" in targets:
        stage = "manifest"
    else:
        stage = "publish"
    state.setdefault("sync_counts", {})[stage] = state.get("sync_counts", {}).get(stage, 0) + 1
    failed = faults.get("sync_" + stage) or (
        state["sync_counts"][stage] in faults.get("fail_" + stage + "_calls", []))
    if not failed or faults.get("persist_sync_errors"):
        disk = state["disk"]
        if any(path == boot or boot in path.parents for path in targets):
            disk["boot"] = files(boot)
        if any(path == state_dir or (path.parent == state_dir and path != boot) for path in targets):
            disk["state"] = {path.name: path.read_text() for path in state_dir.iterdir()
                             if path.is_file() and not path.is_symlink()}
        if any(path == library or library in path.parents for path in targets):
            disk["library"] = files(library)
        if any(path == systemd or path.parent == systemd for path in targets):
            disk["units"] = {path.name: path.read_text() for path in systemd.iterdir()
                             if path.is_file() and not path.is_symlink()}
        if systemd / "multi-user.target.wants" in targets:
            disk["boot_enabled"] = state["boot_enabled"]
        if systemd / "timers.target.wants" in targets:
            disk["timer_enabled"] = state["timer_enabled"]
    if failed:
        code = 1
elif action == "systemctl":
    operation = args[0]
    unit = args[-1]
    if faults.get(operation + "_" + unit) or faults.get(operation):
        code = 1
    elif operation == "daemon-reload":
        pass
    elif operation == "enable":
        assert unit in (boot_unit, timer), args
        directory = systemd / ("multi-user.target.wants" if unit == boot_unit else "timers.target.wants")
        directory.mkdir(exist_ok=True)
        link = directory / unit
        if not link.is_symlink():
            link.symlink_to(systemd / unit)
        state["boot_enabled" if unit == boot_unit else "timer_enabled"] = True
    elif operation == "is-enabled":
        enabled = state["boot_enabled" if unit == boot_unit else "timer_enabled"]
        output = "enabled" if enabled else "disabled"
        code = 0 if enabled else 1
    elif operation == "show":
        assert len(args) == 4 and args[2] == "--value", args
        if args[1] == "--property=LoadState":
            output = "loaded" if (systemd / unit).is_file() else "not-found"
        else:
            assert args[1] == "--property=ActiveState", args
            output = "active" if state["active"].get(unit, False) else "inactive"
    elif operation == "stop":
        assert unit in (timer, service, resume, "debian13s4-maintenance.timer", "debian13s4-maintenance.service",
                        "debian13s4-dotnet.timer", "debian13s4-dotnet.service",
                        "debian13s4-network.timer", "debian13s4-network.service"), args
        state["active"][unit] = False
    elif operation == "start":
        assert unit in (timer, boot_unit), args
        if unit == timer:
            state["active"][timer] = not faults.get("queued_timer_only", False)
        else:
            state["bootstrap_queued"] = True
    else:
        raise AssertionError(args)
else:
    raise AssertionError(action)
database.write_text(json.dumps(state))
event = {"action": action, "args": args, "caller": caller, "stage": stage,
         "before": before, "after": state, "guard": durable_guard(),
         "pending": content(boot / "pending"), "installed": content(boot / "installed"),
         "library": files(library), "code": code}
with Path(log).open("a") as stream:
    stream.write(json.dumps(event) + "\n")
print(output, end="\n" if output else "")
sys.exit(code)
'''


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="debian13s4-bootstrap-tests.")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state_dir = self.root / "state"
        self.boot = self.state_dir / "bootstrap"
        self.library_parent = self.root / "library-parent"
        self.library = self.library_parent / "library"
        self.systemd = self.root / "systemd"
        self.database = self.root / "manager.json"
        self.log = self.root / "events.jsonl"
        self.model = self.root / "manager.py"
        self.model.write_text(MODEL)
        for path in (self.root, self.library_parent, self.systemd):
            path.mkdir(exist_ok=True)
            path.chmod(0o700)
        self.database.write_text(json.dumps({
            "boot_enabled": False, "timer_enabled": False, "active": {},
            "disk": {"state": {}, "boot": {}, "library": {}, "units": {},
                     "boot_enabled": False, "timer_enabled": False}, "faults": {}}))

    def harness(self, source=ENTRY, lock=True):
        quote = shlex.quote
        return f'''
set -Eeuo pipefail
umask 077
source {quote(str(source))}
S4B_STATE_DIR={quote(str(self.state_dir))}
S4B_BOOT_DIR={quote(str(self.boot))}
S4B_LIBRARY_DIR={quote(str(self.library))}
S4B_SYSTEMD_DIR={quote(str(self.systemd))}
s4b_trusted() {{
    local path=$1 mode
    [[ $path == {quote(str(self.root))} || $path == {quote(str(self.root))}/* ]] || return 1
    [[ $path != *'/../'* && $path != */.. && $path != *'/./'* && $path != */. && $path != *'//'* ]] || return 1
    while :; do
        [[ -e $path && ! -L $path && -O $path ]] || return 1
        mode=$(stat --format='%a' -- "$path") || return 1
        (( (8#$mode & 8#022) == 0 )) || return 1
        [[ $path == {quote(str(self.root))} ]] && return 0
        path=${{path%/*}}
    done
}}
s4b_install() {{ /usr/bin/install "$@"; }}
s4b_systemctl() {{ python3 {quote(str(self.model))} {quote(str(self.database))} {quote(str(self.log))} systemctl "${{FUNCNAME[1]}}" "$@"; }}
s4b_sync() {{ python3 {quote(str(self.model))} {quote(str(self.database))} {quote(str(self.log))} sync "${{FUNCNAME[1]}}" "$@"; }}
s4b_prepare
trap 's4b_unlock; s4b_cleanup' EXIT
''' + ('s4b_open_lock "$S4B_BOOT_DIR/lock" S4B_LOCK_FD\n' if lock else '')

    def run_script(self, script, timeout=30):
        return subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", script],
                              text=True, capture_output=True, timeout=timeout)

    def finish(self, additions="", source=ENTRY):
        return self.run_script(self.harness(source) + additions + "\ns4b_finish\n")

    def lock_paths(self):
        for path in (self.state_dir, self.boot):
            path.mkdir(exist_ok=True)
            path.chmod(0o700)
        return ((self.boot / "lock", "S4B_LOCK_FD"),
                (self.state_dir / "repair.lock", "S4B_REPAIR_FD"))

    def lock_attempt(self, path, variable, additions="", timeout=5):
        return self.run_script(self.harness(lock=False) + additions + f'''
before=(/proc/$BASHPID/fd/[0-9]*)
if s4b_open_lock {shlex.quote(str(path))} {variable}; then
    exit 0
else
    result=$?
    [[ -z ${{{variable}}} ]] || exit 99
    after=(/proc/$BASHPID/fd/[0-9]*)
    [[ ${{#before[@]}} == ${{#after[@]}} ]] || exit 99
    exit "$result"
fi
''', timeout=timeout)

    def state(self):
        return json.loads(self.database.read_text())

    def faults(self, **faults):
        state = self.state()
        state["faults"] = faults
        self.database.write_text(json.dumps(state))

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def simulate_reboot(self):
        state = self.state()
        disk = state["disk"]
        for directory, contents in ((self.state_dir, disk["state"]),
                                    (self.boot, disk["boot"]),
                                    (self.library, disk["library"]),
                                    (self.systemd, disk["units"])):
            if directory.exists():
                candidates = directory.iterdir() if directory == self.state_dir else directory.rglob("*")
                for path in candidates:
                    if path.is_file() or path.is_symlink():
                        path.unlink()
            directory.mkdir(parents=True, exist_ok=True)
            for name, data in contents.items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
                path.chmod(0o700 if name.endswith(".sh") else 0o600)
            directory.chmod(0o700)
            for child in directory.rglob("*"):
                if child.is_dir():
                    child.chmod(0o700)
        for unit, target, enabled in ((BOOT, "multi-user", disk["boot_enabled"]),
                                     (TIMER, "timers", disk["timer_enabled"])):
            wants = self.systemd / f"{target}.target.wants"
            wants.mkdir(exist_ok=True)
            wants.chmod(0o700)
            link = wants / unit
            link.unlink(missing_ok=True)
            if enabled:
                link.symlink_to(self.systemd / unit)
        state["active"] = {}
        state["boot_enabled"] = disk["boot_enabled"]
        state["timer_enabled"] = disk["timer_enabled"]
        state["faults"] = {}
        self.database.write_text(json.dumps(state))
        if disk["boot_enabled"] and "pending" in disk["boot"]:
            self.assertIn("setup.sh", disk["boot"])
            self.assertIn(BOOT, disk["units"])
            return self.finish(source=self.boot / "setup.sh")
        self.assertTrue(disk["timer_enabled"] and "installed" in disk["boot"],
                        {key: sorted(value) if isinstance(value, dict) else value for key, value in disk.items()})
        return None

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.boot / "pending").exists())
        self.assertTrue(self.state()["disk"]["timer_enabled"])
        self.assertTrue(self.state()["active"][TIMER])
        self.assertEqual((self.library / "tasks.list").read_text(), "prerequisites:\nnetwork:prerequisites\nmaintenance:prerequisites\ndotnet:prerequisites\n")
        self.assertTrue((self.boot / "installed").is_file())

    def test_self_contained_payload_matches_all_current_sources(self):
        spec = importlib.util.spec_from_file_location("bootstrap_pack", ROOT / "Bootstrap/pack.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(ENTRY.read_bytes(), module.assemble())
        result = self.finish()
        self.assert_success(result)
        for relative, (data, _) in module.assets().items():
            target = self.library / relative[4:] if relative.startswith("lib/") else self.systemd / relative[6:]
            self.assertEqual(target.read_bytes(), data)

    def test_fresh_offline_bootstrap_needs_no_package_or_network_execution(self):
        self.assert_success(self.finish())
        self.assertFalse(any(event["action"] in ("apt-get", "curl") for event in self.events()))
        self.assertFalse(any(event["args"][-1:] == [SERVICE] and event["args"][0] == "start"
                             for event in self.events() if event["action"] == "systemctl"))

    def test_guard_code_intent_and_enablement_are_durable_before_publication(self):
        self.assert_success(self.finish())
        events = self.events()
        for event in events:
            if event["library"] or event["args"][:1] == ["stop"]:
                handed_off = (event["after"]["disk"]["timer_enabled"] and
                              "installed" in event["after"]["disk"]["boot"])
                self.assertTrue(event["guard"] or handed_off,
                                (event["action"], event["stage"], event["args"]))
        stages = [event["stage"] for event in events if event["stage"]]
        self.assertLess(stages.index("arm_data"), stages.index("arm_enablement"))
        self.assertLess(stages.index("arm_enablement"), stages.index("worker"))
        self.assertLess(stages.index("arm_enablement"), stages.index("invalidate"))
        self.assertLess(stages.index("invalidate"), stages.index("worker"))
        self.assertLess(stages.index("worker"), stages.index("publish"))
        self.assertLess(stages.index("publish"), stages.index("manifest"))
        self.assertLess(stages.index("manifest"), stages.index("timer_enablement"))
        self.assertLess(stages.index("timer_enablement"), stages.index("completion"))
        self.assertLess(stages.index("completion"), stages.index("cleanup"))

    def test_preparation_sync_errors_start_no_publication(self):
        for stage in ("arm_data", "arm_enablement"):
            with self.subTest(stage=stage):
                self.faults(**{"sync_" + stage: True})
                result = self.finish()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.library / "repair.sh").exists())
                self.assertFalse(any(event["args"][:1] == ["stop"] for event in self.events()))
        self.faults()
        self.assert_success(self.finish())

    def test_worker_sync_failure_cannot_publish_other_assets(self):
        self.faults(sync_worker=True)
        result = self.finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.library / "tasks.list").exists())
        self.assertFalse((self.systemd / SERVICE).exists())
        self.assert_success(self.simulate_reboot())

    def test_interrupted_phase_publication_recovers_from_durable_runner(self):
        self.faults(fail_publish_calls=[2])
        result = self.finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.library / "tasks.list").exists())
        self.assert_success(self.simulate_reboot())

    def test_crash_after_manifest_publication_still_has_guard_ownership(self):
        self.faults(sync_manifest=True, persist_sync_errors=True)
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertIn("tasks.list", self.state()["disk"]["library"])
        self.assertIn("pending", self.state()["disk"]["boot"])
        self.assert_success(self.simulate_reboot())

    def test_timer_enablement_sync_failure_keeps_guard_for_reboot(self):
        self.faults(sync_timer_enablement=True)
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertFalse(self.state()["disk"]["timer_enabled"])
        self.assert_success(self.simulate_reboot())

    def test_timer_start_failure_is_not_installed_completion(self):
        self.faults(**{"start_" + TIMER: True})
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertFalse((self.boot / "installed").exists())
        self.assertIn("pending", self.state()["disk"]["boot"])
        self.faults()
        self.assert_success(self.finish())

    def test_queued_timer_is_not_confirmed_activation(self):
        self.faults(queued_timer_only=True)
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertFalse((self.boot / "installed").exists())
        self.assert_success(self.simulate_reboot())

    def test_completion_error_cannot_remove_recovery_intent(self):
        self.faults(sync_completion=True)
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertIn("pending", self.state()["disk"]["boot"])
        self.assertNotIn("installed", self.state()["disk"]["boot"])
        self.assert_success(self.simulate_reboot())

    def test_cleanup_error_preserves_completed_handoff_or_pending_recovery(self):
        for persists in (False, True):
            with self.subTest(persists=persists):
                self.faults(sync_cleanup=True, persist_sync_errors=persists)
                self.assertNotEqual(self.finish().returncode, 0)
                disk = self.state()["disk"]
                self.assertTrue(disk["timer_enabled"])
                self.assertIn("installed", disk["boot"])
                resumed = self.simulate_reboot()
                if resumed is not None:
                    self.assert_success(resumed)
                else:
                    self.assertNotIn("pending", disk["boot"])

    def test_restart_after_completed_bootstrap_revalidates_and_rearms(self):
        self.assert_success(self.finish())
        (self.library / "tasks/prerequisites/apply.sh").write_text("false\n")
        self.assert_success(self.finish())
        self.assertEqual((self.library / "tasks/prerequisites/apply.sh").read_bytes(),
                         (ROOT / "Tasks/prerequisites/apply.sh").read_bytes())

    def test_new_bundle_cannot_inherit_old_setup_completion(self):
        self.state_dir.mkdir(mode=0o700)
        ready = self.state_dir / "setup.ready"
        ready.write_text("verified\n")
        ready.chmod(0o600)
        status = self.state_dir / "status"
        status.write_text("state=complete\n")
        status.chmod(0o600)
        self.assert_success(self.finish())
        self.assertFalse(ready.exists())
        self.assertEqual(status.read_text(), "state=bootstrap_pending\n")
        self.assertNotIn("setup.ready", self.state()["disk"]["state"])
        self.assertEqual(self.state()["disk"]["state"]["status"], "state=bootstrap_pending\n")

    def test_readiness_invalidation_error_precedes_any_bundle_publication(self):
        self.state_dir.mkdir(mode=0o700)
        ready = self.state_dir / "setup.ready"
        ready.write_text("verified\n")
        ready.chmod(0o600)
        self.faults(sync_invalidate=True)
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertFalse((self.library / "repair.sh").exists())
        self.assertIn("setup.ready", self.state()["disk"]["state"])
        self.assertIn("pending", self.state()["disk"]["boot"])
        self.assert_success(self.simulate_reboot())
        self.assertNotIn("setup.ready", self.state()["disk"]["state"])

    def test_existing_units_are_stopped_only_after_durable_guard(self):
        for unit in (TIMER, SERVICE, RESUME):
            (self.systemd / unit).write_text("[Unit]\nDescription=Old fixture\n")
            (self.systemd / unit).chmod(0o644)
        state = self.state()
        state["active"] = {TIMER: True, SERVICE: True, RESUME: True}
        self.database.write_text(json.dumps(state))
        self.assert_success(self.finish())
        stopped = [event for event in self.events() if event["args"][:1] == ["stop"]]
        self.assertEqual([event["args"][1] for event in stopped], [TIMER, SERVICE, RESUME])
        self.assertTrue(all(event["guard"] for event in stopped))

    def test_stop_failure_retains_old_bundle_and_pending_guard(self):
        (self.systemd / TIMER).write_text("[Unit]\nDescription=Old fixture\n")
        (self.systemd / TIMER).chmod(0o644)
        self.library.mkdir()
        self.library.chmod(0o755)
        (self.library / "repair.sh").write_text("old-worker\n")
        (self.library / "repair.sh").chmod(0o755)
        self.faults(stop=True)
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertEqual((self.library / "repair.sh").read_text(), "old-worker\n")
        self.assertTrue(self.state()["disk"]["boot_enabled"])
        self.faults()
        self.assert_success(self.finish())

    def test_old_maintenance_is_quiesced_before_any_bundle_publication(self):
        names = ("debian13s4-maintenance.timer", "debian13s4-maintenance.service",
                 "debian13s4-dotnet.timer", "debian13s4-dotnet.service",
                 "debian13s4-network.timer", "debian13s4-network.service")
        state = self.state()
        for name in names:
            (self.systemd / name).write_text("[Unit]\nDescription=Old maintenance\n")
            (self.systemd / name).chmod(0o644)
            state["active"][name] = True
        self.database.write_text(json.dumps(state))
        self.assert_success(self.finish())
        events = self.events()
        published = next(index for index, event in enumerate(events) if event["library"])
        for name in names:
            stopped = next(index for index, event in enumerate(events)
                           if event["action"] == "systemctl" and event["args"] == ["stop", name])
            self.assertLess(stopped, published)
            self.assertTrue(events[stopped]["guard"])
            self.assertFalse(self.state()["active"][name])

    def test_lock_contention_cannot_replace_the_running_worker(self):
        result = self.run_script(self.harness() + '''
exec {fixture_lock}> "$S4B_STATE_DIR/repair.lock"
flock --nonblock "$fixture_lock"
s4b_finish
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.library / "repair.sh").exists())
        self.assertTrue(self.state()["disk"]["boot_enabled"])

    def test_both_lock_admissions_refuse_symlinks_without_changing_victims(self):
        for path, variable in self.lock_paths():
            with self.subTest(variable=variable):
                victim = self.root / (variable + ".victim")
                data = b"preserve these bytes\n\x00\xff"
                victim.write_bytes(data)
                victim.chmod(0o600)
                before = victim.stat()
                path.symlink_to(victim)
                leaf = path.lstat()
                # Exercise the initial admission and actual finish admission.
                script = self.harness()
                if variable == "S4B_REPAIR_FD":
                    script += "\ns4b_finish\n"
                result = self.run_script(script, timeout=20)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual(victim.read_bytes(), data)
                self.assertEqual((victim.stat().st_dev, victim.stat().st_ino),
                                 (before.st_dev, before.st_ino))
                self.assertEqual((path.lstat().st_dev, path.lstat().st_ino),
                                 (leaf.st_dev, leaf.st_ino))
                self.assertTrue(path.is_symlink())
                self.assertFalse((self.library / "repair.sh").exists())
                if variable == "S4B_LOCK_FD":
                    self.assertFalse(self.events())
                    self.assertFalse((self.boot / "pending").exists())
                else:
                    self.assertTrue(self.state()["disk"]["boot_enabled"])
                path.unlink()

    def test_both_lock_admissions_refuse_dangling_links_without_creating_targets(self):
        for path, variable in self.lock_paths():
            with self.subTest(variable=variable):
                victim = self.root / (variable + ".missing")
                path.symlink_to(victim)
                before = path.lstat()
                self.assertEqual(self.lock_attempt(path, variable).returncode, 1)
                self.assertFalse(victim.exists())
                self.assertEqual(path.lstat().st_ino, before.st_ino)
                self.assertTrue(path.is_symlink())
                path.unlink()

    def test_both_lock_admissions_reject_readerless_fifos_within_finite_time(self):
        for path, variable in self.lock_paths():
            with self.subTest(variable=variable):
                os.mkfifo(path, 0o600)
                before = path.lstat()
                started = time.monotonic()
                result = self.lock_attempt(path, variable, timeout=3)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertLess(time.monotonic() - started, 3)
                self.assertEqual(path.lstat(), before)
                self.assertFalse(self.events())
                path.unlink()

    def test_both_lock_admissions_refuse_directories_and_unix_sockets(self):
        for kind in ("directory", "socket"):
            for path, variable in self.lock_paths():
                with self.subTest(kind=kind, variable=variable):
                    # A preceding finish admission may have created the other
                    # ordinary lock. Replace only that fixture-owned regular leaf.
                    if path.is_file() and not path.is_symlink():
                        path.unlink()
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
                        if kind == "directory":
                            path.mkdir(mode=0o700)
                        else:
                            endpoint.bind(str(path))
                            path.chmod(0o600)
                        before = path.lstat()
                        script = self.harness()
                        if variable == "S4B_REPAIR_FD":
                            script += "\ns4b_finish\n"
                        result = self.run_script(script, timeout=20)
                        self.assertNotEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(path.lstat(), before)
                        self.assertFalse((self.library / "repair.sh").exists())
                    if kind == "directory":
                        path.rmdir()
                    else:
                        path.unlink()

    def test_checked_lock_open_refuses_a_real_device_before_opening(self):
        device = Path("/dev/null")
        before = device.stat()
        self.assertTrue(device.is_char_device())
        for variable in ("S4B_LOCK_FD", "S4B_REPAIR_FD"):
            with self.subTest(variable=variable):
                result = self.run_script(f'''
set -Eeuo pipefail
source {shlex.quote(str(ENTRY))}
s4b_open_lock /dev/null {variable}
''', timeout=3)
                self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(device.stat()[:7], before[:7])
        self.assertEqual(device.stat().st_rdev, before.st_rdev)

    def test_both_lock_admissions_refuse_unsafe_modes_without_touching_leaves(self):
        for path, variable in self.lock_paths():
            for mode in (0o620, 0o602, 0o666):
                with self.subTest(variable=variable, mode=oct(mode)):
                    path.write_bytes(b"existing lock data\n")
                    path.chmod(mode)
                    before = path.stat()
                    self.assertEqual(self.lock_attempt(path, variable).returncode, 1)
                    self.assertEqual(path.read_bytes(), b"existing lock data\n")
                    self.assertEqual(path.stat()[:7], before[:7])
                    path.unlink()

    def test_native_lock_leaf_trust_refuses_nonroot_ownership_before_opening(self):
        for path, variable in self.lock_paths():
            with self.subTest(variable=variable):
                path.write_bytes(b"nonroot-owned leaf\n")
                path.chmod(0o600)
                before = path.stat()
                # Adapt only the parent check; the production leaf/ancestor
                # trust function still sees this real non-root-owned leaf.
                result = self.run_script(f'''
set -Eeuo pipefail
source {shlex.quote(str(ENTRY))}
eval "$(declare -f s4b_trusted | sed '1s/s4b_trusted/s4b_original_trusted/')"
s4b_trusted() {{
    [[ $1 == {shlex.quote(str(path.parent))} ]] || s4b_original_trusted "$@"
}}
s4b_open_lock {shlex.quote(str(path))} {variable}
''', timeout=3)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotEqual(before.st_uid, 0)
                self.assertEqual(path.read_bytes(), b"nonroot-owned leaf\n")
                self.assertEqual(path.stat()[:7], before[:7])
                path.unlink()

    def test_both_checked_lock_creations_are_private_and_owned_until_unlock(self):
        for path, variable in self.lock_paths():
            with self.subTest(variable=variable):
                result = self.run_script(self.harness(lock=False) + f'''
umask 000
s4b_open_lock {shlex.quote(str(path))} {variable}
[[ $(umask) == 0000 ]]
descriptor=/proc/$BASHPID/fd/${{{variable}}}
[[ -f $descriptor ]]
[[ $(stat --dereference --format='%u %a %d:%i' -- "$descriptor") == $(stat --format='%u %a %d:%i' -- {shlex.quote(str(path))}) ]]
if flock --nonblock {shlex.quote(str(path))} true; then exit 98; fi
s4b_unlock
[[ -z ${{{variable}}} && ! -e $descriptor ]]
flock --nonblock {shlex.quote(str(path))} true
''', timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.stat().st_uid, os.geteuid())
                self.assertEqual(path.read_bytes(), b"")
                path.unlink()

    def test_both_lock_contention_and_retry_preserve_contents_and_inode(self):
        for path, variable in self.lock_paths():
            with self.subTest(variable=variable):
                data = b"lock content must survive all admissions\n"
                path.write_bytes(data)
                path.chmod(0o600)
                before = path.stat()
                with path.open("rb") as owner:
                    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    result = self.lock_attempt(path, variable)
                    self.assertEqual(result.returncode, 75, result.stderr)
                    self.assertEqual(path.read_bytes(), data)
                    self.assertEqual(path.stat()[:7], before[:7])
                result = self.lock_attempt(path, variable)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat()[:7], before[:7])
                path.unlink()

    def test_descriptor_mismatch_refuses_flock_and_closes_the_new_descriptor(self):
        for path, variable in self.lock_paths():
            with self.subTest(variable=variable):
                path.write_bytes(b"original descriptor\n")
                path.chmod(0o600)
                old = self.root / (variable + ".old")
                result = self.run_script(self.harness(lock=False) + f'''
stat() {{
    if [[ $1 == '--format=%u %a %d:%i' && ${{@: -1}} == {shlex.quote(str(path))} ]]; then
        mv -- {shlex.quote(str(path))} {shlex.quote(str(old))}
        printf 'replacement leaf\\n' > {shlex.quote(str(path))}
        chmod 0600 -- {shlex.quote(str(path))}
    fi
    command stat "$@"
}}
flock() {{ exit 97; }}
before=(/proc/$BASHPID/fd/[0-9]*)
if s4b_open_lock {shlex.quote(str(path))} {variable}; then exit 98; fi
[[ -z ${{{variable}}} ]]
after=(/proc/$BASHPID/fd/[0-9]*)
[[ ${{#before[@]}} == ${{#after[@]}} ]]
''', timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(old.read_bytes(), b"original descriptor\n")
                self.assertEqual(path.read_bytes(), b"replacement leaf\n")
                self.assertNotEqual(old.stat().st_ino, path.stat().st_ino)
                path.unlink()

    def test_descriptor_stat_error_fails_closed_without_leaking_a_descriptor(self):
        for path, variable in self.lock_paths():
            with self.subTest(variable=variable):
                result = self.run_script(self.harness(lock=False) + f'''
stat() {{
    [[ $1 != --dereference ]] || return 1
    command stat "$@"
}}
flock() {{ exit 97; }}
before=(/proc/$BASHPID/fd/[0-9]*)
if s4b_open_lock {shlex.quote(str(path))} {variable}; then exit 98; fi
[[ -z ${{{variable}}} ]]
after=(/proc/$BASHPID/fd/[0-9]*)
[[ ${{#before[@]}} == ${{#after[@]}} ]]
''', timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                path.unlink()

    def test_payload_tampering_rejects_the_bundle_before_publication(self):
        result = self.finish('''
eval "$(declare -f s4b_write_bundle | sed '1s/s4b_write_bundle/s4b_original_bundle/')"
s4b_write_bundle() {
    s4b_original_bundle
    printf 'false\\n' >> "$S4B_STAGE/lib/tasks/prerequisites/apply.sh"
}
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.library / "repair.sh").exists())
        self.assertTrue(self.state()["disk"]["boot_enabled"])

    def test_symlink_destination_is_refused_without_touching_its_target(self):
        victim = self.root / "unrelated"
        victim.write_text("preserve\n")
        self.library.mkdir()
        (self.library / "repair.sh").symlink_to(victim)
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertEqual(victim.read_text(), "preserve\n")

    def test_root_trust_gate_rejects_unprivileged_paths_and_links(self):
        result = self.run_script(f'source {shlex.quote(str(ENTRY))}\ns4b_trusted {shlex.quote(str(self.root))}')
        self.assertNotEqual(result.returncode, 0)
        for path in (str(self.root / "../anything"), str(self.root / "./anything"),
                     str(self.root) + "//anything", "relative", "/tmp", "/var/run"):
            result = self.run_script(f'source {shlex.quote(str(ENTRY))}\ns4b_trusted {shlex.quote(path)}')
            self.assertNotEqual(result.returncode, 0)

    def test_atomic_data_sync_error_keeps_previous_bytes_and_inode(self):
        target = self.root / "target"
        target.write_text("committed\n")
        target.chmod(0o600)
        inode = target.stat().st_ino
        self.faults(sync_file_data=True)
        result = self.run_script(self.harness() + f"\nprintf 'replacement\\n' | s4b_atomic {shlex.quote(str(target))} 0600\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), "committed\n")
        self.assertEqual(target.stat().st_ino, inode)

    def test_rearming_reuses_durable_guard_inodes_on_sync_failure(self):
        self.faults(sync_worker=True)
        self.assertNotEqual(self.finish().returncode, 0)
        targets = (self.boot / "setup.sh", self.boot / "pending", self.systemd / BOOT)
        identities = [(path.stat().st_ino, path.read_bytes()) for path in targets]
        self.faults(sync_arm_data=True)
        self.assertNotEqual(self.finish().returncode, 0)
        self.assertEqual(identities, [(path.stat().st_ino, path.read_bytes()) for path in targets])
        self.assertTrue(self.state()["disk"]["boot_enabled"])

    def test_failed_serializer_cannot_replace_the_existing_boot_runner(self):
        self.faults(sync_worker=True)
        self.assertNotEqual(self.finish().returncode, 0)
        runner = self.boot / "setup.sh"
        previous = runner.read_bytes()
        result = self.finish("s4b_write_runner() { printf 'partial'; return 1; }\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(runner.read_bytes(), previous)

    def test_control_commands_have_a_real_finite_timeout(self):
        started = time.monotonic()
        result = self.run_script(f'''source {shlex.quote(str(ENTRY))}
s4b_control /bin/bash -c 'sleep 30'
''', timeout=20)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertGreaterEqual(time.monotonic() - started, 9)
        self.assertLess(time.monotonic() - started, 18)

    def test_private_runner_round_trip_preserves_payload_and_permissions(self):
        self.assert_success(self.finish())
        runner = self.boot / "setup.sh"
        self.assertEqual(runner.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.boot / "installed").stat().st_mode & 0o777, 0o600)
        checked = subprocess.run(["bash", "-n", str(runner)], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assert_success(self.finish(source=runner))

    def test_boot_unit_reads_protected_runner_without_execute_permission(self):
        self.assert_success(self.finish())
        runner = self.boot / "setup.sh"
        runner.chmod(0o600)
        with self.assertRaises(PermissionError):
            subprocess.run([str(runner), "--help"], capture_output=True, check=True)
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(self.systemd / BOOT)
        command = shlex.split(unit["Service"]["ExecStart"])
        self.assertEqual(command[-1], "--resume")
        command[-1] = "--help"
        result = subprocess.run(command, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unattended setup", result.stdout)

    def test_boot_unit_deadline_scales_with_finite_bundle_and_no_start_cycle(self):
        self.assert_success(self.finish())
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(self.systemd / BOOT)
        self.assertEqual(unit["Service"]["Restart"], "on-failure")
        self.assertEqual(unit["Unit"]["StartLimitIntervalSec"], "0")
        self.assertEqual(unit["Unit"]["ConditionPathExists"], str(self.boot / "pending"))
        self.assertNotIn("Before", unit["Unit"])
        controls = sum(event["action"] in ("systemctl", "sync") for event in self.events())
        bound = int(unit["Service"]["TimeoutStartSec"][:-1])
        count = len([path for path in self.library.rglob("*") if path.is_file()]) + 3
        self.assertGreater(bound, (2 * count + 19 + 3 * 9) * 11)
        self.assertLessEqual(controls, 2 * count + 19 + 3 * 9)
        expanded = self.run_script(self.harness() + '''
S4B_FILES+=(a b c d)
s4b_write_unit
''')
        larger = configparser.ConfigParser(interpolation=None)
        larger.read_string(expanded.stdout)
        self.assertGreater(int(larger["Service"]["TimeoutStartSec"][:-1]), bound)

    def test_control_children_close_both_locks_and_clear_environment(self):
        script = self.harness(lock=False) + '''
s4b_open_lock "$S4B_BOOT_DIR/lock" S4B_LOCK_FD
s4b_open_lock "$S4B_STATE_DIR/repair.lock" S4B_REPAIR_FD
export DEBIAN13S4_FOREIGN=unsafe
s4b_control /bin/bash -c '[[ ! -e /proc/self/fd/$1 && ! -e /proc/self/fd/$2 && -z ${DEBIAN13S4_FOREIGN+x} ]]' fixture "$S4B_LOCK_FD" "$S4B_REPAIR_FD"
'''
        result = self.run_script(script)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_starting_script_refuses_arguments_and_unprivileged_setup(self):
        result = subprocess.run([str(ENTRY), "--configure"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 64)
        result = subprocess.run([str(ENTRY)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 77)
        self.assertIn("root permission", result.stderr)


class PackageTaskTests(unittest.TestCase):
    def run_fixture(self, additions, entry):
        script = f'''
set -Eeuo pipefail
source {shlex.quote(str(ROOT / "Tasks/prerequisites/common.sh"))}
{additions}
{entry}
'''
        return subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                              text=True, capture_output=True, timeout=5)

    def test_installed_packages_and_empty_audit_are_required(self):
        for status in ("install ok installed", "install ok unpacked", "install reinstreq half-installed", "deinstall ok installed"):
            with self.subTest(status=status):
                result = self.run_fixture(f'''
s4p_query() {{ printf '%s\\n' {shlex.quote(status)}; }}
s4p_dpkg() {{ return 0; }}
''', "s4p_verify")
                self.assertEqual(result.returncode == 0, status == "install ok installed", result.stderr)
        result = self.run_fixture('''
s4p_query() { printf 'install ok installed\\n'; }
s4p_dpkg() { printf 'partially installed package\\n'; }
''', "s4p_verify")
        self.assertNotEqual(result.returncode, 0)

    def test_query_and_audit_errors_are_not_readiness(self):
        for additions in ("s4p_query() { return 1; }", '''
s4p_query() { printf 'install ok installed\\n'; }
s4p_dpkg() { return 2; }
'''):
            result = self.run_fixture(additions, "s4p_verify")
            self.assertNotEqual(result.returncode, 0)

    def test_offline_refresh_stops_before_any_configuration_or_install(self):
        result = self.run_fixture('''
s4p_apt() { printf 'apt:%s\\n' "$*"; return 100; }
s4p_dpkg() { printf 'unexpected dpkg\\n'; }
''', "s4p_apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "apt:update\n")

    def test_interrupted_configuration_repairs_dependencies_then_reconfigures(self):
        result = self.run_fixture('''
attempt=0
s4p_apt() { printf 'apt:%s\\n' "$*"; }
s4p_dpkg() { ((attempt += 1)); printf 'dpkg:%s\\n' "$*"; ((attempt > 1)); }
''', "s4p_apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], "apt:update")
        self.assertEqual(lines[2], "apt:--fix-broken install")
        self.assertEqual(lines[1], lines[3])
        self.assertTrue(lines[4].startswith("apt:install ca-certificates "))

    def test_failed_dependency_repair_does_not_attempt_final_install(self):
        result = self.run_fixture('''
s4p_apt() { printf 'apt:%s\\n' "$*"; [[ $1 == update ]]; }
s4p_dpkg() { return 2; }
''', "s4p_apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), ["apt:update", "apt:--fix-broken install"])

    def test_failed_package_install_is_pending(self):
        result = self.run_fixture('''
s4p_apt() { [[ $1 == update ]]; }
s4p_dpkg() { return 0; }
''', "s4p_apply")
        self.assertNotEqual(result.returncode, 0)

    def test_apt_options_preserve_authentication_locks_and_no_removal(self):
        result = self.run_fixture('''
S4P_APT_DIR=/fixture/indexes
apt-get() { printf '%s\\n' "$@"; }
''', "s4p_apt install ca-certificates")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = result.stdout.splitlines()
        for value in ("Dir::Etc::sourceparts=-", "Dir::State::lists=/fixture/indexes/lists",
                      "APT::Update::Error-Mode=any", "Acquire::AllowInsecureRepositories=false",
                      "Acquire::Check-Date=true", "Acquire::Check-Valid-Until=true",
                      "Acquire::AllowDowngradeToInsecureRepositories=false",
                      "APT::Get::AllowUnauthenticated=false", "DPkg::Lock::Timeout=60",
                      "--no-remove", "--no-install-recommends", "--assume-yes"):
            self.assertIn(value, args)
        self.assertFalse(any("Debug::NoLocking" in value for value in args))
        source = (ROOT / "Tasks/prerequisites/debian.sources").read_text()
        self.assertEqual(source.count("Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg"), 2)
        self.assertIn("trixie-security", source)
        self.assertNotIn("stable", source)


class RecoveryIntegrationTests(unittest.TestCase):
    def test_real_package_phases_retry_offline_and_interrupted_installation(self):
        spec = importlib.util.spec_from_file_location("recovery_fixture", ROOT / "Recovery.Tests/test_recovery.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fixture = module.RecoveryTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.task("prerequisites")
        fixture.manifest("prerequisites:\n")
        task_dir = fixture.library / "tasks/prerequisites"
        apt_dir = fixture.root / "apt"
        apt_dir.mkdir()
        binary_dir = fixture.root / "bin"
        binary_dir.mkdir()
        database = fixture.root / "packages.json"
        database.write_text(json.dumps({"offline": True, "partial_install": True,
                                        "statuses": {}, "calls": []}))
        # Relocate only the fixed production paths. Native phase Bash and the
        # worker execute unchanged flow; root ownership, package tools and PID 1
        # remain explicitly substituted. No real package command can be reached.
        for name in ("apply.sh", "verify.sh", "common.sh", "debian.sources"):
            text = (ROOT / "Tasks/prerequisites" / name).read_text()
            text = text.replace("/usr/local/lib/debian13s4/tasks/prerequisites", str(task_dir))
            text = text.replace("/var/lib/apt", str(apt_dir))
            (task_dir / name).write_text(text)
        shim = f'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path({str(fixture.root)!r})
database = Path({str(database)!r})
operation = Path(sys.argv[0]).name
args = sys.argv[1:]
if operation == "stat":
    path = Path(args[-1])
    assert path == root or root in path.parents or path in root.parents
    print("0 755")
    sys.exit(0)
if operation == "install":
    assert root in Path(args[-1]).parents
    kept = []
    offset = 0
    while offset < len(args):
        if args[offset] in ("-o", "-g"):
            offset += 2
        else:
            kept.append(args[offset])
            offset += 1
    sys.exit(subprocess.run(["/usr/bin/install", *kept]).returncode)
state = json.loads(database.read_text())
state["calls"].append([operation, *args])
code = 0
output = ""
if operation == "dpkg-query":
    output = state["statuses"].get(args[-1], "")
    code = 0 if output else 1
elif operation == "dpkg" and "--audit" in args:
    output = "partially installed" if any(value != "install ok installed" for value in state["statuses"].values()) else ""
elif operation == "dpkg":
    assert "--configure" in args and "--pending" in args
    state["statuses"] = {{name: "install ok installed" for name in state["statuses"]}}
elif operation == "apt-get":
    assert os.environ["DEBIAN_FRONTEND"] == "noninteractive"
    assert os.environ["APT_LISTCHANGES_FRONTEND"] == "none"
    assert os.environ["NEEDRESTART_MODE"] == "l"
    if "update" in args:
        code = 100 if state["offline"] else 0
    else:
        assert "install" in args
        packages = args[args.index("install") + 1:]
        state["statuses"] = {{name: "install ok installed" for name in packages}}
        if state["partial_install"]:
            state["partial_install"] = False
            state["statuses"][packages[-1]] = "install ok unpacked"
            code = 100
else:
    raise AssertionError(operation)
database.write_text(json.dumps(state))
print(output, end="\\n" if output else "")
sys.exit(code)
'''
        for name in ("stat", "install", "apt-get", "dpkg", "dpkg-query"):
            path = binary_dir / name
            path.write_text(shim)
            path.chmod(0o755)

        def recover():
            additions = f"S4_PHASE_PATH={shlex.quote(str(binary_dir))}:$S4_PHASE_PATH"
            return subprocess.run(["bash", "--noprofile", "--norc", "-c", fixture.command(additions)],
                                  text=True, capture_output=True, timeout=30)

        first = recover()
        self.assertEqual(first.returncode, 75, first.stdout + first.stderr)
        self.assertIn("apply_failed_1", fixture.state_for("prerequisites"))
        self.assertFalse((fixture.state / "setup.ready").exists())
        self.assertEqual(fixture.stop_count(), 0)
        state = json.loads(database.read_text())
        self.assertFalse(any(call[0] == "dpkg" for call in state["calls"]))
        state["offline"] = False
        database.write_text(json.dumps(state))
        second = recover()
        self.assertEqual(second.returncode, 75, second.stdout + second.stderr)
        self.assertFalse((fixture.state / "setup.ready").exists())
        self.assertEqual(fixture.stop_count(), 0)
        third = recover()
        self.assertEqual(third.returncode, 0, third.stdout + third.stderr)
        self.assertIn("state=complete", fixture.state_for("prerequisites"))
        self.assertTrue((fixture.state / "setup.ready").exists())
        self.assertEqual(fixture.stop_count(), 1)
        self.assertFalse(json.loads(fixture.controller.read_text())["enabled"])


if __name__ == "__main__":
    unittest.main()
