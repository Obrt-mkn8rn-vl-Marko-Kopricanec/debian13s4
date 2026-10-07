import configparser
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


if os.geteuid() == 0:
    raise RuntimeError("Run these substituted unprivileged fixtures as an ordinary user.")

ROOT = Path(__file__).resolve().parents[1]
SERVICE = "debian13s4-maintenance.service"
TIMER = "debian13s4-maintenance.timer"

# Real files/renames/links; replaced root trust, storage persistence and PID 1.
MODEL = r'''
import json
from pathlib import Path
import sys
database, log, action, caller, *args = sys.argv[1:]
db = Path(database)
state = json.loads(db.read_text())
root = db.parent
systemd = root / "systemd"
state_dir = root / "state"
timer = "debian13s4-maintenance.timer"
service = "debian13s4-maintenance.service"
faults = state["faults"]
stage = ""
code = 0
output = ""
if action == "sync":
    if any("maintenance.ready." in arg or "maintenance-intent." in arg for arg in args):
        stage = "ready_data"
    elif str(state_dir / "maintenance.ready") in args:
        stage = "ready_commit"
    elif str(state_dir) in args:
        stage = "invalidate"
    elif str(systemd / "timers.target.wants") in args:
        stage = "enablement"
    else:
        stage = "unit_data"
    if faults.get("sync_" + stage):
        code = 1
    else:
        if any(arg == str(state_dir) or str(state_dir) + "/" in arg for arg in args):
            state["disk"]["ready"] = (state_dir / "maintenance.ready").read_text() if (state_dir / "maintenance.ready").exists() else None
        if any(arg == str(systemd) or str(systemd) + "/" in arg for arg in args):
            state["disk"]["units"] = {path.name: path.read_text() for path in (systemd / timer, systemd / service) if path.is_file()}
        if str(systemd / "timers.target.wants") in args:
            state["disk"]["enabled"] = state["enabled"]
elif action == "systemctl":
    command = args[0]
    unit = args[-1]
    if faults.get(command):
        code = 1
    elif command == "show":
        prop = args[1].split("=", 1)[1]
        if prop == "LoadState":
            output = "loaded" if (systemd / unit).exists() else "not-found"
        elif prop == "ActiveState":
            output = "active" if state["active"].get(unit) else "inactive"
        elif prop == "FragmentPath":
            output = str(systemd / unit)
        elif prop == "DropInPaths":
            output = "foreign.conf" if faults.get("dropin") else ""
        else:
            raise AssertionError(prop)
    elif command == "stop":
        if not faults.get("stop_incomplete"):
            state["active"][unit] = False
    elif command == "daemon-reload":
        pass
    elif command == "enable":
        state["enabled"] = True
        wants = systemd / "timers.target.wants"
        wants.mkdir(exist_ok=True, mode=0o700)
        link = wants / timer
        if not link.is_symlink():
            link.symlink_to(systemd / timer)
    elif command == "is-enabled":
        output = "enabled" if state["enabled"] else "disabled"
        code = 0 if state["enabled"] else 1
    elif command == "start":
        if not faults.get("start_incomplete"):
            state["active"][unit] = True
    elif command == "reboot":
        state["reboot_requested"] = True
    else:
        raise AssertionError(args)
else:
    raise AssertionError(action)
db.write_text(json.dumps(state))
with Path(log).open("a") as stream:
    stream.write(json.dumps({"action": action, "caller": caller, "args": args,
                             "stage": stage, "code": code, "ready": (state_dir / "maintenance.ready").exists(),
                             "disk": state["disk"]}) + "\n")
if output:
    print(output)
sys.exit(code)
'''


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="debian13s4-maintenance-tests.")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.library = self.root / "library"
        self.state_dir = self.root / "state"
        self.systemd = self.root / "systemd"
        for path in (self.library, self.state_dir, self.systemd):
            path.mkdir(mode=0o700)
        self.database = self.root / "manager.json"
        self.log = self.root / "events.jsonl"
        self.packages = self.root / "packages.log"
        self.model = self.root / "model.py"
        self.model.write_text(MODEL)
        self.database.write_text(json.dumps({"enabled": False, "active": {},
                                            "disk": {"ready": None, "units": {}, "enabled": False}, "faults": {}}))
        for source in (ROOT / "Maintenance").iterdir():
            (self.library / source.name).write_bytes(source.read_bytes())
            (self.library / source.name).chmod(0o755 if source.name == "update.sh" else 0o644)

    def harness(self):
        q = shlex.quote
        return f'''
set -Eeuo pipefail
umask 077
source {q(str(self.library / "common.sh"))}
source {q(str(ROOT / "Tasks/prerequisites/common.sh"))}
S4M_LIBRARY={q(str(self.library))}
S4M_STATE={q(str(self.state_dir))}
S4M_SYSTEMD={q(str(self.systemd))}
S4M_REBOOT_MARKER={q(str(self.root / 'reboot-required'))}
FAULT=
s4m_trusted() {{
    local path=$1 mode
    # Native packaged paths are only predicates here; never written/executed.
    if [[ $path == /etc/kernel/postinst.d/unattended-upgrades || $path == /etc/needrestart/needrestart.conf ]]; then return 0; fi
    [[ $path == {q(str(self.root))} || $path == {q(str(self.root))}/* ]] || return 1
    while :; do
        [[ -e $path && ! -L $path && -O $path ]] || return 1
        mode=$(stat --format='%a' -- "$path") || return 1
        (( (8#$mode & 8#022) == 0 )) || return 1
        [[ $path == {q(str(self.root))} ]] && return 0
        path=${{path%/*}}
    done
}}
s4m_systemctl() {{ python3 {q(str(self.model))} {q(str(self.database))} {q(str(self.log))} systemctl "${{FUNCNAME[1]}}" "$@"; }}
s4m_sync() {{ python3 {q(str(self.model))} {q(str(self.database))} {q(str(self.log))} sync "${{FUNCNAME[1]}}" "$@"; }}
s4p_prepare() {{ printf 'prepare\\n' >> {q(str(self.packages))}; }}
s4p_apt() {{ printf 'setup-apt:%s\\n' "$*" >> {q(str(self.packages))}; [[ $FAULT != install ]]; }}
dpkg() {{ printf 'amd64\\n'; }}
uname() {{ printf '6.12.1-amd64\\n'; }}
s4p_query() {{ printf 'install ok installed\\n'; }}
printf '0\\n' > {q(str(self.root / 'configure-count'))}
s4p_dpkg() {{
    printf 'dpkg:%s\\n' "$*" >> {q(str(self.packages))}
    if [[ $1 == --audit ]]; then
        [[ $FAULT != audit_error ]] || return 1
        [[ $FAULT != audit_pending ]] || printf 'incomplete package\\n'
    else
        read -r configure_count < {q(str(self.root / 'configure-count'))}
        ((configure_count += 1))
        printf '%s\\n' "$configure_count" > {q(str(self.root / 'configure-count'))}
        [[ $FAULT != never_configure ]] && [[ $FAULT != configure || $configure_count -gt 1 ]]
    fi
}}
apt-get() {{
    printf 'apt:%s|config:%s|frontend:%s|ucf:%s\\n' "$*" "$APT_CONFIG" "$DEBIAN_FRONTEND" "$UCF_FORCE_CONFFOLD" >> {q(str(self.packages))}
    [[ $FAULT != offline ]] && [[ $FAULT != broken || $1 == update ]]
}}
unattended-upgrade() {{
    printf 'unattended:%s|config:%s\\n' "$*" "$APT_CONFIG" >> {q(str(self.packages))}
    [[ $FAULT != upgrade ]]
}}
needrestart() {{
    printf 'restart:%s|mode:%s\\n' "$*" "$NEEDRESTART_MODE" >> {q(str(self.packages))}
    [[ $FAULT != restart ]]
}}
'''

    def run_fixture(self, action="s4m_apply", additions=""):
        return subprocess.run(["bash", "--noprofile", "--norc", "-c", self.harness() + additions + "\n" + action],
                              capture_output=True, text=True, timeout=30)

    def state(self):
        return json.loads(self.database.read_text())

    def faults(self, **faults):
        state = self.state()
        state["faults"] = faults
        self.database.write_text(json.dumps(state))

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def package_calls(self):
        return self.packages.read_text().splitlines() if self.packages.exists() else []

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def reboot(self):
        state = self.state()
        disk = state["disk"]
        ready = self.state_dir / "maintenance.ready"
        ready.unlink(missing_ok=True)
        if disk["ready"] is not None:
            ready.write_text(disk["ready"])
            ready.chmod(0o600)
        for name in (SERVICE, TIMER):
            target = self.systemd / name
            target.unlink(missing_ok=True)
            if name in disk["units"]:
                target.write_text(disk["units"][name])
                target.chmod(0o644)
        state["enabled"] = disk["enabled"]
        state["active"] = {TIMER: disk["enabled"]}
        state["faults"] = {}
        self.database.write_text(json.dumps(state))

    def test_policy_becomes_ready_only_after_durable_units_and_enablement(self):
        self.assert_success(self.run_fixture())
        self.assert_success(self.run_fixture("s4m_verify"))
        ready_events = [event for event in self.events() if event["stage"] == "ready_commit"]
        self.assertEqual(len(ready_events), 1)
        self.assertTrue(ready_events[0]["disk"]["enabled"])
        self.assertEqual(set(ready_events[0]["disk"]["units"]), {SERVICE, TIMER})
        self.assertEqual((self.state_dir / "maintenance.ready").stat().st_mode & 0o777, 0o600)

    def test_sync_errors_leave_policy_unready_and_retry_across_reboot(self):
        for stage in ("invalidate", "unit_data", "enablement", "ready_data", "ready_commit"):
            with self.subTest(stage=stage):
                self.faults(**{"sync_" + stage: True})
                self.assertNotEqual(self.run_fixture().returncode, 0)
                self.reboot()
                if stage != "ready_commit":
                    self.assertIsNone(self.state()["disk"]["ready"])
                self.assert_success(self.run_fixture())
                self.reboot()
                self.assert_success(self.run_fixture("s4m_verify"))

    def test_activation_errors_are_not_policy_readiness(self):
        for fault in ("daemon-reload", "enable", "is-enabled", "start", "start_incomplete", "dropin", "show"):
            with self.subTest(fault=fault):
                self.faults(**{fault: True})
                self.assertNotEqual(self.run_fixture().returncode, 0)
                self.faults()
                self.assert_success(self.run_fixture())

    def test_stop_error_cannot_overwrite_running_units(self):
        self.assert_success(self.run_fixture())
        before = (self.systemd / SERVICE).read_bytes()
        self.faults(stop=True)
        self.assertNotEqual(self.run_fixture().returncode, 0)
        self.assertEqual((self.systemd / SERVICE).read_bytes(), before)
        self.assertFalse((self.state_dir / "maintenance.ready").exists())

    def test_incomplete_stop_is_not_confirmed_quiescence(self):
        self.assert_success(self.run_fixture())
        self.faults(stop_incomplete=True)
        self.assertNotEqual(self.run_fixture().returncode, 0)

    def test_symlink_unit_destination_never_changes_its_victim(self):
        victim = self.root / "victim"
        victim.write_bytes(b"keep\x00\xff")
        identity = victim.stat().st_ino
        (self.systemd / SERVICE).symlink_to(victim)
        self.assertNotEqual(self.run_fixture().returncode, 0)
        self.assertEqual(victim.read_bytes(), b"keep\x00\xff")
        self.assertEqual(victim.stat().st_ino, identity)

    def test_symlink_readiness_is_refused_without_removal(self):
        victim = self.root / "victim"
        victim.write_text("keep\n")
        (self.state_dir / "maintenance.ready").symlink_to(victim)
        self.assertNotEqual(self.run_fixture().returncode, 0)
        self.assertTrue((self.state_dir / "maintenance.ready").is_symlink())
        self.assertEqual(victim.read_text(), "keep\n")

    def test_tampered_units_and_stale_asset_identity_are_not_ready(self):
        self.assert_success(self.run_fixture())
        (self.systemd / SERVICE).write_text("different\n")
        self.assertNotEqual(self.run_fixture("s4m_verify").returncode, 0)
        self.assert_success(self.run_fixture())
        (self.library / "policy.conf").write_text("changed policy\n")
        self.assertEqual(self.run_fixture("s4m_update").returncode, 75)

    def test_bootstrap_pending_blocks_all_package_operations(self):
        self.assert_success(self.run_fixture())
        self.packages.unlink()
        (self.state_dir / "bootstrap").mkdir(mode=0o700)
        (self.state_dir / "bootstrap/pending").write_text("pending\n")
        self.assertEqual(self.run_fixture("s4m_update").returncode, 75)
        self.assertFalse(self.package_calls())

    def test_no_completed_policy_means_no_package_operations(self):
        self.assertEqual(self.run_fixture("s4m_update").returncode, 75)
        self.assertFalse(self.package_calls())

    def test_offline_refresh_stops_before_configuration_or_upgrade(self):
        self.assert_success(self.run_fixture())
        self.packages.unlink()
        self.assertNotEqual(self.run_fixture("s4m_update", "FAULT=offline\n").returncode, 0)
        calls = self.package_calls()
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[1].startswith("apt:update|config:"))

    def test_interrupted_dpkg_is_repaired_before_upgrade(self):
        self.assert_success(self.run_fixture())
        self.packages.unlink()
        self.assert_success(self.run_fixture("s4m_update", "FAULT=configure\n"))
        calls = self.package_calls()
        self.assertIn("--no-remove --fix-broken install", calls[3])
        self.assertEqual(calls[2], calls[4])
        self.assertTrue(calls[5].startswith("unattended:--verbose|config:"))

    def test_failed_dependency_repair_does_not_attempt_upgrade(self):
        self.assert_success(self.run_fixture())
        self.packages.unlink()
        additions = "FAULT=broken\ns4p_dpkg() { return 1; }\n"
        self.assertNotEqual(self.run_fixture("s4m_update", additions).returncode, 0)
        self.assertFalse(any(call.startswith("unattended:") for call in self.package_calls()))

    def test_upgrade_audit_and_restart_errors_remain_failed(self):
        self.assert_success(self.run_fixture())
        for fault in ("upgrade", "audit_error", "audit_pending", "restart"):
            with self.subTest(fault=fault):
                self.assertNotEqual(self.run_fixture("s4m_update", f"FAULT={fault}\n").returncode, 0)

    def test_update_uses_one_configuration_and_noninteractive_environment(self):
        self.assert_success(self.run_fixture())
        self.packages.unlink()
        self.assert_success(self.run_fixture("s4m_update"))
        calls = self.package_calls()
        self.assertIn(f"config:{self.library / 'policy.conf'}|frontend:noninteractive|ucf:1", calls[1])
        self.assertIn(f"config:{self.library / 'policy.conf'}", calls[3])
        self.assertTrue(calls[-1].endswith("|mode:a"))

    def test_kernel_selector_preserves_stock_cloud_and_rt_flavours(self):
        vectors = [("amd64", "6.12-amd64", "linux-image-amd64"),
                   ("amd64", "6.12-cloud-amd64", "linux-image-cloud-amd64"),
                   ("amd64", "6.12-rt-amd64", "linux-image-rt-amd64"),
                   ("arm64", "6.12-arm64", "linux-image-arm64"),
                   ("arm64", "6.12-cloud-arm64", "linux-image-cloud-arm64")]
        for architecture, release, expected in vectors:
            with self.subTest(architecture=architecture, release=release):
                result = self.run_fixture("s4m_kernel_package", f"dpkg() {{ printf '%s\\n' {architecture}; }}\nuname() {{ printf '%s\\n' {release}; }}\n")
                self.assert_success(result)
                self.assertEqual(result.stdout.strip(), expected)

    def test_unsupported_architecture_fails_without_package_operations(self):
        result = self.run_fixture("s4m_kernel_package", "dpkg() { printf 'riscv64\\n'; }\n")
        self.assertEqual(result.returncode, 78)
        self.assertFalse(self.package_calls())

    def test_native_root_trust_rejects_real_nonroot_files(self):
        result = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                                 f"source {shlex.quote(str(ROOT / 'Maintenance/common.sh'))}; s4m_trusted {shlex.quote(str(self.library / 'common.sh'))}"],
                                capture_output=True, text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)

    def test_native_updater_entry_refuses_unprivileged_execution(self):
        result = subprocess.run(["bash", "--noprofile", "--norc", "-p", str(ROOT / "Maintenance/update.sh")],
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 77)

    def test_existing_kernel_marker_requests_reboot_without_network(self):
        self.assert_success(self.run_fixture())
        self.packages.unlink()
        marker = self.root / "reboot-required"
        marker.write_text("kernel installed\n")
        marker.chmod(0o600)
        result = self.run_fixture("s4m_update", "FAULT=offline\n")
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertTrue(self.state()["reboot_requested"])
        self.assertFalse(any(call.startswith("apt:") for call in self.package_calls()))
        self.assertTrue(marker.exists())
        marker.unlink()  # model /run being cleared on the next boot
        self.assert_success(self.run_fixture("s4m_update"))

    def test_reboot_delivery_error_is_retried_without_erasing_marker(self):
        self.assert_success(self.run_fixture())
        marker = self.root / "reboot-required"
        marker.write_text("pending\n")
        marker.chmod(0o600)
        self.faults(reboot=True)
        self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
        self.assertNotIn("reboot_requested", self.state())
        self.assertTrue(marker.exists())
        self.faults()
        self.assertEqual(self.run_fixture("s4m_update").returncode, 75)
        self.assertTrue(self.state()["reboot_requested"])

    def test_incomplete_packages_and_malformed_reboot_markers_cannot_reboot(self):
        self.assert_success(self.run_fixture())
        marker = self.root / "reboot-required"
        marker.write_text("pending\n")
        marker.chmod(0o600)
        for fault in ("never_configure", "audit_error", "audit_pending"):
            with self.subTest(fault=fault):
                self.assertNotEqual(self.run_fixture("s4m_update", f"FAULT={fault}\n").returncode, 0)
                self.assertNotIn("reboot_requested", self.state())
        marker.unlink()
        victim = self.root / "victim"
        victim.write_text("keep\n")
        marker.symlink_to(victim)
        self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
        self.assertEqual(victim.read_text(), "keep\n")
        self.assertNotIn("reboot_requested", self.state())

    def test_existing_marker_with_broken_dependencies_reaches_online_repair(self):
        self.assert_success(self.run_fixture())
        marker = self.root / "reboot-required"
        marker.write_text("pending\n")
        marker.chmod(0o600)
        additions = '''
apt-get() { [[ $* != *--fix-broken* ]] || touch "$S4M_STATE/repaired.fixture"; }
s4p_dpkg() {
    if [[ $1 == --audit ]]; then return 0; fi
    [[ -f $S4M_STATE/repaired.fixture ]]
}
'''
        self.assertEqual(self.run_fixture("s4m_update", additions).returncode, 75)
        self.assertTrue(self.state()["reboot_requested"])

    def test_new_kernel_marker_after_upgrade_is_requested_after_audit_and_restart(self):
        self.assert_success(self.run_fixture())
        additions = '''
unattended-upgrade() {
    printf 'new kernel\\n' > "$S4M_REBOOT_MARKER"
    chmod 0600 "$S4M_REBOOT_MARKER"
}
'''
        self.assertEqual(self.run_fixture("s4m_update", additions).returncode, 75)
        self.assertTrue(self.state()["reboot_requested"])
        self.assertTrue(any(call.startswith("restart:") for call in self.package_calls()))

    def test_installer_lock_contention_prevents_updates_and_reboots(self):
        self.assert_success(self.run_fixture())
        self.packages.unlink()
        path = self.state_dir / "repair.lock"
        path.write_text("preserve\n")
        path.chmod(0o600)
        with path.open("rb") as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_fixture("s4m_update").returncode, 75)
            self.assertFalse(self.package_calls())
            self.assertEqual(path.read_text(), "preserve\n")
        self.assert_success(self.run_fixture("s4m_update"))
        self.assertEqual(path.read_text(), "preserve\n")

    def test_checked_maintenance_lock_rejects_wrong_kinds_without_blocking(self):
        path = self.state_dir / "repair.lock"
        os.mkfifo(path, 0o600)
        self.assertNotEqual(self.run_fixture("s4m_lock").returncode, 0)
        path.unlink()
        victim = self.root / "victim"
        victim.write_text("keep\n")
        inode = victim.stat().st_ino
        path.symlink_to(victim)
        self.assertNotEqual(self.run_fixture("s4m_lock").returncode, 0)
        self.assertEqual(victim.read_text(), "keep\n")
        self.assertEqual(victim.stat().st_ino, inode)

    def test_native_control_children_close_the_shared_installer_lock(self):
        script = self.harness() + '''
s4m_lock
s4m_control /bin/bash -c '[[ ! -e /proc/self/fd/$1 ]]' fixture "$S4M_REPAIR_FD"
s4m_unlock
'''
        result = subprocess.run(["bash", "-c", script], text=True, capture_output=True, timeout=5)
        self.assert_success(result)

    def test_native_package_children_cannot_inherit_the_shared_lock(self):
        script = self.harness() + '''
s4m_lock
s4m_package /bin/bash -c '[[ ! -e /proc/self/fd/$1 ]]' fixture "$S4M_REPAIR_FD"
[[ -n $S4M_REPAIR_FD ]]
s4m_unlock
'''
        result = subprocess.run(["bash", "-c", script], text=True, capture_output=True, timeout=5)
        self.assert_success(result)

    def run_maintained_phase(self, name, fault=""):
        loader = self.root / "phase-loader.sh"
        loader.write_text(self.harness() + f"\nFAULT={shlex.quote(fault)}\ns4m_load_packages() {{ return 0; }}\n")
        loader.chmod(0o600)
        text = (ROOT / "Tasks/maintenance" / name).read_text().replace(
            "/usr/local/lib/debian13s4/maintenance/common.sh", str(loader))
        script = self.root / name
        script.write_text(text)
        script.chmod(0o600)
        return subprocess.run(["bash", "--noprofile", "--norc", str(script)], capture_output=True, text=True, timeout=30)

    def test_maintained_setup_phases_verify_real_installed_policy_state(self):
        self.assert_success(self.run_maintained_phase("apply.sh"))
        self.assert_success(self.run_maintained_phase("verify.sh"))
        (self.systemd / TIMER).write_text("wrong timer\n")
        self.assertNotEqual(self.run_maintained_phase("verify.sh").returncode, 0)

    def test_maintained_setup_phase_retries_failed_package_delivery(self):
        self.assertNotEqual(self.run_maintained_phase("apply.sh", "install").returncode, 0)
        self.assertFalse((self.state_dir / "maintenance.ready").exists())
        self.assert_success(self.run_maintained_phase("apply.sh"))
        self.assert_success(self.run_maintained_phase("verify.sh"))

    def test_maintained_setup_phase_supplies_noninteractive_package_environment(self):
        loader = self.root / "phase-loader.sh"
        loader.write_text(self.harness() + '''
s4m_load_packages() { return 0; }
s4p_apt() {
    [[ $DEBIAN_FRONTEND == noninteractive && $APT_LISTCHANGES_FRONTEND == none &&
        $NEEDRESTART_MODE == l && $UCF_FORCE_CONFFOLD == 1 ]]
}
''')
        text = (ROOT / "Tasks/maintenance/apply.sh").read_text().replace(
            "/usr/local/lib/debian13s4/maintenance/common.sh", str(loader))
        result = subprocess.run(["bash", "-c", text], capture_output=True, text=True, timeout=30)
        self.assert_success(result)


class NativePolicyTests(unittest.TestCase):
    def test_actual_apt_parser_isolates_and_enforces_the_policy(self):
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "APT_CONFIG": str(ROOT / "Maintenance/policy.conf")}
        result = subprocess.run(["apt-config", "dump"], env=environment, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        for setting in ['Dir::Etc::parts "";', 'Dir::Etc::main "";',
                        'Acquire::Check-Date "true";', 'Acquire::Check-Valid-Until "true";',
                        'Acquire::AllowInsecureRepositories "false";', 'APT::Get::AllowUnauthenticated "false";',
                        'Debug::NoLocking "false";', 'Unattended-Upgrade::MinimalSteps "true";',
                        'Unattended-Upgrade::Automatic-Reboot "false";']:
            self.assertIn(setting, result.stdout)
        origins = [line for line in result.stdout.splitlines() if line.startswith("Unattended-Upgrade::Origins-Pattern:: ")]
        self.assertEqual(len(origins), 3)
        self.assertTrue(all("codename=trixie" in value and "origin=Debian" in value for value in origins))
        self.assertNotIn("DPkg::Pre-Invoke::", result.stdout)

    def test_native_backend_filters_release_origin_metadata(self):
        # Read the installed Debian backend as a Python module; never invoke
        # main/cache/lock/upgrade/reboot. Only its pure origin predicate is used.
        script = r'''
import importlib.machinery
import importlib.util
from types import SimpleNamespace
loader = importlib.machinery.SourceFileLoader("uu_predicate", "/usr/bin/unattended-upgrade")
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
allowed = ["origin=Debian,codename=trixie,label=Debian", "origin=Debian,codename=trixie-updates,label=Debian", "origin=Debian,codename=trixie-security,label=Debian-Security"]
for codename, origin, label, trusted, expected in [
    ("trixie", "Debian", "Debian", True, True),
    ("trixie-updates", "Debian", "Debian", True, True),
    ("trixie-security", "Debian", "Debian-Security", True, True),
    ("forky", "Debian", "Debian", True, False),
    ("trixie-backports", "Debian Backports", "Debian Backports", True, False),
    ("trixie", "Foreign", "Debian", True, False)]:
    value = SimpleNamespace(codename=codename, origin=origin, label=label, trusted=trusted, component="main", site="deb.debian.org", archive="stable")
    assert module.is_allowed_origin(value, allowed) == expected, (value, expected)
'''
        result = subprocess.run(["/usr/bin/python3", "-B", "-c", script], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_service_timer_and_restart_policy_are_bounded_and_repeatable(self):
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(ROOT / "Maintenance" / SERVICE)
        self.assertEqual(unit["Service"]["Restart"], "on-failure")
        self.assertEqual(unit["Service"]["RestartSec"], "5min")
        self.assertEqual(unit["Service"]["TimeoutStartSec"], "1h")
        self.assertEqual(unit["Service"]["KillMode"], "control-group")
        self.assertEqual(unit["Unit"]["StartLimitIntervalSec"], "0")
        self.assertNotIn("ConditionPathExists", unit["Unit"])
        timer = configparser.ConfigParser(interpolation=None)
        timer.read(ROOT / "Maintenance" / TIMER)
        self.assertEqual(timer["Timer"]["OnBootSec"], "5min")
        self.assertEqual(timer["Timer"]["OnUnitInactiveSec"], "1h")
        policy = (ROOT / "Maintenance/needrestart.conf").read_text()
        self.assertIn("require '/etc/needrestart/needrestart.conf'", policy)
        self.assertIn("maintenance|bootstrap|repair|resume", policy)

    def test_bundle_admits_maintenance_after_prerequisites(self):
        spec = importlib.util.spec_from_file_location("packer", ROOT / "Bootstrap/pack.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assets = module.assets()
        self.assertEqual(assets["lib/tasks.list"][0], b"prerequisites:\nmaintenance:prerequisites\n")
        self.assertEqual(assets["lib/maintenance/update.sh"][1], "0755")
        self.assertEqual(module.assemble(), (ROOT / "setup.sh").read_bytes())


if __name__ == "__main__":
    unittest.main()
