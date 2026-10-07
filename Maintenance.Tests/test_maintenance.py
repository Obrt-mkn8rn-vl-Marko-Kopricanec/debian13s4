import configparser
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
import uuid


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
    if str(state_dir / "maintenance.restarts") in args:
        stage = "restart_commit"
    elif any("maintenance.restarts." in arg or "restart-intent." in arg for arg in args):
        stage = "restart_data"
    elif any("maintenance.ready." in arg or "maintenance-intent." in arg for arg in args):
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
    elif stage == "restart_commit" and faults.get("sync_restart_empty") and not (state_dir / "maintenance.restarts").read_text():
        code = 1
    else:
        if any(arg == str(state_dir) or str(state_dir) + "/" in arg for arg in args):
            state["disk"]["ready"] = (state_dir / "maintenance.ready").read_text() if (state_dir / "maintenance.ready").exists() else None
            state["disk"]["restarts"] = (state_dir / "maintenance.restarts").read_text() if (state_dir / "maintenance.restarts").exists() else None
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
        properties = state["services"].get(unit, {})
        if faults.get("show_target") == unit or faults.get("show_property") == prop:
            code = 1
        if prop == "LoadState":
            output = properties.get(prop, "loaded" if unit in state["services"] or (systemd / unit).exists() else "not-found")
        elif prop == "ActiveState":
            output = properties.get(prop, "active" if state["active"].get(unit) else "inactive")
        elif prop in ("RefuseManualStart", "RefuseManualStop", "RemainAfterExit"):
            output = properties.get(prop, "no")
        elif prop == "Result":
            output = properties.get(prop, "success")
        elif prop == "Type":
            output = properties.get(prop, "simple")
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
    elif command == "restart":
        state["clock"] = state.get("clock", 0) + faults.get("restart_ticks", 0)
        properties = state["services"][unit]
        properties["ActiveState"] = "inactive"
        if unit in faults.get("restart_targets", []):
            properties["Result"] = "exit-code"
            code = 1
        else:
            properties["ActiveState"] = "inactive" if faults.get("restart_inactive") else properties.get("after_restart", "active")
            properties["Result"] = "exit-code" if faults.get("restart_bad_result") else "success"
        if faults.get("exit_after_restart"):
            # Kill this disposable owner before it can publish completion.
            import os
            import signal
            os.kill(int(caller), signal.SIGKILL)
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
        self.database.write_text(json.dumps({"enabled": False, "active": {}, "services": {},
                                            "disk": {"ready": None, "units": {}, "enabled": False, "restarts": None}, "faults": {}}))
        self.boot_count = 1
        (self.root / "boot-id").write_text(str(uuid.UUID(int=self.boot_count)) + "\n")
        (self.root / "boot-id").chmod(0o600)
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
S4M_BOOT_FILE={q(str(self.root / 'boot-id'))}
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
s4m_restart_command() {{
    local target
    target=$(s4m_unit_name "$1") || return 1
    python3 {q(str(self.model))} {q(str(self.database))} {q(str(self.log))} systemctl "$BASHPID" restart -- "$target"
}}
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
    [[ ! -f {q(str(self.root / 'scan-output'))} ]] || cat {q(str(self.root / 'scan-output'))}
    [[ $FAULT != restart ]]
}}
'''

    def run_fixture(self, action="s4m_apply", additions="", timeout=30):
        return subprocess.run(["bash", "--noprofile", "--norc", "-c", self.harness() + additions + "\n" + action],
                              capture_output=True, text=True, timeout=timeout)

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

    def targets(self, names, **properties):
        state = self.state()
        state["services"].update({name if name.endswith(".service") else name + ".service":
                                  {"ActiveState": "active", **properties} for name in names})
        self.database.write_text(json.dumps(state))
        (self.root / "scan-output").write_text("".join("NEEDRESTART-SVC: " + name + "\n" for name in names))

    def pending(self):
        path = self.state_dir / "maintenance.restarts"
        return path.read_text().splitlines() if path.exists() else []

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
        pending = self.state_dir / "maintenance.restarts"
        pending.unlink(missing_ok=True)
        if disk["restarts"] is not None:
            pending.write_text(disk["restarts"])
            pending.chmod(0o600)
        self.boot_count += 1
        (self.root / "boot-id").write_text(str(uuid.UUID(int=self.boot_count)) + "\n")
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

    def test_external_command_cannot_replace_a_package_profile_callback(self):
        self.assert_success(self.run_fixture())
        self.packages.unlink()
        result = self.run_fixture("s4m_update", "S4M_UPDATE_UPGRADE=true\n")
        self.assertNotEqual(result.returncode, 0)
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
        self.assertTrue(calls[-1].endswith("|mode:l"))

    def test_zero_exit_discovery_failed_restart_retains_inactive_target(self):
        self.assert_success(self.run_fixture())
        self.targets(["nginx.service"])
        self.faults(restart_targets=["nginx.service"])
        result = self.run_fixture("s4m_update")
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.pending(), ["nginx.service"])
        self.assertEqual(self.state()["disk"]["restarts"], "nginx.service\n")
        self.assertEqual(self.state()["services"]["nginx.service"]["ActiveState"], "inactive")
        restart = [event for event in self.events() if event["args"][0] == "restart"]
        self.assertEqual(len(restart), 1)
        self.assertEqual(restart[0]["code"], 1)
        self.assertIn("-b -r l -l|mode:l", self.package_calls()[-1])

    def test_inactive_pending_target_recovers_without_scan_or_internet(self):
        self.assert_success(self.run_fixture())
        self.targets(["nginx.service"])
        self.faults(restart_targets=["nginx.service"])
        self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
        self.faults()
        (self.root / "scan-output").write_text("")
        result = self.run_fixture("s4m_update", "FAULT=offline\n")
        self.assertNotEqual(result.returncode, 0)  # refresh still retries later
        self.assertEqual(self.state()["services"]["nginx.service"]["ActiveState"], "active")
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.state()["disk"]["restarts"], "")
        self.assert_success(self.run_fixture("s4m_update"))

    def test_bare_default_deny_allow_survives_failed_restart_and_offline_retry(self):
        with (self.library / "needrestart.conf").open("a") as config:
            config.write("$nrconf{defno}=1; $nrconf{override_rc}={qr(^legacy$)=>1};\n")
        self.assert_success(self.run_fixture())
        self.targets(["legacy"])
        self.faults(restart_targets=["legacy.service"])
        self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
        self.assertEqual(self.pending(), ["legacy"])
        self.assertEqual(self.state()["disk"]["restarts"], "legacy\n")
        self.assertEqual(self.state()["services"]["legacy.service"]["ActiveState"], "inactive")
        self.reboot()
        (self.root / "scan-output").write_text("")
        self.faults(restart_targets=["legacy.service"])
        before = len(self.events())
        self.assertNotEqual(self.run_fixture("s4m_update", "FAULT=offline\n").returncode, 0)
        retries = [e for e in self.events()[before:] if e["args"][0] == "restart"]
        self.assertEqual([e["args"][-1] for e in retries], ["legacy.service"])
        self.assertEqual(self.pending(), ["legacy"])
        self.assertEqual(self.state()["disk"]["restarts"], "legacy\n")
        self.faults()
        self.assertNotEqual(self.run_fixture("s4m_update", "FAULT=offline\n").returncode, 0)
        self.assertEqual(self.state()["services"]["legacy.service"]["ActiveState"], "active")
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.state()["disk"]["restarts"], "")
        self.assert_success(self.run_fixture("s4m_update"))

    def test_zero_exit_restart_requires_observed_state_and_result(self):
        self.assert_success(self.run_fixture())
        self.targets(["nginx.service"])
        for fault in ({"restart_inactive": True}, {"restart_bad_result": True}, {"show_property": "Result"}):
            with self.subTest(fault=fault):
                self.faults(**fault)
                self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
                self.assertEqual(self.pending(), ["nginx.service"])
        self.faults()
        self.assert_success(self.run_fixture("s4m_update"))
        self.assertEqual(self.pending(), [])

    def test_oneshot_completion_and_manual_refusals_preserve_unit_semantics(self):
        self.assert_success(self.run_fixture())
        self.targets(["fixture.service"], Type="oneshot", RemainAfterExit="no", after_restart="inactive")
        self.assert_success(self.run_fixture("s4m_update"))
        self.assertEqual(self.pending(), [])
        for property_name in ("RefuseManualStop", "RefuseManualStart"):
            with self.subTest(property=property_name):
                self.targets(["fixture.service"], **{property_name: "yes"})
                before = len([e for e in self.events() if e["args"][0] == "restart"])
                self.assert_success(self.run_fixture("s4m_update"))
                self.assertEqual(len([e for e in self.events() if e["args"][0] == "restart"]), before)
                self.assertEqual(self.pending(), [])

    def test_native_and_controller_exclusions_never_restart(self):
        self.assert_success(self.run_fixture())
        self.targets(["dbus.service", "networking.service", "apt-daily.service",
                      "debian13s4-maintenance.service", "debian13s4-bootstrap.service",
                      "debian13s4-repair.service", "debian13s4-resume.service",
                      "dbus", "networking", "debian13s4-maintenance", "debian13s4-bootstrap",
                      "debian13s4-repair", "debian13s4-resume", "nginx.service"])
        self.assert_success(self.run_fixture("s4m_update"))
        targets = [e["args"][-1] for e in self.events() if e["args"][0] == "restart"]
        self.assertEqual(targets, ["nginx.service"])
        self.assertEqual(self.pending(), [])

    def test_restart_intent_sync_failures_precede_all_service_mutation(self):
        self.assert_success(self.run_fixture())
        self.targets(["nginx.service"])
        for stage in ("restart_data", "restart_commit"):
            with self.subTest(stage=stage):
                self.faults(**{"sync_" + stage: True})
                self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
                self.assertFalse(any(e["args"][0] == "restart" for e in self.events()))
                self.reboot()
        self.assert_success(self.run_fixture("s4m_update"))
        self.assertEqual(self.pending(), [])

    def test_restart_cleanup_sync_error_is_recovered_after_reboot(self):
        self.assert_success(self.run_fixture())
        self.targets(["nginx.service"])
        self.faults(sync_restart_empty=True)
        self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
        self.assertEqual(self.state()["disk"]["restarts"], "nginx.service\n")
        self.reboot()
        (self.root / "scan-output").write_text("")
        self.assertEqual(self.pending(), ["nginx.service"])
        self.assert_success(self.run_fixture("s4m_update"))
        self.assertEqual(self.pending(), [])

    def test_interrupted_prefix_rotates_durable_targets_for_later_retry(self):
        self.assert_success(self.run_fixture())
        self.targets(["alpha.service", "omega.service"])
        self.faults(exit_after_restart=True)
        self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
        self.assertEqual(self.state()["disk"]["restarts"], "omega.service\nalpha.service\n")
        self.reboot()
        (self.root / "scan-output").write_text("")
        self.faults(restart_targets=["alpha.service"])
        before = len(self.events())
        self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
        targets = [e["args"][-1] for e in self.events()[before:] if e["args"][0] == "restart"]
        self.assertEqual(targets[:2], ["omega.service", "alpha.service"])
        self.assertEqual(self.state()["services"]["omega.service"]["ActiveState"], "active")
        self.assertEqual(self.pending(), ["alpha.service"])

    def test_pending_journal_refuses_wrong_kinds_and_malformed_records(self):
        self.assert_success(self.run_fixture())
        path = self.state_dir / "maintenance.restarts"
        victim = self.root / "victim"
        victim.write_text("keep\n")
        inode = victim.stat().st_ino
        path.symlink_to(victim)
        self.assertNotEqual(self.run_fixture("s4m_update", timeout=10).returncode, 0)
        self.assertEqual(victim.read_text(), "keep\n")
        self.assertEqual(victim.stat().st_ino, inode)
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assertNotEqual(self.run_fixture("s4m_update", timeout=10).returncode, 0)
        path.unlink()
        for record in ("--help\n", "../../victim.service\n", "nginx.service extra\n", "@reboot:invalid\n",
                       "@reboot\n", "x" * 255 + "\n"):
            path.write_text(record)
            path.chmod(0o600)
            self.assertNotEqual(self.run_fixture("s4m_update").returncode, 0)
        self.assertFalse(any(e["args"][0] == "restart" for e in self.events()))

    def scaled_restart_budget(self):
        q = shlex.quote
        return f'''
S4M_ATTEMPT_SECONDS=48
S4M_PRE_RESTART_SECONDS=12
S4M_POST_RESTART_SECONDS=12
S4M_FINAL_RESERVE_SECONDS=4
S4M_RESTART_BOUND_SECONDS=4
s4m_now() {{
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("clock",0))' {q(str(self.database))}
}}
'''

    def test_slow_pending_queue_cannot_starve_package_repair_or_reboot(self):
        self.assert_success(self.run_fixture())
        names = [f"slow{index:02d}" for index in range(13)]
        self.targets(names)
        self.assert_success(self.run_fixture("s4m_discover_restarts"))
        # 13 bounded failures need 52 ticks, exceeding a whole 48-tick attempt.
        self.assertGreater(len(names) * 4, 48)
        q = shlex.quote
        additions = self.scaled_restart_budget() + f'''
FAULT=configure
s4m_restart_command() {{
    local target code=0
    target=$(s4m_unit_name "$1") || return 1
    timeout --signal=TERM --kill-after=0.02s 0.04s /bin/sh -c 'sleep 2' || code=$?
    [[ $code == 124 ]] || return 99
    python3 {q(str(self.model))} {q(str(self.database))} {q(str(self.log))} systemctl "$BASHPID" restart -- "$target" || :
    return "$code"
}}
'''
        for attempt in range(4):
            with self.subTest(attempt=attempt):
                before_order = [name for name in self.pending() if not name.startswith("@reboot:")]
                before_clock = self.state().get("clock", 0)
                before_events, before_packages = len(self.events()), len(self.package_calls())
                if attempt == 2:
                    (self.root / "scan-output").write_text("NEEDRESTART-SVC: systemd-manager\n")
                else:
                    (self.root / "scan-output").write_text("")
                self.faults(restart_targets=[name + ".service" for name in names],
                            restart_ticks=4, reboot=attempt == 3)
                result = self.run_fixture("s4m_update", additions, timeout=45)
                self.assertEqual(result.returncode, 75 if attempt == 2 else 1, result.stderr)
                events = self.events()[before_events:]
                restarts = [e["args"][-1] for e in events if e["args"][0] == "restart"]
                self.assertEqual(restarts, [name + ".service" for name in before_order[:6]])
                self.assertEqual(self.state()["clock"] - before_clock, 24)
                pending = [name for name in self.pending() if not name.startswith("@reboot:")]
                self.assertEqual(pending, before_order[6:] + before_order[:6])
                self.assertEqual(set(pending), set(names))
                self.assertEqual(set(self.state()["disk"]["restarts"].splitlines()), set(self.pending()))
                calls = self.package_calls()[before_packages:]
                self.assertTrue(any(c.startswith("apt:update|") for c in calls))
                self.assertTrue(any(c.startswith("apt:--assume-yes --no-remove --fix-broken install|") for c in calls))
                self.assertTrue(any(c.startswith("unattended:--verbose|") for c in calls))
                if attempt == 2:
                    self.assertTrue(any(e["args"][0] == "reboot" and e["code"] == 0 for e in events))
                if attempt == 3:
                    reboots = [e for e in events if e["args"][0] == "reboot"]
                    self.assertEqual(len(reboots), 2)  # early retry and final retry, with repair between
                    self.assertTrue(all(e["code"] == 1 for e in reboots))
                    self.assertTrue(any(name.startswith("@reboot:") for name in self.pending()))

    def test_restart_slice_defers_before_mutation_when_full_target_cannot_fit(self):
        self.assert_success(self.run_fixture())
        self.targets(["legacy"])
        self.assert_success(self.run_fixture("s4m_discover_restarts"))
        before = len(self.events())
        result = self.run_fixture('s4m_load_restarts; s4m_run_restarts "$((100 + S4M_RESTART_BOUND_SECONDS - 1))"',
                                  's4m_now() { printf "100\\n"; }\n')
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(self.pending(), ["legacy"])
        self.assertEqual(self.state()["disk"]["restarts"], "legacy\n")
        self.assertFalse(any(e["args"][0] == "restart" for e in self.events()[before:]))

    def test_late_package_completion_preserves_final_reboot_reserve(self):
        self.assert_success(self.run_fixture())
        self.targets(["legacy"])
        q = shlex.quote
        additions = self.scaled_restart_budget() + f'''
unattended-upgrade() {{
    python3 -c 'import json,sys; from pathlib import Path; p=Path(sys.argv[1]); s=json.loads(p.read_text()); s["clock"]=43; p.write_text(json.dumps(s))' {q(str(self.database))}
    printf 'kernel installed\\n' > "$S4M_REBOOT_MARKER"
    chmod 0600 "$S4M_REBOOT_MARKER"
}}
'''
        result = self.run_fixture("s4m_update", additions)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(self.pending(), ["legacy"])
        self.assertFalse(any(e["args"][0] == "restart" for e in self.events()))
        self.assertTrue(self.state()["reboot_requested"])

    def test_special_restart_hook_requires_durable_reboot_and_new_boot_id(self):
        self.assert_success(self.run_fixture())
        self.targets(["systemd-manager"])
        self.assertEqual(self.run_fixture("s4m_update").returncode, 75)
        boot = (self.root / "boot-id").read_text().strip()
        self.assertEqual(self.pending(), ["@reboot:" + boot])
        self.assertEqual(self.state()["disk"]["restarts"], "@reboot:" + boot + "\n")
        self.assertFalse(any(e["args"][0] == "restart" for e in self.events()))
        (self.root / "scan-output").write_text("")
        self.faults(reboot=True)
        self.assertNotEqual(self.run_fixture("s4m_update", "FAULT=offline\n").returncode, 0)
        self.assertEqual(self.pending(), ["@reboot:" + boot])
        self.reboot()
        self.assert_success(self.run_fixture("s4m_update"))
        self.assertEqual(self.pending(), [])

    def test_restart_command_closes_lock_and_has_its_own_finite_budget(self):
        definition = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                                     '. "$1"; declare -f s4m_restart_command', "fixture", str(ROOT / "Maintenance/common.sh")],
                                    text=True, capture_output=True, timeout=3)
        self.assertEqual(definition.returncode, 0, definition.stderr)
        script = self.harness() + definition.stdout + '''
s4m_lock
timeout() {
    [[ ! -e /proc/$BASHPID/fd/$S4M_REPAIR_FD ]]
    if [[ $3 == 10s ]]; then
        shift 3
        "$@"
        return $?
    fi
    [[ $* == '--signal=TERM --kill-after=10s 300s env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C systemctl restart -- nginx.service' ]]
}
s4m_restart_command nginx.service
s4m_unlock
'''
        self.assertEqual(subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                                        text=True, capture_output=True, timeout=3).returncode, 0)

    def test_custom_restart_hook_failure_and_untrusted_leaf_stay_pending(self):
        hooks = self.root / "hooks"
        hooks.mkdir(mode=0o700)
        hook = hooks / "fixture.service"
        marker = self.root / "hook-ran"
        hook.write_text("#!/bin/sh\nprintf 'attempt\\n' >> " + shlex.quote(str(marker)) + "\nexit 1\n")
        hook.chmod(0o755)
        with (self.library / "needrestart.conf").open("a") as config:
            config.write("$nrconf{restart_d} = '" + str(hooks) + "';\n")
        self.assert_success(self.run_fixture())
        self.targets(["fixture.service"])
        definition = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                                     '. "$1"; declare -f s4m_restart_command', "fixture", str(ROOT / "Maintenance/common.sh")],
                                    text=True, capture_output=True, timeout=3)
        self.assertEqual(definition.returncode, 0, definition.stderr)
        result = self.run_fixture("s4m_update", definition.stdout)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text(), "attempt\n")
        self.assertEqual(self.pending(), ["fixture.service"])
        self.assertEqual(self.state()["disk"]["restarts"], "fixture.service\n")
        victim = self.root / "hook-victim"
        victim.write_text("#!/bin/sh\nexit 0\n")
        victim.chmod(0o755)
        identity = victim.stat().st_ino
        hook.unlink()
        hook.symlink_to(victim)
        self.assertNotEqual(self.run_fixture("s4m_update", definition.stdout).returncode, 0)
        self.assertEqual(self.pending(), ["fixture.service"])
        self.assertEqual(marker.read_text(), "attempt\n")
        self.assertEqual(victim.stat().st_ino, identity)
        self.assertEqual(victim.read_text(), "#!/bin/sh\nexit 0\n")
        hook.unlink()
        hook.write_text("#!/bin/sh\nprintf 'attempt\\n' >> " + shlex.quote(str(marker)) + "\nexit 0\n")
        hook.chmod(0o755)
        self.assert_success(self.run_fixture("s4m_update", definition.stdout))
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.state()["disk"]["restarts"], "")
        self.assertEqual(marker.read_text(), "attempt\nattempt\nattempt\n")

    def test_bare_custom_hook_retains_original_identity_and_checked_unit_state(self):
        hooks = self.root / "hooks"
        hooks.mkdir(mode=0o700)
        hook = hooks / "legacy"
        decoy = hooks / "legacy.service"
        marker = self.root / "hook-ran"
        wrong_marker = self.root / "wrong-hook-ran"
        hook.write_text("#!/bin/sh\nprintf 'attempt\\n' >> " + shlex.quote(str(marker)) + "\nexit 1\n")
        hook.chmod(0o755)
        decoy.write_text("#!/bin/sh\ntouch " + shlex.quote(str(wrong_marker)) + "\nexit 0\n")
        decoy.chmod(0o755)
        decoy_bytes, decoy_inode = decoy.read_bytes(), decoy.stat().st_ino
        with (self.library / "needrestart.conf").open("a") as config:
            config.write("$nrconf{restart_d} = '" + str(hooks) + "';\n")
            config.write("$nrconf{defno}=1; $nrconf{override_rc}={qr(^legacy$)=>1};\n")
        self.assert_success(self.run_fixture())
        self.targets(["legacy"], ActiveState="inactive")
        definition = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                                     '. "$1"; declare -f s4m_restart_command', "fixture", str(ROOT / "Maintenance/common.sh")],
                                    text=True, capture_output=True, timeout=3)
        self.assertEqual(definition.returncode, 0, definition.stderr)
        self.assertNotEqual(self.run_fixture("s4m_update", definition.stdout).returncode, 0)
        self.assertEqual(marker.read_text(), "attempt\n")
        self.assertEqual(self.pending(), ["legacy"])
        self.assertEqual(self.state()["disk"]["restarts"], "legacy\n")
        self.reboot()
        (self.root / "scan-output").write_text("")
        self.assertNotEqual(self.run_fixture("s4m_update", definition.stdout + "FAULT=offline\n").returncode, 0)
        self.assertEqual(marker.read_text(), "attempt\nattempt\n")
        self.assertEqual(self.pending(), ["legacy"])
        self.assertEqual(self.state()["services"]["legacy.service"]["ActiveState"], "inactive")
        hook.write_text("#!/bin/sh\nprintf 'attempt\\n' >> " + shlex.quote(str(marker)) + "\nexit 0\n")
        self.assertNotEqual(self.run_fixture("s4m_update", definition.stdout + "FAULT=offline\n").returncode, 0)
        # A zero-exit hook cannot clear intent while the normalized unit is inactive.
        self.assertEqual(self.pending(), ["legacy"])
        state = self.state()
        state["services"]["legacy.service"]["ActiveState"] = "active"
        self.database.write_text(json.dumps(state))
        self.assertNotEqual(self.run_fixture("s4m_update", definition.stdout + "FAULT=offline\n").returncode, 0)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.state()["disk"]["restarts"], "")
        self.assertEqual(marker.read_text(), "attempt\nattempt\nattempt\nattempt\n")
        self.assertFalse(wrong_marker.exists())
        self.assertEqual(decoy.read_bytes(), decoy_bytes)
        self.assertEqual(decoy.stat().st_ino, decoy_inode)

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
    def test_native_uptime_clock_is_numeric_and_monotonic(self):
        before = int(Path("/proc/uptime").read_text().split()[0].split(".")[0])
        result = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                                 '. "$1"; s4m_now', "fixture", str(ROOT / "Maintenance/common.sh")],
                                capture_output=True, text=True, timeout=3)
        after = int(Path("/proc/uptime").read_text().split()[0].split(".")[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip().isdigit())
        self.assertLessEqual(before, int(result.stdout))
        self.assertLessEqual(int(result.stdout), after)

    def test_shipped_restart_slices_reserve_package_and_final_control_time(self):
        result = subprocess.run(["bash", "--noprofile", "--norc", "-c", '''
. "$1"
printf '%s\\n' "$S4M_ATTEMPT_SECONDS" "$S4M_PRE_RESTART_SECONDS" "$S4M_POST_RESTART_SECONDS" \\
    "$S4M_FINAL_RESERVE_SECONDS" "$S4M_RESTART_BOUND_SECONDS" "$S4M_RESTART_SECONDS" \\
    "$S4M_RESTART_GRACE_SECONDS" "$S4M_CONTROL_SECONDS" "$S4M_CONTROL_GRACE_SECONDS"
''', "fixture", str(ROOT / "Maintenance/common.sh")], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        total, pre, post, final, bound, restart, grace, control, control_grace = map(int, result.stdout.splitlines())
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(ROOT / "Maintenance" / SERVICE)
        timeout = re.fullmatch(r"([0-9]+)(s|min|h)", unit["Service"]["TimeoutStartSec"])
        self.assertIsNotNone(timeout)
        self.assertEqual(total, int(timeout.group(1)) * {"s": 1, "min": 60, "h": 3600}[timeout.group(2)])
        self.assertEqual(bound, restart + grace + 12 * (control + control_grace) + 30)
        self.assertLessEqual(bound, min(pre, post))
        self.assertEqual(total - pre - post - final, 2100)
        self.assertGreaterEqual(final, 2 * (control + control_grace))
        self.assertGreater(13 * restart, total)

    def test_native_ui_does_not_propagate_a_failed_child_exit(self):
        script = '''use NeedRestart::UI;
my $status;
my $ui = NeedRestart::UI->new(0);
$ui->runcmd(sub { $status = system('/bin/false'); });
print "child_status=$status\\n";
'''
        result = subprocess.run(["perl", "-e", script], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "child_status=256\n")

    def test_real_selector_preserves_policy_and_rejects_invalid_targets(self):
        helper = ROOT / "Maintenance/restart-policy.pl"
        result = subprocess.run(["perl", str(helper), str(ROOT / "Maintenance/needrestart.conf")],
                                input="NEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: dbus.service\nNEEDRESTART-SVC: networking.service\nNEEDRESTART-SVC: debian13s4-repair.service\nNEEDRESTART-SVC: debian13s4-repair\nNEEDRESTART-SVC: systemd-manager\n",
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "nginx.service\n@reboot\n")
        with tempfile.TemporaryDirectory(prefix="debian13s4-policy-selector.") as directory:
            config = Path(directory) / "policy.conf"
            # A valid configuration returning false is not a Perl import error.
            config.write_text("$nrconf{defno}=1; $nrconf{override_rc}={qr(^allow)=>1}; $nrconf{blacklist_rc}=[qr(^allow-block)]; 0;\n")
            result = subprocess.run(["perl", str(helper), str(config)],
                                    input="NEEDRESTART-SVC: allow.service\nNEEDRESTART-SVC: allow-block.service\nNEEDRESTART-SVC: other.service\n",
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "allow.service\n")
            config.write_text("$nrconf{defno}=0; 0;\n")
            for target in ("--help", "../../victim", "nginx.service extra", "x" * 255,
                           "@reboot", "@reboot:00000000-0000-0000-0000-000000000001"):
                result = subprocess.run(["perl", str(helper), str(config)], input="NEEDRESTART-SVC: " + target + "\n",
                                        text=True, capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, target)

    def test_real_selector_keeps_original_anchored_policy_and_hook_identity(self):
        helper = ROOT / "Maintenance/restart-policy.pl"
        with tempfile.TemporaryDirectory(prefix="debian13s4-policy-identity.") as directory:
            config = Path(directory) / "policy.conf"
            config.write_text("$nrconf{defno}=1; $nrconf{override_rc}={qr(^legacy$)=>1}; "
                              "$nrconf{restart_d}='" + directory + "'; 0;\n")
            result = subprocess.run(["perl", str(helper), str(config)],
                                    input="NEEDRESTART-SVC: legacy\nNEEDRESTART-SVC: legacy.service\nNEEDRESTART-SVC: legacy\n",
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "legacy\n")
            replay = subprocess.run(["perl", str(helper), str(config)],
                                    input="NEEDRESTART-SVC: " + result.stdout,
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertEqual(replay.stdout, result.stdout)
            for name in ("legacy", "legacy.service"):
                hook = Path(directory) / name
                hook.write_text("#!/bin/sh\nexit 0\n")
                hook.chmod(0o755)
                selected = subprocess.run(["perl", str(helper), str(config), name],
                                          text=True, capture_output=True, timeout=5)
                self.assertEqual(selected.returncode, 0, selected.stderr)
                self.assertEqual(selected.stdout, str(hook) + "\n")
            config.write_text("$nrconf{defno}=0; 0;\n")
            distinct = subprocess.run(["perl", str(helper), str(config)],
                                      input="NEEDRESTART-SVC: legacy\nNEEDRESTART-SVC: legacy.service\n",
                                      text=True, capture_output=True, timeout=5)
            self.assertEqual(distinct.returncode, 0, distinct.stderr)
            self.assertEqual(distinct.stdout, "legacy\nlegacy.service\n")

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
        self.assertIn("do '/etc/needrestart/needrestart.conf'", policy)
        self.assertIn("maintenance|dotnet|bootstrap|repair|resume", policy)

    def test_bundle_admits_maintenance_after_prerequisites(self):
        spec = importlib.util.spec_from_file_location("packer", ROOT / "Bootstrap/pack.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assets = module.assets()
        self.assertEqual(assets["lib/tasks.list"][0], b"prerequisites:\nmaintenance:prerequisites\ndotnet:prerequisites\n")
        self.assertEqual(assets["lib/maintenance/update.sh"][1], "0755")
        self.assertEqual(module.assemble(), (ROOT / "setup.sh").read_bytes())


if __name__ == "__main__":
    unittest.main()
