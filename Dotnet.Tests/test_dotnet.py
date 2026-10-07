import configparser
import fcntl
import hashlib
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


ROOT = Path(__file__).resolve().parents[1]
if os.geteuid() == 0:
    raise RuntimeError("Run these substituted fixtures as an ordinary user.")
spec = importlib.util.spec_from_file_location("maintenance_fixture", ROOT / "Maintenance.Tests/test_maintenance.py")
maintenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(maintenance)
SERVICE = "debian13s4-dotnet.service"
TIMER = "debian13s4-dotnet.timer"
FINGERPRINT = "AA86F75E427A19DD33346403EE4D7792F748182B"


class DotnetTests(unittest.TestCase):
    run_fixture = maintenance.MaintenanceTests.run_fixture
    state = maintenance.MaintenanceTests.state
    faults = maintenance.MaintenanceTests.faults
    events = maintenance.MaintenanceTests.events
    package_calls = maintenance.MaintenanceTests.package_calls
    targets = maintenance.MaintenanceTests.targets
    pending = maintenance.MaintenanceTests.pending
    assert_success = maintenance.MaintenanceTests.assert_success

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="debian13s4-dotnet-tests.", dir="/dev/shm")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.library = self.root / "library"
        self.maintenance = self.root / "maintenance"
        self.state_dir = self.root / "state"
        self.systemd = self.root / "systemd"
        for path in (self.library, self.maintenance, self.state_dir, self.systemd):
            path.mkdir(mode=0o700)
        self.database = self.root / "manager.json"
        self.log = self.root / "events.jsonl"
        self.packages = self.root / "packages.log"
        self.model = self.root / "model.py"
        model = maintenance.MODEL.replace("debian13s4-maintenance", "debian13s4-dotnet")
        model = model.replace("maintenance.ready", "dotnet.ready").replace("maintenance-intent.", "dotnet-intent.")
        self.model.write_text(model)
        self.database.write_text(json.dumps({"enabled": False, "active": {}, "services": {},
                                            "disk": {"ready": None, "units": {}, "enabled": False, "restarts": None},
                                            "faults": {}}))
        self.boot_count = 1
        (self.root / "boot-id").write_text(str(uuid.UUID(int=self.boot_count)) + "\n")
        (self.root / "boot-id").chmod(0o600)
        for source in (ROOT / "Maintenance").iterdir():
            (self.maintenance / source.name).write_bytes(source.read_bytes())
            (self.maintenance / source.name).chmod(0o755 if source.name == "update.sh" else 0o644)
        for source in (ROOT / "Dotnet").iterdir():
            text = source.read_text()
            if source.name == "common.sh":
                text = text.replace("/usr/local/lib/debian13s4/maintenance/common.sh",
                                    str(self.maintenance / "common.sh"))
                text = text.replace("s4m_load_packages\n",
                                    "source " + shlex.quote(str(ROOT / "Tasks/prerequisites/common.sh")) + "\n", 1)
            (self.library / source.name).write_text(text)
            (self.library / source.name).chmod(0o755 if source.name == "update.sh" else 0o644)
        (self.library / "sources.sources").write_bytes(
            (ROOT / "Tasks/prerequisites/debian.sources").read_bytes() + b"\n" +
            (ROOT / "Dotnet/microsoft.sources").read_bytes())
        (self.library / "sources.sources").chmod(0o644)
        self.install_root = self.root / "installed"
        self.install_root.mkdir(mode=0o700)
        self.program = self.install_root / "usr/share/dotnet/dotnet"
        self.program.parent.mkdir(parents=True, mode=0o755)
        self.program.write_text("#!/bin/sh\nprintf '%s\\n' "
                                "'Microsoft.AspNetCore.App 10.0.12 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]' "
                                "'Microsoft.NETCore.App 10.0.12 [/usr/share/dotnet/shared/Microsoft.NETCore.App]'\n")
        self.program.chmod(0o755)
        self.command_link = self.root / "dotnet-link"
        self.command_link.symlink_to(self.program)
        helper = self.library / "verify-payload.pl"
        helper.write_text(helper.read_text().replace("my $install_root = '/';",
                                                    f"my $install_root = '{self.install_root}';")
                          .replace("my $trusted_uid = 0;", f"my $trusted_uid = {os.geteuid()};"))
        helper.chmod(0o644)
        self.admindir = self.install_root / "var/lib/dpkg"
        (self.admindir / "info").mkdir(parents=True, mode=0o755)
        self.payloads = {"dotnet-host": {"usr/share/dotnet/dotnet": self.program.read_bytes()},
                         "dotnet-hostfxr-10.0": {"usr/share/dotnet/host/fxr/10.0.12/libhostfxr.so": b"hostfxr"},
                         "dotnet-runtime-deps-10.0": {"usr/share/doc/dotnet-runtime-deps-10.0/copyright": b"notice"}}
        for package, family, names in (
                ("dotnet-runtime-10.0", "Microsoft.NETCore.App",
                 "libcoreclr.so libclrjit.so libhostpolicy.so libSystem.Native.so "
                 "libSystem.Globalization.Native.so libSystem.IO.Compression.Native.so "
                 "libSystem.Net.Security.Native.so libSystem.Security.Cryptography.Native.OpenSsl.so "
                 "System.Private.CoreLib.dll System.Runtime.dll System.Net.Http.dll "
                 "Microsoft.NETCore.App.deps.json Microsoft.NETCore.App.runtimeconfig.json"),
                ("aspnetcore-runtime-10.0", "Microsoft.AspNetCore.App",
                 "Microsoft.AspNetCore.dll Microsoft.AspNetCore.Hosting.dll Microsoft.AspNetCore.Http.dll "
                 "Microsoft.AspNetCore.Server.Kestrel.dll Microsoft.AspNetCore.Routing.dll "
                 "Microsoft.AspNetCore.App.deps.json Microsoft.AspNetCore.App.runtimeconfig.json")):
            self.payloads[package] = {f"usr/share/dotnet/shared/{family}/10.0.12/{name}":
                                      (name+" fixture bytes\n").encode() for name in names.split()}
        (self.admindir / "status").write_text("".join(
            f"Package: {package}\nStatus: install ok installed\nVersion: 10.0.12-1\n"
            "Architecture: amd64\nMaintainer: fixture\nDescription: fixture\n\n"
            for package in self.payloads))
        (self.admindir / "status").chmod(0o644)
        self.restore_payloads()

    def restore_payloads(self):
        for package, files in self.payloads.items():
            directories = set()
            for name, data in files.items():
                target = self.install_root / name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                target.write_bytes(data)
                target.chmod(0o755 if target == self.program else 0o644)
                directories.update("/"+str(parent) for parent in Path(name).parents if str(parent) != ".")
            (self.admindir / "info" / (package+".list")).write_text(
                "/.\n"+"".join(name+"\n" for name in sorted(directories | {"/"+name for name in files} |
                                                               {"/usr/share/dotnet"})))
            self.refresh_manifest(package)
            (self.admindir / "info" / (package+".list")).chmod(0o644)
        # mkdir(parents=True) uses the process umask for intermediate directories.
        for directory in self.install_root.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)

    def refresh_manifest(self, package):
        metadata = self.admindir / "info" / (package+".md5sums")
        metadata.write_text("".join(hashlib.md5((self.install_root / name).read_bytes()).hexdigest()+
                                    "  "+name+"\n" for name in self.payloads[package]))
        metadata.chmod(0o644)

    def payload(self, family, name):
        return self.install_root / "usr/share/dotnet/shared" / family / "10.0.12" / name

    def assert_registered_and_enumerated(self):
        result = subprocess.run(["dpkg-query", f"--admindir={self.admindir}", "--show",
                                 "--showformat=${Status}\n"], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["install ok installed"]*5)
        result = subprocess.run([str(self.program), "--list-runtimes"],
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Microsoft.NETCore.App 10.0.12", result.stdout)
        self.assertIn("Microsoft.AspNetCore.App 10.0.12", result.stdout)

    def repairing_apt(self):
        # Substitute package delivery only; production health and hashing run unchanged.
        restore = "\n".join("printf %s "+shlex.quote(data.decode())+" > "+
                             shlex.quote(str(self.install_root / name))
                             for files in self.payloads.values() for name,data in files.items())
        return """apt-get() {
    printf 'apt:%s\\n' "$*" >> """+shlex.quote(str(self.packages))+"""
    if [[ $* == *--reinstall* ]]; then
"""+restore+"""
    fi
    return 0
}
"""

    def harness(self):
        q = shlex.quote
        base = maintenance.MaintenanceTests.harness(self).replace(
            "S4M_LIBRARY=" + q(str(self.library)), "S4M_LIBRARY=" + q(str(self.maintenance)))
        return base + f'''
S4D_LIBRARY={q(str(self.library))}
S4D_DOTNET={q(str(self.program))}
S4D_LINK={q(str(self.command_link))}
S4D_APT_DIR={q(str(self.root / "apt"))}
stat() {{
    if [[ $* == "--format=%u -- $S4D_LINK" ]]; then printf '0\\n'; else command stat "$@"; fi
}}
'''

    def apply(self, additions=""):
        return self.run_fixture("s4d_apply", additions)

    def verify(self, additions=""):
        return self.run_fixture("s4d_verify", additions)

    def update(self, additions=""):
        return self.run_fixture("s4d_update", additions)

    def reboot(self):
        state = self.state()
        ready = self.state_dir / "dotnet.ready"
        ready.unlink(missing_ok=True)
        if state["disk"]["ready"] is not None:
            ready.write_text(state["disk"]["ready"])
            ready.chmod(0o600)
        state["enabled"] = state["disk"]["enabled"]
        state["active"] = {TIMER: state["enabled"]}
        state["faults"] = {}
        self.boot_count += 1
        (self.root / "boot-id").write_text(str(uuid.UUID(int=self.boot_count)) + "\n")
        self.database.write_text(json.dumps(state))

    def test_offline_initial_delivery_stays_unready_then_recovers(self):
        self.assertNotEqual(self.apply("FAULT=offline\n").returncode, 0)
        self.assertFalse((self.state_dir / "dotnet.ready").exists())
        self.assertFalse(any(event["args"][0] == "enable" for event in self.events() if event["action"] == "systemctl"))
        self.assert_success(self.apply())
        self.assert_success(self.verify())

    def test_partial_packages_are_repaired_before_runtime_installation(self):
        self.assert_success(self.apply("FAULT=configure\n"))
        calls = self.package_calls()
        fix = next(i for i,c in enumerate(calls) if c.startswith("apt:--assume-yes --no-remove --fix-broken install|"))
        install = next(i for i,c in enumerate(calls) if "install aspnetcore-runtime-10.0" in c)
        self.assertLess(fix, install)

    def test_unrepairable_dependencies_publish_no_readiness_or_timer(self):
        self.assertNotEqual(self.apply("FAULT=never_configure\n").returncode, 0)
        self.assertFalse((self.state_dir / "dotnet.ready").exists())
        self.assertFalse(self.state()["enabled"])

    def test_missing_or_failed_runtime_never_publishes_readiness(self):
        self.program.write_text("#!/bin/sh\nexit 1\n")
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertFalse((self.state_dir / "dotnet.ready").exists())
        self.assertFalse(self.state()["enabled"])

    def test_both_stable_ten_runtimes_are_required(self):
        for output in ("Microsoft.NETCore.App 10.0.12 [/usr/share/dotnet/shared/Microsoft.NETCore.App]",
                       "Microsoft.AspNetCore.App 9.0.12 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]",
                       "Microsoft.AspNetCore.App 10.0.0-preview.1 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]"):
            with self.subTest(output=output):
                self.program.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote(output) + "\n")
                self.refresh_manifest("dotnet-host")
                self.assertNotEqual(self.run_fixture("s4d_runtime").returncode, 0)

    def test_wrong_command_link_never_executes_the_victim(self):
        victim = self.root / "victim"
        victim.write_text("#!/bin/sh\ntouch " + shlex.quote(str(self.root / "executed")) + "\n")
        victim.chmod(0o755)
        self.command_link.unlink()
        self.command_link.symlink_to(victim)
        self.assertNotEqual(self.run_fixture("s4d_runtime").returncode, 0)
        self.assertFalse((self.root / "executed").exists())

    def test_native_link_owner_refuses_unprivileged_ownership(self):
        result = self.run_fixture("s4d_runtime", 'stat() { command stat "$@"; }\n')
        self.assertNotEqual(result.returncode, 0)

    def test_incomplete_package_status_is_not_runtime_readiness(self):
        result = self.run_fixture("s4d_runtime", "s4p_query() { printf 'install ok unpacked\\n'; }\n")
        self.assertNotEqual(result.returncode, 0)

    def test_timer_activation_is_observed_before_private_readiness(self):
        self.assert_success(self.apply())
        path = self.state_dir / "dotnet.ready"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        events = self.events()
        enable = next(i for i,e in enumerate(events) if e["action"] == "systemctl" and e["args"][0] == "enable")
        barrier = next(i for i,e in enumerate(events) if e["stage"] == "enablement")
        start = next(i for i,e in enumerate(events) if e["action"] == "systemctl" and e["args"][0] == "start")
        completion = next(i for i,e in enumerate(events) if e["stage"] == "ready_commit")
        self.assertLess(enable, barrier)
        self.assertLess(barrier, start)
        self.assertLess(start, completion)
        self.assertTrue(self.state()["disk"]["ready"])

    def test_delivery_and_manager_errors_leave_repair_pending(self):
        for fault in ("enable", "start", "start_incomplete", "sync_enablement", "sync_ready_commit"):
            with self.subTest(fault=fault):
                self.faults(**{fault:True})
                self.assertNotEqual(self.apply().returncode, 0)
                # A failed final flush can leave valid volatile observations.
                # Reboot discards unflushed completion; the timer was persisted.
                self.reboot()
                self.assertNotEqual(self.verify().returncode, 0)
                self.faults()
                self.assert_success(self.apply())

    def test_persistence_error_can_retry_after_simulated_reboot(self):
        self.faults(sync_ready_commit=True)
        self.assertNotEqual(self.apply().returncode, 0)
        self.reboot()
        self.assertNotEqual(self.verify().returncode, 0)
        self.assert_success(self.apply())
        self.assert_success(self.verify())

    def test_symbolic_unit_destination_preserves_victim(self):
        victim = self.root / "victim"
        victim.write_text("preserve\n")
        inode = victim.stat().st_ino
        (self.systemd / SERVICE).symlink_to(victim)
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertEqual(victim.read_text(), "preserve\n")
        self.assertEqual(victim.stat().st_ino, inode)

    def test_symbolic_readiness_is_refused_without_removal(self):
        victim = self.root / "victim"
        victim.write_text("preserve\n")
        marker = self.state_dir / "dotnet.ready"
        marker.symlink_to(victim)
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertTrue(marker.is_symlink())
        self.assertEqual(victim.read_text(), "preserve\n")

    def test_bootstrap_pending_blocks_runtime_updates(self):
        self.assert_success(self.apply())
        boot = self.state_dir / "bootstrap"
        boot.mkdir()
        (boot / "pending").write_text("unpublished\n")
        self.packages.unlink()
        self.assertEqual(self.update().returncode, 75)
        self.assertFalse(self.package_calls())

    def test_shared_lock_contention_blocks_runtime_mutations(self):
        self.assert_success(self.apply())
        self.packages.unlink()
        lock = self.state_dir / "repair.lock"
        lock.write_text("preserve\n")
        lock.chmod(0o600)
        with lock.open("rb") as holder:
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.update().returncode, 75)
            self.assertFalse(self.package_calls())
        self.assert_success(self.update())
        self.assertEqual(lock.read_text(), "preserve\n")

    def test_update_uses_runtime_policy_without_debian_unattended_upgrade(self):
        self.assert_success(self.apply())
        self.packages.unlink()
        self.assert_success(self.update())
        calls = self.package_calls()
        self.assertTrue(any("install aspnetcore-runtime-10.0" in c for c in calls))
        self.assertTrue(all(str(self.library / "policy.conf") in c for c in calls if c.startswith("apt:")))
        self.assertFalse(any(c.startswith("unattended:") for c in calls))

    def test_offline_runtime_does_not_change_debian_profile(self):
        self.assert_success(self.apply())
        result = self.run_fixture('s4d_update || :; [[ -z $S4M_UPDATE_POLICY && $S4M_UPDATE_READY == s4m_ready ]]',
                                  "FAULT=offline\n")
        self.assert_success(result)

    def test_removed_runtime_is_reinstalled_before_final_observation(self):
        self.assert_success(self.apply())
        self.packages.unlink()
        status = self.admindir / "status"
        original = status.read_text()
        status.write_text(original.replace("Package: aspnetcore-runtime-10.0\nStatus: install ok installed",
                                           "Package: aspnetcore-runtime-10.0\nStatus: deinstall ok not-installed"))
        restore_status = "printf %s "+shlex.quote(original)+" > "+shlex.quote(str(status))+"\n"
        result = self.update(self.repairing_apt().replace("    fi\n",restore_status+"    fi\n"))
        self.assert_success(result)
        self.assertTrue(any("--reinstall" in call for call in self.package_calls()))
        self.assert_success(self.verify())

    def test_missing_runtime_bytes_request_reinstallation_before_verification(self):
        self.assert_success(self.apply())
        self.packages.unlink()
        self.payload("Microsoft.NETCore.App", "libcoreclr.so").unlink()
        self.assert_registered_and_enumerated()
        self.assertNotEqual(self.verify().returncode, 0)
        result = self.update(self.repairing_apt())
        self.assert_success(result)
        self.assertTrue(any("--reinstall install aspnetcore-runtime-10.0" in call for call in self.package_calls()))
        self.assert_success(self.verify())

    def test_healthy_payload_requires_positive_native_manifest_verification(self):
        self.assert_registered_and_enumerated()
        self.assert_success(self.run_fixture("s4d_runtime"))
        self.assert_success(self.apply())
        self.assertFalse(any("--reinstall" in call for call in self.package_calls()))

    def test_missing_native_core_payload_is_unhealthy_with_successful_enumeration(self):
        self.payload("Microsoft.NETCore.App", "libcoreclr.so").unlink()
        self.assert_registered_and_enumerated()
        result = self.run_fixture("s4d_runtime")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("untrusted path", result.stderr)

    def test_corrupt_core_and_aspnet_payloads_are_unhealthy_with_successful_enumeration(self):
        for family, name in (("Microsoft.NETCore.App", "System.Private.CoreLib.dll"),
                             ("Microsoft.NETCore.App", "System.Net.Http.dll"),
                             ("Microsoft.AspNetCore.App", "Microsoft.AspNetCore.Routing.dll")):
            with self.subTest(name=name):
                self.restore_payloads()
                target = self.payload(family, name)
                original = target.read_bytes()
                target.write_bytes(bytes([original[0]^1])+original[1:])
                self.assert_registered_and_enumerated()
                result = self.run_fixture("s4d_runtime")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("checksum mismatch", result.stderr)

    def test_initial_apply_reinstalls_corrupt_aspnet_and_fully_revalidates(self):
        self.payload("Microsoft.AspNetCore.App", "Microsoft.AspNetCore.dll").write_bytes(b"damaged")
        self.assert_registered_and_enumerated()
        self.assertNotEqual(self.verify().returncode, 0)
        self.assert_success(self.apply(self.repairing_apt()))
        self.assertTrue(any("--reinstall install aspnetcore-runtime-10.0" in call for call in self.package_calls()))
        self.assert_success(self.verify())

    def test_zero_exit_install_without_payload_repair_cannot_publish_readiness(self):
        self.payload("Microsoft.NETCore.App", "System.Private.CoreLib.dll").unlink()
        self.assert_registered_and_enumerated()
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertFalse((self.state_dir / "dotnet.ready").exists())
        self.assertFalse(self.state()["enabled"])
        self.assertTrue(any("--reinstall" in call for call in self.package_calls()))

    def test_recurring_corruption_retains_failure_then_reinstalls_core_and_aspnet(self):
        self.assert_success(self.apply())
        for family,name in (("Microsoft.NETCore.App", "System.Private.CoreLib.dll"),
                            ("Microsoft.AspNetCore.App", "Microsoft.AspNetCore.Routing.dll")):
            with self.subTest(name=name):
                self.payload(family, name).write_bytes(b"damaged")
                self.assert_registered_and_enumerated()
                self.assertNotEqual(self.verify().returncode, 0)
                self.assertNotEqual(self.update().returncode, 0)
                self.assertNotEqual(self.verify().returncode, 0)
                self.assert_success(self.update(self.repairing_apt()))
                self.assert_success(self.verify())

    def test_missing_integrity_metadata_cannot_certify_and_offline_retry_is_preserved(self):
        self.assert_success(self.apply())
        sums = self.admindir / "info/dotnet-runtime-10.0.md5sums"
        sums.unlink()
        self.assertNotEqual(self.verify().returncode, 0)
        self.assertNotEqual(self.update("FAULT=offline\n").returncode, 0)
        self.assertTrue(self.state()["disk"]["ready"])
        self.refresh_manifest("dotnet-runtime-10.0")
        self.assert_success(self.update())

    def test_all_installed_assembly_files_require_checksum_coverage(self):
        for package, name in (("dotnet-runtime-10.0", "System.Net.Http.dll"),
                              ("aspnetcore-runtime-10.0", "Microsoft.AspNetCore.Routing.dll")):
            with self.subTest(package=package):
                self.restore_payloads()
                sums = self.admindir / "info" / (package+".md5sums")
                sums.write_text("".join(line for line in sums.read_text().splitlines(keepends=True)
                                        if not line.endswith("/"+name+"\n")))
                result = self.run_fixture("s4d_runtime")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("no checksum coverage", result.stderr)

    def test_required_native_core_and_aspnet_cannot_disappear_from_both_metadata_sets(self):
        for package, name in (("dotnet-runtime-10.0", "libcoreclr.so"),
                              ("dotnet-runtime-10.0", "System.Private.CoreLib.dll"),
                              ("aspnetcore-runtime-10.0", "Microsoft.AspNetCore.dll")):
            with self.subTest(name=name):
                self.restore_payloads()
                for suffix in (".list", ".md5sums"):
                    metadata = self.admindir / "info" / (package+suffix)
                    metadata.write_text("".join(line for line in metadata.read_text().splitlines(keepends=True)
                                                if not line.endswith("/"+name+"\n")))
                result = self.run_fixture("s4d_runtime")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("required payload is not verifiable", result.stderr)

    def test_empty_invalid_duplicate_and_oversized_manifests_fail_closed(self):
        sums = self.admindir / "info/dotnet-runtime-10.0.md5sums"
        original = sums.read_text()
        for text in ("", "bad digest\n", original+original, "x"*(1024*1024+1)):
            with self.subTest(length=len(text)):
                sums.write_text(text)
                self.assertNotEqual(self.run_fixture("s4d_runtime", timeout=4).returncode, 0)
        sums.write_text(original)
        self.assert_success(self.run_fixture("s4d_runtime"))

    def test_unlisted_checksum_and_missing_inventory_are_not_verifiable(self):
        inventory = self.admindir / "info/dotnet-runtime-10.0.list"
        original = inventory.read_text()
        inventory.write_text("".join(line for line in original.splitlines(keepends=True)
                                     if not line.endswith("/System.Net.Http.dll\n")))
        result = self.run_fixture("s4d_runtime")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum absent from inventory", result.stderr)
        inventory.unlink()
        self.assertNotEqual(self.run_fixture("s4d_runtime").returncode, 0)

    def test_native_fifo_payload_is_rejected_without_blocking(self):
        target = self.payload("Microsoft.NETCore.App", "libcoreclr.so")
        target.unlink()
        os.mkfifo(target, 0o600)
        result = self.run_fixture("s4d_runtime", timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong path kind", result.stderr)

    def test_directory_replacing_required_assembly_is_unverifiable(self):
        target = self.payload("Microsoft.AspNetCore.App", "Microsoft.AspNetCore.dll")
        target.unlink()
        target.mkdir(mode=0o755)
        self.assertNotEqual(self.run_fixture("s4d_runtime", timeout=3).returncode, 0)

    def test_metadata_fifo_is_rejected_before_native_query(self):
        target = self.admindir / "info/dotnet-runtime-10.0.md5sums"
        target.unlink()
        os.mkfifo(target, 0o600)
        self.assertNotEqual(self.run_fixture("s4d_runtime", timeout=3).returncode, 0)

    def test_native_root_owner_rule_is_not_relaxed_by_payload_contents(self):
        helper = self.library / "verify-payload.pl"
        helper.write_text(helper.read_text().replace(f"my $trusted_uid = {os.geteuid()};",
                                                    "my $trusted_uid = 0;"))
        result = self.run_fixture("s4d_runtime")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("untrusted path", result.stderr)

    def test_native_database_locates_unqualified_foreign_architecture_metadata(self):
        status = self.admindir / "status"
        status.write_text(status.read_text().replace("Architecture: amd64", "Architecture: arm64"))
        self.assert_success(self.run_fixture("s4d_runtime"))

    def test_native_database_locates_multiarch_qualified_metadata(self):
        status = self.admindir / "status"
        status.write_text(status.read_text().replace("Architecture: amd64", "Architecture: amd64\nMulti-Arch: same"))
        for target in list((self.admindir / "info").iterdir()):
            package,suffix = target.name.rsplit(".",1)
            target.rename(target.with_name(package+":amd64."+suffix))
        (self.admindir / "info/format").write_text("1\n")
        (self.admindir / "info/format").chmod(0o644)
        self.assert_success(self.run_fixture("s4d_runtime"))

    def test_symbolic_payload_preserves_victim_bytes_and_inode(self):
        target = self.payload("Microsoft.AspNetCore.App", "Microsoft.AspNetCore.dll")
        victim = self.root / "payload-victim"
        victim.write_bytes(target.read_bytes())
        before = victim.stat()
        target.unlink()
        target.symlink_to(victim)
        self.assertNotEqual(self.run_fixture("s4d_runtime").returncode, 0)
        self.assertEqual((victim.stat().st_ino,victim.read_bytes()), (before.st_ino, self.payloads[
            "aspnetcore-runtime-10.0"]["usr/share/dotnet/shared/Microsoft.AspNetCore.App/10.0.12/Microsoft.AspNetCore.dll"]))

    def test_unsafe_payload_and_metadata_modes_are_unverifiable(self):
        for target in (self.payload("Microsoft.NETCore.App", "System.Runtime.dll"),
                       self.admindir / "info/aspnetcore-runtime-10.0.md5sums"):
            with self.subTest(path=target):
                target.chmod(0o666)
                self.assertNotEqual(self.run_fixture("s4d_runtime").returncode, 0)
                target.chmod(0o644)
        self.assert_success(self.run_fixture("s4d_runtime"))

    def test_wrong_registered_framework_version_cannot_validate_another_directory(self):
        status = self.admindir / "status"
        status.write_text(status.read_text().replace(
            "Package: aspnetcore-runtime-10.0\nStatus: install ok installed\nVersion: 10.0.12-1",
            "Package: aspnetcore-runtime-10.0\nStatus: install ok installed\nVersion: 10.0.13-1"))
        self.assertNotEqual(self.run_fixture("s4d_runtime").returncode, 0)

    def test_payload_verification_uses_the_finite_control_deadline(self):
        helper = self.library / "verify-payload.pl"
        helper.write_text(helper.read_text().replace("my $limit = 1024 * 1024;", "sleep 5; my $limit = 1024 * 1024;"))
        result = self.run_fixture("s4d_runtime", "S4M_CONTROL_SECONDS=0.1\nS4M_CONTROL_GRACE_SECONDS=0.1\n", timeout=3)
        self.assertNotEqual(result.returncode, 0)

    def test_failed_post_update_runtime_is_not_success(self):
        self.assert_success(self.apply())
        self.program.write_text("#!/bin/sh\nexit 1\n")
        self.assertNotEqual(self.update().returncode, 0)

    def test_runtime_uses_checked_restart_and_retains_inactive_failure(self):
        self.assert_success(self.apply())
        self.targets(["web"])
        self.faults(restart_targets=["web.service"])
        self.assertNotEqual(self.update().returncode, 0)
        self.assertEqual(self.pending(), ["web"])
        self.assertEqual(self.state()["services"]["web.service"]["ActiveState"], "inactive")
        (self.root / "scan-output").write_text("")
        self.faults()
        self.assertNotEqual(self.update("FAULT=offline\n").returncode, 0)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.state()["services"]["web.service"]["ActiveState"], "active")

    def test_runtime_controller_is_excluded_from_its_restart_scan(self):
        self.assert_success(self.apply())
        self.targets([SERVICE, "debian13s4-dotnet"])
        self.assert_success(self.update())
        self.assertFalse(any(e["args"][0] == "restart" for e in self.events() if e["action"] == "systemctl"))

    def test_existing_healthy_reboot_intent_gets_an_offline_turn(self):
        self.assert_success(self.apply())
        marker = self.root / "reboot-required"
        marker.write_text("kernel\n")
        marker.chmod(0o600)
        self.assertEqual(self.update("FAULT=offline\n").returncode, 75)
        self.assertTrue(self.state()["reboot_requested"])

    def test_asset_or_unit_tampering_invalidates_readiness(self):
        self.assert_success(self.apply())
        (self.library / "microsoft-2025.asc").write_text("wrong key\n")
        self.assertNotEqual(self.verify().returncode, 0)
        self.assertEqual(self.update().returncode, 75)

    def test_unsupported_architecture_starts_no_package_operation(self):
        result = self.apply("dpkg() { printf 'armhf\\n'; }\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.package_calls())

    def test_maintained_task_phases_recover_from_delivery_failure(self):
        loader = self.root / "phase-loader.sh"
        loader.write_text(self.harness()+"\nFAULT=offline\n")
        apply = (ROOT / "Tasks/dotnet/apply.sh").read_text().replace(
            "/usr/local/lib/debian13s4/dotnet/common.sh",str(loader))
        failed = subprocess.run(["bash","-c",apply],text=True,capture_output=True,timeout=30)
        self.assertNotEqual(failed.returncode,0)
        self.assertFalse((self.state_dir / "dotnet.ready").exists())
        loader.write_text(self.harness())
        for name in ("apply.sh", "verify.sh"):
            script = (ROOT / "Tasks/dotnet" / name).read_text().replace(
                "/usr/local/lib/debian13s4/dotnet/common.sh", str(loader))
            result = subprocess.run(["bash","-c",script],text=True,capture_output=True,timeout=30)
            self.assert_success(result)

    def test_slow_runtime_restart_queue_reserves_signed_runtime_delivery(self):
        self.assert_success(self.apply())
        names = [f"slow{index:02d}" for index in range(13)]
        self.targets(names)
        self.assert_success(self.run_fixture("s4m_discover_restarts"))
        additions = maintenance.MaintenanceTests.scaled_restart_budget(self)
        for attempt in range(2):
            before = len(self.package_calls())
            order = self.pending()
            self.faults(restart_targets=[name+".service" for name in names],restart_ticks=4)
            self.assertNotEqual(self.update(additions).returncode,0)
            self.assertEqual(self.pending(),order[6:]+order[:6])
            self.assertTrue(any("install aspnetcore-runtime-10.0" in call
                                for call in self.package_calls()[before:]))


class NativePolicyTests(unittest.TestCase):
    def test_starting_runtime_worker_refuses_unprivileged_execution(self):
        result = subprocess.run(["bash","-p",str(ROOT / "Dotnet/update.sh")],
                                text=True,capture_output=True,timeout=3)
        self.assertEqual(result.returncode,77)

    def test_embedded_public_key_matches_the_official_fingerprint(self):
        with tempfile.TemporaryDirectory(dir="/dev/shm") as directory:
            result = subprocess.run(["gpg","--batch","--no-options","--homedir",directory,
                                     "--show-keys","--with-colons",str(ROOT / "Dotnet/microsoft-2025.asc")],
                                    text=True,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([line.split(":")[9] for line in result.stdout.splitlines() if line.startswith("fpr:")],
                         [FINGERPRINT])
        self.assertEqual(hashlib.sha256((ROOT / "Dotnet/microsoft-2025.asc").read_bytes()).hexdigest(),
                         "d45224d594d969f084232deaaf97c58ca502a9d964c362d7aaef5a76e16b3dd1")

    def test_runtime_timer_has_independent_finite_retry_and_boot_delivery(self):
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(ROOT / "Dotnet" / SERVICE)
        self.assertEqual(unit["Service"]["TimeoutStartSec"],"1h")
        self.assertEqual(unit["Service"]["Restart"],"on-failure")
        self.assertEqual(unit["Service"]["RestartSec"],"5min")
        self.assertEqual(unit["Service"]["KillMode"],"control-group")
        self.assertEqual(unit["Unit"]["StartLimitIntervalSec"],"0")
        timer = configparser.ConfigParser(interpolation=None)
        timer.read(ROOT / "Dotnet" / TIMER)
        self.assertEqual(timer["Timer"]["OnBootSec"],"10min")
        self.assertEqual(timer["Timer"]["OnUnitInactiveSec"],"1h")
        self.assertEqual(timer["Install"]["WantedBy"],"timers.target")

    def test_runtime_is_an_independent_authenticated_repair_task(self):
        spec = importlib.util.spec_from_file_location("packer",ROOT / "Bootstrap/pack.py")
        packer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packer)
        assets = packer.assets()
        self.assertIn(b"dotnet:prerequisites\n",assets["lib/tasks.list"][0])
        self.assertEqual(assets["lib/dotnet/sources.sources"][0],
                         (ROOT / "Tasks/prerequisites/debian.sources").read_bytes()+b"\n"+
                         (ROOT / "Dotnet/microsoft.sources").read_bytes())
        self.assertEqual(assets["lib/dotnet/update.sh"][1],"0755")
        self.assertEqual(packer.assemble(),(ROOT / "setup.sh").read_bytes())


if __name__ == "__main__":
    unittest.main()
