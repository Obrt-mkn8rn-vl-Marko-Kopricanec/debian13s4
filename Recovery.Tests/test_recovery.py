import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest


PROJECT = Path(__file__).resolve().parents[1]
WORKER = PROJECT / "Recovery" / "repair.sh"


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="debian13s4-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.library = self.root / "library"
        self.state = self.root / "state"
        self.library.mkdir()
        (self.state / "results").mkdir(parents=True)
        self.calls = self.root / "calls"
        self.timer_calls = self.root / "timer-calls"
        self.timer_failure = self.root / "timer-failure"
        self.entries = []

    def task(self, name, dependencies=(), apply=None, verify=None):
        directory = self.library / "tasks" / name
        directory.mkdir(parents=True)
        ready = self.root / f"{name}.ready"
        calls = shlex.quote(str(self.calls))
        if apply is None:
            apply = f"printf '%s\\n' {shlex.quote(name)} >> {calls}\n: > {shlex.quote(str(ready))}\n"
        if verify is None:
            verify = f"test -f {shlex.quote(str(ready))}\n"
        (directory / "apply.sh").write_text(apply)
        (directory / "verify.sh").write_text(verify)
        self.entries.append(f"{name}: {' '.join(dependencies)}")
        self.manifest("\n".join(self.entries) + "\n")
        return ready

    def manifest(self, text):
        (self.library / "tasks.list").write_text(text)

    def command(self, additions=""):
        # Only these disposable fixtures bypass the production root-ownership
        # gate; the gate itself is tested separately without an override.
        return f"""
set -Eeuo pipefail
source {shlex.quote(str(WORKER))}
S4_LIBRARY_DIR={shlex.quote(str(self.library))}
S4_STATE_DIR={shlex.quote(str(self.state))}
s4_trusted_path() {{ return 0; }}
s4_stop_timer() {{
    printf 'stop\\n' >> {shlex.quote(str(self.timer_calls))}
    test ! -f {shlex.quote(str(self.timer_failure))}
}}
{additions}
s4_recover
"""

    def recover(self, additions=""):
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", self.command(additions)],
            text=True,
            capture_output=True,
            timeout=10,
        )

    def state_for(self, task):
        return (self.state / "results" / task).read_text()

    def test_offline_attempt_recovers_on_a_later_invocation(self):
        internet = self.root / "internet-available"
        packages = self.root / "packages.ready"
        self.task("local")
        self.task(
            "packages",
            apply=f"test -f {shlex.quote(str(internet))}\n: > {shlex.quote(str(packages))}\n",
        )
        self.task("web", dependencies=("packages",))
        first = self.recover()
        self.assertEqual(first.returncode, 75, first.stderr)
        self.assertIn("state=complete", self.state_for("local"))
        self.assertIn("state=pending", self.state_for("packages"))
        self.assertIn("dependency_pending", self.state_for("web"))
        self.assertFalse(self.timer_calls.exists())
        self.assertFalse((self.state / "setup.ready").exists())
        internet.touch()
        second = self.recover()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.calls.read_text().splitlines(), ["local", "web"])
        self.assertEqual(self.timer_calls.read_text(), "stop\n")
        self.assertIn("state=complete", (self.state / "status").read_text())

    def test_apply_success_without_verification_does_not_stop_timer(self):
        self.task("certificate", apply="true\n", verify="false\n")
        result = self.recover()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertIn("verification_failed_1", self.state_for("certificate"))
        self.assertFalse(self.timer_calls.exists())
        self.assertFalse((self.state / "setup.ready").exists())

    def test_errexit_stops_a_failed_apply_before_later_commands(self):
        forbidden = self.root / "must-not-run"
        self.task("partial", apply=f"false\n: > {shlex.quote(str(forbidden))}\n")
        result = self.recover()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse(forbidden.exists())
        self.assertIn("apply_failed_1", self.state_for("partial"))

    def test_pipefail_rejects_a_failed_pipeline(self):
        forbidden = self.root / "must-not-run"
        self.task("pipeline", apply=f"false | cat\n: > {shlex.quote(str(forbidden))}\n")
        result = self.recover()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse(forbidden.exists())

    def test_verifier_does_not_mask_an_earlier_error(self):
        self.task("bad_check", apply="true\n", verify="false\ntrue\n")
        result = self.recover()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse(self.timer_calls.exists())

    def test_independent_tasks_finish_when_another_dependency_is_pending(self):
        self.task("network", apply="false\n")
        dependent = self.task("tls", dependencies=("network",))
        independent = self.task("local_hardening")
        result = self.recover()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse(dependent.exists())
        self.assertTrue(independent.exists())
        self.assertIn("dependency_pending", self.state_for("tls"))

    def test_existing_correct_setup_is_verified_without_reapplying(self):
        ready = self.task("existing", apply="false\n")
        ready.touch()
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.calls.exists())
        self.assertIn("reason=verified", self.state_for("existing"))
        self.assertEqual(self.timer_calls.read_text(), "stop\n")

    def test_cached_success_is_rechecked_after_a_regression(self):
        ready = self.task("service")
        first = self.recover()
        self.assertEqual(first.returncode, 0, first.stderr)
        ready.unlink()
        (self.library / "tasks/service/apply.sh").write_text("false\n")
        second = self.recover()
        self.assertEqual(second.returncode, 75, second.stderr)
        self.assertFalse((self.state / "setup.ready").exists())
        self.assertIn("state=pending", self.state_for("service"))
        self.assertEqual(self.timer_calls.read_text(), "stop\n")

    def test_timer_control_failure_is_retried_without_reapplying_setup(self):
        self.task("setup")
        self.timer_failure.touch()
        first = self.recover()
        self.assertEqual(first.returncode, 75, first.stderr)
        self.assertFalse((self.state / "setup.ready").exists())
        self.assertIn("timer_stop_pending", (self.state / "status").read_text())
        self.timer_failure.unlink()
        second = self.recover()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.calls.read_text(), "setup\n")
        self.assertEqual(self.timer_calls.read_text(), "stop\nstop\n")

    def test_long_running_phase_times_out_and_remains_pending(self):
        self.task("slow", apply="sleep 10\n")
        result = self.recover("S4_PHASE_TIMEOUT=0.1s\nS4_KILL_DELAY=0.1s")
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertIn("apply_failed_124", self.state_for("slow"))
        self.assertFalse(self.timer_calls.exists())

    def test_task_environment_does_not_inherit_shell_code(self):
        injected = self.root / "injected"
        bash_env = self.root / "bash-env"
        bash_env.write_text(f": > {shlex.quote(str(injected))}\n")
        ready = self.root / "environment.ready"
        self.task(
            "environment",
            apply=f"""
test "$DEBIAN_FRONTEND" = noninteractive
test "${{BASH_ENV+x}}" != x
! declare -F untrusted_function
: > {shlex.quote(str(ready))}
""",
        )
        result = self.recover(f"""
export BASH_ENV={shlex.quote(str(bash_env))}
untrusted_function() {{ : > {shlex.quote(str(injected))}; }}
export -f untrusted_function
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(injected.exists())

    def test_second_worker_does_not_run_tasks_while_the_lock_is_held(self):
        started = self.root / "started"
        ready = self.root / "exclusive.ready"
        self.task(
            "exclusive",
            apply=f"""
: > {shlex.quote(str(started))}
sleep 1
printf 'once\\n' >> {shlex.quote(str(self.calls))}
: > {shlex.quote(str(ready))}
""",
        )
        first = subprocess.Popen(
            ["bash", "--noprofile", "--norc", "-c", self.command()],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            while not started.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(started.exists())
            second = self.recover()
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("already running", second.stderr)
            _, stderr = first.communicate(timeout=5)
            self.assertEqual(first.returncode, 0, stderr)
            self.assertEqual(self.calls.read_text(), "once\n")
            self.assertEqual(self.timer_calls.read_text(), "stop\n")
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate()

    def test_invalid_registry_never_runs_tasks_or_retains_readiness(self):
        self.task("valid")
        cases = [
            "",
            "# no setup tasks\n",
            "valid\n",
            "valid:\nvalid:\n",
            "../escape:\n",
            "valid: missing\n",
            "valid: valid\n",
            "later: valid\nvalid:\n",
            "bad-task:\n",
            "valid: $(touch injected)\n",
        ]
        for registry in cases:
            with self.subTest(registry=registry):
                self.manifest(registry)
                (self.state / "setup.ready").touch()
                result = self.recover()
                self.assertEqual(result.returncode, 78, result.stderr)
                self.assertFalse(self.calls.exists())
                self.assertFalse(self.timer_calls.exists())
                self.assertFalse((self.state / "setup.ready").exists())
                self.assertIn("invalid_bundle", (self.state / "status").read_text())

    def test_missing_phase_script_rejects_the_bundle_before_execution(self):
        self.task("valid")
        self.task("missing")
        (self.library / "tasks/missing/verify.sh").unlink()
        result = self.recover()
        self.assertEqual(result.returncode, 78, result.stderr)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.timer_calls.exists())

    def test_state_write_failure_cannot_report_success_or_stop_timer(self):
        self.task("state")
        result = self.recover("s4_atomic_write() { return 1; }")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.timer_calls.exists())
        self.assertFalse((self.state / "setup.ready").exists())

    def test_completion_state_files_are_private(self):
        self.task("private_state")
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in (
            self.state / "status",
            self.state / "setup.ready",
            self.state / "results/private_state",
        ):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_timer_shutdown_targets_only_the_retry_timer(self):
        command = f"""
set -Eeuo pipefail
source {shlex.quote(str(WORKER))}
systemctl() {{ printf '%s\\n' "$@" > {shlex.quote(str(self.timer_calls))}; }}
s4_stop_timer
"""
        result = subprocess.run(["bash", "-c", command], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.timer_calls.read_text().splitlines()
        targets = [value for value in arguments if value.endswith((".timer", ".service"))]
        self.assertEqual(targets, ["debian13s4-repair.timer"])
        self.assertIn("disable", arguments)
        self.assertIn("--now", arguments)
        self.assertIn("--no-block", arguments)

    def test_trust_gate_rejects_links_noncanonical_and_writable_paths(self):
        candidate = self.root / "candidate"
        candidate.touch()
        link = self.root / "link"
        link.symlink_to("/usr/bin/bash")
        paths = [
            candidate,
            link,
            self.root / "missing",
            "/tmp/../usr/bin/bash",
            "/usr//bin/bash",
            "/bin/bash",
            "usr/bin/bash",
        ]
        for path in paths:
            with self.subTest(path=str(path)):
                command = f"source {shlex.quote(str(WORKER))}; s4_trusted_path {shlex.quote(str(path))}"
                result = subprocess.run(["bash", "-c", command], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
        valid = f"source {shlex.quote(str(WORKER))}; s4_trusted_path /usr/bin/bash"
        result = subprocess.run(["bash", "-c", valid], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "Requires an unprivileged test runner")
    def test_direct_worker_invocation_refuses_an_unprivileged_user(self):
        result = subprocess.run(["bash", str(WORKER)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 77)
        self.assertIn("must run as root", result.stderr)

    def test_worker_does_not_accept_configuration_arguments(self):
        result = subprocess.run(
            ["bash", str(WORKER), "--state-dir", str(self.root)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 64)


if __name__ == "__main__":
    unittest.main()
