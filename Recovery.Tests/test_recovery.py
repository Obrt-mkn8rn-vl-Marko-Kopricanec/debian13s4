import array
import configparser
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time
import unittest


PROJECT = Path(__file__).resolve().parents[1]
WORKER = PROJECT / "Recovery" / "repair.sh"
TIMER = "debian13s4-repair.timer"
RESUME = "debian13s4-resume.service"


# A disposable manager model, never the host's systemctl. Persisting enablement
# separately from activity models partial disable/reload failures and reboot.
FAKE_SYSTEMCTL = r'''
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
state_dir = Path(sys.argv[2])
log = Path(sys.argv[3])
args = sys.argv[4:]
state = json.loads(path.read_text())
timer = "debian13s4-repair.timer"
resume = "debian13s4-resume.service"
operation, unit = args[0], args[-1]
assert unit in (timer, resume), args
with log.open("a") as stream:
    stream.write(json.dumps({"args": args, "state": state,
                            "ready": (state_dir / "setup.ready").exists(),
                            "pending": (state_dir / "timer-stop.pending").exists()}) + "\n")
faults = state.get("faults", {})
code = 0
output = ""
if operation == "enable":
    if faults.get("enable_guard" if unit == resume else "enable_timer"):
        code = 1
    else:
        state["guard_enabled" if unit == resume else "enabled"] = True
elif operation == "stop":
    assert unit == timer
    state["stop_reads"] = faults.get("stop_lag_reads", 0)
    state["active"] = "deactivating" if state["stop_reads"] or faults.get("stop_forever") else "inactive"
    if faults.get("stop_error"):
        code = 1
elif operation == "disable":
    assert unit == timer
    # The persistent change succeeds even if the following reload fails.
    state["enabled"] = False
    if faults.get("disable_reload"):
        code = 1
elif operation == "start":
    assert unit == timer
    if faults.get("start_timer"):
        code = 1
    else:
        state["active"] = "active"
elif operation == "is-enabled":
    enabled = state["guard_enabled" if unit == resume else "enabled"]
    output = "enabled" if enabled else "disabled"
    code = 0 if enabled else 1
elif operation == "show":
    assert args[1:-1] == ["--property=ActiveState", "--value"]
    if state["active"] == "deactivating" and not faults.get("stop_forever"):
        if state["stop_reads"]:
            state["stop_reads"] -= 1
        else:
            state["active"] = "inactive"
    output = state["active"]
else:
    raise AssertionError(args)
path.write_text(json.dumps(state))
if output:
    print(output)
sys.exit(code)
'''


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
        self.controller = self.root / "manager.json"
        self.controller.write_text(json.dumps({"enabled": True, "active": "active", "guard_enabled": False}))
        self.fake_systemctl = self.root / "systemctl.py"
        self.fake_systemctl.write_text(FAKE_SYSTEMCTL)
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

    def command(self, additions="", entry="s4_recover"):
        # Only these disposable fixtures bypass the production root-ownership
        # gate; the gate itself is tested separately without an override.
        return f"""
set -Eeuo pipefail
source {shlex.quote(str(WORKER))}
S4_LIBRARY_DIR={shlex.quote(str(self.library))}
S4_STATE_DIR={shlex.quote(str(self.state))}
s4_trusted_path() {{ return 0; }}
s4_systemctl() {{
    s4_control python3 {shlex.quote(str(self.fake_systemctl))} \
        {shlex.quote(str(self.controller))} {shlex.quote(str(self.state))} \
        {shlex.quote(str(self.timer_calls))} "$@"
}}
S4_POLL_INTERVAL_MS=10
unset NOTIFY_SOCKET
{additions}
{entry}
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

    def manager_state(self, **changes):
        state = json.loads(self.controller.read_text())
        state.update(changes)
        self.controller.write_text(json.dumps(state))
        return state

    def control_calls(self):
        if not self.timer_calls.exists():
            return []
        return [json.loads(line) for line in self.timer_calls.read_text().splitlines()]

    def stop_count(self):
        return sum(call["args"] == ["stop", TIMER] for call in self.control_calls())

    def unit(self, name):
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read(PROJECT / "Recovery" / name)
        return parser

    def notified_attempt(self):
        notification = self.root / "notification"
        notification.unlink(missing_ok=True)
        additions = f"""
S4_PHASE_TIMEOUT_MS=150
S4_KILL_DELAY_MS=50
S4_TASK_OVERHEAD_MS=100
S4_ATTEMPT_OVERHEAD_MS=200
S4_CONTROL_TIMEOUT_MS=100
S4_CONTROL_KILL_MS=50
NOTIFY_SOCKET=fixture
s4_notify() {{
    if [[ $1 == --ready ]]; then
        printf 'ready\\n' > {shlex.quote(str(notification))}
    else
        printf '%s\\n' "$1" >> {shlex.quote(str(notification))}
    fi
}}
"""
        process = subprocess.Popen(
            ["bash", "--noprofile", "--norc", "-c", self.command(additions)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            lines = []
            while len(lines) != 2 and time.monotonic() < deadline:
                if notification.exists():
                    lines = notification.read_text().splitlines()
                if len(lines) != 2:
                    time.sleep(0.005)
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0], "ready")
            self.assertTrue(lines[1].startswith("EXTEND_TIMEOUT_USEC="))
            # Model the manager's finite deadline using the actual notification
            # emitted by the worker, rather than an unrelated harness constant.
            budget = int(lines[1].split("=", 1)[1]) / 1_000_000
            stdout, stderr = process.communicate(timeout=budget)
            return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), budget
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def simulate_reboot(self):
        state = self.manager_state()
        state["active"] = "active" if state["enabled"] else "inactive"
        self.controller.write_text(json.dumps(state))
        # This is the shipped boot unit's enablement + ConditionPathExists gate,
        # not a host boot or unit activation. The actual resume code runs below.
        unit = self.unit(RESUME)
        self.assertEqual(unit["Install"]["WantedBy"], "multi-user.target")
        self.assertEqual(unit["Unit"]["ConditionPathExists"], "/var/lib/debian13s4/timer-stop.pending")
        if state["guard_enabled"] and (self.state / "timer-stop.pending").exists():
            return subprocess.run(
                ["bash", "-c", self.command(entry="s4_resume")],
                text=True, capture_output=True, timeout=10,
            )
        return None

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
        self.assertEqual(self.stop_count(), 1)
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
        self.assertEqual(self.stop_count(), 1)

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
        self.assertEqual(self.stop_count(), 1)

    def test_timer_control_failure_is_retried_without_reapplying_setup(self):
        self.task("setup")
        self.manager_state(faults={"stop_error": True})
        first = self.recover()
        self.assertEqual(first.returncode, 75, first.stderr)
        self.assertFalse((self.state / "setup.ready").exists())
        self.assertIn("timer_stop_pending", (self.state / "status").read_text())
        self.assertTrue(self.manager_state()["enabled"])
        self.assertEqual(self.manager_state()["active"], "active")
        self.manager_state(faults={})
        second = self.recover()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.calls.read_text(), "setup\n")
        self.assertEqual(self.stop_count(), 2)

    def test_long_running_phase_times_out_and_remains_pending(self):
        self.task("slow", apply="sleep 10\n")
        result = self.recover("S4_PHASE_TIMEOUT_MS=100\nS4_KILL_DELAY_MS=100")
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertIn("apply_failed_124", self.state_for("slow"))
        self.assertFalse(self.timer_calls.exists())

    def test_slow_prefix_cannot_starve_later_tasks_across_retries(self):
        self.task("slow_prefix", apply="sleep 10\n", verify="sleep 10\n")
        first_local = self.task("local_one")
        started = time.monotonic()
        first, first_budget = self.notified_attempt()
        # Two 150 ms timeouts consume the entire old scaled fixed deadline.
        self.assertGreaterEqual(time.monotonic() - started, 0.3)
        self.assertEqual(first.returncode, 75, first.stderr)
        self.assertTrue(first_local.exists())
        self.assertIn("apply_failed_124", self.state_for("slow_prefix"))
        second_local = self.task("local_two")
        second, second_budget = self.notified_attempt()
        self.assertEqual(second.returncode, 75, second.stderr)
        self.assertTrue(second_local.exists())
        self.assertGreater(second_budget, first_budget)
        self.assertEqual(self.calls.read_text().splitlines(), ["local_one", "local_two"])

    def test_term_resistant_prefix_uses_kill_grace_without_starvation(self):
        self.task("resistant", apply="trap '' TERM\nsleep 10\n", verify="trap '' TERM\nsleep 10\n")
        local = self.task("local")
        result, _ = self.notified_attempt()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertIn("apply_failed_137", self.state_for("resistant"))
        self.assertTrue(local.exists())

    def test_shipped_deadlines_cover_every_phase_grace_and_control_call(self):
        service = self.unit("debian13s4-repair.service")["Service"]
        self.assertEqual(service["Type"], "notify")
        self.assertEqual(service["NotifyAccess"], "all")
        self.assertEqual(service["TimeoutStartSec"], "1min")
        self.assertEqual(service["RuntimeMaxSec"], "1min")
        self.assertEqual(service["KillMode"], "control-group")
        command = f"""
source {shlex.quote(str(WORKER))}
printf '%s %s %s %s %s %s %s %s\\n' "$S4_PHASE_TIMEOUT_MS" "$S4_KILL_DELAY_MS" \
    "$S4_TASK_OVERHEAD_MS" "$S4_ATTEMPT_OVERHEAD_MS" "$S4_CONTROL_CALL_BUDGET" \
    "$S4_CONTROL_TIMEOUT_MS" "$S4_CONTROL_KILL_MS" "$S4_POLL_INTERVAL_MS"
for count in 1 2 1000; do
    S4_TASKS=()
    for ((i = 0; i < count; i++)); do S4_TASKS+=(task); done
    s4_attempt_budget_ms
done
"""
        result = subprocess.run(["bash", "-c", command], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        phase, grace, task_margin, attempt_margin, calls, control, kill, poll = map(int, lines[0].split())
        self.assertGreaterEqual(calls, 23)
        self.assertLess(control + kill, 60_000)
        for count, budget in zip((1, 2, 1000), map(int, lines[1:])):
            self.assertEqual(budget, count * (3 * (phase + grace) + task_margin)
                             + attempt_margin + calls * (control + kill + poll))
            self.assertGreater(budget, count * 3 * (phase + grace))
        # Resume takes at most eight control calls and two poll delays.
        self.assertLess(8 * (control + kill) + 2 * poll, 120_000)
        for name in ("debian13s4-repair.service", RESUME):
            policy = self.unit(name)["Service"]
            self.assertEqual(policy["Restart"], "on-failure")
            self.assertNotIn("SuccessExitStatus", policy)

    def test_deadline_notification_failure_starts_no_tasks(self):
        self.task("setup")
        for failed_message in ("--ready", "EXTEND_TIMEOUT_USEC"):
            with self.subTest(failed_message=failed_message):
                (self.state / "setup.ready").touch()
                result = self.recover(f"""
NOTIFY_SOCKET=fixture
s4_notify() {{ [[ $1 != {shlex.quote(failed_message)}* ]]; }}
""")
                self.assertEqual(result.returncode, 75, result.stderr)
                self.assertFalse(self.calls.exists())
                self.assertFalse(self.timer_calls.exists())
                self.assertFalse((self.state / "setup.ready").exists())
                self.assertIn("deadline_pending", (self.state / "status").read_text())

    def test_real_notification_helper_waits_for_both_acknowledgements(self):
        self.task("setup")
        notification_socket = self.root / "notify.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
            server.bind(str(notification_socket))
            server.settimeout(5)
            process = subprocess.Popen(
                ["bash", "-c", self.command(f"export NOTIFY_SOCKET={shlex.quote(str(notification_socket))}")],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            messages = []
            acknowledged = 0
            try:
                while acknowledged < 2:
                    data, ancillary, flags, _ = server.recvmsg(4096, socket.CMSG_SPACE(32))
                    self.assertFalse(flags & socket.MSG_CTRUNC)
                    descriptors = array.array("i")
                    for level, kind, payload in ancillary:
                        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                            descriptors.frombytes(payload)
                    try:
                        if data == b"BARRIER=1":
                            # Closing the passed descriptor acknowledges the
                            # notification. Neither phase may run before both.
                            self.assertFalse(self.calls.exists())
                            self.assertTrue(descriptors)
                            acknowledged += 1
                        else:
                            messages.append(data.decode())
                    finally:
                        for descriptor in descriptors:
                            os.close(descriptor)
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(messages[0], "READY=1")
                self.assertTrue(messages[1].startswith("EXTEND_TIMEOUT_USEC="))
                self.assertEqual(self.calls.read_text(), "setup\n")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_control_commands_have_a_real_finite_timeout(self):
        result = subprocess.run(
            ["bash", "-c", self.command("S4_CONTROL_TIMEOUT_MS=100\nS4_CONTROL_KILL_MS=50",
                                        entry="s4_control sleep 10")],
            text=True, capture_output=True, timeout=2,
        )
        self.assertEqual(result.returncode, 124, result.stderr)

    def test_partial_disable_reload_failure_restores_enablement(self):
        self.task("setup")
        self.manager_state(faults={"disable_reload": True})
        result = self.recover()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse((self.state / "setup.ready").exists())
        self.assertTrue((self.state / "timer-stop.pending").exists())
        self.assertTrue(self.manager_state()["guard_enabled"])
        self.assertTrue(self.manager_state()["enabled"])
        self.assertEqual(self.manager_state()["active"], "active")
        restore = [call for call in self.control_calls() if call["args"] == ["enable", TIMER]]
        self.assertEqual(len(restore), 1)
        self.assertFalse(restore[0]["state"]["enabled"])

    def test_queued_stop_is_not_completion(self):
        self.task("setup")
        self.manager_state(faults={"stop_forever": True})
        result = self.recover()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse((self.state / "setup.ready").exists())
        self.assertIn("timer_stop_pending", (self.state / "status").read_text())
        self.assertFalse(any(call["args"][0] == "disable" for call in self.control_calls()))
        self.assertTrue(self.manager_state()["enabled"])
        self.assertEqual(self.manager_state()["active"], "active")

    def test_delayed_stop_is_confirmed_before_completion(self):
        self.task("setup")
        self.manager_state(faults={"stop_lag_reads": 1})
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        disable = next(call for call in self.control_calls() if call["args"][0] == "disable")
        self.assertEqual(disable["state"]["active"], "inactive")
        self.assertEqual(self.manager_state()["active"], "inactive")

    def test_failed_restore_has_a_durable_reboot_recovery_trigger(self):
        self.task("setup")
        self.manager_state(faults={"disable_reload": True, "enable_timer": True})
        first = self.recover()
        self.assertEqual(first.returncode, 75, first.stderr)
        self.assertFalse(self.manager_state()["enabled"])
        self.assertTrue(self.manager_state()["guard_enabled"])
        # A reboot alone would leave a disabled timer inactive. The armed boot
        # service must restore it, including when its own first retry fails.
        failed_resume = self.simulate_reboot()
        self.assertIsNotNone(failed_resume)
        self.assertEqual(failed_resume.returncode, 75, failed_resume.stderr)
        self.assertTrue((self.state / "timer-stop.pending").exists())
        self.manager_state(faults={})
        resumed = self.simulate_reboot()
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertTrue(self.manager_state()["enabled"])
        self.assertEqual(self.manager_state()["active"], "active")
        final = self.recover()
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(self.calls.read_text(), "setup\n")
        self.assertFalse((self.state / "timer-stop.pending").exists())
        self.assertTrue((self.state / "setup.ready").exists())
        self.assertIsNone(self.simulate_reboot())

    def test_boot_guard_must_be_armed_before_timer_mutation(self):
        self.task("setup")
        self.manager_state(faults={"enable_guard": True})
        result = self.recover()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(self.stop_count(), 0)
        self.assertTrue(self.manager_state()["enabled"])
        self.assertEqual(self.manager_state()["active"], "active")
        self.assertFalse((self.state / "setup.ready").exists())

    def test_publication_failure_keeps_boot_recovery_after_successful_shutdown(self):
        self.task("setup")
        result = self.recover(f"""
mv() {{
    if [[ ${{*: -1}} == {shlex.quote(str(self.state / 'setup.ready'))} ]]; then
        return 1
    fi
    command mv "$@"
}}
""")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.state / "setup.ready").exists())
        self.assertFalse(self.manager_state()["enabled"])
        self.assertEqual(self.manager_state()["active"], "inactive")
        self.assertTrue((self.state / "timer-stop.pending").exists())
        resumed = self.simulate_reboot()
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        final = self.recover()
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(self.calls.read_text(), "setup\n")

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
            self.assertEqual(self.stop_count(), 1)
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
        self.task("setup")
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.control_calls()
        self.assertEqual([call["args"] for call in calls if call["args"][0] in ("stop", "disable")],
                         [["stop", TIMER], ["disable", TIMER]])
        self.assertTrue(all("--no-block" not in call["args"] and "--now" not in call["args"] for call in calls))
        self.assertTrue(all(not call["ready"] for call in calls))
        self.assertTrue(all(call["pending"] for call in calls))
        self.assertFalse(self.manager_state()["enabled"])
        self.assertEqual(self.manager_state()["active"], "inactive")
        self.assertFalse((self.state / "timer-stop.pending").exists())

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
