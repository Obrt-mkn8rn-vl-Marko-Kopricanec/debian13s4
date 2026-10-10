"""Private controller tests with distinct retained running input snapshots."""
import json
from pathlib import Path
import subprocess
import unittest
from fixture_web import PrivateWeb


class WebStartupTests(unittest.TestCase):
    def setUp(self):self.fixture=PrivateWeb();self.addCleanup(self.fixture.close)
    def run_controller(self,command):return self.fixture.controller(command,timeout=120)
    def state(self):return json.loads(self.fixture.database.read_bytes())
    def events(self):return [json.loads(row) for row in (self.fixture.root/'events.jsonl').read_text().splitlines()]
    def apply(self):
        child=self.run_controller('s4w_apply');self.assertEqual(child.returncode,0,child.stderr.decode());return child

    def test_apply_acknowledges_one_start_and_noop_keeps_loaded_inode(self):
        self.apply();path=self.fixture.root/'state/web.loaded';raw=path.read_bytes();inode=path.stat().st_ino
        self.assertEqual(self.state()['starts'],1)
        child=self.run_controller('s4w_verify && s4w_repair');self.assertEqual(child.returncode,0,child.stderr.decode())
        self.assertEqual(self.state()['starts'],1);self.assertEqual(path.read_bytes(),raw);self.assertEqual(path.stat().st_ino,inode)

    def test_same_listener_public_host_change_requires_new_loaded_generation(self):
        self.apply();old=self.state()['loaded_config']
        self.fixture.value['applications']['mk8.sava']['hostname']='changed.example.invalid';self.fixture.settings()
        child=self.run_controller('s4w_repair');self.assertEqual(child.returncode,0,child.stderr.decode())
        self.assertEqual(self.state()['starts'],2);self.assertNotEqual(self.state()['loaded_config'],old)
        self.assertIn(b'changed.example.invalid',bytes.fromhex(self.state()['loaded_config']))

    def test_same_path_private_key_change_restarts_despite_stable_modeled_native_replies(self):
        self.apply();key=Path(self.fixture.value['applications']['mk8.sava']['private_key']);before=self.state()['loaded_keys']
        key.write_bytes(self.fixture.pem(True,b'new private key model bytes'))
        child=self.run_controller('s4w_repair');self.assertEqual(child.returncode,0,child.stderr.decode())
        self.assertEqual(self.state()['starts'],2);self.assertNotEqual(self.state()['loaded_keys'],before)
        self.assertEqual(self.state()['loaded_keys']['mk8.sava'],key.read_bytes().hex())

    def test_unknown_generation_is_not_healthy_noop(self):
        self.apply();(self.fixture.root/'state/web.loaded').unlink()
        child=self.run_controller('s4w_repair');self.assertEqual(child.returncode,0,child.stderr.decode());self.assertEqual(self.state()['starts'],2)

    def test_changed_inputs_failed_stop_preserves_old_disk_and_loaded_bytes(self):
        self.apply();old=self.fixture.m.CONFIG.read_bytes();loaded=self.state()['loaded_config']
        self.fixture.value['applications']['mk8.sava']['body_bytes']=2048;self.fixture.settings();self.fixture.faults(stop=True)
        self.assertNotEqual(self.run_controller('s4w_repair').returncode,0)
        self.assertEqual(self.fixture.m.CONFIG.read_bytes(),old);self.assertEqual(self.state()['loaded_config'],loaded)
        self.assertEqual(self.state()['starts'],1)

    def test_changed_generation_failed_start_is_inactive_without_loaded_ack(self):
        self.apply();self.fixture.value['applications']['mk8.sava']['idle_seconds']=61;self.fixture.settings();self.fixture.faults(start=True)
        self.assertNotEqual(self.run_controller('s4w_repair').returncode,0)
        self.assertFalse(self.state()['active']['debian13s4-web-server.service']);self.assertFalse((self.fixture.root/'state/web.loaded').exists())

    def test_failed_crypto_syntax_listener_or_sync_cannot_be_ready(self):
        for fault in ('verify','syntax','foreign_socket','sync_loaded'):
            with self.subTest(fault=fault):
                private=PrivateWeb();self.addCleanup(private.close);private.faults(**{fault:True})
                child=private.controller('s4w_apply',timeout=120)
                self.assertNotEqual(child.returncode,0)
                self.assertFalse((private.root/'state/web.ready').exists())
                self.assertFalse(json.loads(private.database.read_bytes())['active'].get('debian13s4-web-server.service',False))

    def test_foreign_vendor_service_is_refused_without_stop_adoption(self):
        self.fixture.faults(vendor_active=True)
        self.assertNotEqual(self.run_controller('s4w_apply').returncode,0)
        self.assertEqual(self.state()['starts'],0)
        self.assertFalse(any(row['action']=='systemctl' and row['args']==['stop','nginx.service'] for row in self.events()))

    def test_masked_vendor_still_requires_positive_inactive_no_pid(self):
        self.fixture.faults(vendor_load='masked')
        child=self.run_controller('s4w_vendor_inactive');self.assertEqual(child.returncode,0,child.stderr.decode())
        self.fixture.faults(vendor_active=True)
        self.assertNotEqual(self.run_controller('s4w_vendor_inactive').returncode,0)

    def test_pending_guard_and_shared_lock_precede_all_native_manager_actions(self):
        guard=self.fixture.root/'state/bootstrap';guard.mkdir(mode=0o700);(guard/'pending').write_text('pending\n')
        self.assertEqual(self.run_controller('s4w_repair').returncode,75);self.assertFalse((self.fixture.root/'events.jsonl').exists())
        (guard/'pending').unlink()
        child=self.run_controller('exec {private_lock}> "$S4M_STATE/repair.lock"\nflock --nonblock "$private_lock"\ns4w_repair')
        self.assertEqual(child.returncode,75);self.assertFalse((self.fixture.root/'events.jsonl').exists())

    def test_missing_packages_or_input_never_calls_apt_or_creates_certificates(self):
        self.fixture.faults(packages=True)
        self.assertNotEqual(self.run_controller('s4w_apply').returncode,0);self.assertEqual(self.state()['starts'],0)
        self.fixture.faults(packages=False);self.fixture.m.PREP.INPUT.unlink()
        self.assertNotEqual(self.run_controller('s4w_apply').returncode,0);self.assertEqual(self.state()['starts'],0)

    def test_duplicate_or_invalid_named_manager_identity_refuses_verification(self):
        self.apply()
        for value in ('ActiveState=active\nMainPID=1\nMainPID=2\nInvocationID='+'a'*32,
                      'ActiveState=active\nMainPID=0\nInvocationID='+'a'*32):
            self.fixture.faults(generation=value)
            self.assertNotEqual(self.run_controller('s4w_verify').returncode,0)

    def test_replaced_native_binary_and_account_inventory_require_new_start(self):
        self.apply();self.fixture.m.PASSWD.write_bytes(self.fixture.m.PASSWD.read_bytes().replace(b':Web:',b':Changed:'))
        child=self.run_controller('s4w_repair');self.assertEqual(child.returncode,0,child.stderr.decode());self.assertEqual(self.state()['starts'],2)
        self.fixture.m.NGINX.write_bytes(self.fixture.m.NGINX.read_bytes()+b'\n# changed private native identity\n')
        child=self.run_controller('s4w_repair');self.assertEqual(child.returncode,0,child.stderr.decode());self.assertEqual(self.state()['starts'],3)

    def test_timeout_joins_owned_controller_session_before_private_removal(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.fixture.controller('sleep 30',timeout=.05)
        self.assertEqual(self.fixture.private_processes(),[])



if __name__=='__main__':unittest.main()
