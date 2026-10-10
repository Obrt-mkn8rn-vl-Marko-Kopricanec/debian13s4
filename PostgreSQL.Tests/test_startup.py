"""Persistent private manager/startup snapshots, never host systemctl/SQL."""
import json
import subprocess
import unittest
from fixture_pg import PrivatePG


class StartupTests(unittest.TestCase):
    def setUp(self):self.fixture=PrivatePG();self.addCleanup(self.fixture.close)
    def run_controller(self,command):
        return subprocess.run(['/bin/bash','-p','-c',self.fixture.shell(command)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
    def state(self):return json.loads(self.fixture.database.read_bytes())
    def events(self):return [json.loads(row) for row in (self.fixture.root/'events.jsonl').read_text().splitlines()]
    def apply(self):
        result=self.run_controller('s4g_apply');self.assertEqual(result.returncode,0,result.stderr.decode());return result

    def test_apply_starts_once_records_generation_and_noop_retains_it(self):
        self.apply();marker=self.fixture.root/'state/postgresql.loaded';before=marker.read_bytes();inode=marker.stat().st_ino
        self.assertEqual(self.state()['starts'],1)
        result=self.run_controller('s4g_verify && s4g_repair')
        self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(self.state()['starts'],1)
        self.assertEqual(marker.read_bytes(),before);self.assertEqual(marker.stat().st_ino,inode)

    def test_same_path_capacity_change_stops_before_replace_and_restarts(self):
        self.apply();self.fixture.faults(loaded_snapshot=True)
        self.fixture.value['max_connections']=48
        self.fixture.write(self.fixture.m.PREP.INPUT,self.fixture.m.PREP.canonical(self.fixture.value))
        reply=self.fixture.catalog();self.fixture.write(self.fixture.root/'catalog.json',json.dumps(reply).encode())
        result=self.run_controller('s4g_repair');self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(self.state()['starts'],2)
        self.assertIn(b'max_connections = 48\n',bytes.fromhex(self.state()['loaded_config']))
        self.assertEqual(self.run_controller('s4g_verify').returncode,0)

    def test_same_uid_postgres_account_change_requires_new_start_generation(self):
        self.apply();before=self.state()['starts']
        path=self.fixture.m.PREP.PASSWD
        path.write_bytes(path.read_bytes().replace(b'PostgreSQL:/nonexistent:/bin/bash',b'PostgreSQL:/changed:/bin/bash'))
        result=self.run_controller('s4g_repair');self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(self.state()['starts'],before+1)

    def test_ready_marker_private_mode_size_and_single_link_are_mandatory(self):
        self.apply();path=self.fixture.root/'state/postgresql.ready';raw=path.read_bytes()
        path.chmod(0o644);self.assertNotEqual(self.run_controller('s4g_verify').returncode,0)
        path.chmod(0o600);path.write_bytes(b'x'*4097)
        self.assertNotEqual(self.run_controller('s4g_verify').returncode,0)
        path.write_bytes(raw);other=self.fixture.root/'state/extra-link'
        import os
        os.link(path,other)
        self.assertNotEqual(self.run_controller('s4g_verify').returncode,0)
        other.unlink();self.assertEqual(self.run_controller('s4g_verify').returncode,0)

    def test_replaced_server_binary_requires_a_new_acknowledged_start(self):
        self.apply();self.fixture.m.SERVER.write_bytes(b'#!/bin/sh\nexit 2\n')
        result=self.run_controller('s4g_repair');self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(self.state()['starts'],2)

    def test_unknown_generation_is_not_healthy_noop(self):
        self.apply();(self.fixture.root/'state/postgresql.loaded').unlink()
        result=self.run_controller('s4g_repair');self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(self.state()['starts'],2)

    def test_changed_generation_stop_failure_preserves_old_config_and_refuses(self):
        self.apply();before=(self.fixture.m.CONFIG/'postgresql.conf').read_bytes()
        self.fixture.value['max_connections']=48;self.fixture.write(self.fixture.m.PREP.INPUT,self.fixture.m.PREP.canonical(self.fixture.value))
        self.fixture.faults(stop=True)
        result=self.run_controller('s4g_repair');self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.fixture.m.CONFIG/'postgresql.conf').read_bytes(),before)
        self.assertEqual(self.state()['starts'],1)

    def test_changed_generation_start_failure_cannot_return_success(self):
        self.apply();self.fixture.faults(start=True)
        (self.fixture.root/'state/postgresql.loaded').unlink()
        result=self.run_controller('s4g_repair');self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.state()['active']['debian13s4-postgresql-server.service'])
        self.assertFalse((self.fixture.root/'state/postgresql.loaded').exists())

    def test_failed_catalog_and_ack_sync_leave_no_ready_success(self):
        for fault in ('wrong_catalog','sync_loaded'):
            with self.subTest(fault=fault):
                private=PrivatePG();self.addCleanup(private.close);private.faults(**{fault:True})
                result=subprocess.run(['/bin/bash','-p','-c',private.shell('s4g_apply')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse((private.root/'state/postgresql.ready').exists())
                self.assertFalse(json.loads(private.database.read_bytes())['active'].get('debian13s4-postgresql-server.service',False))

    def test_bounded_package_verification_keeps_parent_package_contract_unchanged(self):
        result=self.run_controller('s4m_load_packages\noriginal=${S4P_PACKAGES[*]}\ns4g_packages\n[[ ${S4P_PACKAGES[*]} == "$original" ]]')
        self.assertEqual(result.returncode,0,result.stderr.decode())
        rows=[row for row in self.events() if row['action'] in ('package','audit')]
        self.assertEqual(len(rows),3)
        self.assertEqual(rows[-1]['args'],['--audit'])

    def test_pending_guard_and_lock_contention_precede_any_manager_call(self):
        guard=self.fixture.root/'state/bootstrap';guard.mkdir(mode=0o700);(guard/'pending').write_text('pending\n')
        self.assertEqual(self.run_controller('s4g_repair').returncode,75)
        self.assertFalse((self.fixture.root/'events.jsonl').exists())
        (guard/'pending').unlink()
        result=self.run_controller('exec {private_lock}> "$S4M_STATE/repair.lock"\nflock --nonblock "$private_lock"\ns4g_repair')
        self.assertEqual(result.returncode,75);self.assertFalse((self.fixture.root/'events.jsonl').exists())

    def test_missing_enrollment_or_packages_never_creates_cluster(self):
        self.fixture.m.ENROLLMENT.unlink();self.assertNotEqual(self.run_controller('s4g_apply').returncode,0)
        self.assertFalse((self.fixture.m.DATA/'postmaster.pid').exists())
        self.assertEqual((self.fixture.m.DATA/'PG_VERSION').read_bytes(),b'17\n')
        self.fixture.write(self.fixture.m.ENROLLMENT,self.fixture.m.PREP.canonical(self.fixture.enrolled));self.fixture.faults(packages=True)
        self.assertNotEqual(self.run_controller('s4g_apply').returncode,0);self.assertEqual(self.state()['starts'],0)

    def test_dropin_and_malformed_named_instance_refuse_verification(self):
        self.apply();self.fixture.faults(dropin=True)
        self.assertNotEqual(self.run_controller('s4g_verify').returncode,0)
        self.fixture.faults(dropin=False)
        for value in ('ActiveState=active\nMainPID=1\nMainPID=2\nInvocationID='+'a'*32,
                      'ActiveState=active\nMainPID=0\nInvocationID='+'a'*32):
            self.fixture.faults(generation=value)
            self.assertNotEqual(self.run_controller('s4g_verify').returncode,0)


if __name__=='__main__':unittest.main()
