"""Private controller/peer/start-generation models; no native PG or PID1."""
import json
import subprocess
import unittest
from pathlib import Path

from fixture_pg import PrivatePG


class AccessStartupTests(unittest.TestCase):
    def setUp(self):
        self.fixture=PrivatePG();self.addCleanup(self.fixture.close)

    def run_controller(self,command,fixture=None):
        fixture=self.fixture if fixture is None else fixture
        return subprocess.run(['/bin/bash','-p','-c',fixture.shell(command)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)

    def state(self,fixture=None):
        return json.loads((self.fixture if fixture is None else fixture).database.read_bytes())

    def apply(self):
        result=self.run_controller('s4g_apply');self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_apply_and_noop_require_both_actual_private_peer_identities_without_a_restart(self):
        self.apply();marker=self.fixture.root/'state/postgresql.loaded';raw=marker.read_bytes();inode=marker.stat().st_ino
        result=self.run_controller('s4g_verify && s4g_repair')
        self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(self.state()['starts'],1)
        self.assertEqual(marker.read_bytes(),raw);self.assertEqual(marker.stat().st_ino,inode)
        rows=[json.loads(line) for line in self.fixture.ledger.read_text().splitlines()]
        self.assertTrue(any(row['kind']=='peer:dns_demo' for row in rows));self.assertTrue(any(row['kind']=='peer:mail_demo' for row in rows))
        self.assertIn(b'postgresql/access.py',raw)

    def test_each_peer_refusal_or_unsafe_schema_blocks_initial_ack_and_ready_and_stops_server(self):
        for fault,value in (('peer_refuse','dns_demo'),('peer_refuse','mail_demo'),('peer_public_create',True),('peer_read_only',True)):
            private=PrivatePG();self.addCleanup(private.close);private.faults(**{fault:value})
            with self.subTest(fault=fault,value=value):
                result=self.run_controller('s4g_apply',private);self.assertNotEqual(result.returncode,0)
                self.assertEqual(self.state(private)['starts'],1)
                self.assertFalse(self.state(private)['active']['debian13s4-postgresql-server.service'])
                self.assertFalse((private.root/'state/postgresql.loaded').exists())
                self.assertFalse((private.root/'state/postgresql.ready').exists())
                self.assertFalse((private.root/'data/postmaster.pid').exists())

    def test_previously_acknowledged_server_with_changed_peer_access_is_not_healthy_after_repair(self):
        self.apply();self.fixture.faults(peer_refuse='mail_demo')
        self.assertNotEqual(self.run_controller('s4g_verify').returncode,0)
        result=self.run_controller('s4g_repair');self.assertEqual(result.returncode,75)
        self.assertFalse(self.state()['active']['debian13s4-postgresql-server.service'])
        self.assertFalse((self.fixture.root/'state/postgresql.loaded').exists())
        # One ordinary controlled repair start follows checked inactivity; no SQL
        # provisioning/delivery operation is present, and failure is not success.
        self.assertEqual(self.state()['starts'],2)

    def test_access_code_identity_change_requires_guarded_reapply_and_failed_start_refuses(self):
        self.apply();path=self.fixture.root/'library/postgresql/access.py';path.write_bytes(path.read_bytes()+b'\n# changed private policy generation\n')
        # A library-code change invalidates ready itself: normal repair MUST
        # stop/refuse. Only the guarded apply path can acknowledge new code.
        self.assertEqual(self.run_controller('s4g_repair').returncode,75)
        self.assertEqual(self.state()['starts'],1)
        self.assertFalse(self.state()['active']['debian13s4-postgresql-server.service'])
        self.assertFalse((self.fixture.root/'state/postgresql.loaded').exists())
        result=self.run_controller('s4g_apply');self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(self.state()['starts'],2)
        path.write_bytes(path.read_bytes()+b'\n# another private generation\n');self.fixture.faults(start=True)
        self.assertEqual(self.run_controller('s4g_repair').returncode,75)
        self.assertNotEqual(self.run_controller('s4g_apply').returncode,0)
        self.assertEqual(self.state()['starts'],2)
        self.assertFalse(self.state()['active']['debian13s4-postgresql-server.service'])
        self.assertFalse((self.fixture.root/'state/postgresql.loaded').exists())


if __name__=='__main__':unittest.main()
