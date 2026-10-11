"""Mandatory upstream admission in private controller SOURCE delivery models."""
import json
from pathlib import Path
import unittest
from fixture_web import PrivateWeb, ROOT


class UpstreamStartupTests(unittest.TestCase):
    def setUp(self):
        self.fixture=PrivateWeb();self.addCleanup(self.fixture.close)
    def state(self,fixture=None):
        return json.loads((fixture or self.fixture).database.read_bytes())
    def probes(self,fixture=None):
        path=(fixture or self.fixture).root/'upstream.jsonl'
        return [json.loads(row) for row in path.read_bytes().splitlines()] if path.exists() else []
    def apply(self):
        child=self.fixture.controller('s4w_apply',timeout=120)
        self.assertEqual(child.returncode,0,child.stderr.decode())
    def test_apply_checks_all_upstreams_before_and_after_start_and_binds_code_identity(self):
        self.apply();rows=self.probes()
        self.assertEqual([row['app'] for row in rows[:3]],list(self.fixture.m.PREP.APPLICATIONS))
        self.assertEqual([row['starts'] for row in rows[:3]],[0,0,0])
        self.assertEqual([row['app'] for row in rows[3:6]],list(self.fixture.m.PREP.APPLICATIONS))
        self.assertEqual([row['starts'] for row in rows[3:6]],[1,1,1])
        loaded=self.fixture.root/'state/web.loaded';ready=self.fixture.root/'state/web.ready'
        self.assertIn(b' web/upstream.py\n',loaded.read_bytes());self.assertIn(b' web/upstream.py\n',ready.read_bytes())
        raw=loaded.read_bytes();inode=loaded.stat().st_ino;count=len(rows)
        child=self.fixture.controller('s4w_verify && s4w_repair',timeout=120)
        self.assertEqual(child.returncode,0,child.stderr.decode());self.assertEqual(self.state()['starts'],1)
        self.assertEqual(loaded.read_bytes(),raw);self.assertEqual(loaded.stat().st_ino,inode)
        self.assertEqual(len(self.probes())-count,6)
    def test_each_unavailable_upstream_refuses_before_nginx_start(self):
        for app in self.fixture.m.PREP.APPLICATIONS:
            with self.subTest(app=app):
                private=PrivateWeb();self.addCleanup(private.close);private.faults(upstream=app)
                child=private.controller('s4w_apply',timeout=120)
                self.assertNotEqual(child.returncode,0)
                self.assertEqual(self.state(private)['starts'],0)
                self.assertFalse((private.root/'state/web.loaded').exists())
                self.assertFalse((private.root/'state/web.ready').exists())
                self.assertFalse(self.state(private)['active'].get('debian13s4-web-server.service',False))
    def test_post_start_upstream_failure_stops_without_acknowledging_or_starting_twice(self):
        for app in self.fixture.m.PREP.APPLICATIONS:
            with self.subTest(app=app):
                private=PrivateWeb();self.addCleanup(private.close);private.faults(upstream_after_start=app)
                child=private.controller('s4w_apply',timeout=120)
                self.assertNotEqual(child.returncode,0)
                self.assertEqual(self.state(private)['starts'],1)
                self.assertFalse(self.state(private)['active']['debian13s4-web-server.service'])
                self.assertFalse((private.root/'state/web.loaded').exists())
                self.assertFalse((private.root/'state/web.ready').exists())
    def test_acknowledged_server_losing_upstream_is_not_healthy_and_repair_fails_inactive(self):
        self.apply();self.fixture.faults(upstream='mk8.email')
        child=self.fixture.controller('s4w_verify',timeout=120);self.assertNotEqual(child.returncode,0)
        self.assertEqual(self.state()['starts'],1)
        child=self.fixture.controller('s4w_repair',timeout=120);self.assertEqual(child.returncode,75)
        self.assertEqual(self.state()['starts'],1);self.assertFalse(self.state()['active']['debian13s4-web-server.service'])
        self.assertFalse((self.fixture.root/'state/web.loaded').exists())
    def test_upstream_code_drift_requires_guarded_reapply_after_normal_repair_stops(self):
        self.apply();path=self.fixture.root/'library/web/upstream.py'
        path.write_bytes(path.read_bytes()+b'\n# changed private Source generation\n')
        child=self.fixture.controller('s4w_repair',timeout=120);self.assertEqual(child.returncode,75)
        self.assertEqual(self.state()['starts'],1);self.assertFalse((self.fixture.root/'state/web.loaded').exists())
        self.apply();self.assertEqual(self.state()['starts'],2)
        self.assertIn(b' web/upstream.py\n',(self.fixture.root/'state/web.loaded').read_bytes())
    def test_same_path_upstream_ca_change_requires_new_acknowledged_generation(self):
        self.apply();loaded=self.fixture.root/'state/web.loaded';old=loaded.read_bytes()
        ca=Path(self.fixture.value['applications']['mk8.sava']['upstream_ca'])
        ca.write_bytes(self.fixture.pem(body=b'changed PRIVATE CA MODEL'))
        child=self.fixture.controller('s4w_repair',timeout=120);self.assertEqual(child.returncode,0,child.stderr.decode())
        self.assertEqual(self.state()['starts'],2);self.assertNotEqual(loaded.read_bytes(),old)
    def test_missing_upstream_asset_refuses_before_manager_or_probe_entry(self):
        (self.fixture.root/'library/web/upstream.py').unlink()
        child=self.fixture.controller('s4w_apply',timeout=120);self.assertNotEqual(child.returncode,0)
        self.assertEqual(self.probes(),[]);self.assertEqual(self.state()['starts'],0)
        self.assertFalse((self.fixture.root/'events.jsonl').exists())
    def test_input_drift_during_preflight_never_starts_or_acknowledges(self):
        self.fixture.faults(upstream_config_drift=True)
        child=self.fixture.controller('s4w_apply',timeout=120);self.assertNotEqual(child.returncode,0)
        self.assertEqual(self.state()['starts'],0);self.assertFalse((self.fixture.root/'state/web.loaded').exists())
        self.assertFalse((self.fixture.root/'state/web.ready').exists())
    def test_pending_guard_and_contended_repair_lock_precede_upstream_entry(self):
        path=self.fixture.root/'state/bootstrap';path.mkdir(mode=0o700);guard=path/'pending';guard.write_text('pending\n')
        self.assertEqual(self.fixture.controller('s4w_repair',timeout=120).returncode,75)
        self.assertEqual(self.probes(),[]);guard.unlink()
        child=self.fixture.controller('exec {private_lock}> "$S4M_STATE/repair.lock"\nflock --nonblock "$private_lock"\ns4w_repair',timeout=120)
        self.assertEqual(child.returncode,75);self.assertEqual(self.probes(),[])
    def production_policy(self):
        common=(ROOT/'Web/common.sh').read_text()
        function=common[common.index('s4w_policy() ('):common.index('\ns4w_action()')]
        return "source /dev/stdin <<'PRIVATE_EXACT_POLICY'\n"+function+"\nPRIVATE_EXACT_POLICY\n"
    def test_real_policy_dispatches_fixed_upstream_without_arguments_environment_or_lock_leak(self):
        root=self.fixture.root;program=root/'library/web/upstream.py'
        program.write_text('import json,os,sys\nfrom pathlib import Path\n'+
            f'root=Path({str(root)!r})\n'+
            "fd=int((root/'fd.number').read_text());expected=(root/'state/repair.lock').stat()\n"+
            "try:\n fact=os.fstat(fd);leaked=(fact.st_dev,fact.st_ino)==(expected.st_dev,expected.st_ino)\n"+
            "except OSError:leaked=False\n"+
            "print(json.dumps({'argv':sys.argv[1:],'environment':dict(os.environ),'repair_lock_leaked':leaked}))\n")
        child=self.fixture.controller(self.production_policy()+
            's4m_lock\nprintf "%s\\n" "$S4M_REPAIR_FD" > '+str(root/'fd.number')+'\ns4w_policy --upstream',timeout=120)
        self.assertEqual(child.returncode,0,child.stderr.decode());value=json.loads(child.stdout)
        self.assertEqual(value['argv'],[]);self.assertFalse(value['repair_lock_leaked'])
        self.assertEqual(value['environment'],{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
    def test_real_upstream_dispatch_refuses_extra_argument_before_child_entry(self):
        flag=self.fixture.root/'unexpected-entry';program=self.fixture.root/'library/web/upstream.py'
        program.write_text('from pathlib import Path\n'+f'Path({str(flag)!r}).write_text("entry")\n')
        child=self.fixture.controller(self.production_policy()+'s4w_policy --upstream unexpected',timeout=120)
        self.assertEqual(child.returncode,1);self.assertFalse(flag.exists());self.assertEqual(child.stdout,b'')


if __name__=='__main__':unittest.main()
