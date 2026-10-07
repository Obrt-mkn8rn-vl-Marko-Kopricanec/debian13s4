import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "Maintenance/retain-kernels.py"

# Real libapt cache, dependency/protection logic and production planner. Only
# commit delivery modifies synthetic dpkg registration; no host dpkg is run.
DRIVER = r'''
import importlib.util,json,os,stat,sys
from pathlib import Path
import apt,apt_pkg
helper, root, running, action, fault = sys.argv[1:]
root = Path(root)
spec = importlib.util.spec_from_file_location("retention",helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
cache = apt.Cache(memonly=True)
garbage = sorted(p.name for p in cache if p.is_auto_removable)
calls = []
def commit(**kwargs):
    names = [p.name for p in cache.get_changes()]
    assert kwargs == {"allow_unauthenticated":False}
    calls.append(names)
    if fault == "commit_error": raise RuntimeError("substituted commit error")
    if fault == "commit_false": return False
    if fault == "unchanged": return True
    records = (root/"dpkg/status").read_text().strip().split("\n\n")
    changed = []
    for record in records:
        name = record.splitlines()[0].split(": ",1)[1]
        if name in names or (fault == "changed_retained" and name == "linux-image-amd64"):
            record = record.replace("Status: install ok installed","Status: deinstall ok config-files")
        changed.append(record)
    (root/"dpkg/status").write_text("\n\n".join(changed)+"\n\n")
    return True
def audit():
    if fault == "audit_error": raise RuntimeError("substituted post-removal audit error")
cache.commit = commit
module.audit = audit
try:
    if action.startswith("entry_"):
        # Fixture trust/UID and boot observation; the entrypoint's profile,
        # planner, native private SystemLock and postconditions remain real.
        module.POLICY=root/"apt.conf"
        module.TRUSTED_UID=os.geteuid()
        def trusted(path,directory=False):
            path=Path(path)
            assert path==root or root in path.parents
            info=path.lstat()
            kind=stat.S_ISDIR if directory else stat.S_ISREG
            assert kind(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o022
        module.trusted=trusted
        module.os.uname=lambda: type("BootObservation",(),{"release":running})()
        original_cache=apt.Cache
        def factory(**kwargs):
            global cache
            if action=="entry_apply": assert apt_pkg.pkgsystem_is_locked()
            cache=original_cache(**kwargs)
            cache.commit=commit
            return cache
        apt.Cache=factory
        sys.argv=[helper,"--apply" if action=="entry_apply" else "--plan"]
        sys.exit(module.main())
    elif action == "plan":
        name, retained = module.select(cache,running)
        result,message = 0,{"selected":name,"retained":sorted(retained)}
    else:
        result,message = module.transact(cache,running,True)
    print(json.dumps({**message,"garbage":garbage,"commits":calls,"code":result},sort_keys=True))
    sys.exit(result)
except Exception as error:
    print(str(error),file=sys.stderr)
    sys.exit(1)
'''


class KernelRetentionTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            raise RuntimeError("Run these private native APT caches as an ordinary user.")
        self.temp = tempfile.TemporaryDirectory(prefix="debian13s4-kernel-tests.", dir="/dev/shm")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.architecture = "amd64"
        for name in ("dpkg", "dpkg/updates", "lists", "lists/partial", "archives", "archives/partial"):
            (self.root/name).mkdir(mode=0o700)
        (self.root/"sources.list").write_text("")
        self.config = self.root/"apt.conf"
        text = (ROOT/"Maintenance/policy.conf").read_text()
        text += f'''
Dir::Etc::sourcelist "{self.root}/sources.list";
Dir::State::status "{self.root}/dpkg/status";
Dir::State::extended_states "{self.root}/extended_states";
Dir::State::lists "{self.root}/lists";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Cache::archives "{self.root}/archives";
APT::Architecture "amd64";
#clear APT::Architectures;
APT::Architectures {{ "amd64"; }};
'''
        self.config.write_text(text)
        self.config.chmod(0o600)
        self.environment = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C", "LC_ALL":"C",
                            "APT_CONFIG":str(self.config)}
        self.records = []
        self.auto = []
        for number in range(1,8):
            self.image(number)
        self.package("linux-image-amd64", "6.12.7-1", depends="linux-image-6.12.7+deb13-amd64")
        self.package("unrelated-library", "1", auto=True)
        self.running = "6.12.5+deb13-amd64"
        self.save()

    def package(self,name,version,auto=False,depends="",status="install ok installed",priority="optional",essential=False):
        record = f"Package: {name}\nStatus: {status}\nArchitecture: amd64\nVersion: {version}\nPriority: {priority}\n"
        if depends: record += "Depends: "+depends+"\n"
        if essential: record += "Essential: yes\n"
        self.records.append(record+"Description: disposable native-cache fixture\n")
        if auto: self.auto.append(name)

    def image(self,number,flavour="amd64",legacy=False,**kwargs):
        release = f"6.12.0-{number}-{flavour}" if legacy else f"6.12.{number}+deb13-{flavour}"
        self.package("linux-image-"+release, f"6.12.{number}-1",auto=True,**kwargs)
        return "linux-image-"+release

    def save(self):
        (self.root/"dpkg/status").write_text("\n".join(self.records)+"\n")
        (self.root/"dpkg/status").chmod(0o600)
        (self.root/"extended_states").write_text("".join(
            "Package: "+name+"\nArchitecture: "+self.architecture+"\nAuto-Installed: 1\n\n" for name in self.auto))
        (self.root/"extended_states").chmod(0o600)

    def run_case(self,action="plan",fault=""):
        self.save()
        result = subprocess.run(["/usr/bin/python3","-I","-B","-c",DRIVER,str(HELPER),str(self.root),
                                 self.running,action,fault],env=self.environment,text=True,capture_output=True,timeout=30)
        if result.returncode in (0,75):
            self.message = json.loads(result.stdout)
        return result

    def test_native_current_names_retain_three_versions_and_select_one(self):
        result = self.run_case()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.message["selected"],"linux-image-6.12.1+deb13-amd64")
        self.assertTrue({"linux-image-6.12.5+deb13-amd64","linux-image-6.12.6+deb13-amd64",
                         "linux-image-6.12.7+deb13-amd64","linux-image-amd64"} <= set(self.message["retained"]))
        self.assertEqual(self.message["commits"],[])

    def test_old_running_image_remains_even_outside_latest_three(self):
        self.running = "6.12.1+deb13-amd64"
        self.assertEqual(self.run_case().returncode,0)
        self.assertIn("linux-image-"+self.running,self.message["retained"])
        self.assertEqual(self.message["selected"],"linux-image-6.12.2+deb13-amd64")

    def test_legacy_and_cloud_names_have_the_same_checked_retention(self):
        self.records,self.auto=[],[]
        for number in range(1,6): self.image(number,"cloud-amd64",legacy=True)
        self.package("linux-image-cloud-amd64","6.12.5-1",depends="linux-image-6.12.0-5-cloud-amd64")
        self.running="6.12.0-4-cloud-amd64"
        self.assertEqual(self.run_case().returncode,0)
        self.assertEqual(self.message["selected"],"linux-image-6.12.0-1-cloud-amd64")

    def test_separate_flavours_keep_their_own_recent_fallbacks(self):
        for number in range(10,14): self.image(number,"rt-amd64")
        self.assertEqual(self.run_case().returncode,0)
        kept=set(self.message["retained"])
        self.assertTrue({f"linux-image-6.12.{n}+deb13-rt-amd64" for n in (11,12,13)} <= kept)
        self.assertIn("linux-image-6.12.6+deb13-amd64",kept)

    def test_arm64_metadata_uses_native_dependency_and_protection_rules(self):
        self.architecture="arm64"
        self.records=[r.replace("amd64","arm64") for r in self.records]
        self.auto=[n.replace("amd64","arm64") for n in self.auto]
        self.config.write_text(self.config.read_text().replace('"amd64"','"arm64"'))
        self.running=self.running.replace("amd64","arm64")
        result=self.run_case()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.message["selected"],"linux-image-6.12.1+deb13-arm64")

    def test_native_entry_plan_checks_actual_profile_without_committing(self):
        result=self.run_case("entry_plan")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.message["selected"],"linux-image-6.12.1+deb13-amd64")
        self.assertFalse((self.root/"dpkg/lock").exists())

    def test_native_entry_apply_holds_private_lock_before_loading_the_cache(self):
        result=self.run_case("entry_apply")
        self.assertEqual(result.returncode,75,result.stderr)
        self.assertEqual(self.message["removed"],"linux-image-6.12.1+deb13-amd64")
        self.assertTrue((self.root/"dpkg/lock-frontend").exists())

    def test_native_private_package_lock_contention_preserves_registration(self):
        before=(self.root/"dpkg/status").read_bytes()
        with (self.root/"dpkg/lock-frontend").open("a+") as stream:
            fcntl.lockf(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=self.run_case("entry_apply")
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertIn("lock",result.stderr)
        self.assertEqual((self.root/"dpkg/status").read_bytes(),before)

    def test_entry_refuses_weakened_protection_locking_and_host_fragment_inputs(self):
        text=self.config.read_text()
        for setting in ('APT::Protect-Kernels "false";', 'Debug::NoLocking "true";',
                        'APT::NeverAutoRemove::KernelCount "3";',
                        'Dir::Etc::parts "/etc/apt/apt.conf.d";',
                        '#clear APT::VersionedKernelPackages;'):
            with self.subTest(setting=setting):
                self.config.write_text(text+setting+"\n")
                result=self.run_case("entry_apply")
                self.assertEqual(result.returncode,1,result.stderr)
                self.assertFalse((self.root/"dpkg/lock").exists())

    def test_manual_and_held_images_cannot_be_selected(self):
        self.auto.remove("linux-image-6.12.1+deb13-amd64")
        self.records=[r.replace("Status: install ok installed","Status: hold ok installed")
                      if r.startswith("Package: linux-image-6.12.2+") else r for r in self.records]
        self.assertEqual(self.run_case().returncode,0)
        self.assertEqual(self.message["selected"],"linux-image-6.12.3+deb13-amd64")

    def test_required_dependency_image_is_not_native_garbage(self):
        self.package("kernel-consumer","1",depends="linux-image-6.12.1+deb13-amd64")
        self.assertEqual(self.run_case().returncode,0)
        self.assertNotIn("linux-image-6.12.1+deb13-amd64",self.message["garbage"])
        self.assertEqual(self.message["selected"],"linux-image-6.12.2+deb13-amd64")

    def test_essential_or_important_images_and_unrelated_garbage_are_kept(self):
        self.records=[r.replace("Priority: optional","Priority: important")
                      if r.startswith("Package: linux-image-6.12.1+") else r for r in self.records]
        self.records=[r.replace("Description:","Essential: yes\nDescription:")
                      if r.startswith("Package: linux-image-6.12.2+") else r for r in self.records]
        self.assertEqual(self.run_case().returncode,0)
        self.assertIn("unrelated-library",self.message["garbage"])
        self.assertEqual(self.message["selected"],"linux-image-6.12.3+deb13-amd64")

    def test_unknown_images_headers_and_unsigned_names_never_enter_scope(self):
        for name in ("linux-image-custom", "linux-headers-6.12.1+deb13-amd64",
                     "linux-image-6.12.1+deb13-amd64-unsigned", "linux-image-6.12.1+deb14-amd64"):
            self.package(name,"0",auto=True)
        self.assertEqual(self.run_case().returncode,0)
        self.assertEqual(self.message["selected"],"linux-image-6.12.1+deb13-amd64")

    def test_unidentified_running_kernel_refuses_removal(self):
        self.running="unknown-custom-kernel"
        self.assertNotEqual(self.run_case("apply").returncode,0)

    def test_missing_metapackage_or_partial_kernel_refuses_removal(self):
        original=list(self.records)
        for fault in ("missing_meta","partial"):
            with self.subTest(fault=fault):
                self.records=[r for r in original if not (fault=="missing_meta" and r.startswith("Package: linux-image-amd64\n"))]
                if fault=="partial":
                    self.records=[r.replace("Status: install ok installed","Status: install ok unpacked")
                                  if r.startswith("Package: linux-image-6.12.1+") else r for r in self.records]
                self.assertNotEqual(self.run_case("apply").returncode,0)

    def test_broken_dependencies_or_dpkg_journal_refuse_removal(self):
        self.package("broken-consumer","1",depends="nonexistent-dependency")
        self.assertNotEqual(self.run_case().returncode,0)
        self.records.pop()
        (self.root/"dpkg/updates/0001").write_text("interrupted\n")
        self.assertNotEqual(self.run_case().returncode,0)

    def test_one_checked_removal_remains_pending_when_more_are_eligible(self):
        result=self.run_case("apply")
        self.assertEqual(result.returncode,75,result.stderr)
        self.assertEqual(self.message["commits"],[["linux-image-6.12.1+deb13-amd64"]])
        self.assertTrue(self.message["pending"])

    def test_failed_native_commit_or_zero_exit_nonremoval_cannot_complete(self):
        for fault in ("commit_error","commit_false","unchanged","changed_retained","audit_error"):
            with self.subTest(fault=fault):
                self.assertEqual(self.run_case("apply",fault).returncode,1)

    def test_successful_retries_reach_retained_set_without_network(self):
        selected=[]
        for attempt in range(5):
            result=self.run_case("apply")
            self.assertIn(result.returncode,(0,75),result.stderr)
            selected.extend(self.message["commits"])
            self.records=(self.root/"dpkg/status").read_text().strip().split("\n\n")
            self.records=[r+"\n" for r in self.records]
            if result.returncode==0: break
        self.assertEqual(len(selected),4)
        self.assertFalse(self.message["pending"])
        self.assertEqual(result.returncode,0)

    def test_running_host_trust_checks_are_read_only_and_reject_private_leaves(self):
        command = ("import importlib.util; s=importlib.util.spec_from_file_location('k',"+repr(str(HELPER))+
                   "); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                   "m.trusted('/etc/debian_version'); m.trusted('/etc',directory=True); "
                   "m.trusted("+repr(str(self.config))+")")
        result=subprocess.run(["/usr/bin/python3","-I","-B","-c",command],text=True,capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("untrusted kernel maintenance path",result.stderr)


if __name__ == "__main__":
    unittest.main()
