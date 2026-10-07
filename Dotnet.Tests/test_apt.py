import datetime
import getpass
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = "AA86F75E427A19DD33346403EE4D7792F748182B"


class NativeAptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise RuntimeError("Run private native APT fixtures as an ordinary user.")
        cls.temp = tempfile.TemporaryDirectory(prefix="debian13s4-dotnet-apt.",dir="/dev/shm")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.root.chmod(0o700)
        cls.keys = cls.root / "keys"
        cls.keys.mkdir(mode=0o700)
        cls.addClassCleanup(cls.stop_agent)
        for name in ("allowed","other"):
            cls.gpg("--quick-generate-key",name+"@fixture.invalid","rsa2048","sign","0")
        result = cls.gpg("--list-keys","--with-colons")
        cls.fingerprints = [line.split(":")[9] for line in result.stdout.splitlines() if line.startswith("fpr:")]
        cls.key = cls.root / "public.asc"
        cls.key.write_text(cls.gpg("--armor","--export").stdout)
        cls.key.chmod(0o644)

    @classmethod
    def stop_agent(cls):
        subprocess.run(["gpgconf","--homedir",str(cls.keys),"--kill","gpg-agent"],
                       text=True,capture_output=True,timeout=5,check=True)

    @classmethod
    def gpg(cls,*arguments):
        result = subprocess.run(["gpg","--batch","--no-options","--homedir",str(cls.keys),
                                 "--pinentry-mode","loopback","--passphrase","",*arguments],
                                text=True,capture_output=True,timeout=20)
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return result

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case.",dir=self.root))
        self.addCleanup(shutil.rmtree,self.case)
        for name in ("lists","lists/partial","archives","archives/partial","log"):
            (self.case/name).mkdir(mode=0o700)
        (self.case/"status").write_text("")
        self.sources = self.case / "source.sources"
        self.config = self.case / "apt.conf"
        text = (ROOT / "Dotnet/policy.conf").read_text().replace(
            "/usr/local/lib/debian13s4/maintenance/policy.conf",str(ROOT / "Maintenance/policy.conf"))
        text = text.replace("/usr/local/lib/debian13s4/dotnet/sources.sources",str(self.sources))
        text = text.replace("/usr/local/lib/debian13s4/dotnet/preferences",str(ROOT / "Dotnet/preferences"))
        text = text.replace("/var/lib/apt/debian13s4-dotnet/lists",str(self.case/"lists"))
        text += f'''
Dir::State::status "{self.case}/status";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Cache::archives "{self.case}/archives";
Dir::Log "{self.case}/log";
APT::Sandbox::User "{getpass.getuser()}";
APT::Architecture "amd64";
#clear APT::Architectures;
APT::Architectures {{ "amd64"; }};
'''
        self.config.write_text(text)
        self.environment = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin",
                            "APT_CONFIG":str(self.config),"LANG":"C","LC_ALL":"C"}

    def run_apt(self,*command):
        return subprocess.run(command,env=self.environment,text=True,capture_output=True,timeout=20)

    def repository(self,days_old=0,signer=0,tamper=False):
        repository = self.case / "repo"
        distribution = repository / "dists/trixie"
        binary = distribution / "main/binary-amd64"
        binary.mkdir(parents=True)
        packages = b""
        (binary/"Packages").write_bytes(packages)
        date = datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=days_old)
        release = ("Origin: microsoft-debian-trixie-prod trixie\n"
                   "Label: microsoft-debian-trixie-prod trixie\n"
                   "Suite: trixie\nCodename: trixie\nArchitectures: amd64\nComponents: main\n"
                   "Date: "+date.strftime("%a, %d %b %Y %H:%M:%S +0000")+"\n"
                   "SHA256:\n "+hashlib.sha256(packages).hexdigest()+" 0 main/binary-amd64/Packages\n")
        (distribution/"Release").write_text(release)
        self.gpg("--armor","--local-user",self.fingerprints[signer],
                 "--output",str(distribution/"InRelease"),"--clearsign",str(distribution/"Release"))
        if tamper:
            target = distribution / "InRelease"
            target.write_text(target.read_text().replace("Suite: trixie","Suite: altered"))
        source = (ROOT / "Dotnet/microsoft.sources").read_text()
        source = source.replace("https://packages.microsoft.com/debian/13/prod",repository.as_uri())
        source = source.replace("/usr/local/lib/debian13s4/dotnet/microsoft-2025.asc",str(self.key))
        source = source.replace(FINGERPRINT,self.fingerprints[0])
        self.sources.write_text(source)

    def test_native_apt_accepts_a_valid_scoped_signature(self):
        self.repository()
        result = self.run_apt("apt-get","update")
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_native_apt_rejects_a_tampered_signed_release(self):
        self.repository(tamper=True)
        self.assertNotEqual(self.run_apt("apt-get","update").returncode,0)

    def test_native_apt_rejects_other_signer_even_in_the_same_key_file(self):
        self.repository(signer=1)
        self.assertNotEqual(self.run_apt("apt-get","update").returncode,0)

    def test_native_apt_rejects_old_release_without_vendor_expiration(self):
        self.repository(days_old=15)
        result = self.run_apt("apt-get","update")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("expired",result.stderr)

    def test_actual_configuration_keeps_host_fragments_and_debian_lists_isolated(self):
        self.repository()
        result = self.run_apt("apt-config","dump")
        self.assertEqual(result.returncode,0,result.stderr)
        for setting in ('Dir::Etc::parts "";','Dir::Etc::main "";','Dir::Etc::sourceparts "-";',
                        'Acquire::Check-Date "true";','Acquire::Check-Valid-Until "true";',
                        'Acquire::AllowInsecureRepositories "false";','APT::Get::AllowUnauthenticated "false";'):
            self.assertIn(setting,result.stdout)
        self.assertIn(str(self.case/"lists"),result.stdout)
        self.assertNotIn("DPkg::Pre-Invoke::",result.stdout)
        self.assertEqual((ROOT / "Maintenance/policy.conf").read_text().count("packages.microsoft.com"),0)

    def candidate_cache(self):
        self.sources.write_text((ROOT / "Tasks/prerequisites/debian.sources").read_text()+"\n"+
                                (ROOT / "Dotnet/microsoft.sources").read_text())
        lists = self.case / "lists"
        microsoft = "packages.microsoft.com_debian_13_prod_dists_trixie"
        records = []
        for name,versions in (
                ("aspnetcore-runtime-10.0",["10.0.1","10.0.2"]),
                ("dotnet-runtime-10.0",["10.0.2"]),
                ("dotnet-runtime-deps-10.0",["10.0.2"]),
                ("dotnet-hostfxr-10.0",["10.0.2"]),
                ("dotnet-host",["8.0.1","10.0.2","11.0.1"]),
                ("powershell",["10.0.1"]),("dotnet-sdk-10.0",["10.0.100"]),
                ("aspnetcore-runtime-11.0",["11.0.1"])):
            for version in versions:
                records.append(f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
                               "Filename: pool/example.deb\nSize: 0\nSHA256: "+hashlib.sha256(b"").hexdigest()+"\n\n")
        (lists/(microsoft+"_main_binary-amd64_Packages")).write_text("".join(records))
        (lists/(microsoft+"_Release")).write_text(
            "Origin: microsoft-debian-trixie-prod trixie\nLabel: microsoft-debian-trixie-prod trixie\n"
            "Suite: trixie\nCodename: trixie\nArchitectures: amd64\nComponents: main\n")
        debian = "deb.debian.org_debian_dists_trixie"
        (lists/(debian+"_main_binary-amd64_Packages")).write_text(
            "Package: libc6\nVersion: 2.41-12\nArchitecture: amd64\nFilename: pool/libc6.deb\n\n")
        (lists/(debian+"_Release")).write_text("Origin: Debian\nLabel: Debian\nSuite: stable\nCodename: trixie\n")

    def test_native_candidate_policy_allows_only_ten_runtime_and_debian_dependencies(self):
        # Only libapt candidate selection is tested by these synthetic caches;
        # signature acceptance is exercised separately with the local signed repo.
        self.candidate_cache()
        for package,expected in (("aspnetcore-runtime-10.0","10.0.2"),("dotnet-host","10.0.2"),
                                 ("libc6","2.41-12"),("powershell","(none)"),
                                 ("dotnet-sdk-10.0","(none)"),("aspnetcore-runtime-11.0","(none)")):
            with self.subTest(package=package):
                result = self.run_apt("apt-cache","policy",package)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn("Candidate: "+expected,result.stdout)

    def test_native_no_remove_resolver_cannot_select_unrelated_microsoft_package(self):
        self.candidate_cache()
        result = self.run_apt("apt-get","--simulate","--assume-yes","--no-remove","install","powershell")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("no installation candidate",result.stderr)


if __name__ == "__main__":
    unittest.main()
