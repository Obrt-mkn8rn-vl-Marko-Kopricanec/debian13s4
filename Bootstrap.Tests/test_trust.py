"""Fresh private filesystem checks, equivalent to the existing harness grammar."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import fixture_delivery as delivery


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        (self.root/'child').mkdir(mode=0o700);self.file=self.root/'child/file';self.file.write_text('private\n');self.file.chmod(0o600)
    def trust(self,path):return delivery.trusted(self.root,str(path))
    def test_parent_root_and_owned_nonwritable_file_are_positive(self):
        self.assertTrue(self.trust(self.root));self.assertTrue(self.trust(self.file))
    def test_current_mode_ancestry_and_missing_replacements_refuse_without_cached_success(self):
        self.assertTrue(self.trust(self.file));self.file.chmod(0o666);self.assertFalse(self.trust(self.file))
        self.file.chmod(0o600);self.assertTrue(self.trust(self.file))
        self.file.parent.chmod(0o777);self.assertFalse(self.trust(self.file));self.file.parent.chmod(0o700)
        self.file.unlink();self.assertFalse(self.trust(self.file))
    def test_all_symbolic_ancestors_and_broken_links_refuse(self):
        link=self.root/'linked';link.symlink_to(self.file.parent,target_is_directory=True)
        self.assertFalse(self.trust(link/'file'));link.unlink();link.symlink_to(self.root/'absent')
        self.assertFalse(self.trust(link))
        self.file.unlink();self.file.symlink_to(self.root/'absent');self.assertFalse(self.trust(self.file))
    def test_foreign_uid_and_stat_errors_refuse(self):
        actual=self.file.lstat()
        with patch.object(delivery.os,'lstat',return_value=type('Fact',(),{'st_mode':actual.st_mode,'st_uid':os.geteuid()+1})()):
            self.assertFalse(self.trust(self.file))
        with patch.object(delivery.os,'lstat',side_effect=PermissionError('private')):self.assertFalse(self.trust(self.file))
    def test_noncanonical_or_outside_paths_refuse_before_filesystem_entry(self):
        paths=('/outside',str(self.root)+'-other/file',str(self.root)+'/./file',str(self.root)+'/../file',str(self.root)+'//file',str(self.root)+'/child/..',str(self.root)+'/child/.','relative')
        with patch.object(delivery.os,'lstat',side_effect=AssertionError('entry')):
            for path in paths:
                with self.subTest(path=path):self.assertFalse(self.trust(path))
    def test_complete_private_path_mode_matrix_matches_existing_bash_predicate(self):
        # Native Bash/file tests below acquired ordinary-UID private tmpfs only;
        # no production trust function, host path or native service is invoked.
        for mode in (0o000,0o400,0o600,0o644,0o640,0o666,0o622):
            self.file.chmod(mode)
            script='''path=$1;root=$2
[[ $path == "$root" || $path == "$root"/* ]] || exit 1
[[ $path != *'/../'* && $path != */.. && $path != *'/./'* && $path != */. && $path != *'//'* ]] || exit 1
while :; do
 [[ -e $path && ! -L $path && -O $path ]] || exit 1
 mode=$(stat --format='%a' -- "$path") || exit 1
 (( (8#$mode & 8#022) == 0 )) || exit 1
 [[ $path == "$root" ]] && exit 0
 path=${path%/*}
done
'''
            child=subprocess.run(['/bin/bash','-c',script,'private',str(self.file),str(self.root)],capture_output=True,timeout=5)
            with self.subTest(mode=mode):self.assertEqual(self.trust(self.file),child.returncode==0)
    def test_closed_trust_request_refuses_extra_arguments(self):
        import io
        for data in (b'3\0trust\0path\0extra\0',b'2\0trust\0\0'):
            with self.subTest(data=data),self.assertRaises(ValueError):delivery.request(io.BytesIO(data))
    def test_real_client_observes_file_drift_and_preserves_model_state_events(self):
        from test_bootstrap import BootstrapTests
        fixture=BootstrapTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        child=fixture.run_script(fixture.harness(lock=False)+'''
private_body() {
s4b_trusted "$S4B_BOOT_DIR"
printf 'safe\n' > "$S4B_BOOT_DIR/private"
chmod 600 "$S4B_BOOT_DIR/private"
s4b_trusted "$S4B_BOOT_DIR/private"
chmod 666 "$S4B_BOOT_DIR/private"
if s4b_trusted "$S4B_BOOT_DIR/private"; then exit 99; fi
s4b_systemctl daemon-reload
}
private_body
''',timeout=5)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertEqual(len(fixture.events()),1);self.assertEqual(fixture.events()[0]['args'],['daemon-reload'])

    def test_transport_lock_does_not_consume_production_flock_failure_hook(self):
        from test_bootstrap import BootstrapTests
        fixture=BootstrapTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        child=fixture.run_script(fixture.harness(lock=False)+'''
flock() { exit 97; }
s4b_trusted "$S4B_BOOT_DIR"
''',timeout=5)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertEqual(fixture.events(),[])


if __name__=='__main__':unittest.main()
