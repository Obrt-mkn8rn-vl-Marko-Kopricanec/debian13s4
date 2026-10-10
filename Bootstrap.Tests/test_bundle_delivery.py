"""Private exact-byte unpacking controls; no installed files or host services."""

import hashlib
import importlib.util
import os
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

from fixture_process import run_bash

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('bootstrap_bundle_pack', ROOT / 'Bootstrap/pack.py')
PACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACK)


class BundleDeliveryTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            raise RuntimeError('ordinary UID required')
        self.temp = tempfile.TemporaryDirectory(prefix='debian13s4-bundle-delivery.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.stage = self.root / 'stage'
        self.stage.mkdir(mode=0o700)
        self.entry = self.root / 'entry.sh'
        self.ledger = self.root / 'calls'

    def run_bundle(self, bundle=None, additions=''):
        if bundle is None:
            self.entry.write_bytes(PACK.assemble())
        else:
            with patch.object(PACK, 'assets', return_value=bundle):
                self.entry.write_bytes(PACK.assemble())
        script = f'''
set -Eeuo pipefail
umask 077
source {shlex.quote(str(self.entry))}
S4B_STAGE={shlex.quote(str(self.stage))}
mkdir() {{
    printf '%s\\n' mkdir >> {shlex.quote(str(self.ledger))}
    /usr/bin/mkdir "$@"
}}
cat() {{
    printf '%s\\n' cat >> {shlex.quote(str(self.ledger))}
    /usr/bin/cat "$@"
}}
{additions}
s4b_write_bundle
'''
        return run_bash(script, 10)

    def test_current_whole_bundle_uses_one_directory_command_and_no_payload_child(self):
        result = self.run_bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ledger.read_text().splitlines(), ['mkdir'])
        self.assertEqual(set(p.relative_to(self.stage).as_posix() for p in self.stage.rglob('*') if p.is_file()),
                         set(PACK.assets()) | {'files.sha256'})
        for name, (data, _) in PACK.assets().items():
            with self.subTest(name=name):
                self.assertEqual((self.stage / name).read_bytes(), data)
        expected = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                           for name, (data, _) in PACK.assets().items())
        self.assertEqual((self.stage / 'files.sha256').read_bytes(), expected.encode())

    def test_utf8_multiline_and_shell_syntax_remain_exact_unevaluated_data(self):
        marker = self.root / 'must-not-exist'
        data = ("héllo\r\n'\"\\$`\n$(touch " + str(marker) + ")\n\n").encode()
        bundle = {'lib/tasks.list': (data, '0644'), 'lib/other': (b'tail\n', '0644')}
        result = self.run_bundle(bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.stage / 'lib/tasks.list').read_bytes(), data)
        self.assertEqual((self.stage / 'lib/other').read_bytes(), b'tail\n')
        self.assertFalse(marker.exists())

    def test_nul_non_utf8_and_missing_final_newline_are_refused_before_output(self):
        for data in (b'prefix\0suffix\n', b'\xff\n', b'missing LF'):
            with self.subTest(data=data), patch.object(PACK, 'assets', return_value={'lib/data': (data, '0644')}):
                with self.assertRaises((ValueError, UnicodeError)):
                    PACK.assemble()
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_c_locale_does_not_reencode_utf8_payload_or_interpret_format_data(self):
        data = 'é\n%s %b %n \\u00e9\n'.encode('utf-8')
        result = self.run_bundle({'lib/text': (data, '0644')}, additions='export LC_ALL=C LANG=C')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.stage / 'lib/text').read_bytes(), data)

    def test_directory_failure_does_not_publish_payload_or_checksum(self):
        result = self.run_bundle(additions='mkdir() { return 19; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_payload_open_failure_does_not_publish_checksum_or_later_payload(self):
        (self.stage / 'lib').mkdir(mode=0o700)
        (self.stage / 'lib/first').mkdir(mode=0o700)
        result = self.run_bundle({'lib/first': (b'first\n', '0644'), 'lib/later': (b'later\n', '0644')})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.stage / 'lib/later').exists())
        self.assertFalse((self.stage / 'files.sha256').exists())

    def test_payload_printf_failure_does_not_continue_to_checksum(self):
        result = self.run_bundle({'lib/first': (b'first\n', '0644'), 'lib/later': (b'later\n', '0644')},
                                 additions="printf() { return 23; }\nmkdir() { /usr/bin/mkdir \"$@\"; }")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.stage / 'lib/later').exists())
        self.assertFalse((self.stage / 'files.sha256').exists())

    def test_checksum_printf_failure_cannot_report_success(self):
        result = self.run_bundle({'lib/first': (b'first\n', '0644')}, additions='''
printf() {
    if [[ $2 == *'  lib/first'* ]]; then return 29; fi
    builtin printf "$@"
}
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.stage / 'lib/first').read_bytes(), b'first\n')


if __name__ == '__main__':
    unittest.main()
