import contextlib
import copy
import importlib.util
import io
import json
import os
import signal
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_nft', ROOT / 'Firewall/nft.py')
NFT = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(NFT)
KERNEL = NFT.KERNEL


def message():
    return {'nftables': [{'metainfo': {'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}}]}


class RulesetTests(unittest.TestCase):
    def test_native_metainfo_only_is_positive_and_privately_copied(self):
        value = message();info = NFT.empty_ruleset(value);value['nftables'][0]['metainfo']['version'] = '1.1.4'
        self.assertEqual(info['version'], '1.1.3')

    def test_missing_duplicate_misordered_or_extra_metainfo_is_not_empty(self):
        for value in (None, [], {}, {'nftables': []}, message() | {'extra': 1}, {'nftables': [None]},
                      {'nftables': [{'table': {}}, message()['nftables'][0]]}, {'nftables': message()['nftables'] * 2}):
            with self.subTest(value=value), self.assertRaises(NFT.Pending):NFT.empty_ruleset(value)

    def test_every_table_family_and_reserved_name_owner_flags_refuse(self):
        for family in ('ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev'):
            for name in ('filter', 'debian13s4'):
                value = message();value['nftables'].append({'table': {'family': family, 'name': name, 'handle': 1, 'flags': ['owner', 'persist'], 'comment': 'debian13s4'}})
                with self.subTest(family=family, name=name), self.assertRaises(NFT.Pending):NFT.empty_ruleset(value)

    def test_chains_nat_flowtables_sets_rules_stateful_and_unknown_objects_refuse(self):
        for kind in ('chain', 'rule', 'set', 'map', 'element', 'flowtable', 'counter', 'quota', 'ct helper', 'limit', 'ct timeout', 'ct expectation', 'add', 'flush', 'unknown'):
            value = message();value['nftables'].append({kind: {'family': 'inet', 'table': 'debian13s4', 'type': 'nat'}})
            with self.subTest(kind=kind), self.assertRaises(NFT.Pending):NFT.empty_ruleset(value)

    def test_metainfo_schema_boolean_future_version_and_missing_extra_fields_refuse(self):
        for schema in (True, False, 0, 2, '1', None):
            value = message();value['nftables'][0]['metainfo']['json_schema_version'] = schema
            with self.subTest(schema=schema), self.assertRaises(NFT.Pending):NFT.empty_ruleset(value)
        for key in message()['nftables'][0]['metainfo']:
            value = message();del value['nftables'][0]['metainfo'][key]
            with self.subTest(key=key), self.assertRaises(NFT.Pending):NFT.empty_ruleset(value)
        value = message();value['nftables'][0]['metainfo']['extra'] = 1
        with self.assertRaises(NFT.Pending):NFT.empty_ruleset(value)

    def test_version_and_release_types_controls_encoding_and_lengths_are_bounded(self):
        for key, bad in (('version', None), ('version', 1), ('version', 'v1.1.3'), ('version', '1.1'), ('version', '1.1.3\n'), ('version', '1' * 33),
                         ('release_name', None), ('release_name', []), ('release_name', ''), ('release_name', 'x\n'), ('release_name', '\ud800'), ('release_name', 'x' * 129)):
            value = message();value['nftables'][0]['metainfo'][key] = bad
            with self.subTest(key=key, bad=repr(bad)), self.assertRaises(NFT.Pending):NFT.empty_ruleset(value)


class ObservationTests(unittest.TestCase):
    def observe(self, **overrides):
        settings = {'query': lambda deadline: message()};settings.update(overrides);return NFT.observe(**settings)

    def test_two_complete_queries_share_one_window_and_namespace(self):
        seen = [];ns = KERNEL.namespace()
        result = self.observe(query=lambda deadline: seen.append(deadline) or message())
        self.assertEqual(len(seen), 2);self.assertEqual(seen[0], seen[1]);self.assertEqual(result['namespace'], ns);self.assertIs(result['empty'], True)
        self.assertEqual(result['source']['binary'], str(NFT.BINARY))

    def test_invalid_deadline_refuses_before_any_query_or_scope(self):
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(NFT.Pending):self.observe(deadline=deadline, query=lambda **kw: self.fail('query'), scope=lambda: self.fail('scope'))

    def test_inherited_window_is_never_widened_beyond_own_cap(self):
        start = KERNEL.now()
        for budget in (5, 1000):
            seen = []
            with patch.object(KERNEL, 'now', return_value=start):self.observe(deadline=start + budget, query=lambda deadline: seen.append(deadline) or message())
            self.assertEqual(seen, [start + min(budget, NFT.ATTEMPT_SECONDS)] * 2)

    def test_metadata_or_namespace_change_and_final_expiry_refuse(self):
        values = [message(), message()];values[1]['nftables'][0]['metainfo']['release_name'] = 'changed';iterator = iter(values)
        with self.assertRaises(NFT.Pending):self.observe(query=lambda deadline: next(iterator))
        iterator = iter([KERNEL.namespace(), KERNEL.namespace() + 1])
        with self.assertRaises(NFT.Pending):self.observe(scope=lambda: next(iterator))
        with patch.object(NFT, 'ATTEMPT_SECONDS', 0), self.assertRaises(NFT.Pending):self.observe()

    def test_foreign_state_in_second_read_never_publishes_empty_receipt(self):
        values = [message(), message()];values[1]['nftables'].append({'table': {'family': 'inet', 'name': 'debian13s4'}});iterator = iter(values)
        with self.assertRaises(NFT.Pending):self.observe(query=lambda deadline: next(iterator))

    def test_query_failure_and_invalid_zero_boolean_namespace_refuse(self):
        def failure(deadline):raise OSError('fixture')
        with self.assertRaises(OSError):self.observe(query=failure)
        for namespace in (0, True, '1', None):
            with self.subTest(namespace=namespace), self.assertRaises(NFT.Pending):self.observe(scope=lambda: namespace)

    def test_receipt_false_missing_extra_source_and_namespace_are_unverifiable(self):
        receipt = self.observe()
        for key, bad in (('empty', 1), ('empty', False), ('namespace', True), ('namespace', 0), ('schema', 'other')):
            with self.subTest(key=key), self.assertRaises(NFT.Pending):NFT.validate_receipt(receipt | {key: bad})
        for key in receipt:
            value = copy.deepcopy(receipt);del value[key]
            with self.subTest(key=key), self.assertRaises(NFT.Pending):NFT.validate_receipt(value)
        value = copy.deepcopy(receipt);value['source']['binary'] = '/bin/false'
        with self.assertRaises(NFT.Pending):NFT.validate_receipt(value)
        with self.assertRaises(NFT.Pending):NFT.validate_receipt(receipt | {'extra': 1})


class PrivateNative(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-nft-', dir='/dev/shm');self.root = Path(self.directory.name);self.binary = self.root / 'nft';self.ledger = self.root / 'ledger'
        self.settings = [patch.object(NFT, 'BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def executable(self, body):
        self.binary.write_text('#!/usr/bin/python3 -B\n' + body + '\n');self.binary.chmod(0o700)

    def query(self):return NFT.native_query(KERNEL.now() + 10)


class NativeTests(PrivateNative):
    def test_fixed_read_only_argv_clears_environment_closes_inherited_descriptors(self):
        fd = os.open(self.root / 'fd', os.O_CREAT | os.O_WRONLY, 0o600);os.set_inheritable(fd, True)
        self.executable(f"import json,os,sys\ntry:\n os.fstat({fd});leaked=True\nexcept OSError:\n leaked=False\nopen({str(self.ledger)!r},'w').write(json.dumps([sys.argv[1:],dict(os.environ),leaked]))\nprint({json.dumps(message())!r})")
        try:
            with patch.dict(os.environ, {'NFT_CTX_FLAGS': 'bad', 'LD_PRELOAD': 'bad', 'TASK_SECRET': 'bad'}):self.assertEqual(self.query(), message())
            args, environment, leaked = json.loads(self.ledger.read_text());self.assertEqual(args, list(NFT.COMMAND));self.assertFalse(leaked);self.assertFalse(set(environment)&{'NFT_CTX_FLAGS','LD_PRELOAD','TASK_SECRET'})
        finally:os.close(fd)

    def test_invalid_deadline_and_unavailable_binary_do_not_execute(self):
        self.executable(f"open({str(self.ledger)!r},'w').write('unexpected')")
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(NFT.Pending):NFT.native_query(deadline)
        self.assertFalse(self.ledger.exists());self.binary.unlink()
        with self.assertRaises(FileNotFoundError):self.query()

    def test_nonzero_stderr_invalid_utf8_duplicate_json_and_truncation_are_failures(self):
        for body in ('raise SystemExit(1)', f"import sys;print({json.dumps(message())!r});print('warning',file=sys.stderr)",
                     "import os;os.write(1,b'\\xff')", "print('{\"nftables\":[],\"nftables\":[]}')", "print('{')"):
            self.executable(body)
            with self.subTest(body=body), self.assertRaises(NFT.Pending):self.query()

    def test_each_channel_has_an_independent_checked_limit(self):
        for channel in (1, 2):
            self.executable(f"import os;os.write({channel},b'x'*{NFT.MAX_BYTES + 1})")
            with self.subTest(channel=channel), self.assertRaises(NFT.Pending):self.query()

    def test_pipe_eof_does_not_count_as_native_root_completion(self):
        self.executable('import os,time\nos.close(1);os.close(2);time.sleep(60)')
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.1), self.assertRaises(NFT.Pending):self.query()

    def test_unreaped_leader_child_holding_capture_is_killed_in_its_owned_group(self):
        marker = self.root / 'child'
        self.executable(f"import json,os,time\npid=os.fork()\nif pid:\n fields=open('/proc/'+str(pid)+'/stat').read().rsplit(')',1)[1].split()\n open({str(marker)!r},'w').write(json.dumps({{'pid':pid,'start':fields[19],'group':os.getpgid(pid),'session':os.getsid(pid)}}))\n print({json.dumps(message())!r},flush=True)\n os._exit(0)\ntime.sleep(60)")
        signals = [];killpg = NFT.os.killpg
        def recorded(group, value):signals.append((group,value));return killpg(group,value)
        try:
            with patch.object(NFT.os, 'killpg', side_effect=recorded), self.assertRaises(NFT.Pending):self.query()
            self.assertTrue(marker.exists());owned = json.loads(marker.read_text())
            self.assertEqual(owned['group'], owned['session']);self.assertIn((owned['group'], signal.SIGKILL), signals)
            for _ in range(100):
                try:
                    fields=Path('/proc/'+str(owned['pid'])+'/stat').read_text().rsplit(')',1)[1].split()
                except FileNotFoundError:break
                if fields[19]!=owned['start'] or fields[0]=='Z':break
                time.sleep(0.01)
            else:self.fail('owned child stayed live after captured group termination')
        finally:
            if marker.exists():
                owned = json.loads(marker.read_text())
                try:
                    entry=Path('/proc/'+str(owned['pid']));fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
                    if entry.stat().st_uid==os.geteuid() and fields[19]==owned['start'] and fields[0]!='Z' and int(fields[2])==owned['group'] and int(fields[3])==owned['session']:os.kill(owned['pid'], signal.SIGKILL)
                except (FileNotFoundError,ProcessLookupError):pass

    def test_symbolic_wrong_kind_owner_and_writable_path_refuse_before_execution(self):
        self.executable(f"open({str(self.ledger)!r},'w').write('unexpected')")
        with patch.object(KERNEL, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(NFT.Pending):self.query()
        self.binary.chmod(0o720)
        with self.assertRaises(NFT.Pending):self.query()
        self.binary.chmod(0o700);original = self.root / 'original';self.binary.rename(original);self.binary.symlink_to(original)
        with self.assertRaises(NFT.Pending):self.query()
        self.binary.unlink();os.mkfifo(self.binary)
        with self.assertRaises(NFT.Pending):self.query()
        self.assertFalse(self.ledger.exists())

    def test_native_binary_replacement_after_capture_cannot_certify_a_read(self):
        self.executable(f"from pathlib import Path\nPath({str(self.binary)!r}).write_text('replaced')\nprint({json.dumps(message())!r})")
        with self.assertRaisesRegex(NFT.Pending, 'binary changed'):self.query()

    def test_real_private_complete_empty_observation_is_positive(self):
        self.executable(f"print({json.dumps(message())!r})")
        result = NFT.observe();self.assertIs(result['empty'], True);self.assertEqual(result['source']['binary'], str(self.binary))

    def test_real_private_reserved_table_or_warning_cli_has_no_healthy_stdout(self):
        foreign = message();foreign['nftables'].append({'table': {'family': 'inet', 'name': 'debian13s4', 'handle': 1}})
        for body in (f"print({json.dumps(foreign)!r})", f"import sys;print({json.dumps(message())!r});print('warning',file=sys.stderr)"):
            self.executable(body);out, err = io.StringIO(), io.StringIO()
            with self.subTest(body=body), patch.object(NFT.sys, 'argv', ['nft.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(NFT.main(), 75)
            self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())

    def test_cli_success_and_argument_refusal_use_only_fixed_native_read(self):
        self.executable(f"print({json.dumps(message())!r})");out = io.StringIO()
        with patch.object(NFT.sys, 'argv', ['nft.py']), contextlib.redirect_stdout(out):self.assertEqual(NFT.main(), 0)
        self.assertIs(json.loads(out.getvalue())['empty'], True)
        out = io.StringIO()
        with patch.object(NFT.sys, 'argv', ['nft.py', 'flush']), contextlib.redirect_stdout(out):self.assertEqual(NFT.main(), 64)
        self.assertEqual(out.getvalue(), '')


if __name__ == '__main__':unittest.main()
