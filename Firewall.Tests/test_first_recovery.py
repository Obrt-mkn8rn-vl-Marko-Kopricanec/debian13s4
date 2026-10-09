import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_first_create as plan_fixture
import test_first_match as match_fixture
import test_nft_manifest as native_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_recovery', ROOT / 'Firewall/first_recovery.py')
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)
HISTORY, AUDIT, REGISTER, MATCH = RECOVERY.HISTORY, RECOVERY.AUDIT, RECOVERY.REGISTER, RECOVERY.MATCH
STATE, KERNEL, NFT = RECOVERY.STATE, RECOVERY.KERNEL, RECOVERY.STATE.NFT


def encoded(value):return STATE.encoded(value) + b'\n'


class PrivateRecovery:
    def __init__(self, test):
        helper = plan_fixture.PlanTests();helper.setUp()
        try:self.payload = helper.prepare()
        finally:helper.doCleanups()
        self.plan = json.loads(self.payload);self.namespace = self.plan['namespace']
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-recovery-', dir='/dev/shm')
        test.addCleanup(directory.cleanup);self.root = Path(directory.name);self.root.chmod(0o700)
        self.registration, self.uncertainty = self.root / 'registration', self.root / 'uncertainty'
        for path in (self.registration, self.uncertainty):path.mkdir(mode=0o700);path.chmod(0o700)
        for backend in (REGISTER._STORAGE, HISTORY._STORAGE):
            for setting in (patch.object(backend, 'TRUST_ROOT', self.root), patch.object(backend, 'TRUSTED_UID', os.geteuid())):
                setting.start();test.addCleanup(setting.stop)
        self.registered = self.registration / REGISTER.LEAF;self.saved = self.uncertainty / HISTORY.LEAF
        REGISTER.create(self.registration, self.payload)
        self.original = HISTORY.record(self.uncertainty, self.payload, self.model())
        # Intention-derived SOURCE MODEL, not an independent formatter,
        # owner, fresh-coexistence or native result oracle.
        self.native = match_fixture.marked(self.plan)

    def model(self, **changes):
        evidence = {'command': (str(HISTORY.TRANSPORT.BINARY), '--file', '-'), 'namespace': self.namespace,
            'deadline': HISTORY.KERNEL.now() + 3, 'proposal_sha256': hashlib.sha256(self.payload).hexdigest(),
            'correlation_id': self.plan['correlation_id'], 'transaction_sha256': self.plan['transaction_sha256'],
            'input': self.plan['transaction'].encode('utf-8'), 'input_written': 0,
            'stdout': b'', 'stderr': b'', 'received': {'stdout': 0, 'stderr': 0},
            'returncode': None, 'cleanup_errors': ()}
        evidence.update(changes)
        result = HISTORY.TRANSPORT.Uncertain('modeled uncertain delivery', evidence)
        result.__cause__ = HISTORY.Pending('modeled capture failure');return result

    def query(self, deadline):return copy.deepcopy(self.native)

    def inspect(self, **settings):
        return RECOVERY.inspect(self.registration, self.uncertainty,
            **({'query': self.query, 'scope': lambda: self.namespace} | settings))

    def change_history(self):
        value = HISTORY.checked(self.original);value['evidence']['returncode'] = 0
        raw = encoded(value);self.saved.write_bytes(HISTORY.envelope(raw));return raw

    def change_registration(self):
        payload = encoded(self.plan | {'namespace': self.namespace + 1})
        self.registered.write_bytes(REGISTER.envelope(payload));return payload


class RecoveryTests(unittest.TestCase):
    def setUp(self):self.fixture = PrivateRecovery(self)

    def clock(self):
        value = [KERNEL.now()]
        kernels = {id(k): k for k in (KERNEL, MATCH.KERNEL, HISTORY.KERNEL, HISTORY._STORAGE.KERNEL)}
        for kernel in kernels.values():
            setting = patch.object(kernel, 'now', side_effect=lambda: value[0]);setting.start();self.addCleanup(setting.stop)
        return value

    def test_complete_uncertainty_and_registered_audit_bytes_remain_bound_and_read_only(self):
        before = [(p.read_bytes(), p.stat().st_ino) for p in (self.fixture.saved, self.fixture.registered)]
        reads, contexts = [], []
        with patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, patch.object(REGISTER, 'load', wraps=REGISTER.load) as registration:
            raw = self.fixture.inspect(query=lambda end: reads.append(end) or self.fixture.query(end),
                scope=lambda: contexts.append(1) or self.fixture.namespace)
        value = json.loads(raw);audit = json.loads(value['audit'])
        self.assertIs(type(raw), bytes);self.assertEqual(raw, encoded(value));self.assertLessEqual(len(raw), RECOVERY.MAX_OUTPUT)
        self.assertEqual(value['schema'], 'debian13s4-first-create-uncertain-source-inspection-1')
        self.assertEqual(value['state'], 'uncertain-source-correspondence-only')
        self.assertEqual(value['profile'], 'registered-uncertain-attempt-marked-source-1')
        self.assertEqual(value['uncertainty'].encode('utf-8'), self.fixture.original)
        self.assertEqual(value['uncertainty_sha256'], hashlib.sha256(self.fixture.original).hexdigest())
        self.assertEqual(value['proposal_sha256'], hashlib.sha256(self.fixture.payload).hexdigest())
        for key in ('namespace', 'correlation_id', 'transaction_sha256'):self.assertEqual(value[key], self.fixture.plan[key])
        self.assertEqual(audit['comparison']['intention'], self.fixture.plan['intention'])
        self.assertEqual(value['audit'].encode('utf-8'), encoded(audit))
        self.assertEqual(history.call_count, 2);self.assertEqual(registration.call_count, 4)
        self.assertEqual(len(reads), 2);self.assertEqual(reads[0], reads[1]);self.assertEqual(len(contexts), 6)
        self.assertEqual([(p.read_bytes(), p.stat().st_ino) for p in (self.fixture.saved, self.fixture.registered)], before)

    def test_zero_exit_full_input_and_empty_output_never_become_completion_or_retry(self):
        error = self.fixture.model(returncode=0, input_written=len(self.fixture.plan['transaction'].encode()))
        original = HISTORY.capture(self.fixture.payload, error);self.fixture.saved.write_bytes(HISTORY.envelope(original))
        result = json.loads(self.fixture.inspect());history = json.loads(result['uncertainty'])
        self.assertEqual(result['state'], 'uncertain-source-correspondence-only')
        self.assertEqual(history['state'], 'historical-uncertain-no-retry');self.assertEqual(history['evidence']['returncode'], 0)
        self.assertEqual(history['evidence']['stdout_hex'], '');self.assertEqual(history['evidence']['stderr_hex'], '')

    def test_missing_or_corrupt_either_history_refuses_before_source(self):
        for path in (self.fixture.saved, self.fixture.registered):
            before = path.read_bytes()
            for content in (None, b'broken', encoded({'state': 'completed'})):
                if content is None:path.unlink()
                else:path.write_bytes(content);path.chmod(0o600)
                with self.subTest(path=path.name, content=content), self.assertRaises((OSError, ValueError)):
                    self.fixture.inspect(query=lambda end: self.fail('invalid store SOURCE'))
            path.write_bytes(before);path.chmod(0o600)

    def test_nonprivate_symbolic_and_external_linked_history_refuses_before_source(self):
        for path in (self.fixture.saved, self.fixture.registered):
            with self.subTest(path=path.name, damage='mode'):
                path.chmod(0o660)
                with self.assertRaises(ValueError):self.fixture.inspect(query=lambda end: self.fail('unsafe SOURCE'))
                path.chmod(0o600)
            extra = self.fixture.root / 'external';os.link(path, extra)
            with self.subTest(path=path.name, damage='link'), self.assertRaises(ValueError):
                self.fixture.inspect(query=lambda end: self.fail('external link SOURCE'))
            extra.unlink();before = path.read_bytes();path.unlink();extra.write_bytes(before);extra.chmod(0o600);path.symlink_to(extra)
            with self.subTest(path=path.name, damage='symbolic'), self.assertRaises((OSError, ValueError)):
                self.fixture.inspect(query=lambda end: self.fail('symbolic SOURCE'))
            path.unlink();path.write_bytes(before);path.chmod(0o600);extra.unlink()

    def test_valid_but_different_registered_plan_refuses_before_source(self):
        changed = self.fixture.change_registration();self.assertEqual(REGISTER.load(self.fixture.registration), changed)
        with self.assertRaisesRegex(ValueError, 'disagree'):
            self.fixture.inspect(query=lambda end: self.fail('different registered input SOURCE'))

    def test_matching_foreign_historical_context_refuses_before_source(self):
        changed = self.fixture.change_registration();plan = json.loads(changed)
        error = self.fixture.model(namespace=plan['namespace'], proposal_sha256=hashlib.sha256(changed).hexdigest())
        self.fixture.saved.write_bytes(HISTORY.envelope(HISTORY.capture(changed, error)))
        with self.assertRaisesRegex(ValueError, 'disagree'):
            self.fixture.inspect(query=lambda end: self.fail('foreign context SOURCE'))

    def test_rehashed_outer_uncertainty_cannot_hide_unsafe_input_or_wrong_inner_profile(self):
        for field, replacement in (('state', 'completed'), ('schema', 'debian13s4-first-create-registration-1')):
            value = HISTORY.checked(self.fixture.original);value[field] = replacement;raw = encoded(value)
            outer = json.loads(HISTORY.envelope(self.fixture.original));outer['payload'] = raw.decode();outer['payload_sha256'] = hashlib.sha256(raw).hexdigest()
            self.fixture.saved.write_bytes(encoded(outer))
            with self.subTest(field=field), self.assertRaises(ValueError):self.fixture.inspect(query=lambda end: self.fail('forged SOURCE'))
        value = HISTORY.checked(self.fixture.original);value['evidence']['input_hex'] = b'flush ruleset\n'.hex();raw = encoded(value)
        outer['payload'] = raw.decode();outer['payload_sha256'] = hashlib.sha256(raw).hexdigest();self.fixture.saved.write_bytes(encoded(outer))
        with self.assertRaises(ValueError):self.fixture.inspect(query=lambda end: self.fail('unsafe input SOURCE'))

    def test_initial_context_and_deadline_types_refuse_before_disk(self):
        with patch.object(HISTORY, 'load', side_effect=AssertionError('disk')):
            for value in (True, False, 0, -1, 1 << 64, '1', None):
                with self.subTest(scope=value), self.assertRaises(ValueError):self.fixture.inspect(scope=lambda: value)
            for end in (True, False, KERNEL.now() - 1, float('nan'), float('inf'), '10'):
                with self.subTest(deadline=end), self.assertRaises(ValueError):self.fixture.inspect(deadline=end)
            for key in ('query', 'scope'):
                with self.subTest(reader=key), self.assertRaises(ValueError):self.fixture.inspect(**{key: None})

    def test_all_real_loads_and_source_queries_share_capped_inherited_window(self):
        clock = self.clock();hload, rload = HISTORY.load, REGISTER.load
        for seconds in (2, 100):
            deadlines = []
            def history(path, deadline):deadlines.append(deadline);return hload(path, deadline=deadline)
            def registration(path, deadline):deadlines.append(deadline);return rload(path, deadline=deadline)
            with patch.object(HISTORY, 'load', side_effect=history), patch.object(REGISTER, 'load', side_effect=registration):
                self.fixture.inspect(deadline=clock[0] + seconds, query=lambda end: deadlines.append(end) or self.fixture.query(end))
            self.assertEqual(deadlines, [clock[0] + min(seconds, 10)] * 8)

    def test_changed_valid_uncertainty_after_audit_withholds_receipt(self):
        original = AUDIT.audit
        def audit(*args, **kwargs):result = original(*args, **kwargs);self.fixture.change_history();return result
        with patch.object(AUDIT, 'audit', side_effect=audit), self.assertRaisesRegex(ValueError, 'uncertainty bytes changed'):
            self.fixture.inspect()

    def test_changed_valid_registration_after_audit_withholds_receipt(self):
        original = AUDIT.audit
        def audit(*args, **kwargs):result = original(*args, **kwargs);self.fixture.change_registration();return result
        with patch.object(AUDIT, 'audit', side_effect=audit), self.assertRaisesRegex(ValueError, 'registration bytes changed'):
            self.fixture.inspect()

    def test_corruption_or_unsafe_mode_after_source_hits_final_real_uncertainty_load(self):
        original = AUDIT.audit
        for damage in ('bytes', 'mode'):
            self.fixture.saved.write_bytes(HISTORY.envelope(self.fixture.original));self.fixture.saved.chmod(0o600)
            def audit(*args, **kwargs):
                result = original(*args, **kwargs)
                if damage == 'bytes':self.fixture.saved.write_bytes(b'damaged')
                else:self.fixture.saved.chmod(0o660)
                return result
            with self.subTest(damage=damage), patch.object(AUDIT, 'audit', side_effect=audit), self.assertRaises(ValueError):self.fixture.inspect()

    def test_registration_damage_during_second_source_delivery_is_not_hidden(self):
        calls = []
        def query(end):
            calls.append(1)
            if len(calls) == 2:self.fixture.registered.write_bytes(b'damaged')
            return self.fixture.query(end)
        with self.assertRaises(ValueError):self.fixture.inspect(query=query)
        self.assertEqual(len(calls), 2)

    def test_receipt_encoding_precedes_final_uncertainty_and_registration_loads(self):
        events = [];hload, rload, encode = HISTORY.load, REGISTER.load, STATE.encoded
        def history(path, deadline):events.append('history');return hload(path, deadline=deadline)
        def registration(path, deadline):events.append('registration');return rload(path, deadline=deadline)
        def encoding(value):
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-uncertain-source-inspection-1':events.append('receipt')
            return encode(value)
        with patch.object(HISTORY, 'load', side_effect=history), patch.object(REGISTER, 'load', side_effect=registration), patch.object(STATE, 'encoded', side_effect=encoding):self.fixture.inspect()
        self.assertEqual(events, ['history', 'registration', 'registration', 'registration', 'receipt', 'history', 'registration'])

    def test_encoding_expiry_prevents_final_history_load(self):
        clock = self.clock();encode = STATE.encoded
        def encoding(value):
            result = encode(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-first-create-uncertain-source-inspection-1':clock[0] += 11
            return result
        with patch.object(STATE, 'encoded', side_effect=encoding), patch.object(HISTORY, 'load', wraps=HISTORY.load) as load, self.assertRaises(ValueError):self.fixture.inspect()
        self.assertEqual(load.call_count, 1)

    def test_expiry_after_final_uncertainty_load_prevents_final_registration_load(self):
        clock = self.clock();original = HISTORY.load;calls = []
        def load(path, deadline):
            result = original(path, deadline=deadline);calls.append(1)
            if len(calls) == 2:clock[0] = deadline
            return result
        with patch.object(HISTORY, 'load', side_effect=load), patch.object(REGISTER, 'load', wraps=REGISTER.load) as registration, self.assertRaises(ValueError):self.fixture.inspect()
        self.assertEqual(registration.call_count, 3)

    def test_expiry_after_final_registration_load_withholds_receipt(self):
        clock = self.clock();original = REGISTER.load;calls = []
        def load(path, deadline):
            result = original(path, deadline=deadline);calls.append(1)
            if len(calls) == 4:clock[0] = deadline
            return result
        with patch.object(REGISTER, 'load', side_effect=load), self.assertRaises(ValueError):self.fixture.inspect()
        self.assertEqual(len(calls), 4)

    def test_output_bound_refuses_before_final_disk_reads(self):
        with patch.object(RECOVERY, 'MAX_OUTPUT', 1), patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, patch.object(REGISTER, 'load', wraps=REGISTER.load) as registration, self.assertRaises(ValueError):self.fixture.inspect()
        self.assertEqual(history.call_count, 1);self.assertEqual(registration.call_count, 3)

    def test_final_true_context_is_checked_after_both_final_real_loads(self):
        for final in (True, self.fixture.namespace + 1):
            calls = []
            def scope():calls.append(1);return final if len(calls) == 6 else self.fixture.namespace
            with self.subTest(final=final), patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, patch.object(REGISTER, 'load', wraps=REGISTER.load) as registration, self.assertRaises(ValueError):self.fixture.inspect(scope=scope)
            self.assertEqual(history.call_count, 2);self.assertEqual(registration.call_count, 4)

    def test_no_hash_encoding_compile_or_store_load_follows_final_context(self):
        contexts = [];guards = []
        def scope():
            contexts.append(1)
            if len(contexts) == 6:
                for target, name in ((RECOVERY.hashlib, 'sha256'), (STATE, 'encoded'), (MATCH.PLAN.MANIFEST, 'expected'), (HISTORY, 'load'), (REGISTER, 'load')):
                    setting = patch.object(target, name, side_effect=AssertionError('work after final context'));setting.start();guards.append(setting)
            return self.fixture.namespace
        try:result = self.fixture.inspect(scope=scope)
        finally:
            for setting in reversed(guards):setting.stop()
        self.assertIs(type(result), bytes);self.assertEqual(len(contexts), 6)

    def test_second_whole_source_handle_comment_and_metainfo_drift_refuse(self):
        for change in ('handle', 'comment', 'meta'):
            calls = []
            def query(end):
                value = self.fixture.query(end);calls.append(1)
                if len(calls) == 2:
                    if change == 'meta':value['nftables'][0]['metainfo']['release_name'] = 'changed'
                    else:native_fixture.objects(value, 'table')[0][change] = 999 if change == 'handle' else 'foreign'
                return value
            with self.subTest(change=change), self.assertRaises(ValueError):self.fixture.inspect(query=query)
            self.assertEqual(len(calls), 2)

    def test_only_checked_anonymous_statistics_may_change_and_last_values_survive(self):
        calls = []
        def query(end):
            value = self.fixture.query(end);calls.append(1)
            for rule in native_fixture.objects(value, 'rule'):
                for expression in rule['expr']:
                    if 'counter' in expression:expression['counter'] = {'packets': len(calls) - 1, 'bytes': 0}
            return value
        result = json.loads(self.fixture.inspect(query=query));audit = json.loads(result['audit'])
        observed = audit['comparison']['observation']
        self.assertEqual(len(calls), 2);self.assertEqual(observed['policy'], self.fixture.plan['intention']['policy'])
        self.assertTrue(observed['statistics']);self.assertEqual({row['packets'] for row in observed['statistics']}, {1})

    def test_matching_marker_does_not_admit_accept_all_or_extra_foreign_objects(self):
        for change in ('accept', 'foreign', 'empty'):
            native = copy.deepcopy(self.fixture.native)
            if change == 'accept':native_fixture.objects(native, 'chain')[0]['policy'] = 'accept'
            elif change == 'foreign':native['nftables'].append({'table': {'family': 'ip', 'name': 'foreign', 'handle': 9999}})
            else:native = {'nftables': [native['nftables'][0]]}
            with self.subTest(change=change), self.assertRaises(ValueError):self.fixture.inspect(query=lambda end: copy.deepcopy(native))

    def test_audit_contract_identity_canonical_bytes_and_complete_intention_are_checked(self):
        original = AUDIT.audit
        for field, replacement in (('namespace', True), ('correlation_id', '0' * 64), ('transaction_sha256', '0' * 64),
                                   ('proposal_sha256', '0' * 64), ('profile', 'resolved'), ('schema', 'other'),
                                   ('state', 'applied'), ('historical_admission_profile', 'other')):
            def audit(*args, **kwargs):value = json.loads(original(*args, **kwargs));value[field] = replacement;return encoded(value)
            with self.subTest(field=field), patch.object(AUDIT, 'audit', side_effect=audit), self.assertRaises(ValueError):self.fixture.inspect()
        def intention(*args, **kwargs):
            value = json.loads(original(*args, **kwargs));value['comparison']['intention']['policy']['rules']['input'][0]['expr'] = [{'accept': None}];return encoded(value)
        with patch.object(AUDIT, 'audit', side_effect=intention), self.assertRaises(ValueError):self.fixture.inspect()
        with patch.object(AUDIT, 'audit', side_effect=lambda *args, **kwargs: b' ' + original(*args, **kwargs)), self.assertRaises(ValueError):self.fixture.inspect()

    def test_unknown_or_missing_audit_contract_fields_refuse(self):
        original = AUDIT.audit
        for change in ('extra', 'missing'):
            def audit(*args, **kwargs):
                value = json.loads(original(*args, **kwargs))
                if change == 'extra':value['extra'] = True
                else:del value['state']
                return encoded(value)
            with self.subTest(change=change), patch.object(AUDIT, 'audit', side_effect=audit), self.assertRaises(ValueError):self.fixture.inspect()

    def test_inspection_never_submits_records_creates_retries_or_deletes_history(self):
        targets = ((HISTORY.TRANSPORT, 'transmit'), (HISTORY, 'record'), (REGISTER, 'create'), (HISTORY._STORAGE.os, 'unlink'))
        settings = []
        try:
            for target, name in targets:
                setting = patch.object(target, name, side_effect=AssertionError('inspection mutation'));setting.start();settings.append(setting)
            result = self.fixture.inspect()
        finally:
            for setting in reversed(settings):setting.stop()
        self.assertIs(type(result), bytes)


class NativeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivateRecovery(self);self.binary = self.fixture.root / 'nft-source';self.calls = self.fixture.root / 'calls'
        for setting in (patch.object(NFT, 'BINARY', self.binary), patch.object(MATCH.KERNEL, 'TRUST_ROOT', self.fixture.root),
                        patch.object(MATCH.KERNEL, 'TRUSTED_UID', os.geteuid())):
            setting.start();self.addCleanup(setting.stop)

    def executable(self, body=None):
        prefix = '#!/usr/bin/python3 -B\nimport json,os,sys\n'
        prefix += f'with open({str(self.calls)!r},"a") as stream:stream.write(json.dumps([sys.argv[1:],dict(os.environ)])+"\\n")\n'
        body = f'print(json.dumps({self.fixture.native!r}))\n' if body is None else body
        self.binary.write_text(prefix + body);self.binary.chmod(0o700)

    def inspect(self):return RECOVERY.inspect(self.fixture.registration, self.fixture.uncertainty, scope=KERNEL.namespace)

    def test_complete_real_private_capture_parser_and_pair_loads_keep_uncertainty(self):
        self.executable()
        with patch.dict(os.environ, {'TASK_SECRET': 'not-a-native-input', 'NFT_CTX_FLAGS': 'ignored'}):raw = self.inspect()
        value = json.loads(raw);rows = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        for argv, environment in rows:
            self.assertEqual(argv, ['--json', '--numeric', '--handle', 'list', 'ruleset'])
            self.assertNotIn('TASK_SECRET', environment);self.assertNotIn('NFT_CTX_FLAGS', environment)
        self.assertEqual(value['uncertainty'].encode(), self.fixture.original)
        self.assertEqual(value['state'], 'uncertain-source-correspondence-only')
        self.assertEqual(json.loads(value['audit'])['comparison']['intention'], self.fixture.plan['intention'])

    def test_warning_nonzero_and_malformed_native_delivery_withhold_inspection(self):
        for suffix in ('sys.stderr.buffer.write(b"warning\\xff")\n', 'raise SystemExit(9)\n', 'sys.stdout.buffer.write(b"\\xff")\n'):
            self.executable(suffix)
            with self.subTest(suffix=suffix), self.assertRaises((OSError, ValueError)):self.inspect()

    def test_actual_second_read_child_damages_uncertainty_before_final_real_load(self):
        counter = self.fixture.root / 'count'
        self.executable(f'from pathlib import Path\np=Path({str(counter)!r})\nn=int(p.read_text())+1 if p.exists() else 1\np.write_text(str(n))\n' +
            f'if n==2:Path({str(self.fixture.saved)!r}).write_bytes(b"damaged")\nprint(json.dumps({self.fixture.native!r}))\n')
        with self.assertRaises(ValueError):self.inspect()
        self.assertEqual(counter.read_text(), '2');self.assertEqual(len(self.calls.read_text().splitlines()), 2)

    def test_actual_second_read_child_changes_handles_and_cannot_resolve_uncertainty(self):
        counter = self.fixture.root / 'count'
        self.executable(f'from pathlib import Path\np=Path({str(counter)!r})\nn=int(p.read_text())+1 if p.exists() else 1\np.write_text(str(n))\nvalue={self.fixture.native!r}\n' +
            'if n==2:\n for row in value["nftables"]:\n  if "table" in row:row["table"]["handle"]+=1\nprint(json.dumps(value))\n')
        with self.assertRaises(ValueError):self.inspect()
        self.assertEqual(counter.read_text(), '2');self.assertEqual(HISTORY.load(self.fixture.uncertainty), self.fixture.original)

    def test_actual_private_uncertain_submission_is_inspected_without_second_submission(self):
        binary = self.fixture.root / 'nft-submit';entries = self.fixture.root / 'submissions'
        binary.write_text('#!/usr/bin/python3 -B\nimport sys\n' +
            f'with open({str(entries)!r},"a") as stream:stream.write("entry\\n")\n' +
            'data=sys.stdin.buffer.read()\nsys.stdout.buffer.write(b"out\\r\\n\\0\\xff")\nsys.stderr.buffer.write(b"err\\r\\xe2\\x82")\n')
        binary.chmod(0o700)
        self.fixture.saved.unlink()
        with patch.object(HISTORY.TRANSPORT, 'BINARY', binary), patch.object(HISTORY.KERNEL, 'TRUST_ROOT', self.fixture.root), patch.object(HISTORY.KERNEL, 'TRUSTED_UID', os.geteuid()):
            with self.assertRaises(HISTORY.TRANSPORT.Uncertain) as caught:HISTORY.TRANSPORT.transmit(self.fixture.payload)
            original = HISTORY.record(self.fixture.uncertainty, self.fixture.payload, caught.exception)
            self.executable()
            with patch.object(HISTORY.TRANSPORT, 'transmit', side_effect=AssertionError('retry')):raw = self.inspect()
        value = json.loads(raw);history = json.loads(value['uncertainty'])
        self.assertEqual(value['uncertainty'].encode(), original);self.assertEqual(entries.read_text(), 'entry\n')
        self.assertEqual(len(self.calls.read_text().splitlines()), 2);self.assertEqual(history['evidence']['returncode'], 0)
        self.assertEqual(bytes.fromhex(history['evidence']['stdout_hex']), b'out\r\n\0\xff')
        self.assertEqual(bytes.fromhex(history['evidence']['stderr_hex']), b'err\r\xe2\x82')
        self.assertEqual(history['state'], 'historical-uncertain-no-retry')
