import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_auto_intent as automatic_fixture
import test_first_create as plan_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_refresh', ROOT / 'Firewall/first_refresh.py')
REFRESH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFRESH)
REGISTER, MATCH, STATE, PLAN = REFRESH.REGISTER, REFRESH.MATCH, REFRESH.STATE, REFRESH.PLAN
BACKEND = REGISTER._STORAGE
ASSEMBLY, KERNEL, POLICY = automatic_fixture.ASSEMBLY, automatic_fixture.KERNEL, automatic_fixture.POLICY


class ReprepareTests(unittest.TestCase):
    def setUp(self):
        self.helper = plan_fixture.PlanTests();self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        self.original = self.helper.prepare();self.plan = json.loads(self.original);self.namespace = self.plan['namespace']
        directory = tempfile.TemporaryDirectory(prefix='debian13s4-first-refresh-', dir='/dev/shm');self.addCleanup(directory.cleanup)
        self.root = Path(directory.name);self.root.chmod(0o700)
        self.store = self.root / 'registration';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf = self.store / REGISTER.LEAF
        for setting in (patch.object(BACKEND, 'TRUST_ROOT', self.root), patch.object(BACKEND, 'TRUSTED_UID', os.geteuid()),
                        patch.object(REFRESH, 'ASSEMBLY', ASSEMBLY)):
            setting.start();self.addCleanup(setting.stop)
        REGISTER.create(self.store, self.original)

    def prepare(self, **settings):
        return REFRESH.prepare(self.store, **(self.helper.helper.readers() | settings))

    def clock(self):
        value = [KERNEL.now()]
        for kernel in (KERNEL, BACKEND.KERNEL):
            setting = patch.object(kernel, 'now', side_effect=lambda: value[0]);setting.start();self.addCleanup(setting.stop)
        return value

    def test_real_registration_and_complete_new_empty_admission_reproduce_the_same_intention(self):
        before = self.leaf.read_bytes();inode = self.leaf.stat().st_ino
        with patch.object(REGISTER, 'load', wraps=REGISTER.load) as load:raw = self.prepare()
        value = json.loads(raw)
        self.assertIs(type(raw), bytes);self.assertEqual(raw, STATE.encoded(value) + b'\n');self.assertLessEqual(len(raw), REFRESH.MAX_OUTPUT)
        self.assertEqual(value['schema'], 'debian13s4-registered-first-create-reprepare-1')
        self.assertEqual(value['state'], 'reprepared-source-intention')
        self.assertEqual(value['profile'], 'registered-first-create-empty-source-repreparation-1')
        self.assertEqual(value['namespace'], self.namespace);self.assertEqual(value['admission_profile'], PLAN.AUTO.ADMISSION)
        self.assertEqual(value['proposal'].encode('utf-8'), self.original)
        self.assertEqual(value['proposal_sha256'], hashlib.sha256(self.original).hexdigest())
        for name in ('correlation_id', 'transaction_sha256'):self.assertEqual(value[name], self.plan[name])
        self.assertEqual(load.call_count, 2);self.assertEqual(self.leaf.read_bytes(), before);self.assertEqual(self.leaf.stat().st_ino, inode)
        self.assertEqual({p.name for p in self.store.iterdir()}, {REGISTER.LEAF})

    def test_registered_correlation_is_reused_without_entropy_or_new_registration_creation(self):
        with patch.object(PLAN.secrets, 'token_hex', side_effect=AssertionError('new ID')), \
                patch.object(REGISTER, 'create', side_effect=AssertionError('new registration')):
            value = json.loads(self.prepare())
        self.assertEqual(value['correlation_id'], self.plan['correlation_id'])

    def test_unknown_topology_compiler_scope_identifier_and_noncallable_readers_refuse_before_load(self):
        with patch.object(REGISTER, 'load', side_effect=AssertionError('disk')):
            for settings in ({'topology': {}}, {'compiler': POLICY.compile_policy}, {'scope': lambda: 1},
                             {'identifier': 'a' * 64}, {'nft': None}, {'path_reader': lambda: self.store}):
                with self.subTest(settings=settings), self.assertRaises(ValueError):self.prepare(**settings)

    def test_invalid_deadlines_and_true_positive_context_admission_precede_disk_or_sources(self):
        with patch.object(REGISTER, 'load', side_effect=AssertionError('disk')):
            for end in (True, False, float('nan'), float('inf'), 'later', KERNEL.now() - 1, 10 ** 10000):
                with self.subTest(kind=type(end).__name__), self.assertRaises(ValueError):self.prepare(deadline=end)
            for namespace in (True, False, 0, -1, 1 << 64, '1', None):
                with self.subTest(namespace=namespace), patch.object(KERNEL, 'namespace', return_value=namespace), self.assertRaises(ValueError):self.prepare()

    def test_missing_corrupt_and_forged_registration_refuse_before_current_native_admission(self):
        for data in (None, b'broken', STATE.encoded({'state': 'applied'}) + b'\n'):
            if data is None:self.leaf.unlink()
            else:self.leaf.write_bytes(data);self.leaf.chmod(0o600)
            with self.subTest(data=data), self.assertRaises((OSError, ValueError)):
                self.prepare(nft=lambda **settings: self.fail('invalid history source read'))

    def test_checked_history_from_another_context_never_grants_current_admission(self):
        plan = self.plan | {'namespace': self.namespace + 1};other = STATE.encoded(plan) + b'\n'
        self.leaf.write_bytes(REGISTER.envelope(other));self.assertEqual(REGISTER.load(self.store), other)
        with self.assertRaises(ValueError):self.prepare(nft=lambda **settings: self.fail('foreign history source read'))

    def test_two_real_loads_and_all_sources_share_one_minimum_inherited_window(self):
        clock = self.clock();real = REGISTER.load
        for parent, expected in ((clock[0] + 5, clock[0] + 5), (clock[0] + 100, clock[0] + 60)):
            loads, calls = [], [];readers = self.helper.helper.readers()
            def load(path, deadline):loads.append(deadline);return real(path, deadline=deadline)
            for name, callback in tuple(readers.items()):
                readers[name] = lambda deadline, name=name, callback=callback: calls.append((name, deadline)) or callback(deadline)
            with patch.object(REGISTER, 'load', side_effect=load):REFRESH.prepare(self.store, deadline=parent, **readers)
            self.assertEqual(loads, [expected, expected]);self.assertEqual(len(calls), 21)
            self.assertEqual({deadline for name, deadline in calls}, {expected})

    def test_matching_or_foreign_existing_nft_objects_are_not_adopted(self):
        for row in ({}, automatic_fixture.nft_receipt(self.namespace) | {'empty': False},
                    {'schema': 'debian13s4-first-create-source-match-1', 'namespace': self.namespace}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                self.prepare(nft=lambda deadline: row, dhcp=lambda **settings: self.fail('nonempty source service read'))

    def test_missing_legacy_classifier_program_and_link_reporting_never_means_empty(self):
        for name in ('legacy', 'classifiers', 'bpf', 'bpf_links'):
            def missing(deadline):raise OSError('reporting unavailable')
            with self.subTest(name=name), self.assertRaises(OSError):self.prepare(**{name: missing})

    def test_instantiated_dhcp6_is_still_unsupported_before_dns_or_compilation(self):
        self.helper.helper.records['dhcp4']['interfaces'][0].update(dhcp6=True, state6='stopped')
        with self.assertRaisesRegex(ValueError, 'DHCPv6'):self.prepare(dns=lambda **settings: self.fail('DHCPv6 dns admission'))

    def test_consistent_current_input_drift_is_not_relabelled_the_registered_intention(self):
        value = self.helper.helper.records
        value['dns']['dns'][0]['address'] = '1.1.1.1'
        with self.assertRaisesRegex(ValueError, 'differs from registration'):self.prepare()

    def test_current_source_changes_between_rounds_are_not_an_unchanged_intention(self):
        calls = []
        def dns(deadline):
            calls.append(1);row = copy.deepcopy(self.helper.helper.records['dns'])
            if len(calls) == 2:row['source']['sha256'] = 'a' * 64
            return row
        with self.assertRaisesRegex(ValueError, 'between rounds'):self.prepare(dns=dns)
        self.assertEqual(len(calls), 2)

    def test_real_second_load_and_receipt_encoding_precede_all_final_source_admissions(self):
        events = [];real_load, real_encode = REGISTER.load, STATE.encoded
        def load(*args, **kwargs):events.append('load');return real_load(*args, **kwargs)
        def encode(value):
            data = real_encode(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-registered-first-create-reprepare-1':events.append('receipt')
            return data
        readers = self.helper.helper.readers()
        for name, callback in tuple(readers.items()):
            readers[name] = lambda deadline, name=name, callback=callback: events.append(name) or callback(deadline)
        with patch.object(REGISTER, 'load', side_effect=load), patch.object(STATE, 'encoded', side_effect=encode):REFRESH.prepare(self.store, **readers)
        self.assertEqual(events, ['load'] + ['nft', 'legacy', 'classifiers', 'bpf', 'bpf_links', 'dhcp', 'dns', 'ntp'] * 2 +
                         ['receipt', 'load', 'nft', 'legacy', 'classifiers', 'bpf', 'bpf_links'])

    def test_changed_valid_registered_bytes_during_compiler_turn_withhold_prepared_receipt(self):
        encode = STATE.encoded
        def encoded(value):
            raw = encode(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-registered-first-create-reprepare-1':
                other = self.plan | {'namespace': self.namespace + 1}
                self.leaf.write_bytes(REGISTER.envelope(encode(other) + b'\n'))
            return raw
        with patch.object(STATE, 'encoded', side_effect=encoded), self.assertRaisesRegex(ValueError, 'bytes changed'):self.prepare()

    def test_damage_or_unsafe_mode_during_receipt_encoding_fail_the_second_real_load(self):
        real = STATE.encoded
        for damage in ('bytes', 'mode'):
            self.leaf.write_bytes(REGISTER.envelope(self.original));self.leaf.chmod(0o600)
            def encoded(value):
                raw = real(value)
                if type(value) is dict and value.get('schema') == 'debian13s4-registered-first-create-reprepare-1':
                    if damage == 'bytes':self.leaf.write_bytes(b'damaged')
                    else:self.leaf.chmod(0o660)
                return raw
            with self.subTest(damage=damage), patch.object(STATE, 'encoded', side_effect=encoded), self.assertRaises(ValueError):self.prepare()

    def test_second_load_lease_expiry_is_rechecked_before_final_nft_admission(self):
        clock = self.clock();until = int((clock[0] + 1) * 1000000)
        for name in ('preferred_until', 'valid_until'):self.helper.helper.records['dhcp4']['attributions'][0][name] = until
        real = REGISTER.load;loads = [];nft_calls = []
        def load(*args, **kwargs):
            value = real(*args, **kwargs);loads.append(1)
            if len(loads) == 2:clock[0] += 2
            return value
        def nft(deadline):nft_calls.append(1);return automatic_fixture.nft_receipt(self.namespace)
        with patch.object(REGISTER, 'load', side_effect=load), self.assertRaisesRegex(ValueError, 'attribution expired'):self.prepare(nft=nft)
        self.assertEqual(len(loads), 2);self.assertEqual(len(nft_calls), 2)

    def test_initial_and_second_load_deadline_expiry_withhold_sources_or_receipt(self):
        clock = self.clock();real = REGISTER.load
        for turn in (1, 2):
            loads, calls = [], []
            def load(*args, **kwargs):
                value = real(*args, **kwargs);loads.append(1)
                if len(loads) == turn:clock[0] += 61
                return value
            def nft(deadline):calls.append(1);return automatic_fixture.nft_receipt(self.namespace)
            with self.subTest(turn=turn), patch.object(REGISTER, 'load', side_effect=load), self.assertRaises(ValueError):self.prepare(nft=nft)
            self.assertEqual(len(loads), turn);self.assertEqual(len(calls), 0 if turn == 1 else 2)

    def test_receipt_bound_and_encoding_expiry_refuse_before_second_load_or_final_sources(self):
        with patch.object(REFRESH, 'MAX_OUTPUT', 1), patch.object(REGISTER, 'load', wraps=REGISTER.load) as load, self.assertRaises(ValueError):self.prepare()
        self.assertEqual(load.call_count, 1)
        clock = self.clock();real = STATE.encoded
        def encoded(value):
            data = real(value)
            if type(value) is dict and value.get('schema') == 'debian13s4-registered-first-create-reprepare-1':clock[0] += 61
            return data
        with patch.object(STATE, 'encoded', side_effect=encoded), patch.object(REGISTER, 'load', wraps=REGISTER.load) as load, self.assertRaises(ValueError):self.prepare()
        self.assertEqual(load.call_count, 1)

    def test_every_final_empty_source_receipt_remains_mandatory_after_second_load(self):
        for name in ('nft', 'legacy', 'classifiers', 'bpf', 'bpf_links'):
            reader = self.helper.helper.readers()[name];calls = []
            def changed(deadline):
                calls.append(1);row = reader(deadline)
                if len(calls) == 3:
                    if name == 'nft':row['empty'] = False
                    elif name == 'legacy':row['source']['identity'][1] += 100
                    elif name == 'classifiers':row['links'][1]['mtu'] = 1400
                    else:row['lookup'].update(result=0, errno=0, next_id=1)
                return row
            with self.subTest(name=name), patch.object(REGISTER, 'load', wraps=REGISTER.load) as load, self.assertRaises(ValueError):self.prepare(**{name: changed})
            self.assertEqual(len(calls), 3);self.assertEqual(load.call_count, 2)

    def test_preparer_return_schema_profile_context_and_exact_compiler_object_cannot_be_forged(self):
        observe = ASSEMBLY.observe
        for key in ('schema', 'profile', 'namespace', 'policy'):
            def changed(**settings):
                result = observe(**settings)
                result[key] = result['policy'].encode().decode() if key == 'policy' else True if key == 'namespace' else 'foreign'
                return result
            with self.subTest(key=key), patch.object(ASSEMBLY, 'observe', side_effect=changed), self.assertRaises(ValueError):self.prepare()

    def test_repeated_compiler_invocation_or_missing_compiler_turn_withholds_output(self):
        observe = ASSEMBLY.observe
        def twice(**settings):
            compiler = settings['compiler']
            def repeated(raw):compiler(raw);return compiler(raw)
            return observe(**(settings | {'compiler': repeated}))
        with patch.object(ASSEMBLY, 'observe', side_effect=twice), self.assertRaises(ValueError):self.prepare()
        with patch.object(ASSEMBLY, 'observe', return_value={'schema': 'debian13s4-assembled-policy-1', 'profile': PLAN.AUTO.ADMISSION}), self.assertRaises(ValueError):self.prepare()

    def test_no_hash_encoding_compilation_or_store_load_follows_final_preparer_fences(self):
        final = [];observe = ASSEMBLY.observe;real_encode, real_hash, real_load = STATE.encoded, hashlib.sha256, REGISTER.load
        def observed(**settings):value = observe(**settings);final.append(True);return value
        def encoded(value):self.assertFalse(final);return real_encode(value)
        def digest(value):self.assertFalse(final);return real_hash(value)
        def load(*args, **kwargs):self.assertFalse(final);return real_load(*args, **kwargs)
        with patch.object(ASSEMBLY, 'observe', side_effect=observed), patch.object(STATE, 'encoded', side_effect=encoded), \
                patch.object(hashlib, 'sha256', side_effect=digest), patch.object(REGISTER, 'load', side_effect=load):raw = self.prepare()
        self.assertIs(type(raw), bytes);self.assertEqual(final, [True])

    def test_final_wrapper_context_must_be_typed_equal_and_within_the_shared_window(self):
        for last in (True, self.namespace + 1, '1'):
            calls = []
            def scope():calls.append(1);return last if len(calls) == 3 else self.namespace
            with self.subTest(last=last), patch.object(KERNEL, 'namespace', side_effect=scope), self.assertRaises(ValueError):self.prepare()
            self.assertEqual(len(calls), 3)


class NativeTests(automatic_fixture.PrivateNative):
    def setUp(self):
        super().setUp()
        alias = patch.object(REFRESH, 'ASSEMBLY', ASSEMBLY);alias.start();self.settings.append(alias)
        alias = patch.object(plan_fixture.PLAN, 'ASSEMBLY', ASSEMBLY);alias.start();self.settings.append(alias)
        for setting in (patch.object(BACKEND, 'TRUST_ROOT', self.root), patch.object(BACKEND, 'TRUSTED_UID', os.geteuid())):
            setting.start();self.settings.append(setting)
        self.store = self.root / 'registration';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf = self.store / REGISTER.LEAF
        self.fixtures(tc_kind='fq_codel');self.original = plan_fixture.PLAN.prepare();self.plan = json.loads(self.original)
        REGISTER.create(self.store, self.original)
        self.fixtures(tc_kind='fq_codel');self.bpf_calls.clear();self.link_calls.clear()

    def prepare(self):
        return REFRESH.prepare(self.store)

    def test_complete_private_native_empty_admissions_and_registration_reproduce_exact_plan(self):
        before = self.leaf.read_bytes()
        with patch.object(REGISTER, 'load', wraps=REGISTER.load) as load:raw = self.prepare()
        value = json.loads(raw);self.assertEqual(value['proposal'].encode(), self.original);self.assertEqual(load.call_count, 2)
        self.assertEqual(value['namespace'], KERNEL.namespace());self.assertEqual(self.leaf.read_bytes(), before)
        self.assertEqual(len(self.bpf_calls), 6);self.assertEqual(len(self.link_calls), 6)
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind == 'ip' for kind, _, _ in rows), 258)
        self.assertEqual(sum(kind == 'bus' for kind, _, _ in rows), 100)
        self.assertEqual(sum(kind == 'tc' for kind, _, _ in rows), 12)
        self.assertEqual(sum(kind == 'nft' for kind, _, _ in rows), 6)
        for kind, argv, environment in rows:
            self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})
            if kind == 'nft':self.assertEqual(argv, list(ASSEMBLY.NFT.COMMAND))

    def test_actual_existing_reserved_table_refuses_before_bus_or_new_registration_creation(self):
        value = {'nftables': [{'metainfo': {'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}},
                               {'table': {'family': 'inet', 'name': 'debian13s4', 'handle': 1,
                                          'comment': PLAN.COMMENT_PREFIX + self.plan['correlation_id']}}]}
        self.executable(self.nft, f'print({json.dumps(value)!r})')
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(any(json.loads(line)[0] == 'bus' for line in self.ledger.read_text().splitlines()))

    def test_actual_current_dns_change_refuses_instead_of_replacing_registered_transaction(self):
        self.fixtures(tc_kind='fq_codel', dns='9.9.9.9');self.bpf_calls.clear();self.link_calls.clear();before = self.leaf.read_bytes()
        with self.assertRaisesRegex(ValueError, 'differs from registration'):self.prepare()
        self.assertEqual(self.leaf.read_bytes(), before)

    def test_actual_program_or_link_presence_after_receipt_encoding_blocks_final_admission(self):
        real = STATE.encoded
        for kind in ('program', 'link'):
            self.fixtures(tc_kind='fq_codel');self.bpf_calls.clear();self.link_calls.clear()
            self.bpf_present = self.link_present = False
            def encoded(value):
                raw = real(value)
                if type(value) is dict and value.get('schema') == 'debian13s4-registered-first-create-reprepare-1':
                    if kind == 'program':self.bpf_present = True
                    else:self.link_present = True
                return raw
            with self.subTest(kind=kind), patch.object(STATE, 'encoded', side_effect=encoded), self.assertRaises(ValueError):self.prepare()
            self.assertEqual(len(self.bpf_calls), 5 if kind == 'program' else 6)
            self.assertEqual(len(self.link_calls), 4 if kind == 'program' else 5)

    def test_actual_permission_error_is_not_empty_program_or_link_admission(self):
        self.link_error = errno.EPERM
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(len(self.link_calls), 1)
        self.assertFalse(any(json.loads(line)[0] == 'bus' for line in self.ledger.read_text().splitlines()))


if __name__ == '__main__':unittest.main()
