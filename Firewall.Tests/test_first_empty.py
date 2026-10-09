import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_first_refresh as registered_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_first_empty', ROOT / 'Firewall/first_empty.py')
EMPTY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EMPTY)
HISTORY, REGISTER, MATCH, STATE, PLAN = EMPTY.HISTORY, EMPTY.REGISTER, EMPTY.MATCH, EMPTY.STATE, EMPTY.PLAN
ASSEMBLY, KERNEL = registered_fixture.ASSEMBLY, registered_fixture.KERNEL
SCHEMA = 'debian13s4-registered-uncertainty-empty-source-1'


def encoded(value):return STATE.encoded(value) + b'\n'


def model(payload, **changes):
    plan = json.loads(payload)
    evidence = {'command': (str(HISTORY.TRANSPORT.BINARY), '--file', '-'), 'namespace': plan['namespace'],
        'deadline': HISTORY.KERNEL.now() + 3, 'proposal_sha256': hashlib.sha256(payload).hexdigest(),
        'correlation_id': plan['correlation_id'], 'transaction_sha256': plan['transaction_sha256'],
        'input': plan['transaction'].encode(), 'input_written': 0, 'stdout': b'', 'stderr': b'',
        'received': {'stdout': 0, 'stderr': 0}, 'returncode': None, 'cleanup_errors': ()}
    evidence.update(changes);error = HISTORY.TRANSPORT.Uncertain('modeled uncertain entry', evidence)
    error.__cause__ = HISTORY.Pending('modeled capture failure');return error


def configure(test, fixture):
    for backend in (REGISTER._STORAGE, HISTORY._STORAGE):
        for setting in (patch.object(backend, 'TRUST_ROOT', fixture.root), patch.object(backend, 'TRUSTED_UID', os.geteuid())):
            setting.start();test.addCleanup(setting.stop)
    setting = patch.object(EMPTY, 'ASSEMBLY', ASSEMBLY);setting.start();test.addCleanup(setting.stop)
    fixture.history = fixture.root / 'uncertainty';fixture.history.mkdir(mode=0o700);fixture.history.chmod(0o700)
    fixture.saved = fixture.history / HISTORY.LEAF
    fixture.uncertain = HISTORY.record(fixture.history, fixture.original, model(fixture.original))


class EmptyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = registered_fixture.ReprepareTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        configure(self, self.fixture)
        self.plan, self.namespace = self.fixture.plan, self.fixture.namespace

    def prepare(self, **settings):
        return EMPTY.prepare(self.fixture.store, self.fixture.history, **(self.fixture.helper.helper.readers() | settings))

    def clock(self):
        value = [KERNEL.now()]
        for kernel in {id(k): k for k in (KERNEL, REGISTER.KERNEL, HISTORY.KERNEL, HISTORY._STORAGE.KERNEL)}.values():
            setting = patch.object(kernel, 'now', side_effect=lambda: value[0]);setting.start();self.addCleanup(setting.stop)
        return value

    def change_history(self):
        value = HISTORY.checked(self.fixture.uncertain);value['evidence']['returncode'] = 0
        self.fixture.saved.write_bytes(HISTORY.envelope(encoded(value)))

    def test_real_registered_uncertainty_and_complete_empty_preparation_retain_whole_original_bytes(self):
        before = [(p.read_bytes(), p.stat().st_ino) for p in (self.fixture.leaf, self.fixture.saved)]
        with patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, patch.object(REGISTER, 'load', wraps=REGISTER.load) as register:raw = self.prepare()
        value = json.loads(raw)
        self.assertIs(type(raw), bytes);self.assertEqual(raw, encoded(value));self.assertLessEqual(len(raw), EMPTY.MAX_OUTPUT)
        self.assertEqual(value['schema'], SCHEMA);self.assertEqual(value['state'], 'uncertain-empty-source-intention-only')
        self.assertEqual(value['profile'], 'registered-uncertainty-empty-source-repreparation-1')
        self.assertEqual(value['admission_profile'], PLAN.AUTO.ADMISSION);self.assertEqual(value['namespace'], self.namespace)
        self.assertEqual(value['proposal'].encode(), self.fixture.original)
        self.assertEqual(value['uncertainty'].encode(), self.fixture.uncertain)
        self.assertEqual(value['proposal_sha256'], hashlib.sha256(self.fixture.original).hexdigest())
        self.assertEqual(value['uncertainty_sha256'], hashlib.sha256(self.fixture.uncertain).hexdigest())
        for key in ('correlation_id', 'transaction_sha256'):self.assertEqual(value[key], self.plan[key])
        self.assertEqual(history.call_count, 2);self.assertEqual(register.call_count, 2)
        self.assertEqual([(p.read_bytes(), p.stat().st_ino) for p in (self.fixture.leaf, self.fixture.saved)], before)

    def test_empty_source_with_zero_exit_full_input_remains_uncertain_and_does_not_retry(self):
        raw = HISTORY.capture(self.fixture.original, model(self.fixture.original, returncode=0, input_written=len(self.plan['transaction'].encode())))
        self.fixture.saved.write_bytes(HISTORY.envelope(raw))
        with (patch.object(HISTORY.TRANSPORT, 'transmit', side_effect=AssertionError('retry')),
                patch.object(HISTORY, 'record', side_effect=AssertionError('history mutation')),
                patch.object(REGISTER, 'create', side_effect=AssertionError('new registration')),
                patch.object(PLAN.secrets, 'token_hex', side_effect=AssertionError('new correlation'))):
            value = json.loads(self.prepare())
        history = json.loads(value['uncertainty']);self.assertEqual(history['state'], 'historical-uncertain-no-retry')
        self.assertEqual(history['evidence']['returncode'], 0);self.assertEqual(value['state'], 'uncertain-empty-source-intention-only')

    def test_invalid_reader_and_context_admission_precede_both_disk_loads(self):
        with patch.object(HISTORY, 'load', side_effect=AssertionError('disk')):
            for settings in ({'compiler': lambda raw: ''}, {'topology': {}}, {'scope': lambda: 1}, {'identifier': 'a' * 64}, {'nft': None}):
                with self.subTest(settings=settings), self.assertRaises(ValueError):self.prepare(**settings)
            for context in (True, False, 0, -1, 1 << 64, '1', None):
                with self.subTest(context=context), patch.object(KERNEL, 'namespace', return_value=context), self.assertRaises(ValueError):self.prepare()
            for end in (True, False, float('inf'), float('nan'), 'future', KERNEL.now() - 1):
                with self.subTest(deadline=end), self.assertRaises(ValueError):self.prepare(deadline=end)

    def test_missing_corrupt_unsafe_or_linked_uncertainty_refuses_before_sources(self):
        original = self.fixture.saved.read_bytes()
        for damage in ('missing', 'bytes', 'mode', 'link'):
            if damage == 'missing':self.fixture.saved.unlink()
            elif damage == 'bytes':self.fixture.saved.write_bytes(b'corrupt')
            elif damage == 'mode':self.fixture.saved.chmod(0o660)
            else:os.link(self.fixture.saved, self.fixture.root / 'extra')
            with self.subTest(damage=damage), self.assertRaises((OSError, ValueError)):
                self.prepare(nft=lambda **settings: self.fail('invalid history source'))
            extra = self.fixture.root / 'extra'
            if extra.exists():extra.unlink()
            if self.fixture.saved.exists():self.fixture.saved.unlink()
            self.fixture.saved.write_bytes(original);self.fixture.saved.chmod(0o600)

    def test_initial_registered_plan_mismatch_or_missing_registration_refuses_before_sources(self):
        self.fixture.leaf.write_bytes(REGISTER.envelope(encoded(self.plan | {'namespace': self.namespace + 1})))
        with self.assertRaisesRegex(ValueError, 'differs'):self.prepare(nft=lambda **settings: self.fail('different registered input'))
        self.fixture.leaf.unlink()
        with self.assertRaises(OSError):self.prepare(nft=lambda **settings: self.fail('missing registration source'))

    def test_matching_foreign_context_and_rehashed_invalid_uncertainty_are_not_admission(self):
        other = encoded(self.plan | {'namespace': self.namespace + 1})
        self.fixture.leaf.write_bytes(REGISTER.envelope(other))
        self.fixture.saved.write_bytes(HISTORY.envelope(HISTORY.capture(other, model(other))))
        with self.assertRaises(ValueError):self.prepare(nft=lambda **settings: self.fail('foreign history source'))
        value = HISTORY.checked(self.fixture.uncertain);value['evidence']['input_hex'] = b'flush ruleset\n'.hex()
        packet = encoded(value);outer = json.loads(HISTORY.envelope(self.fixture.uncertain))
        outer['payload'] = packet.decode();outer['payload_sha256'] = hashlib.sha256(packet).hexdigest()
        self.fixture.saved.write_bytes(encoded(outer))
        with self.assertRaises(ValueError):self.prepare(nft=lambda **settings: self.fail('unsafe rehashed source'))

    def test_two_real_history_registration_loads_and_all_observers_share_parent_sixty_cap(self):
        clock = self.clock();hload, rload = HISTORY.load, REGISTER.load
        for seconds in (5, 100):
            deadlines = [];readers = self.fixture.helper.helper.readers()
            def history(path, deadline):deadlines.append(deadline);return hload(path, deadline=deadline)
            def register(path, deadline):deadlines.append(deadline);return rload(path, deadline=deadline)
            for key, reader in tuple(readers.items()):readers[key] = lambda deadline, reader=reader: deadlines.append(deadline) or reader(deadline)
            with patch.object(HISTORY, 'load', side_effect=history), patch.object(REGISTER, 'load', side_effect=register):
                EMPTY.prepare(self.fixture.store, self.fixture.history, deadline=clock[0] + seconds, **readers)
            self.assertEqual(deadlines, [clock[0] + min(seconds, 60)] * 25)

    def test_complete_intention_and_both_second_loads_precede_every_final_source_fence(self):
        events = [];hload, rload, encode = HISTORY.load, REGISTER.load, STATE.encoded
        def history(*args, **settings):events.append('history');return hload(*args, **settings)
        def register(*args, **settings):events.append('register');return rload(*args, **settings)
        def encoding(value):
            result = encode(value)
            if type(value) is dict and value.get('schema') == SCHEMA:events.append('receipt')
            return result
        readers = self.fixture.helper.helper.readers()
        for key, reader in tuple(readers.items()):readers[key] = lambda deadline, key=key, reader=reader: events.append(key) or reader(deadline)
        with patch.object(HISTORY, 'load', side_effect=history), patch.object(REGISTER, 'load', side_effect=register), patch.object(STATE, 'encoded', side_effect=encoding):
            EMPTY.prepare(self.fixture.store, self.fixture.history, **readers)
        self.assertEqual(events, ['history', 'register'] + ['nft', 'legacy', 'classifiers', 'bpf', 'bpf_links', 'dhcp', 'dns', 'ntp'] * 2 +
            ['receipt', 'history', 'register', 'nft', 'legacy', 'classifiers', 'bpf', 'bpf_links'])

    def test_valid_uncertainty_drift_during_encoding_refuses_before_final_sources(self):
        real = STATE.encoded;calls = []
        def encode(value):
            data = real(value)
            if type(value) is dict and value.get('schema') == SCHEMA:self.change_history()
            return data
        nft = self.fixture.helper.helper.readers()['nft']
        with patch.object(STATE, 'encoded', side_effect=encode), self.assertRaisesRegex(ValueError, 'uncertainty bytes changed'):
            self.prepare(nft=lambda deadline: calls.append(1) or nft(deadline))
        self.assertEqual(len(calls), 2)

    def test_valid_registration_drift_after_final_history_read_withholds_receipt(self):
        real = HISTORY.load;calls = []
        def load(*args, **settings):
            result = real(*args, **settings);calls.append(1)
            if len(calls) == 2:self.fixture.leaf.write_bytes(REGISTER.envelope(encoded(self.plan | {'namespace': self.namespace + 1})))
            return result
        with patch.object(HISTORY, 'load', side_effect=load), self.assertRaisesRegex(ValueError, 'registration bytes changed'):self.prepare()
        self.assertEqual(len(calls), 2)

    def test_lease_expiry_during_second_history_read_is_rechecked_before_final_nft(self):
        clock = self.clock();real = HISTORY.load;loads, calls = [], []
        row = self.fixture.helper.helper.records['dhcp4']['attributions'][0]
        row['preferred_until'] = row['valid_until'] = int((clock[0] + 1) * 1000000)
        def load(*args, **settings):
            data = real(*args, **settings);loads.append(1)
            if len(loads) == 2:clock[0] += 2
            return data
        nft = self.fixture.helper.helper.readers()['nft']
        with patch.object(HISTORY, 'load', side_effect=load), self.assertRaisesRegex(ValueError, 'attribution expired'):
            self.prepare(nft=lambda deadline: calls.append(1) or nft(deadline))
        self.assertEqual(len(loads), 2);self.assertEqual(len(calls), 2)

    def test_expired_second_history_load_prevents_second_registration_admission(self):
        clock = self.clock();real = HISTORY.load;calls = []
        def load(*args, **settings):
            data = real(*args, **settings);calls.append(1)
            if len(calls) == 2:clock[0] += 61
            return data
        with patch.object(HISTORY, 'load', side_effect=load), patch.object(REGISTER, 'load', wraps=REGISTER.load) as registration, self.assertRaises(ValueError):self.prepare()
        self.assertEqual(registration.call_count, 1)

    def test_initial_history_load_expiry_prevents_registration_or_observer_admission(self):
        clock = self.clock();real = HISTORY.load
        def load(*args, **settings):result = real(*args, **settings);clock[0] += 61;return result
        with patch.object(HISTORY, 'load', side_effect=load), patch.object(REGISTER, 'load', side_effect=AssertionError('later disk')), self.assertRaises(ValueError):self.prepare()

    def test_encoding_expiry_or_oversize_refuses_before_second_history_load(self):
        with patch.object(EMPTY, 'MAX_OUTPUT', 1), patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, self.assertRaises(ValueError):self.prepare()
        self.assertEqual(history.call_count, 1)
        clock = self.clock();real = STATE.encoded
        def encode(value):
            result = real(value)
            if type(value) is dict and value.get('schema') == SCHEMA:clock[0] += 61
            return result
        with patch.object(STATE, 'encoded', side_effect=encode), patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, self.assertRaises(ValueError):self.prepare()
        self.assertEqual(history.call_count, 1)

    def test_current_complete_input_drift_cannot_update_uncertain_original_intention(self):
        before = self.fixture.saved.read_bytes();self.fixture.helper.helper.records['dns']['dns'][0]['address'] = '1.1.1.1'
        with self.assertRaisesRegex(ValueError, 'differs from registered uncertainty'):self.prepare()
        self.assertEqual(self.fixture.saved.read_bytes(), before)

    def test_all_final_empty_receipts_still_refuse_drift_after_second_history_load(self):
        for name in ('nft', 'legacy', 'classifiers', 'bpf', 'bpf_links'):
            real = self.fixture.helper.helper.readers()[name];calls = []
            def reader(deadline):
                calls.append(1);row = real(deadline)
                if len(calls) == 3:
                    if name == 'nft':row['empty'] = False
                    elif name == 'legacy':row['source']['identity'][1] += 100
                    elif name == 'classifiers':row['links'][1]['mtu'] = 1400
                    else:row['lookup'].update(result=0, errno=0, next_id=1)
                return row
            with self.subTest(name=name), patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, self.assertRaises(ValueError):self.prepare(**{name: reader})
            self.assertEqual(history.call_count, 2);self.assertEqual(len(calls), 3)

    def test_matching_marked_existing_state_never_becomes_empty_uncertainty_admission(self):
        row = registered_fixture.automatic_fixture.nft_receipt(self.namespace);row['empty'] = False
        with self.assertRaises(ValueError):self.prepare(nft=lambda deadline: row, dhcp=lambda **settings: self.fail('nonempty services'))

    def test_missing_or_failed_registry_reporting_and_instantiated_dhcp6_remain_pending(self):
        for name in ('legacy', 'classifiers', 'bpf', 'bpf_links'):
            def absent(deadline):raise OSError('unreported')
            with self.subTest(name=name), self.assertRaises(OSError):self.prepare(**{name: absent})
        self.fixture.helper.helper.records['dhcp4']['interfaces'][0].update(dhcp6=True, state6='stopped')
        with self.assertRaisesRegex(ValueError, 'DHCPv6'):self.prepare(dns=lambda **settings: self.fail('dhcp6 resolver'))

    def test_preparer_return_requires_profile_true_context_and_same_transaction_object(self):
        real = ASSEMBLY.observe
        for key in ('schema', 'profile', 'namespace', 'policy'):
            def observed(**settings):
                result = real(**settings);result[key] = result['policy'].encode().decode() if key == 'policy' else True if key == 'namespace' else 'other';return result
            with self.subTest(key=key), patch.object(ASSEMBLY, 'observe', side_effect=observed), self.assertRaises(ValueError):self.prepare()

    def test_repeated_or_missing_compiler_turn_cannot_return_an_empty_source_receipt(self):
        real = ASSEMBLY.observe
        def observed(**settings):
            compile_intention = settings['compiler']
            def twice(raw):compile_intention(raw);return compile_intention(raw)
            return real(**(settings | {'compiler': twice}))
        with patch.object(ASSEMBLY, 'observe', side_effect=observed), self.assertRaises(ValueError):self.prepare()
        with patch.object(ASSEMBLY, 'observe', return_value={'schema': 'debian13s4-assembled-policy-1', 'profile': PLAN.AUTO.ADMISSION}), self.assertRaises(ValueError):self.prepare()

    def test_no_history_load_hash_encoding_or_compilation_follows_final_preparer_fences(self):
        real = ASSEMBLY.observe;guards = []
        def observed(**settings):
            result = real(**settings)
            for target, name in ((HISTORY, 'load'), (REGISTER, 'load'), (STATE, 'encoded'), (EMPTY.hashlib, 'sha256'), (EMPTY.MANIFEST, 'expected')):
                setting = patch.object(target, name, side_effect=AssertionError('post-preparer work'));setting.start();guards.append(setting)
            return result
        try:
            with patch.object(ASSEMBLY, 'observe', side_effect=observed):raw = self.prepare()
        finally:
            for setting in reversed(guards):setting.stop()
        self.assertIs(type(raw), bytes)

    def test_wrapper_final_context_and_time_cannot_promote_prepared_uncertainty(self):
        for final in (True, self.namespace + 1):
            calls = []
            def scope():calls.append(1);return final if len(calls) == 3 else self.namespace
            with self.subTest(final=final), patch.object(KERNEL, 'namespace', side_effect=scope), self.assertRaises(ValueError):self.prepare()
        clock = self.clock();real = ASSEMBLY.observe
        def observed(**settings):result = real(**settings);clock[0] += 61;return result
        with patch.object(ASSEMBLY, 'observe', side_effect=observed), self.assertRaises(ValueError):self.prepare()


class NativeEmptyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = registered_fixture.NativeTests();self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown);self.addCleanup(self.fixture.doCleanups)
        configure(self, self.fixture)

    def prepare(self):return EMPTY.prepare(self.fixture.store, self.fixture.history)

    def test_complete_private_capture_empty_admission_retains_registered_uncertainty_without_submission(self):
        before = self.fixture.saved.read_bytes()
        with (patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, patch.object(REGISTER, 'load', wraps=REGISTER.load) as register,
                patch.object(HISTORY.TRANSPORT, 'transmit', side_effect=AssertionError('retry'))):raw = self.prepare()
        value = json.loads(raw);self.assertEqual(value['uncertainty'].encode(), self.fixture.uncertain)
        self.assertEqual(value['proposal'].encode(), self.fixture.original);self.assertEqual(value['state'], 'uncertain-empty-source-intention-only')
        self.assertEqual(history.call_count, 2);self.assertEqual(register.call_count, 2);self.assertEqual(self.fixture.saved.read_bytes(), before)
        self.assertEqual(len(self.fixture.bpf_calls), 6);self.assertEqual(len(self.fixture.link_calls), 6)
        rows = [json.loads(line) for line in self.fixture.ledger.read_text().splitlines()]
        self.assertEqual({kind:sum(row[0] == kind for row in rows) for kind in ('ip', 'bus', 'tc', 'nft')}, {'ip':258,'bus':100,'tc':12,'nft':6})
        for kind, argv, environment in rows:
            self.assertFalse(set(environment) & {'TASK_SECRET', 'NFT_CTX_FLAGS'})
            if kind == 'nft':self.assertEqual(argv, list(ASSEMBLY.NFT.COMMAND))

    def test_actual_existing_registered_marker_refuses_before_services_and_second_history_load(self):
        value = {'nftables':[{'metainfo':{'version':'1.1.3','release_name':'fixture','json_schema_version':1}},
            {'table':{'family':'inet','name':'debian13s4','handle':1,'comment':PLAN.COMMENT_PREFIX+self.fixture.plan['correlation_id']}}]}
        self.fixture.executable(self.fixture.nft, f'print({json.dumps(value)!r})')
        with patch.object(HISTORY, 'load', wraps=HISTORY.load) as history, self.assertRaises(ValueError):self.prepare()
        self.assertEqual(history.call_count, 1);self.assertFalse(any(json.loads(line)[0]=='bus' for line in self.fixture.ledger.read_text().splitlines()))

    def test_actual_capture_followed_by_history_damage_blocks_final_source_queries(self):
        real = STATE.encoded
        def encode(value):
            result = real(value)
            if type(value) is dict and value.get('schema')==SCHEMA:self.fixture.saved.write_bytes(b'damaged')
            return result
        with patch.object(STATE, 'encoded', side_effect=encode), self.assertRaises(ValueError):self.prepare()
        rows = [json.loads(line) for line in self.fixture.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind=='nft' for kind,argv,env in rows), 4)

    def test_actual_program_or_link_registration_after_second_history_load_refuses(self):
        real = HISTORY.load
        for kind in ('program','link'):
            self.fixture.fixtures(tc_kind='fq_codel');self.fixture.bpf_calls.clear();self.fixture.link_calls.clear()
            self.fixture.bpf_present = self.fixture.link_present = False;calls = []
            def load(*args, **settings):
                data = real(*args, **settings);calls.append(1)
                if len(calls)==2:
                    if kind=='program':self.fixture.bpf_present = True
                    else:self.fixture.link_present = True
                return data
            with self.subTest(kind=kind), patch.object(HISTORY, 'load', side_effect=load), self.assertRaises(ValueError):self.prepare()
            self.assertEqual(len(calls), 2);self.assertEqual(len(self.fixture.bpf_calls), 5 if kind=='program' else 6)
            self.assertEqual(len(self.fixture.link_calls), 4 if kind=='program' else 5)

    def test_actual_consistent_new_dns_does_not_replace_the_uncertain_registered_input(self):
        self.fixture.fixtures(tc_kind='fq_codel',dns='9.9.9.9');self.fixture.bpf_calls.clear();self.fixture.link_calls.clear()
        before = self.fixture.saved.read_bytes()
        with self.assertRaisesRegex(ValueError, 'differs from registered uncertainty'):self.prepare()
        self.assertEqual(self.fixture.saved.read_bytes(), before)

    def test_actual_single_private_uncertain_entry_plus_empty_sources_never_resubmits(self):
        binary = self.fixture.root/'nft-submit';entries = self.fixture.root/'entries'
        binary.write_text('#!/usr/bin/python3 -B\nimport sys\n'+f'open({str(entries)!r},"a").write("entry\\n")\n'+
            'data=sys.stdin.buffer.read()\nsys.stdout.buffer.write(b"out\\0\\xff")\nsys.stderr.buffer.write(b"err\\r\\xe2\\x82")\n');binary.chmod(0o700)
        self.fixture.saved.unlink()
        with patch.object(HISTORY.TRANSPORT,'BINARY',binary), patch.object(HISTORY.KERNEL,'TRUST_ROOT',self.fixture.root), patch.object(HISTORY.KERNEL,'TRUSTED_UID',os.geteuid()):
            with self.assertRaises(HISTORY.TRANSPORT.Uncertain) as caught:HISTORY.TRANSPORT.transmit(self.fixture.original)
            original = HISTORY.record(self.fixture.history, self.fixture.original, caught.exception)
            with patch.object(HISTORY.TRANSPORT,'transmit',side_effect=AssertionError('retry')):value=json.loads(self.prepare())
        history=json.loads(value['uncertainty']);self.assertEqual(value['uncertainty'].encode(),original)
        self.assertEqual(history['state'],'historical-uncertain-no-retry');self.assertEqual(history['evidence']['returncode'],0)
        self.assertEqual(bytes.fromhex(history['evidence']['stdout_hex']),b'out\0\xff')
        self.assertEqual(bytes.fromhex(history['evidence']['stderr_hex']),b'err\r\xe2\x82');self.assertEqual(entries.read_text(),'entry\n')
        self.assertEqual(value['state'],'uncertain-empty-source-intention-only')
