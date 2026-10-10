"""Private first-create intention models; never submission or installed authority.

Reuse real protected files/EMPTY admission/compiler, with finite TEST DATA and
ordinary-UID/private structured or executable delivery substitutions only.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_dns_prepare as source_fixture
import test_assemble as assembly_fixture
import test_first_match as old_match_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_dns_first_create',ROOT/'Firewall/dns_first_create.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
REAL_TOKEN = M.secrets.token_hex


class DNSFirstCreateTests(unittest.TestCase):
    def setUp(self):
        self.source = source_fixture.DNSEmptyPreparationTests()
        self.addCleanup(self.source.doCleanups); self.source.setUp()
        for owner,key,value in ((M,'PREPARE',source_fixture.M),(M,'KERNEL',source_fixture.M.KERNEL)):
            adapter=patch.object(owner,key,value);adapter.start();self.addCleanup(adapter.stop)
        self.token=patch.object(M.secrets,'token_hex',return_value='f'*64)
        self.token.start();self.addCleanup(self.token.stop)
        self.namespace=self.source.namespace

    def prepare(self, **overrides):
        return M.prepare(**(self.source.readers()|overrides))

    def record(self, **overrides):
        return json.loads(self.prepare(**overrides))

    def test_whole_canonical_proposal_binds_original_source_and_transaction_hashes(self):
        raw=self.prepare();value=json.loads(raw)
        self.assertEqual(raw,M.PREPARE.DNS.BASE.canonical(value))
        self.assertEqual(set(value),{'schema','profile','state','namespace','correlation_id',
            'source_intention','source_sha256','transaction','transaction_sha256'})
        self.assertEqual(value['state'],'prepared-dns-first-create-intention-only')
        self.assertEqual(value['namespace'],self.namespace)
        self.assertEqual(value['correlation_id'],'f'*64)
        self.assertEqual(value['source_sha256'],hashlib.sha256(value['source_intention'].encode()).hexdigest())
        self.assertEqual(value['transaction_sha256'],hashlib.sha256(value['transaction'].encode()).hexdigest())
        self.assertNotIn('owned',value);self.assertNotIn('applied',value)

    def test_complete_original_dns_body_is_verbatim_and_only_outer_frame_changes(self):
        value=self.record();source=json.loads(value['source_intention']);original=source['intention']['compiler']['policy']
        prefix='destroy table inet debian13s4\ntable inet debian13s4 {\n'
        new='create table inet debian13s4 {\n    comment "'+M.COMMENT_PREFIX+'f'*64+'"\n'
        self.assertEqual(value['transaction'],new+original[len(prefix):])
        self.assertEqual(value['transaction'][len(new):],original[len(prefix):])
        self.assertNotIn('destroy table',value['transaction']);self.assertNotIn('flush ruleset',value['transaction'])
        self.assertEqual(value['transaction'].count('comment '),1)
        self.assertEqual(value['transaction'].count('set '),17)
        self.assertEqual(value['transaction'].count('policy drop;'),3)
        self.assertNotEqual(source['intention']['compiler']['compiler_sha256'],value['transaction_sha256'])
        self.assertEqual(source['intention']['compiler']['compiler_sha256'],hashlib.sha256(original.encode()).hexdigest())

    def test_source_retains_whole_protected_service_and_real_expanded_expected_representation(self):
        value=self.record();source=json.loads(value['source_intention']);service=json.loads(source['service_intention'])
        self.assertEqual(service['configuration']['value'],self.source.value)
        self.assertEqual(source['service_sha256'],hashlib.sha256(source['service_intention'].encode()).hexdigest())
        expected=M.PREPARE.MANIFEST.expected(source['topology'].encode(),source['dns_configuration'].encode(),source['kernel_snapshot'].encode())
        self.assertEqual(source['intention'],expected)
        self.assertEqual(source['state'],'prepared-public-dns-empty-source-intention-only')
        self.assertEqual(source['namespace'],value['namespace'])
        self.assertEqual(len(expected['compiler']['bindings']),2)
        self.assertEqual(len(service['plan']['units']),3)

    def test_default_commentless_entry_remains_byte_equal_to_retained_source_intention(self):
        first=self.record();plain=M.PREPARE.prepare(**self.source.readers())
        self.assertEqual(first['source_intention'].encode(),plain)
        self.assertTrue(json.loads(plain)['intention']['compiler']['policy'].startswith('destroy table '))
        self.assertNotIn(M.COMMENT_PREFIX,plain.decode())

    def test_identifier_generation_requires_exact_token_length_and_lowercase_hex_before_files(self):
        for identifier in ('', 'f'*63, 'f'*65, 'F'*64, 'g'*64, True, None, b'f'*64, 'f'*63+'\n'):
            with self.subTest(identifier=identifier),patch.object(M.secrets,'token_hex',return_value=identifier) as token, \
                patch.object(M.PREPARE,'_prepare',side_effect=AssertionError('protected source')):
                with self.assertRaises(ValueError):self.prepare()
                token.assert_called_once_with(32)

    def test_deadline_and_unknown_delivery_refuse_before_entropy_or_source(self):
        for deadline in (True,float('nan'),float('inf'),'future',M.KERNEL.now()-1,10**10000):
            with self.subTest(kind=type(deadline).__name__),patch.object(M.secrets,'token_hex',side_effect=AssertionError('entropy')):
                with self.assertRaises(ValueError):self.prepare(deadline=deadline)
        for kw in ({'compiler':lambda:None},{'identifier':'f'*64},{'configuration':{}},{'scope':lambda:1},
            {'builder':lambda:None},{'healthy':True},{'kernel':None}):
            with self.subTest(kw=kw),patch.object(M.secrets,'token_hex',side_effect=AssertionError('entropy')):
                with self.assertRaises(ValueError):self.prepare(**kw)
        with self.assertRaises(ValueError):M.PREPARE.prepare(builder=lambda:None,**self.source.readers())

    def test_initial_namespace_requires_true_positive_uint64_before_entropy(self):
        for namespace in (0,True,-1,'1',1<<64):
            with self.subTest(namespace=namespace),patch.object(M.KERNEL,'namespace',return_value=namespace), \
                patch.object(M.secrets,'token_hex',side_effect=AssertionError('entropy')):
                with self.assertRaises(ValueError):self.prepare()

    def test_entropy_return_expiry_and_namespace_change_refuse_before_protected_entry(self):
        instant=M.KERNEL.now()
        for kind in ('time','context'):
            with patch.object(M.KERNEL,'now',return_value=instant) as clock, \
                patch.object(M.KERNEL,'namespace',return_value=self.namespace) as scope:
                def token(length):
                    if kind=='time':clock.return_value=instant+61
                    else:scope.return_value=self.namespace+1
                    return 'f'*64
                with self.subTest(kind=kind),patch.object(M.secrets,'token_hex',side_effect=token), \
                    patch.object(M.PREPARE,'_prepare',side_effect=AssertionError('protected source')):
                    with self.assertRaises(ValueError):self.prepare()

    def test_whole_marker_transaction_encoding_precedes_second_service_and_final_sources(self):
        events=[];real_service=M.PREPARE.DNS.prepare;real_encode=M.PREPARE.DNS.BASE.canonical
        def service(**kw):events.append('service');return real_service(**kw)
        def encoded(record):
            if type(record) is dict and record.get('schema')=='debian13s4-dns-first-create-1':events.append('first-encoded')
            return real_encode(record)
        readers=self.source.readers()
        for name,fn in tuple(readers.items()):
            if name=='kernel':readers[name]=lambda key,deadline,fn=fn:events.append('kernel') or fn(key,deadline)
            else:readers[name]=lambda deadline,name=name,fn=fn:events.append(name) or fn(deadline)
        with patch.object(M.PREPARE.DNS,'prepare',side_effect=service),patch.object(M.PREPARE.DNS.BASE,'canonical',side_effect=encoded):
            M.prepare(**readers)
        self.assertEqual(events[0],'service')
        self.assertEqual(events[1:17],['nft','legacy','classifiers','bpf','bpf_links','dhcp','dns','ntp']*2)
        self.assertEqual(events[17:37],['kernel']*20)
        self.assertEqual(events[37:],['first-encoded','service','nft','legacy','classifiers','bpf','bpf_links'])

    def test_missing_protected_configuration_and_foreign_existing_table_never_make_plan(self):
        M.PREPARE.DNS.INPUT.unlink()
        with patch.object(M.PREPARE.ASSEMBLY,'observe',side_effect=AssertionError('source')):
            with self.assertRaises(OSError):self.prepare()
        self.source.write()
        with self.assertRaises(ValueError):self.prepare(nft=lambda deadline:assembly_fixture.nft_receipt(self.namespace)|{'empty':False})

    def test_full_source_byte_bound_refuses_before_second_protected_preparation(self):
        real=M.PREPARE.DNS.prepare
        with patch.object(M.PREPARE,'MAX_OUTPUT',1),patch.object(M.PREPARE.DNS,'prepare',wraps=real) as service:
            with self.assertRaisesRegex(ValueError,'source intention exceeds'):self.prepare()
        self.assertEqual(service.call_count,1)

    def test_distinct_transaction_expansion_is_counted_before_second_protected_preparation(self):
        plain=json.loads(M.PREPARE.prepare(**self.source.readers()));length=len(plain['intention']['compiler']['policy'].encode())
        real=M.PREPARE.DNS.prepare
        with patch.object(M.PREPARE.ASSEMBLY.POLICY,'MAX_OUTPUT',length+1),patch.object(M.PREPARE.DNS,'prepare',wraps=real) as service:
            with self.assertRaisesRegex(ValueError,'transaction exceeds'):self.prepare()
        self.assertEqual(service.call_count,1)

    def test_complete_first_receipt_byte_bound_refuses_before_second_protected_preparation(self):
        real=M.PREPARE.DNS.prepare
        with patch.object(M,'MAX_OUTPUT',1),patch.object(M.PREPARE.DNS,'prepare',wraps=real) as service:
            with self.assertRaisesRegex(ValueError,'first-create intention exceeds'):self.prepare()
        self.assertEqual(service.call_count,1)

    def test_bad_real_compiler_frame_cannot_be_replaced_with_arbitrary_transaction(self):
        real=M.PREPARE.MANIFEST.expected
        for frame in ('table inet debian13s4 {}\n','destroy table inet other\ntable inet debian13s4 {\n}\n',
            'destroy table inet debian13s4\ntable inet debian13s4 {\n}!',True):
            def expected(*args):
                value=real(*args);value['compiler']['policy']=frame;return value
            with self.subTest(frame=frame),patch.object(M.PREPARE.MANIFEST,'expected',side_effect=expected):
                with self.assertRaisesRegex(ValueError,'compiler transaction frame'):self.prepare()

    def test_correlation_is_generated_once_and_inherited_capped_deadline_is_preserved(self):
        instant=M.KERNEL.now();seen=[];real=M.PREPARE._prepare
        def prepare(builder,deadline,**kw):
            seen.append(deadline);return real(builder,deadline=deadline,**kw)
        for seconds in (5,1000):
            with patch.object(M.KERNEL,'now',return_value=instant),patch.object(M.secrets,'token_hex',return_value='f'*64) as token, \
                patch.object(M.PREPARE,'_prepare',side_effect=prepare):
                self.prepare(deadline=instant+seconds)
            token.assert_called_once_with(32)
        self.assertEqual(seen,[instant+5,instant+60])

    def test_second_real_protected_read_detects_changed_settings_after_encoding(self):
        real=M.PREPARE.DNS.BASE.canonical;nft_calls=[]
        def encoded(record):
            raw=real(record)
            if type(record) is dict and record.get('schema')=='debian13s4-dns-first-create-1':
                self.source.value['node']='changed';self.source.write()
            return raw
        def nft(deadline):nft_calls.append(deadline);return assembly_fixture.nft_receipt(self.namespace)
        with patch.object(M.PREPARE.DNS.BASE,'canonical',side_effect=encoded):
            with self.assertRaisesRegex(ValueError,'service intention changed'):self.prepare(nft=nft)
        self.assertEqual(len(nft_calls),2)

    def test_final_nft_and_global_program_link_drift_withhold_encoded_first_plan(self):
        for name in ('nft','bpf','bpf_links'):
            fn=self.source.readers()[name];calls=[0]
            def reader(deadline):calls[0]+=1;return fn(deadline) if calls[0]<3 else {}
            with self.subTest(name=name),self.assertRaises(ValueError):self.prepare(**{name:reader})
            self.assertEqual(calls[0],3)

    def test_final_policy_must_be_the_same_complete_transaction_object(self):
        real=M.PREPARE.ASSEMBLY.observe
        def observe(**kw):
            value=real(**kw);value['policy']=value['policy'].encode().decode();return value
        with patch.object(M.PREPARE.ASSEMBLY,'observe',side_effect=observe):
            with self.assertRaisesRegex(ValueError,'same complete'):self.prepare()

    def test_no_first_encoding_hash_or_protected_io_after_final_assembly_return(self):
        done=[False];real=M.PREPARE.ASSEMBLY.observe
        def observe(**kw):value=real(**kw);done[0]=True;return value
        def guard(fn):
            def call(*args,**kw):self.assertFalse(done[0]);return fn(*args,**kw)
            return call
        with patch.object(M.PREPARE.ASSEMBLY,'observe',side_effect=observe), \
            patch.object(M.PREPARE.DNS.BASE,'canonical',side_effect=guard(M.PREPARE.DNS.BASE.canonical)), \
            patch.object(M.PREPARE.DNS.BASE,'read_protected',side_effect=guard(M.PREPARE.DNS.BASE.read_protected)), \
            patch.object(M.hashlib,'sha256',side_effect=guard(M.hashlib.sha256)):
            payload=self.prepare()
        self.assertTrue(done[0]);self.assertTrue(payload.endswith(b'\n'))

    def test_original_historical_checker_and_commentless_projector_remain_closed(self):
        payload=self.prepare()
        with self.assertRaises(ValueError):old_match_fixture.MATCH.checked(payload)
        self.assertEqual(old_match_fixture.MATCH.PLAN.COMMENT_PREFIX,'debian13s4-first-create-v1-')
        self.assertNotEqual(M.COMMENT_PREFIX,old_match_fixture.MATCH.PLAN.COMMENT_PREFIX)
        source=json.loads(json.loads(payload)['source_intention'])
        self.assertNotIn('comment',source['intention']['nft_policy']['table'])
        model=old_match_fixture.native_fixture.native(json.loads(source['topology']))
        projector=M.PREPARE.MANIFEST.STATE.project
        self.assertIn('policy',projector(copy.deepcopy(model)))
        old_match_fixture.native_fixture.objects(model,'table')[0]['comment']=M.COMMENT_PREFIX+'f'*64
        with self.assertRaises(ValueError):projector(model)

    def test_twenty_private_kernel_captures_can_prepare_a_marked_intention_without_submission(self):
        binary,ledger=self.source.private_kernel();readers=self.source.readers();del readers['kernel']
        value=json.loads(M.prepare(**readers));rows=[json.loads(line) for line in ledger.read_text().splitlines()]
        self.assertEqual(len(rows),20)
        self.assertEqual([r['argv'] for r in rows],[['-j','-N',*args] for args in M.KERNEL.COMMANDS.values()]*2)
        for row in rows:
            self.assertEqual(row['env'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
            self.assertEqual(row['pid'],row['sid']);self.assertGreater(row['pid'],0)
        self.assertTrue(value['transaction'].startswith('create table inet debian13s4 {\n'))
        self.assertEqual(value['state'],'prepared-dns-first-create-intention-only')
        self.assertNotEqual(str(binary),'/usr/bin/ip')
