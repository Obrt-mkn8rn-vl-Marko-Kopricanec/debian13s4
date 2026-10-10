"""Registered/fresh protected SOURCE integration under private delivery models.

Finite fixture DATA are not assigned sites. No real host/tool/manager/app calls.
New executions never retroactively widen sealed registration/checker coverage.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_dns_first_create as fixture
import test_first_create as old_plan_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_dns_first_refresh', ROOT/'Firewall/dns_first_refresh.py')
F = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(F)
R, S = F.REGISTER, F.REGISTER._STORAGE
P = fixture.source_fixture.M


class DNSFirstRefreshTests(unittest.TestCase):
    def setUp(self):
        self.producer = fixture.DNSFirstCreateTests();self.addCleanup(self.producer.doCleanups);self.producer.setUp()
        self.original = self.producer.prepare();self.plan = json.loads(self.original)
        self.producer.token.stop()  # Restore token_hex16 staging entropy, retain protected source files.
        self.source = self.producer.source;self.namespace = self.plan['namespace']
        private = tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(private.cleanup)
        self.root = Path(private.name);self.root.chmod(0o700)
        self.store = self.root/'registered';self.store.mkdir(mode=0o700);self.store.chmod(0o700)
        self.leaf = self.store/R.LEAF
        for owner, name, value in ((F,'PREPARE',P),(F,'KERNEL',P.KERNEL),
            (S,'TRUST_ROOT',self.root),(S,'TRUSTED_UID',os.getuid())):
            adapter = patch.object(owner,name,value);adapter.start();self.addCleanup(adapter.stop)
        R.create(self.store,self.original)

    def prepare(self, **kw):
        return F.prepare(self.store,**(self.source.readers()|kw))

    def clock(self):
        value = [P.KERNEL.now()]
        for kernel in (P.KERNEL,S.KERNEL):
            adapter = patch.object(kernel,'now',side_effect=lambda:value[0]);adapter.start();self.addCleanup(adapter.stop)
        return value

    def test_real_two_locked_loads_and_fresh_protected_empty_rounds_retain_whole_original_bytes(self):
        before = self.leaf.read_bytes();inode = self.leaf.stat().st_ino
        with patch.object(R,'load',wraps=R.load) as load:raw = self.prepare()
        value = json.loads(raw)
        self.assertIs(type(raw),bytes);self.assertEqual(raw,F.MATCH.encoded(value))
        self.assertEqual(value['schema'],'debian13s4-dns-first-refresh-1')
        self.assertEqual(value['state'],'reprepared-dns-empty-source-intention-only')
        self.assertEqual(value['profile'],'registered-public-dns-first-create-empty-source-repreparation-v1')
        self.assertEqual(value['namespace'],self.namespace);self.assertEqual(value['admission_profile'],P.ADMISSION)
        self.assertEqual(value['proposal'].encode(),self.original)
        self.assertEqual(value['proposal_sha256'],hashlib.sha256(self.original).hexdigest())
        for key in ('correlation_id','source_sha256','transaction_sha256'):self.assertEqual(value[key],self.plan[key])
        self.assertEqual(load.call_count,2);self.assertEqual(self.leaf.read_bytes(),before)
        self.assertEqual(self.leaf.stat().st_ino,inode);self.assertEqual({p.name for p in self.store.iterdir()},{R.LEAF})

    def test_no_new_identifier_storage_mutation_or_transmission_is_needed(self):
        with patch.object(fixture.M.secrets,'token_hex',side_effect=AssertionError('entropy')), \
            patch.object(R,'create',side_effect=AssertionError('registration mutation')):
            self.assertEqual(json.loads(self.prepare())['correlation_id'],self.plan['correlation_id'])

    def test_unknown_or_noncallable_reader_and_compiler_scope_settings_refuse_before_load(self):
        for kw in ({'compiler':lambda:None},{'scope':lambda:1},{'configuration':{}},{'topology':{}},
            {'identifier':'f'*64},{'health':True},{'kernel':None},{'nft':False}):
            with self.subTest(kw=kw),patch.object(R,'load',side_effect=AssertionError('load')):
                with self.assertRaises(ValueError):self.prepare(**kw)

    def test_invalid_deadline_and_nonpositive_or_untyped_context_refuse_before_history(self):
        for end in (True,float('nan'),float('inf'),'future',P.KERNEL.now()-1,10**10000):
            with self.subTest(type=type(end).__name__),patch.object(R,'load',side_effect=AssertionError('load')):
                with self.assertRaises(ValueError):self.prepare(deadline=end)
        for ns in (True,0,-1,1<<64,'1',None):
            with self.subTest(ns=ns),patch.object(P.KERNEL,'namespace',return_value=ns),patch.object(R,'load',side_effect=AssertionError('load')):
                with self.assertRaises(ValueError):self.prepare()

    def test_missing_corrupt_unsafe_or_linked_registration_refuses_before_fresh_service(self):
        for kind in ('missing','bytes','mode','link'):
            self.leaf.write_bytes(R.envelope(self.original));self.leaf.chmod(0o600)
            other = self.store/'external'
            if kind=='missing':self.leaf.unlink()
            elif kind=='bytes':self.leaf.write_bytes(b'broken')
            elif kind=='mode':self.leaf.chmod(0o660)
            else:os.link(self.leaf,other)
            with self.subTest(kind=kind),patch.object(P.DNS,'prepare',side_effect=AssertionError('service')):
                with self.assertRaises((ValueError,OSError)):self.prepare()
            if other.exists():other.unlink()

    def test_checked_historical_namespace_mismatch_refuses_before_current_source(self):
        with patch.object(P.KERNEL,'namespace',return_value=self.namespace+1), \
            patch.object(P.DNS,'prepare',side_effect=AssertionError('service')):
            with self.assertRaisesRegex(ValueError,'context differs'):self.prepare()

    def test_positive_inherited_minimum_window_passes_to_both_loads_service_and_kernel(self):
        now = self.clock()[0];real_load, real_service = R.load,P.DNS.prepare
        for parent, end in ((now+5,now+5),(now+100,now+60)):
            loads=[];services=[];kernel=[]
            def load(path,deadline):loads.append(deadline);return real_load(path,deadline=deadline)
            def service(**kw):services.append(kw['deadline']);return real_service(**kw)
            def query(name,deadline):kernel.append(deadline);return copy.deepcopy(self.source.data[name])
            with patch.object(R,'load',side_effect=load),patch.object(P.DNS,'prepare',side_effect=service):
                self.prepare(deadline=parent,kernel=query)
            self.assertEqual(loads,[end,end]);self.assertEqual(services,[end,end])
            self.assertEqual(len(kernel),20);self.assertEqual(set(kernel),{min(end,now+10)})

    def test_receipt_then_second_locked_history_then_second_service_precede_final_empty_checks(self):
        events=[];load, service, encode = R.load,P.DNS.prepare,F.MATCH.encoded
        def loaded(*a,**kw):events.append('load');return load(*a,**kw)
        def prepared(**kw):events.append('service');return service(**kw)
        def encoded(value):
            raw=encode(value)
            if type(value) is dict and value.get('schema')=='debian13s4-dns-first-refresh-1':events.append('receipt')
            return raw
        readers=self.source.readers()
        for name,fn in tuple(readers.items()):
            if name=='kernel':readers[name]=lambda key,deadline,fn=fn:events.append('kernel:'+key) or fn(key,deadline)
            else:readers[name]=lambda deadline,name=name,fn=fn:events.append(name) or fn(deadline)
        with patch.object(R,'load',side_effect=loaded),patch.object(P.DNS,'prepare',side_effect=prepared),patch.object(F.MATCH,'encoded',side_effect=encoded):
            F.prepare(self.store,**readers)
        self.assertEqual(events,['load','service']+['nft','legacy','classifiers','bpf','bpf_links','dhcp','dns','ntp']*2+
            ['kernel:'+name for name in P.KERNEL.COMMANDS]*2+['receipt','load','service','nft','legacy','classifiers','bpf','bpf_links'])

    def test_complete_valid_protected_configuration_drift_is_not_relabelled_history(self):
        self.source.value['node']='changed';self.source.write()
        with self.assertRaisesRegex(ValueError,'differs from registration'):self.prepare()

    def test_complete_valid_account_inventory_drift_is_not_relabelled_history(self):
        P.DNS.PASSWD.write_bytes(self.source.passwd+b'unrelated:x:404:444::/:/bin/false\n')
        with self.assertRaisesRegex(ValueError,'differs from registration'):self.prepare()

    def test_healthy_current_dns_resolver_change_is_not_relabelled_registered_policy(self):
        self.source.records['dns']['dns'][0]['address']='9.9.9.9'
        with self.assertRaisesRegex(ValueError,'differs from registration'):self.prepare()

    def test_whole_kernel_ancillary_drift_and_changed_public_address_refuse(self):
        for kind in ('mtu','address'):
            data=copy.deepcopy(self.source.data)
            if kind=='mtu':data['links'][1]['mtu']=1500
            else:data['addresses'][1]['addr_info'][0]['local']='192.168.50.101'
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.prepare(kernel=lambda name,deadline:data[name])

    def test_all_existing_even_matching_nft_objects_and_missing_coexistence_reports_refuse(self):
        for name in ('nft','legacy','classifiers','bpf','bpf_links'):
            with self.subTest(name=name),self.assertRaises(ValueError):self.prepare(**{name:lambda deadline:{}})
        fn=self.source.readers()['nft']
        with self.assertRaises(ValueError):self.prepare(nft=lambda deadline:fn(deadline)|{'empty':False})

    def test_instantiated_dhcp6_stays_unsupported(self):
        self.source.records['dhcp4']['interfaces'][0].update(dhcp6=True,state6='stopped')
        with self.assertRaisesRegex(ValueError,'DHCPv6'):self.prepare()

    def test_two_complete_kernel_rounds_and_changed_source_rounds_are_not_selected_away(self):
        calls=[]
        def kernel(name,deadline):
            data=copy.deepcopy(self.source.data[name]);calls.append(name)
            if len(calls)==11:data[1]['mtu']=1500
            return data
        with self.assertRaisesRegex(ValueError,'between samples'):self.prepare(kernel=kernel)
        self.assertEqual(len(calls),20)
        turns=[]
        def dns(deadline):
            row=copy.deepcopy(self.source.records['dns']);turns.append(1)
            if len(turns)==2:row['source']['sha256']='a'*64
            return row
        with self.assertRaisesRegex(ValueError,'between rounds'):self.prepare(dns=dns)

    def test_changed_valid_registration_after_receipt_encoding_withholds_output(self):
        encode=F.MATCH.encoded
        other=copy.deepcopy(self.plan);other['correlation_id']='a'*64
        other['transaction']=other['transaction'].replace(self.plan['correlation_id'],other['correlation_id'])
        other['transaction_sha256']=hashlib.sha256(other['transaction'].encode()).hexdigest();other=encode(other)
        def encoded(value):
            raw=encode(value)
            if type(value) is dict and value.get('schema')=='debian13s4-dns-first-refresh-1':self.leaf.write_bytes(R.envelope(other))
            return raw
        with patch.object(F.MATCH,'encoded',side_effect=encoded),self.assertRaisesRegex(ValueError,'bytes changed'):self.prepare()

    def test_registration_corruption_or_mode_damage_at_receipt_encoding_fails_real_second_load(self):
        encode=F.MATCH.encoded
        for kind in ('bytes','mode'):
            self.leaf.write_bytes(R.envelope(self.original));self.leaf.chmod(0o600)
            def encoded(value):
                raw=encode(value)
                if type(value) is dict and value.get('schema')=='debian13s4-dns-first-refresh-1':
                    if kind=='bytes':self.leaf.write_bytes(b'damaged')
                    else:self.leaf.chmod(0o660)
                return raw
            with self.subTest(kind=kind),patch.object(F.MATCH,'encoded',side_effect=encoded),self.assertRaises(ValueError):self.prepare()

    def test_initial_or_second_real_load_return_expiry_withholds_service_or_final_sources(self):
        clock=self.clock();load=R.load
        for turn in (1,2):
            calls=[];services=[];now=clock[0];service=P.DNS.prepare
            def loaded(*a,**kw):
                raw=load(*a,**kw);calls.append(1)
                if len(calls)==turn:clock[0]=now+61
                return raw
            def prepared(**kw):services.append(1);return service(**kw)
            with self.subTest(turn=turn),patch.object(R,'load',side_effect=loaded),patch.object(P.DNS,'prepare',side_effect=prepared),self.assertRaises(ValueError):self.prepare()
            self.assertEqual(len(calls),turn);self.assertEqual(len(services),0 if turn==1 else 1)

    def test_second_load_lease_expiry_precedes_final_empty_admission(self):
        clock=self.clock();until=int((clock[0]+1)*1000000);load=R.load;loads=[];nft=[]
        for name in ('preferred_until','valid_until'):self.source.records['dhcp4']['attributions'][0][name]=until
        def loaded(*a,**kw):
            raw=load(*a,**kw);loads.append(1)
            if len(loads)==2:clock[0]+=2
            return raw
        fn=self.source.readers()['nft']
        def query(deadline):nft.append(1);return fn(deadline)
        with patch.object(R,'load',side_effect=loaded),self.assertRaisesRegex(ValueError,'attribution expired'):self.prepare(nft=query)
        self.assertEqual(len(loads),2);self.assertEqual(len(nft),2)

    def test_receipt_cap_and_encoding_expiry_precede_second_load(self):
        with patch.object(F,'MAX_OUTPUT',1),patch.object(R,'load',wraps=R.load) as loads,self.assertRaises(ValueError):self.prepare()
        self.assertEqual(loads.call_count,1)
        clock=self.clock();encode=F.MATCH.encoded
        def encoded(value):
            raw=encode(value)
            if type(value) is dict and value.get('schema')=='debian13s4-dns-first-refresh-1':clock[0]+=61
            return raw
        with patch.object(F.MATCH,'encoded',side_effect=encoded),patch.object(R,'load',wraps=R.load) as loads,self.assertRaises(ValueError):self.prepare()
        self.assertEqual(loads.call_count,1)

    def test_each_final_empty_report_still_required_after_second_locked_registration_load(self):
        for name in ('nft','legacy','classifiers','bpf','bpf_links'):
            fn=self.source.readers()[name];calls=[]
            def query(deadline):calls.append(1);return fn(deadline) if len(calls)<3 else {}
            with self.subTest(name=name),patch.object(R,'load',wraps=R.load) as loads,self.assertRaises(ValueError):self.prepare(**{name:query})
            self.assertEqual(len(calls),3);self.assertEqual(loads.call_count,2)

    def test_second_protected_service_change_after_registration_load_still_refuses(self):
        load=R.load;calls=[]
        def loaded(*a,**kw):
            raw=load(*a,**kw);calls.append(1)
            if len(calls)==2:self.source.value['node']='changed';self.source.write()
            return raw
        with patch.object(R,'load',side_effect=loaded),self.assertRaisesRegex(ValueError,'service intention changed'):self.prepare()
        self.assertEqual(len(calls),2)

    def test_repeated_builder_turn_and_preparer_receipt_substitution_cannot_return_success(self):
        real=P._prepare
        def twice(builder,**kw):
            def repeat(record):builder(record);return builder(record)
            return real(repeat,**kw)
        with patch.object(P,'_prepare',side_effect=twice),self.assertRaises(ValueError):self.prepare()
        def changed(builder,**kw):return bytes(bytearray(real(builder,**kw)))
        with patch.object(P,'_prepare',side_effect=changed),self.assertRaisesRegex(ValueError,'different receipt object'):self.prepare()

    def test_no_hash_encoding_compilation_protected_read_or_load_after_complete_preparer_return(self):
        done=[];real=P._prepare
        def prepared(*a,**kw):result=real(*a,**kw);done.append(True);return result
        def checked(fn):
            def call(*a,**kw):self.assertFalse(done);return fn(*a,**kw)
            return call
        with patch.object(P,'_prepare',side_effect=prepared),patch.object(R,'load',side_effect=checked(R.load)), \
            patch.object(F.MATCH,'encoded',side_effect=checked(F.MATCH.encoded)),patch.object(hashlib,'sha256',side_effect=checked(hashlib.sha256)), \
            patch.object(P.DNS.BASE,'read_protected',side_effect=checked(P.DNS.BASE.read_protected)),patch.object(P.MANIFEST,'expected',side_effect=checked(P.MANIFEST.expected)):
            raw=self.prepare()
        self.assertEqual(done,[True]);self.assertIs(type(raw),bytes)

    def test_final_outer_context_type_and_expiry_are_checked_after_preparer_return(self):
        real=P._prepare
        for kind in ('bool','other','expired'):
            now=P.KERNEL.now()
            with patch.object(P.KERNEL,'namespace',return_value=self.namespace) as ns,patch.object(P.KERNEL,'now',return_value=now) as clock:
                def prepared(*a,**kw):
                    result=real(*a,**kw)
                    if kind=='expired':clock.return_value=now+61
                    else:ns.return_value=True if kind=='bool' else self.namespace+1
                    return result
                with self.subTest(kind=kind),patch.object(P,'_prepare',side_effect=prepared),self.assertRaises(ValueError):self.prepare()

    def test_distinct_real_load_expiry_after_readback_refuses_before_any_fresh_service(self):
        clock=self.clock();read=S.read_at
        def readback(*a,**kw):raw=read(*a,**kw);clock[0]+=11;return raw
        with patch.object(S,'read_at',side_effect=readback),patch.object(P.DNS,'prepare',side_effect=AssertionError('service')):
            with self.assertRaisesRegex(ValueError,'storage window'):self.prepare()

    def test_direct_old_first_registration_and_dns_registration_refuse_each_others_complete_envelopes(self):
        old=F.MATCH.module('private_old_first_registration_matrix','first_register.py')
        producer=old_plan_fixture.PlanTests();self.addCleanup(producer.doCleanups);producer.setUp()
        try:payload=producer.prepare()
        finally:producer.doCleanups()
        dns=R.envelope(self.original);generic=old.envelope(payload)
        with self.assertRaises(ValueError):old.checked(dns)
        with self.assertRaises(ValueError):R.checked(generic)
        with self.assertRaises(ValueError):old.envelope(self.original)
        with self.assertRaises(ValueError):R.envelope(payload)
        self.assertEqual(old.LEAF,'first-create.json');self.assertEqual(R.LEAF,'dns-first-create.json')
        self.assertEqual(R.load(self.store),self.original)

    def test_private_actual_twenty_kernel_captures_retain_fixed_argv_env_and_owned_sessions(self):
        binary,ledger=self.source.private_kernel();readers=self.source.readers();del readers['kernel']
        raw=F.prepare(self.store,**readers);rows=[json.loads(line) for line in ledger.read_text().splitlines()]
        self.assertEqual(len(rows),20);self.assertEqual([r['argv'] for r in rows],[['-j','-N',*args] for args in P.KERNEL.COMMANDS.values()]*2)
        for row in rows:
            self.assertEqual(row['env'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'});self.assertEqual(row['pid'],row['sid']);self.assertGreater(row['pid'],0)
        self.assertEqual(json.loads(raw)['proposal'].encode(),self.original);self.assertNotEqual(str(binary),'/usr/bin/ip')
