"""Private whole SOURCE models and fixed owned-child delivery, not host nft.

Native-shaped replies are intention-derived DATA, not formatter/kernel proof.
Addresses, namespace and other explicit settings are finite TEST DATA only.
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

from test_dns_policy import settings, reported, encoded
from test_kernel import policy_input

ROOT = Path(__file__).resolve().parents[1]


def loaded():
    spec=importlib.util.spec_from_file_location('private_dns_manifest',ROOT/'Firewall/dns_manifest.py')
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


def native(policy):
    rows=[{'metainfo':{'version':'1.1.3','release_name':'private DNS intention MODEL','json_schema_version':1}}]
    handle=1
    for kind, values in (('table',[policy['table']]),('chain',policy['chains'].values()),
        ('set',policy['sets'].values()),('rule',[row for chain in policy['rules'].values() for row in chain])):
        for row in values:
            row=copy.deepcopy(row);row['handle']=handle;handle+=1
            if kind=='rule':row['expr'][-2]={'counter':{'packets':3,'bytes':180}}
            rows.append({kind:row})
    return {'nftables':rows}


def objects(value, kind):
    return [entry[kind] for entry in value['nftables'] if kind in entry]


class DNSManifestTests(unittest.TestCase):
    def setUp(self):
        self.m=loaded();self.kernel=reported();self.settings=settings()
        self.raw=policy_input(self.m.COMPILER.KERNEL.normalize(self.kernel['snapshot']))
        self.dns=encoded(self.settings);self.frame=encoded(self.kernel)
        self.expected=self.m.expected(self.raw,self.dns,self.frame)
        self.source=native(self.expected['nft_policy'])

    def verify(self, sources=None, scope=lambda:123456, **kw):
        values=iter(copy.deepcopy([self.source,self.source] if sources is None else sources))
        return self.m.verify(self.raw,self.dns,self.frame,query=lambda deadline:next(values),scope=scope,**kw)

    def test_complete_expected_uses_real_compiler_and_closed_translator_not_hash_shortcut(self):
        actual=self.m.expected(self.raw,self.dns,self.frame)
        compiled=json.loads(self.m.COMPILER.compile_intention(self.raw,self.dns,self.frame))
        self.assertEqual(actual['compiler'],compiled)
        self.assertEqual(actual['nft_fingerprint'],hashlib.sha256(self.m.STATE.encoded(actual['nft_policy'])).hexdigest())
        self.assertEqual(len(actual['nft_policy']['sets']),17)
        self.assertEqual(actual['nft_policy']['rules']['forward'],[])
        self.assertEqual(sum(map(len,actual['nft_policy']['rules'].values())),compiled['policy'].count(' counter '))
        self.assertNotEqual(actual['nft_policy'],self.m.BASE.expected(self.raw)['policy'])

    def test_private_translator_reuses_entire_accepted_bodies_without_mutating_original_globals(self):
        compiler=self.m.BASE.POLICY.compile_policy;old=self.m.BASE.expected(self.raw)
        self.m.expected(self.raw,self.dns,self.frame)
        self.assertIs(self.m.BASE.POLICY.compile_policy,compiler)
        self.assertEqual(self.m.BASE.expected(self.raw),old)
        real=self.m.COMPILER.compile_intention
        def broken(*args):
            value=json.loads(real(*args));value['policy']=value['policy'].replace('table inet','unsupported inet',1)
            return encoded(value)
        with patch.object(self.m.COMPILER,'compile_intention',side_effect=broken),self.assertRaises(ValueError):
            self.m.expected(self.raw,self.dns,self.frame)
        self.assertIs(self.m.BASE.POLICY.compile_policy,compiler)
        self.assertEqual(self.m.BASE.expected(self.raw),old)

    def test_owned_compiler_adapter_refuses_different_topology_and_identity_mismatch(self):
        factory=self.m.module;checks=[]
        def inspected(name,filename):
            result=factory(name,filename);original=result.expected
            def translate(raw):
                with self.assertRaises(self.m.Pending):result.POLICY.compile_policy(raw+b' ')
                with self.assertRaises(self.m.Pending):result.POLICY.compile_policy(bytearray(raw))
                checks.append('owned');return original(raw)
            result.expected=translate;return result
        with patch.object(self.m,'module',side_effect=inspected):self.m.expected(self.raw,self.dns,self.frame)
        self.assertEqual(checks,['owned'])
        real=self.m.COMPILER.compile_intention
        def mismatch(*args):
            value=json.loads(real(*args));value['compiler_sha256']='0'*64;return encoded(value)
        with patch.object(self.m.COMPILER,'compile_intention',side_effect=mismatch),self.assertRaises(self.m.Pending):
            self.m.expected(self.raw,self.dns,self.frame)

    def test_full_canonical_receipt_keeps_compiler_settings_bindings_hashes_source_handles_and_statistics(self):
        raw=self.verify();value=json.loads(raw)
        self.assertEqual(raw,self.m.STATE.encoded(value)+b'\n')
        self.assertEqual(value['state'],'dns-intention-source-correspondence-only')
        self.assertEqual(value['namespace'],123456);self.assertEqual(value['intention'],self.expected)
        self.assertEqual(value['observation'],self.m.STATE.project(self.source))
        self.assertEqual(value['intention']['compiler']['dns_configuration'],self.settings)
        self.assertEqual(value['intention']['compiler']['kernel_snapshot_sha256'],hashlib.sha256(self.frame).hexdigest())

    def test_original_commentless_policy_and_structurally_admitted_accept_all_refuse_whole_intention(self):
        old=native(self.m.BASE.expected(self.raw)['policy'])
        unsafe=copy.deepcopy(self.source)
        for row in objects(unsafe,'rule'):
            if row['chain']=='input':row['expr']=[{'counter':{'packets':0,'bytes':0}},{'accept':None}]
        self.assertTrue(self.m.STATE.project(unsafe))
        for source in (old,unsafe):
            with self.subTest(source=source),self.assertRaises(self.m.Pending):self.verify([source,source])

    def test_every_added_dns_match_and_verdict_remains_bound_in_both_rounds(self):
        original_rules=len(self.m.BASE.expected(self.raw)['policy']['rules']['input'])
        indices=[i for i,row in enumerate(objects(self.source,'rule')) if row['chain']=='input']
        first_added=indices[original_rules]
        for round_number in (0,1):
            for change in ('interface','address','direction','state','port','original_port','verdict'):
                source=copy.deepcopy(self.source);rule=objects(source,'rule')[first_added]
                if change=='verdict':rule['expr'][-1]={'drop':None}
                else:
                    position={'interface':0,'address':1,'direction':2,'state':3,'port':4,'original_port':5}[change]
                    rule['expr'][position]['match']['right']={'interface':'eth1','address':'192.168.50.101',
                        'direction':1,'state':2,'port':54,'original_port':54}[change]
                sources=[copy.deepcopy(self.source),copy.deepcopy(self.source)];sources[round_number]=source
                with self.subTest(round_number=round_number,change=change),self.assertRaises(self.m.Pending):self.verify(sources)

    def test_counter_position_match_order_rule_order_and_named_elements_cannot_be_selected_away(self):
        for change in ('counter','match','rule','set'):
            source=copy.deepcopy(self.source);rule=objects(source,'rule')[-1]
            if change=='counter':rule['expr'].insert(0,rule['expr'].pop(-2))
            elif change=='match':rule['expr'][0],rule['expr'][1]=rule['expr'][1],rule['expr'][0]
            elif change=='rule':
                rows=source['nftables'];a=next(i for i,r in enumerate(rows) if 'rule' in r and r['rule']['chain']=='input')
                rows[a],rows[a+1]=rows[a+1],rows[a]
            else:objects(source,'set')[0]['elem']=['198.51.100.0']
            with self.subTest(change=change),self.assertRaises(self.m.Pending):self.verify([source,source])

    def test_whole_foreign_extra_missing_marked_and_unsupported_objects_refuse(self):
        for extra in ({'table':{'family':'inet','name':'foreign','handle':999}}, {'flowtable':{}},
            {'rule':{'family':'inet','table':'foreign','chain':'input','handle':999,'expr':[]}}):
            source=copy.deepcopy(self.source);source['nftables'].append(extra)
            with self.subTest(extra=extra),self.assertRaises(self.m.Pending):self.verify([source,source])
        for change in ('missing','comment','flags','metadata'):
            source=copy.deepcopy(self.source)
            if change=='missing':source['nftables'].pop()
            elif change=='comment':objects(source,'table')[0]['comment']='forged-public-marker'
            elif change=='flags':objects(source,'table')[0]['flags']=['owner']
            else:source['nftables'][0]['metainfo']['json_schema_version']=True
            with self.subTest(change=change),self.assertRaises(self.m.Pending):self.verify([source,source])

    def test_full_handle_source_metadata_and_nonstatistical_identity_drift_refuse(self):
        for kind in ('table','chain','set','rule','metadata'):
            second=copy.deepcopy(self.source)
            if kind=='metadata':second['nftables'][0]['metainfo']['release_name']='different source'
            else:objects(second,kind)[0]['handle']+=1000
            with self.subTest(kind=kind),self.assertRaises(self.m.Pending):self.verify([self.source,second])

    def test_only_checked_anonymous_statistics_may_vary_or_reset_and_final_values_survive(self):
        second=copy.deepcopy(self.source)
        for row in objects(second,'rule'):row['expr'][-2]={'counter':{'packets':0,'bytes':1}}
        value=json.loads(self.verify([self.source,second]))
        self.assertTrue(value['observation']['statistics'])
        self.assertTrue(all(row['packets']==0 and row['bytes']==1 for row in value['observation']['statistics']))
        self.assertEqual(value['observation']['fingerprint'],self.m.STATE.project(self.source)['fingerprint'])
        for count in (True,-1,1.0,2**64):
            source=copy.deepcopy(self.source);objects(source,'rule')[0]['expr'][-2]['counter']['packets']=count
            with self.subTest(count=count),self.assertRaises(self.m.Pending):self.verify([source,source])

    def test_wrong_typed_context_or_reported_namespace_refuses_before_query(self):
        for scope in (lambda:0,lambda:True,lambda:1.0,lambda:2**64,lambda:123457):
            query=unittest.mock.Mock()
            with self.subTest(scope=scope),self.assertRaises(self.m.Pending):
                self.m.verify(self.raw,self.dns,self.frame,query=query,scope=scope)
            query.assert_not_called()
        for frame in (b'{}',b'\xff',encoded(self.kernel).replace(b'"namespace":123456',b'"namespace":true')):
            query=unittest.mock.Mock()
            with self.assertRaises(ValueError):self.m.verify(self.raw,self.dns,frame,query=query,scope=lambda:123456)
            query.assert_not_called()

    def test_invalid_callback_or_inherited_deadline_refuses_before_compiler_and_query(self):
        for deadline in (True,float('nan'),float('inf'),'10',self.m.KERNEL.now()-1):
            with patch.object(self.m,'expected') as expected,patch.object(self.m.STATE.NFT,'native_query') as query,self.assertRaises(self.m.Pending):
                self.m.verify(self.raw,self.dns,self.frame,query=query,scope=lambda:123456,deadline=deadline)
            expected.assert_not_called();query.assert_not_called()
        for query,scope in ((None,lambda:123456),(lambda end:self.source,None)):
            with patch.object(self.m,'expected') as expected,self.assertRaises(self.m.Pending):
                self.m.verify(self.raw,self.dns,self.frame,query=query,scope=scope)
            expected.assert_not_called()

    def test_one_capped_window_binds_compile_both_queries_and_final_fence(self):
        clock=[100.0];ends=[];real=self.m.expected
        def expected(*args):clock[0]=105.0;return real(*args)
        def query(end):ends.append(end);return copy.deepcopy(self.source)
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m,'expected',side_effect=expected):
            self.m.verify(self.raw,self.dns,self.frame,query=query,scope=lambda:123456,deadline=108.0)
        self.assertEqual(ends,[108.0,108.0])
        clock[0]=100.0;ends=[]
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]):
            self.m.verify(self.raw,self.dns,self.frame,query=query,scope=lambda:123456,deadline=200.0)
        self.assertEqual(ends,[110.0,110.0])

    def test_compile_and_each_read_expiry_withhold_receipt_without_extra_queries(self):
        real=self.m.expected;clock=[100.0];calls=[]
        def expired(*args):value=real(*args);clock[0]=110.0;return value
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m,'expected',side_effect=expired),self.assertRaises(self.m.Pending):
            self.m.verify(self.raw,self.dns,self.frame,query=lambda end:calls.append(end),scope=lambda:123456)
        self.assertEqual(calls,[])
        for when in (1,2):
            clock[0]=100.0;calls=[]
            def query(end):
                calls.append(end)
                if len(calls)==when:clock[0]=end
                return copy.deepcopy(self.source)
            with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),self.assertRaises(self.m.Pending):
                self.m.verify(self.raw,self.dns,self.frame,query=query,scope=lambda:123456)
            self.assertEqual(len(calls),when)

    def test_entire_receipt_encodes_before_final_context_without_post_fence_work(self):
        events=[];encode=self.m.STATE.encoded;factory=self.m.expected
        def expected(*args):events.append('compile');return factory(*args)
        def encoding(value):
            if type(value) is dict and value.get('state')=='dns-intention-source-correspondence-only':events.append('encode')
            return encode(value)
        def query(end):events.append('query');return copy.deepcopy(self.source)
        with patch.object(self.m,'expected',side_effect=expected),patch.object(self.m.STATE,'encoded',side_effect=encoding):
            self.m.verify(self.raw,self.dns,self.frame,query=query,scope=lambda:events.append('scope') or 123456)
        self.assertEqual(events,['scope','compile','query','query','encode','scope'])

    def test_final_true_integer_context_and_after_encoding_time_are_required(self):
        for last in (True,123456.0,123457,0):
            scopes=iter((123456,last))
            with self.subTest(last=last),self.assertRaises(self.m.Pending):self.verify(scope=lambda:next(scopes))
        clock=[100.0];encode=self.m.STATE.encoded
        def encoding(value):
            raw=encode(value)
            if type(value) is dict and value.get('state')=='dns-intention-source-correspondence-only':clock[0]=110.0
            return raw
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.STATE,'encoded',side_effect=encoding),self.assertRaises(self.m.Pending):self.verify()

    def test_receipt_only_bound_refuses_after_complete_policy_without_relaxing_compiler(self):
        amount=len(self.verify())
        self.assertLess(len(self.expected['compiler']['policy'].encode()),amount)
        with patch.object(self.m,'MAX_OUTPUT',amount-1),self.assertRaises(self.m.Pending):self.verify()
        with patch.object(self.m,'MAX_OUTPUT',amount):self.assertEqual(len(self.verify()),amount)

    def test_no_cli_store_transport_assembly_or_protected_file_entry_is_joined(self):
        self.assertFalse(hasattr(self.m,'main'));self.assertFalse(hasattr(self.m,'transmit'))
        with (patch.object(self.m.COMPILER.DNS.BASE,'read_protected',side_effect=AssertionError('no disk')),
              patch.object(self.m.KERNEL.subprocess,'Popen',side_effect=AssertionError('no native'))):
            raw=self.verify()
        self.assertEqual(json.loads(raw)['state'],'dns-intention-source-correspondence-only')


class DNSManifestPrivateCaptureTests(unittest.TestCase):
    def setUp(self):
        private=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(private.cleanup)
        self.root=Path(private.name);self.root.chmod(0o700);self.m=loaded()
        self.m.KERNEL.TRUST_ROOT=self.root;self.m.KERNEL.TRUSTED_UID=os.getuid()
        self.binary=self.root/'nft-model';self.m.STATE.NFT.BINARY=self.binary;self.ledger=self.root/'ledger'
        self.kernel=reported();self.settings=settings()
        self.raw=policy_input(self.m.COMPILER.KERNEL.normalize(self.kernel['snapshot']))
        self.dns=encoded(self.settings);self.frame=encoded(self.kernel)
        self.source=native(self.m.expected(self.raw,self.dns,self.frame)['nft_policy'])

    def executable(self, body=None):
        if body is None:body='print('+json.dumps(self.source).__repr__()+')\n'
        code=('#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\n'
            f'with open({str(self.ledger)!r},"a") as f:f.write(json.dumps({{"argv":sys.argv[1:],"env":dict(os.environ),"pid":os.getpid(),"sid":os.getsid(0)}})+"\\n")\n'+body)
        self.binary.write_text(code);self.binary.chmod(0o700)

    def verify(self):
        return self.m.verify(self.raw,self.dns,self.frame,query=self.m.STATE.NFT.native_query,scope=lambda:123456)

    def test_actual_private_fixed_capture_preserves_two_argv_environment_and_session_records(self):
        self.executable();value=json.loads(self.verify());rows=[json.loads(row) for row in self.ledger.read_text().splitlines()]
        self.assertEqual(value['state'],'dns-intention-source-correspondence-only')
        self.assertEqual(len(rows),2)
        for row in rows:
            self.assertEqual(row['argv'],['--json','--numeric','--handle','list','ruleset'])
            self.assertEqual(row['env'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
            self.assertEqual(row['pid'],row['sid']);self.assertGreater(row['pid'],0)
        self.assertEqual(value['observation']['source']['binary'],str(self.binary))

    def test_warning_nonzero_malformed_and_foreign_actual_delivery_refuse(self):
        foreign=copy.deepcopy(self.source);foreign['nftables'].append({'flowtable':{}})
        for body in ("print('{')\n",'raise SystemExit(1)\n',
            'print('+json.dumps(self.source).__repr__()+');print("warning",file=sys.stderr)\n',
            'print('+json.dumps(foreign).__repr__()+')\n'):
            self.executable(body)
            with self.subTest(body=body),self.assertRaises(self.m.Pending):self.verify()

    def test_actual_second_read_handle_drift_refuses_even_matching_complete_policy(self):
        body=(f'p=Path({str(self.root/"turn")!r});n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))\n'
            f'v=json.loads({json.dumps(self.source)!r});v["nftables"][1]["table"]["handle"]+=n;print(json.dumps(v))\n')
        self.executable(body)
        with self.assertRaisesRegex(self.m.Pending,'facts changed'):self.verify()
        self.assertEqual((self.root/'turn').read_text(),'2')

    def test_bad_reported_context_precedes_actual_private_child_entry(self):
        self.executable();self.kernel['namespace']=123457;self.frame=encoded(self.kernel)
        with self.assertRaises(self.m.Pending):self.verify()
        self.assertFalse(self.ledger.exists())


if __name__ == '__main__':unittest.main()
