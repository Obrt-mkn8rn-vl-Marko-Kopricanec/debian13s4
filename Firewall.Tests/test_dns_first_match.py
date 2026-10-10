"""Historical/marked SOURCE models, not current files/NSS/native ownership.

Finite explicit TEST DATA and private fixed-child deliveries only. New matrix
coverage belongs to these controls, not to sealed e5ce execution/history.
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

import test_dns_first_create as plan_fixture
import test_dns_manifest as native_fixture

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('private_dns_first_match',ROOT/'Firewall/dns_first_match.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)


class DNSFirstMatchTests(unittest.TestCase):
    def setUp(self):
        self.producer=plan_fixture.DNSFirstCreateTests();self.addCleanup(self.producer.doCleanups);self.producer.setUp()
        self.payload=self.producer.prepare();self.plan=json.loads(self.payload)
        self.source=json.loads(self.plan['source_intention']);self.service=json.loads(self.source['service_intention'])
        self.namespace=self.plan['namespace']
        self.native=native_fixture.native(self.source['intention']['nft_policy'])
        native_fixture.objects(self.native,'table')[0]['comment']=M.PLAN.COMMENT_PREFIX+self.plan['correlation_id']

    def repack(self, plan=None, source=None, service=None):
        plan=copy.deepcopy(self.plan if plan is None else plan)
        source=copy.deepcopy(self.source if source is None else source)
        if service is not None:
            source['service_intention']=M.encoded(service).decode();source['service_sha256']=M.digest(M.encoded(service))
        plan['source_intention']=M.encoded(source).decode();plan['source_sha256']=M.digest(M.encoded(source))
        plan['transaction_sha256']=M.digest(plan['transaction'].encode())
        return M.encoded(plan)

    def verify(self, values=None, **kw):
        values=iter(copy.deepcopy([self.native,self.native] if values is None else values))
        return M.verify(self.payload,query=lambda end:next(values),scope=lambda:self.namespace,**kw)

    def test_complete_canonical_historical_plan_and_whole_receipt_commitments_recompute(self):
        self.assertEqual(M.checked(self.payload),self.plan)
        raw=self.verify();value=json.loads(raw)
        self.assertEqual(raw,M.encoded(value))
        self.assertEqual(value['state'],'dns-first-create-source-correspondence-only')
        self.assertEqual(value['proposal_sha256'],M.digest(self.payload))
        self.assertEqual(value['source_sha256'],self.plan['source_sha256'])
        self.assertEqual(value['transaction_sha256'],self.plan['transaction_sha256'])
        self.assertEqual(value['intention'],self.source['intention'])
        self.assertEqual(value['observation']['comment'],M.PLAN.COMMENT_PREFIX+self.plan['correlation_id'])
        self.assertEqual(value['observation']['policy'],M.MARKED.project(self.native,value['observation']['comment'])['policy'])

    def test_checker_never_reads_current_files_queries_current_context_or_native_entries(self):
        with patch.object(M.DNS.BASE,'read_protected',side_effect=AssertionError('files')), \
            patch.object(M.DNS,'prepare',side_effect=AssertionError('prepare')), \
            patch.object(M.KERNEL,'namespace',side_effect=AssertionError('scope')), \
            patch.object(M.KERNEL,'now',side_effect=AssertionError('clock')), \
            patch.object(M.STATE.NFT,'native_query',side_effect=AssertionError('query')):
            self.assertEqual(M.checked(self.payload),self.plan)

    def test_recomputed_outer_hashes_cannot_repair_destructive_or_unsafe_transaction(self):
        for text in (self.plan['transaction'].replace('create table','destroy table',1),
            self.plan['transaction'].replace('policy drop;','policy accept;',1),
            self.plan['transaction']+'flush ruleset\n'):
            value=copy.deepcopy(self.plan);value['transaction']=text
            with self.subTest(text=text[:30]),self.assertRaises(ValueError):M.checked(self.repack(plan=value))

    def test_whole_real_compiler_translator_and_all_three_inputs_are_independently_bound(self):
        for path in ('policy','hash','bindings','expected','fingerprint','kernel','settings','topology'):
            source=copy.deepcopy(self.source)
            if path=='policy':source['intention']['compiler']['policy']=source['intention']['compiler']['policy'].replace('policy drop;','policy accept;',1)
            elif path=='hash':source['intention']['compiler']['compiler_sha256']='0'*64
            elif path=='bindings':source['intention']['compiler']['bindings'][0]['address']='192.168.50.101'
            elif path=='expected':source['intention']['nft_policy']['chains']['input']['policy']='accept'
            elif path=='fingerprint':source['intention']['nft_fingerprint']='0'*64
            elif path=='kernel':
                data=json.loads(source['kernel_snapshot']);data['namespace']+=1;source['kernel_snapshot']=M.encoded(data).decode()
            elif path=='settings':
                data=json.loads(source['dns_configuration']);data['node']='changed';source['dns_configuration']=M.encoded(data).decode()
            else:
                data=json.loads(source['topology']);data['dns'][0]['address']='192.168.50.2';source['topology']=M.encoded(data)[:-1].decode()
            with self.subTest(path=path),self.assertRaises(ValueError):M.checked(self.repack(source=source))

    def test_whole_units_and_argv_must_equal_real_settings_render_even_with_repaired_hashes(self):
        for change in ('unit','argv','listener','ipc','state','hash'):
            service=copy.deepcopy(self.service);unit=M.DNS.APP_UNIT
            if change=='unit':service['plan']['units'][unit]+='ExecStartPost=/bin/sh\n';service['unit_sha256'][unit]=M.digest(service['plan']['units'][unit].encode())
            elif change=='argv':service['plan']['argv'][unit].append('--control')
            elif change=='listener':service['plan']['listeners'][0]['port']=54
            elif change=='ipc':service['plan']['ipc']['socket_mode']='0777'
            elif change=='state':service['plan']['state_directory']='/tmp/unsafe'
            else:service['unit_sha256'][unit]='0'*64
            with self.subTest(change=change),self.assertRaises(ValueError):M.checked(self.repack(service=service))

    def test_closed_outer_source_and_service_schema_types_names_and_states_refuse(self):
        for level in ('plan','source','service'):
            original={'plan':self.plan,'source':self.source,'service':self.service}[level]
            for field,value in (('schema',True),('state','ready'),('namespace',True),('namespace',self.namespace+1),('extra',1)):
                changed=copy.deepcopy(original);changed[field]=value
                settings={'plan':changed} if level=='plan' else {level:changed}
                with self.subTest(level=level,field=field),self.assertRaises(ValueError):M.checked(self.repack(**settings))

    def test_correlations_and_nested_hashes_require_complete_exact_commitments(self):
        for value in ('f'*63,'F'*64,True,None,'f'*63+'\n'):
            plan=copy.deepcopy(self.plan);plan['correlation_id']=value
            with self.subTest(value=value),self.assertRaises(ValueError):M.checked(self.repack(plan=plan))
        for level,field in (('plan','source_sha256'),('plan','transaction_sha256'),('source','service_sha256')):
            plan=copy.deepcopy(self.plan);source=copy.deepcopy(self.source)
            if level=='plan':plan[field]='0'*64;raw=M.encoded(plan)
            else:source[field]='0'*64;raw=self.repack(source=source)
            with self.subTest(field=field),self.assertRaises(ValueError):M.checked(raw)

    def test_noncanonical_duplicate_nonfinite_float_unicode_and_recursive_records_refuse(self):
        for raw in (self.payload+b'\n',self.payload[:-1],bytearray(self.payload),
            self.payload.replace(b'"namespace":',b'"namespace":0,"namespace":',1),
            self.payload.replace(b'"namespace":'+str(self.namespace).encode(),b'"namespace":1.0',1),
            self.payload.replace(b'"namespace":'+str(self.namespace).encode(),b'"namespace":NaN',1),
            b'\xff',b'['*1500+b'0'+b']'*1500):
            with self.subTest(type=type(raw).__name__),self.assertRaises(ValueError):M.checked(raw)
        source=copy.deepcopy(self.source);source['service_intention']='\ud800'
        with self.assertRaises(ValueError):M.checked(self.repack(source=source))

    def test_outer_and_nested_bounds_precede_decode_and_recompilation(self):
        with patch.object(M.PLAN,'MAX_OUTPUT',1),patch.object(M.COMPILER,'decode',side_effect=AssertionError('decode')):
            with self.assertRaises(ValueError):M.checked(self.payload)
        with patch.object(M.PREPARE,'MAX_OUTPUT',1),patch.object(M.MANIFEST,'expected',side_effect=AssertionError('compile')):
            with self.assertRaises(ValueError):M.checked(self.payload)
        with patch.object(M.DNS,'MAX_OUTPUT',1),patch.object(M.MANIFEST,'expected',side_effect=AssertionError('compile')):
            with self.assertRaises(ValueError):M.checked(self.payload)

    def test_reported_file_identity_shapes_and_configuration_digest_length_are_checked(self):
        for key in ('configuration','user_source','group_source'):
            for field,value in (('path','relative'),('path','/etc/../passwd'),('sha256','G'*64),
                ('identity',[]),('identity',[1,1,True,0,0,1,0,0]),('identity',[1,0,0o100600,0,0,1,0,0]),
                ('identity',[1,1,0o120777,0,0,1,0,0]),('identity',[1,1,0o100622,0,0,1,0,0]),
                ('identity',[1,1,0o100600,0,0,1,True,0])):
                service=copy.deepcopy(self.service);row=service[key]['source'] if key=='configuration' else service[key];row[field]=value
                with self.subTest(key=key,field=field,value=value),self.assertRaises(ValueError):M.checked(self.repack(service=service))
        for change in ('hash','size','private'):
            service=copy.deepcopy(self.service);row=service['configuration']['source']
            if change=='hash':row['sha256']='0'*64
            elif change=='size':row['identity'][5]+=1
            else:row['identity'][2]=0o100644
            with self.subTest(change=change),self.assertRaises(ValueError):M.checked(self.repack(service=service))

    def test_reported_selected_accounts_and_ipc_group_are_typed_distinct_nonlogin_system_facts(self):
        user=next(iter(self.service['accounts']['users']))
        for field,value in (('uid',True),('uid',0),('uid',1000),('primary_gid',0),('shell','/bin/bash')):
            service=copy.deepcopy(self.service);service['accounts']['users'][user][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):M.checked(self.repack(service=service))
        for change in ('uid','gid','ipc','members'):
            service=copy.deepcopy(self.service);users=list(service['accounts']['users'].values())
            if change=='uid':users[1]['uid']=users[0]['uid']
            elif change=='gid':users[1]['primary_gid']=users[0]['primary_gid']
            elif change=='ipc':service['accounts']['ipc_group']['gid']=users[0]['primary_gid']
            else:service['accounts']['ipc_group']['members']=[]
            with self.subTest(change=change),self.assertRaises(ValueError):M.checked(self.repack(service=service))

    def test_forgeable_shape_valid_history_does_not_attest_files_nss_inventory_or_ownership(self):
        service=copy.deepcopy(self.service)
        service['user_source']['sha256']='0'*64
        service['user_source']['identity'][6]=-1
        user=next(iter(service['accounts']['users']));service['accounts']['users'][user]['uid']=407
        raw=self.repack(service=service)
        with patch.object(M.DNS.BASE,'read_protected',side_effect=AssertionError('current files')):
            self.assertEqual(M.checked(raw),json.loads(raw))
        self.assertNotEqual(json.loads(raw)['source_sha256'],self.plan['source_sha256'])

    def test_missing_wrong_duplicate_or_extra_table_markers_refuse_whole_dump(self):
        for change in ('missing','wrong','oldprefix','duplicate','foreign'):
            value=copy.deepcopy(self.native);table=native_fixture.objects(value,'table')[0]
            if change=='missing':del table['comment']
            elif change=='wrong':table['comment']=M.PLAN.COMMENT_PREFIX+'0'*64
            elif change=='oldprefix':table['comment']='debian13s4-first-create-v1-'+'f'*64
            elif change=='duplicate':value['nftables'].append({'table':copy.deepcopy(table)})
            else:value['nftables'].append({'flowtable':{}})
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify([value,value])

    def test_matching_marker_on_structurally_admitted_accept_all_policy_is_not_safe_intention(self):
        value=copy.deepcopy(self.native)
        for rule in native_fixture.objects(value,'rule'):
            if rule['chain']=='input':rule['expr']=[{'counter':{'packets':0,'bytes':0}},{'accept':None}]
        self.assertIn('policy',M.MARKED.project(value,M.PLAN.COMMENT_PREFIX+self.plan['correlation_id']))
        with self.assertRaisesRegex(ValueError,'complete DNS intention'):self.verify([value,value])

    def test_each_added_dns_rule_match_and_verdict_is_corrupted_in_each_round(self):
        base=M.MANIFEST.BASE.expected(self.source['topology'].encode())['policy']['rules']
        expected=self.source['intention']['nft_policy']['rules'];rules=native_fixture.objects(self.native,'rule')
        added=[]
        for chain in ('input','output'):
            originals=base[chain]
            for index,row in enumerate(rules):
                if row['chain']==chain and {k:v for k,v in row.items() if k!='handle'} not in originals:
                    # Compare canonical projected rules: native counters carry statistics.
                    projection=M.MARKED.project(self.native,M.PLAN.COMMENT_PREFIX+self.plan['correlation_id'])['policy']['rules'][chain]
                    local=sum(rule['chain']==chain for rule in rules[:index])
                    if projection[local] not in originals:added.append(index)
        self.assertEqual(len(added),12);visited=[]
        for index in added:
            for position,statement in enumerate(rules[index]['expr']):
                if not ('match' in statement or position==len(rules[index]['expr'])-1):continue
                for round_number in (0,1):
                    value=copy.deepcopy(self.native);row=native_fixture.objects(value,'rule')[index]
                    if 'match' in statement:
                        original=statement['match']['right']
                        row['expr'][position]['match']['right']=original+'-wrong' if type(original) is str else (1 if original!=1 else 2)
                    else:row['expr'][position]={'drop':None} if 'accept' in statement else {'accept':None}
                    pair=[copy.deepcopy(self.native),copy.deepcopy(self.native)];pair[round_number]=value
                    with self.subTest(rule=index,position=position,round=round_number),self.assertRaises(ValueError):self.verify(pair)
                    visited.append((index,position,round_number))
        self.assertEqual({i for i,_,_ in visited},set(added))
        self.assertEqual({r for _,_,r in visited},{0,1})

    def test_anonymous_uint64_statistics_may_vary_and_reset_but_not_type_or_position(self):
        changed=copy.deepcopy(self.native)
        for rule in native_fixture.objects(changed,'rule'):rule['expr'][-2]['counter']={'packets':0,'bytes':(1<<64)-1}
        value=json.loads(self.verify([self.native,changed]))
        self.assertTrue(all(r['packets']==0 and r['bytes']==(1<<64)-1 for r in value['observation']['statistics']))
        for packets in (True,-1,1<<64,1.0):
            bad=copy.deepcopy(self.native);native_fixture.objects(bad,'rule')[0]['expr'][-2]['counter']['packets']=packets
            with self.subTest(packets=packets),self.assertRaises(ValueError):self.verify([self.native,bad])

    def test_handles_metainfo_rule_order_and_unsupported_objects_are_not_filtered_away(self):
        for change in ('table','set','rule','meta','order','foreign'):
            value=copy.deepcopy(self.native)
            if change in ('table','set','rule'):native_fixture.objects(value,change)[0]['handle']+=1000
            elif change=='meta':value['nftables'][0]['metainfo']['version']='changed'
            elif change=='order':
                indices=[i for i,row in enumerate(value['nftables']) if 'rule' in row and row['rule']['chain']=='input'];a,b=indices[:2];value['nftables'][a],value['nftables'][b]=value['nftables'][b],value['nftables'][a]
            else:value['nftables'].append({'map':{}})
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify([self.native,value])

    def test_deadlines_deliveries_initial_context_and_historical_mismatch_precede_queries(self):
        for deadline in (True,float('nan'),float('inf'),'future',M.KERNEL.now()-1,10**10000):
            with self.subTest(kind=type(deadline).__name__),self.assertRaises(ValueError):M.verify(self.payload,query=lambda end:self.fail('query'),deadline=deadline)
        for scope in (lambda:True,lambda:0,lambda:self.namespace+1):
            with self.assertRaises(ValueError):M.verify(self.payload,query=lambda end:self.fail('query'),scope=scope)
        for query,scope in ((None,lambda:self.namespace),(lambda end:self.native,None)):
            with self.assertRaises(ValueError):M.verify(self.payload,query=query,scope=scope)

    def test_complete_receipt_encoding_precedes_final_typed_context_and_time(self):
        events=[];real=M.encoded
        def encode(value):
            if type(value) is dict and value.get('state')=='dns-first-create-source-correspondence-only':events.append('receipt')
            return real(value)
        with patch.object(M,'encoded',side_effect=encode):
            M.verify(self.payload,query=lambda end:events.append('query') or copy.deepcopy(self.native),scope=lambda:events.append('scope') or self.namespace)
        self.assertEqual(events,['scope','query','query','receipt','scope'])
        for final in (True,self.namespace+1,self.namespace*1.0):
            scope=iter((self.namespace,final))
            with self.subTest(final=final),self.assertRaises(ValueError):M.verify(self.payload,query=lambda end:copy.deepcopy(self.native),scope=lambda:next(scope))
        instant=M.KERNEL.now()
        def expire(value):
            raw=real(value)
            if type(value) is dict and value.get('state')=='dns-first-create-source-correspondence-only':clock.return_value=instant+11
            return raw
        with patch.object(M.KERNEL,'now',return_value=instant) as clock,patch.object(M,'encoded',side_effect=expire):
            with self.assertRaises(ValueError):self.verify()

    def test_complete_comparison_receipt_cap_is_independent_of_safe_plan(self):
        with patch.object(M,'MAX_OUTPUT',1),self.assertRaisesRegex(ValueError,'receipt exceeds'):self.verify()

    def private(self, body=None):
        private=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(private.cleanup)
        root=Path(private.name);root.chmod(0o700);binary=root/'nft';ledger=root/'ledger.ndjson'
        script=('#!/usr/bin/python3 -B\nimport json,os,sys\nfrom pathlib import Path\n'
            f'ledger=Path({str(ledger)!r})\n'
            "with ledger.open('a') as f:f.write(json.dumps({'argv':sys.argv[1:],'env':dict(os.environ),'pid':os.getpid(),'sid':os.getsid(0)})+'\\n')\n")
        if body is None:body='print('+repr(json.dumps(self.native))+')\n'
        binary.write_text(script+body);binary.chmod(0o700)
        for owner,key,value in ((M.STATE.NFT,'BINARY',binary),(M.MARKED.STATE.NFT,'BINARY',binary),
            (M.STATE.NFT.KERNEL,'TRUST_ROOT',root),(M.STATE.NFT.KERNEL,'TRUSTED_UID',os.getuid())):
            adapter=patch.object(owner,key,value);adapter.start();self.addCleanup(adapter.stop)
        return root,binary,ledger

    def test_two_actual_private_fixed_nft_captures_keep_argv_env_sessions_and_marked_source(self):
        root,binary,ledger=self.private()
        value=json.loads(M.verify(self.payload,query=M.STATE.NFT.native_query,scope=lambda:self.namespace))
        rows=[json.loads(line) for line in ledger.read_text().splitlines()]
        self.assertEqual(len(rows),2)
        for row in rows:
            self.assertEqual(row['argv'],['--json','--numeric','--handle','list','ruleset'])
            self.assertEqual(row['env'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
            self.assertEqual(row['pid'],row['sid']);self.assertGreater(row['pid'],0)
        self.assertEqual(value['observation']['source']['binary'],str(binary))

    def test_actual_private_warning_nonzero_foreign_and_handle_drift_withhold_receipt(self):
        foreign=copy.deepcopy(self.native);foreign['nftables'].append({'map':{}})
        drift=("n=len(ledger.read_text().splitlines())\n"+f'value=json.loads({json.dumps(self.native)!r})\n'+
            "value['nftables'][1]['table']['handle']+=n\nprint(json.dumps(value))\n")
        for body in ('print('+repr(json.dumps(self.native))+');print("warning",file=sys.stderr)\n',
            'raise SystemExit(9)\n','print('+repr(json.dumps(foreign))+')\n',drift):
            root,binary,ledger=self.private(body)
            with self.subTest(body=body[:24]),self.assertRaises(ValueError):M.verify(self.payload,query=M.STATE.NFT.native_query,scope=lambda:self.namespace)
            self.assertEqual(len(ledger.read_text().splitlines()),2 if body==drift else 1)

    def test_invalid_historical_bytes_or_wrong_context_precede_actual_private_child_entry(self):
        root,binary,ledger=self.private()
        for payload,scope in ((self.payload+b'\n',lambda:self.namespace),(self.payload,lambda:self.namespace+1)):
            with self.subTest(payload=payload[-2:]),self.assertRaises(ValueError):M.verify(payload,query=M.STATE.NFT.native_query,scope=scope)
        self.assertFalse(ledger.exists())
