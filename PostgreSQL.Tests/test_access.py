"""Protected inputs/fixed private peer-capture SOURCE models, no real SQL/NSS."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from fixture_pg import PrivatePG, ROOT


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.fixture=PrivatePG();self.addCleanup(self.fixture.close)
        context=self.fixture.context();context.__enter__();self.addCleanup(context.close)
        spec=importlib.util.spec_from_file_location('private_pg_access',ROOT/'PostgreSQL/access.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.m.LIVE=self.fixture.m;self.m.PREP=self.fixture.m.PREP;self.m.KERNEL=self.fixture.m.KERNEL
        self.m.Pending=self.fixture.m.Pending;self.calls=[]

    def reply(self,app):
        role=self.fixture.value['applications'][app]['role']
        return json.loads((self.fixture.root/('peer-'+role+'.json')).read_bytes())

    def read(self,kind,end):
        self.calls.append((kind,end))
        return json.dumps(self.reply(kind[5:]) if kind.startswith('peer:') else self.fixture.reply).encode()

    def check(self,**kw):return self.m.check(**({'read':self.read}|kw))

    def test_real_admin_and_two_complete_peer_rounds_bind_both_explicit_applications(self):
        raw=self.check();value=json.loads(raw)
        self.assertEqual(value['state'],'enrolled-local-postgresql-peer-source-only')
        self.assertEqual(value['namespace'],4711);self.assertEqual(value['admin']['catalog'],self.fixture.reply)
        self.assertEqual(value['applications'],{app:self.reply(app) for app in self.fixture.value['applications']})
        self.assertEqual(raw,self.m.PREP.canonical(value))
        self.assertEqual([kind for kind,_ in self.calls],['catalog','catalog','peer:mk8.dns','peer:mk8.email','peer:mk8.dns','peer:mk8.email','catalog','catalog'])
        self.assertEqual(len({end for _,end in self.calls}),1)

    def test_each_peer_session_identity_and_typed_fact_refuses_in_each_round(self):
        for app in self.m.PREP.APPLICATIONS:
            for field,bad in (('version',True),('version',170007),('user','postgres'),('database','postgres'),
                    ('client','127.0.0.1'),('authentication','trust'),('authentication',None),('start','other server'),
                    ('recovery',True),('read_only',True),('read_only',0),('recovery',0)):
                for round_number in (0,1):
                    count=[]
                    def read(kind,end):
                        if kind!='peer:'+app:return self.read(kind,end)
                        value=self.reply(app);count.append(1)
                        if len(count)==round_number+1:value[field]=bad
                        return json.dumps(value).encode()
                    with self.subTest(app=app,field=field,round=round_number),self.assertRaises(ValueError):self.m.check(read=read)

    def test_each_selected_role_flag_requires_the_exact_boolean_contract(self):
        for app in self.m.PREP.APPLICATIONS:
            for field in self.reply(app)['role']:
                for bad in (not (field=='login'),0,1,None):
                    value=self.reply(app);value['role'][field]=bad
                    with self.subTest(app=app,field=field,bad=bad),self.assertRaises(ValueError):
                        self.m.peer(value,app,self.fixture.record,self.fixture.reply)

    def test_database_owner_encoding_each_effective_right_and_public_acl_refuse(self):
        for app in self.m.PREP.APPLICATIONS:
            for field,bad in (('owner','postgres'),('encoding','SQL_ASCII'),('connect',False),('create',False),
                    ('temp',False),('public_access',True),('connect',1),('public_access',0)):
                value=self.reply(app);value['database_access'][field]=bad
                with self.subTest(app=app,field=field),self.assertRaises(ValueError):
                    self.m.peer(value,app,self.fixture.record,self.fixture.reply)

    def test_public_schema_owner_effective_usage_create_and_public_create_refuse(self):
        for app in self.m.PREP.APPLICATIONS:
            for field,bad in (('owner','postgres'),('usage',False),('create',False),('public_create',True),
                    ('usage',1),('public_create',0)):
                value=self.reply(app);value['schema_access'][field]=bad
                with self.subTest(app=app,field=field),self.assertRaises(ValueError):
                    self.m.peer(value,app,self.fixture.record,self.fixture.reply)
            value=self.reply(app);value['schema_access']['owner']=self.fixture.value['applications'][app]['role']
            self.assertEqual(self.m.peer(value,app,self.fixture.record,self.fixture.reply),value)

    def test_every_peer_object_is_closed_and_required_null_or_array_deliveries_refuse(self):
        for name in (None,'role','database_access','schema_access'):
            for change in ('extra','missing','null','array'):
                value=self.reply('mk8.dns');row=value if name is None else value[name]
                if change=='extra':row['foreign']=True
                elif change=='missing':del row[next(iter(row))]
                elif name is None:value=None if change=='null' else []
                else:value[name]=None if change=='null' else []
                with self.subTest(name=name,change=change),self.assertRaises(ValueError):
                    self.m.peer(value,'mk8.dns',self.fixture.record,self.fixture.reply)

    def test_swapped_application_reply_cannot_satisfy_other_configured_peer(self):
        with self.assertRaises(ValueError):
            self.m.peer(self.reply('mk8.email'),'mk8.dns',self.fixture.record,self.fixture.reply)
        for app in ('foreign',True,None):
            with self.subTest(app=app),self.assertRaises(ValueError):
                self.m.peer(self.reply('mk8.dns'),app,self.fixture.record,self.fixture.reply)

    def test_same_admitted_privileges_but_changed_schema_owner_between_rounds_refuse(self):
        count=[]
        def read(kind,end):
            if kind!='peer:mk8.dns':return self.read(kind,end)
            value=self.reply('mk8.dns');count.append(1)
            if len(count)==2:value['schema_access']['owner']='dns_demo'
            return json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError,'peer SOURCE changed'):self.m.check(read=read)
        self.assertEqual(len(count),2)

    def test_server_change_after_peers_is_rejected_by_real_selected_admin_checker(self):
        count=[]
        def read(kind,end):
            if kind!='catalog':return self.read(kind,end)
            value=copy.deepcopy(self.fixture.reply);count.append(1)
            if len(count)>2:value['start']='new postmaster'
            return json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError,'admin SOURCE changed'):self.m.check(read=read)
        self.assertEqual(len(count),4)

    def test_admin_failure_prevents_any_application_peer_attempt(self):
        value=copy.deepcopy(self.fixture.reply);value['roles'][1]['super']=True
        def read(kind,end):
            self.assertEqual(kind,'catalog');return json.dumps(value).encode()
        with self.assertRaises(ValueError):self.m.check(read=read)

    def test_invalid_missing_or_changed_protected_inputs_never_allow_a_peer(self):
        self.m.PREP.INPUT.chmod(0o644)
        with self.assertRaises(ValueError):self.m.check(read=lambda *args:self.fail('native reached'))
        self.m.PREP.INPUT.chmod(0o600);self.m.LIVE.ENROLLMENT.unlink()
        with self.assertRaises(OSError):self.m.check(read=lambda *args:self.fail('native reached'))

    def test_invalid_deliveries_deadlines_and_typed_context_refuse_before_admin_entry(self):
        for deadline in (True,float('inf'),float('nan'),'later',self.m.KERNEL.now()-1,10**10000):
            with self.subTest(kind=type(deadline).__name__),self.assertRaises(ValueError):
                self.m.check(read=lambda *args:self.fail('native'),deadline=deadline)
        for context in (True,0,-1,1<<64,'1'):
            with patch.object(self.m.KERNEL,'namespace',return_value=context),self.assertRaises(ValueError):
                self.m.check(read=lambda *args:self.fail('native'))
        with self.assertRaises(ValueError):self.m.check(read=False)

    def test_positive_inherited_deadline_is_capped_for_every_real_admin_and_peer_read(self):
        start=self.m.KERNEL.now();end=start+2
        with patch.object(self.m.KERNEL,'now',return_value=start):self.check(deadline=end)
        self.assertEqual({window for _,window in self.calls},{end})

    def test_raw_peer_bounds_duplicate_nonfinite_float_utf8_and_nonbytes_refuse(self):
        good=json.dumps(self.reply('mk8.dns')).encode()
        raws=(bytearray(good),b'',b'[]',b'\xff',b'x'*(self.m.LIVE.MAX_BYTES+1),
            good.replace(b'{',b'{"user":"foreign",',1),good.replace(b'170006',b'NaN'),good.replace(b'170006',b'170006.0'))
        for raw in raws:
            def read(kind,end):return raw if kind.startswith('peer:') else self.read(kind,end)
            with self.subTest(kind=type(raw).__name__,size=len(raw)),self.assertRaises(ValueError):self.m.check(read=read)

    def test_expiry_after_each_delivered_peer_withholds_the_complete_receipt(self):
        for position in range(1,5):
            start=self.m.KERNEL.now();clock=[start];count=[]
            def read(kind,end):
                value=self.read(kind,end)
                if kind.startswith('peer:'):
                    count.append(1)
                    if len(count)==position:clock[0]=start+11
                return value
            with self.subTest(position=position),patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),self.assertRaises(ValueError):self.m.check(read=read)
            self.assertEqual(len(count),position)

    def test_encoding_precedes_final_real_intention_read_and_typed_scope_time_fences(self):
        real=self.m.PREP.canonical;events=[];intention=self.m.LIVE.intention
        def encode(value):
            raw=real(value)
            if type(value) is dict and value.get('state')=='enrolled-local-postgresql-peer-source-only':events.append('receipt')
            return raw
        def prepare(end):
            if 'receipt' in events:events.append('final-intention')
            return intention(end)
        with patch.object(self.m.PREP,'canonical',side_effect=encode),patch.object(self.m.LIVE,'intention',side_effect=prepare):self.check()
        self.assertEqual(events,['receipt','final-intention'])
        for change in ('context','clock','input'):
            start=self.m.KERNEL.now();clock=[start];scope=[4711];original=self.m.PREP.INPUT.read_bytes()
            def encode(value):
                raw=real(value)
                if type(value) is dict and value.get('state')=='enrolled-local-postgresql-peer-source-only':
                    if change=='context':scope[0]=True
                    elif change=='clock':clock[0]=start+11
                    else:self.m.PREP.INPUT.write_bytes(original.replace(b'"max_connections":40',b'"max_connections":48'))
                return raw
            with self.subTest(change=change),patch.object(self.m.PREP,'canonical',side_effect=encode), \
                    patch.object(self.m.KERNEL,'namespace',side_effect=lambda:scope[0]), \
                    patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),self.assertRaises(ValueError):self.check()
            self.m.PREP.INPUT.write_bytes(original)

    def test_result_bound_is_independent_of_valid_peer_and_admin_facts(self):
        with patch.object(self.m,'MAX_OUTPUT',1),self.assertRaisesRegex(ValueError,'receipt exceeds'):self.check()

    def test_eight_actual_private_captures_keep_exact_user_database_sql_env_and_session(self):
        value=json.loads(self.m.check())
        self.assertEqual(value['applications'],{app:self.reply(app) for app in self.m.PREP.APPLICATIONS})
        rows=[json.loads(line) for line in self.fixture.ledger.read_text().splitlines()]
        self.assertEqual(len(rows),8)
        self.assertEqual([row['kind'] for row in rows],['catalog','catalog','peer:dns_demo','peer:mail_demo','peer:dns_demo','peer:mail_demo','catalog','catalog'])
        for row in rows:
            self.assertEqual(row['environment'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'});self.assertEqual(row['pid'],row['sid'])
            if row['kind'].startswith('peer:'):
                role=row['kind'][5:];item=next(x for x in self.fixture.value['applications'].values() if x['role']==role)
                self.assertEqual(row['argv'][1:4],['-u',role,'--']);self.assertEqual(row['argv'][14],item['database'])
                self.assertEqual(row['argv'][-1],self.m.LIVE.PEER_SQL)

    def test_private_peer_authentication_failure_warning_and_overflow_refuse(self):
        for fault in ('peer_refuse','peer_warning','peer_large','peer_public_create','peer_read_only'):
            self.fixture.faults(**{fault:True})
            with self.subTest(fault=fault),self.assertRaises(ValueError):self.m.check()
            self.fixture.faults(**{fault:False})

    def test_private_peer_timeout_reaps_the_one_owned_attempt_without_retry(self):
        self.fixture.faults(peer_sleep=True);start=self.m.KERNEL.now();end=start+3
        def clock():
            if self.fixture.ledger.exists():return end+1
            return start
        with patch.object(self.m.KERNEL,'now',side_effect=clock),self.assertRaises((ValueError,subprocess.TimeoutExpired)):
            self.m.LIVE.native('peer:mk8.dns',end)
        rows=[json.loads(line) for line in self.fixture.ledger.read_text().splitlines()]
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['kind'],'peer:dns_demo');self.assertEqual(rows[0]['pid'],rows[0]['sid'])

    def test_peer_native_unknown_kind_and_unsafe_configuration_precede_child_entry(self):
        for kind in ('peer:other','peer:postgres','peer:mk8.sava'):
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.m.LIVE.native(kind,self.m.KERNEL.now()+3)
        self.m.PREP.INPUT.write_bytes(b'{}\n')
        with self.assertRaises(ValueError):self.m.LIVE.native('peer:mk8.dns',self.m.KERNEL.now()+3)
        self.assertFalse(self.fixture.ledger.exists())

    def test_cli_binary_sink_admission_full_count_flush_and_unsupported_action(self):
        for stdout in (None,object(),io.StringIO()):
            with patch.object(sys,'argv',['access.py','--access']),patch.object(sys,'stdout',stdout), \
                    patch.object(sys,'stderr',io.StringIO()),patch.object(self.m,'check',side_effect=AssertionError('before sink')):
                self.assertEqual(self.m.main(),75)
        class Sink:
            def __init__(self,count):self.buffer=self;self.count=count;self.payload=None;self.flushed=False
            def write(self,raw):self.payload=raw;return len(raw) if self.count=='full' else self.count
            def flush(self):self.flushed=True
        for count in (True,None,0,'full'):
            sink=Sink(count)
            with patch.object(sys,'argv',['access.py','--access']),patch.object(sys,'stdout',sink),patch.object(sys,'stderr',io.StringIO()):
                self.assertEqual(self.m.main(),0 if count=='full' else 75)
            self.assertIs(type(sink.payload),bytes);self.assertEqual(sink.flushed,count=='full')
        with patch.object(sys,'argv',['access.py','--check']),patch.object(sys,'stderr',io.StringIO()), \
                patch.object(self.m,'check',side_effect=AssertionError('invalid action')):self.assertEqual(self.m.main(),75)


if __name__=='__main__':unittest.main()
