"""Ordinary-UID paired Sava FILE/key SOURCE controls; no RPC or app entry."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class SavaTransportTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('private_sava_identity_fixture',ROOT/'Applications.Tests/test_identities.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        self.helper=fixture.IdentityTests();self.addCleanup(self.helper.doCleanups);self.helper.setUp();self.root=self.helper.root
        spec=importlib.util.spec_from_file_location('private_sava_transport',ROOT/'Applications/sava_transport.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        ids=self.m.IDENTITIES;old=self.helper.m
        ids.BASE.TRUST_ROOT=self.root;ids.BASE.TRUSTED_UID=os.geteuid()
        ids.INPUT=old.INPUT;ids.PASSWD=old.PASSWD;ids.GROUP=old.GROUP
        ids.RELEASE.INPUT=old.RELEASE.INPUT;ids.RELEASE.RELEASE_ROOT=old.RELEASE.RELEASE_ROOT
        ids.KERNEL.namespace=lambda:4711
        self.m.INPUT=self.root/'sava-transport.json';self.m.SETTINGS_ROOT=self.root/'etc/sava'
        self.m.SETTINGS_ROOT.mkdir(parents=True,mode=0o700);self.m.SETTINGS_ROOT.parent.chmod(0o700)
        self.descriptor={'schema':1,'application_settings':str(self.m.SETTINGS_ROOT/'application.json'),
            'gateway_settings':str(self.m.SETTINGS_ROOT/'gateway.json'),'access_key':str(self.m.SETTINGS_ROOT/'rpc.key')}
        self.key=bytes(range(1,33));self.account_key=base64.b64encode(b'c'*32).decode();self.data_key=base64.b64encode(b'd'*32).decode()
        self.value={'Sava':{'DataPath':'/srv/sava-private-fixture/data','DefaultAccount':'fixtureacct',
            'Accounts':{'fixtureacct':self.account_key},'DataEncryptionKeys':{'fixtureacct':self.data_key},
            'AccountCapabilities':{'fixtureacct':{'VersioningEnabled':False}},'ObjectReplicationPolicies':[],
            'AllowAnonymousPublicAccess':False,'MaximumRequestBodyBytes':1048576,'BearerAuthentication':{'Enabled':False}},
            'ApplicationTransport':{'Endpoint':'http://127.0.0.1:12345/internal/application',
            'AccessKeyFile':self.descriptor['access_key'],'MaximumControlFrameBytes':4096,
            'ConnectTimeout':'00:00:05','RequestTimeout':'00:10:00'}}
        self.write()

    def write(self,app=None,gateway=None,key=None,descriptor=None):
        self.m.INPUT.write_bytes(self.m.BASE.canonical(self.descriptor if descriptor is None else descriptor));self.m.INPUT.chmod(0o600)
        for field,value in (('application_settings',self.value if app is None else app),('gateway_settings',self.value if gateway is None else gateway)):
            p=Path(self.descriptor[field]);p.write_bytes(self.m.BASE.canonical(value));p.chmod(0o600)
        p=Path(self.descriptor['access_key']);p.write_bytes(base64.b64encode(self.key)+b'\n' if key is None else key);p.chmod(0o600)

    def test_real_complete_sources_pair_policy_transport_and_key_without_secret_values_or_execution(self):
        before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.Popen',side_effect=AssertionError('no app or RPC')),patch.object(Path,'exists',side_effect=AssertionError('no storage existence observation')):raw=self.m.prepare()
        r=json.loads(raw);self.assertEqual(r['state'],'sava-split-transport-policy-source-only');self.assertEqual(r['namespace'],4711)
        self.assertEqual(r['settings']['key_bytes'],32);self.assertEqual(r['settings']['key_material_sha256'],hashlib.sha256(self.key).hexdigest())
        self.assertEqual(r['settings']['policy_sha256'],hashlib.sha256(self.m.BASE.canonical(self.value['Sava'])).hexdigest())
        for secret in (self.account_key,self.data_key,base64.b64encode(self.key).decode()):self.assertNotIn(secret.encode(),raw)
        self.assertEqual(r['settings']['rpc'],{'address':'127.0.0.1','port':12345,'path':'/internal/application','scheme':'http'})
        self.assertEqual({p:p.read_bytes() for p in before},before)

    def test_private_ipv4_and_ipv6_endpoints_are_explicit_and_no_hostname_tls_or_alias_fallback(self):
        value=copy.deepcopy(self.value);value['ApplicationTransport']['Endpoint']='http://[::1]:12345/internal/application';self.write(value,value)
        self.assertEqual(json.loads(self.m.prepare())['settings']['rpc']['address'],'::1')
        for bad in ('http://localhost:12345/internal/application','http://127.0.0.2:12345/internal/application',
            'https://127.0.0.1:12345/internal/application','http://127.0.0.1:012345/internal/application',
            'http://user@127.0.0.1:12345/internal/application','http://127.0.0.1:12345/internal/application?x=1',
            'http://127.0.0.1:12345/internal/application/','http://0.0.0.0:12345/internal/application',True,None,
            'http://127.0.0.1:5432/internal/application','http://127.0.0.1:65536/internal/application'):
            with self.subTest(bad=bad),self.assertRaises(self.m.Pending):self.m.endpoint(bad)

    def test_descriptor_closed_schema_true_integer_and_every_explicit_path_required(self):
        for field in self.descriptor:
            value=copy.deepcopy(self.descriptor);del value[field]
            with self.subTest(field=field),self.assertRaises(self.m.Pending):self.m.checked(value)
        for field,bad in (('schema',True),('schema',1.0),('healthy',True),('account','other'),('key','inline')):
            value=copy.deepcopy(self.descriptor);value[field]=bad
            with self.assertRaises(self.m.Pending):self.m.checked(value)

    def test_product_descendant_distinct_file_paths_refuse_alias_link_spelling_and_unrelated_private_paths(self):
        for bad in ('/etc/passwd',str(self.m.SETTINGS_ROOT),str(self.m.SETTINGS_ROOT/'../else.json'),
            str(self.m.SETTINGS_ROOT)+'/x//a.json',str(self.m.SETTINGS_ROOT/'a b.json'),str(self.m.SETTINGS_ROOT/'%n.json'),
            str(self.m.SETTINGS_ROOT/'rpc.key'),'relative.json',True):
            value=copy.deepcopy(self.descriptor);value['application_settings']=bad
            with self.subTest(bad=bad),self.assertRaises(self.m.Pending):self.m.checked(value)
        value=copy.deepcopy(self.descriptor);value['gateway_settings']=value['application_settings']
        with self.assertRaises(self.m.Pending):self.m.checked(value)

    def test_all_four_private_modes_and_link_ancestry_refuse(self):
        for p in (self.m.INPUT,*map(Path,(self.descriptor[k] for k in self.m.FILES))):
            p.chmod(0o644)
            with self.subTest(path=p),self.assertRaises(self.m.Pending):self.m.prepare()
            p.chmod(0o600)
        p=Path(self.descriptor['access_key']);alias=self.root/'alias';os.link(p,alias)
        with self.assertRaises(self.m.Pending):self.m.prepare()
        alias.unlink();p.rename(alias);p.symlink_to(alias)
        with self.assertRaises(self.m.Pending):self.m.prepare()
        p.unlink();alias.rename(p);self.m.SETTINGS_ROOT.chmod(0o777)
        with self.assertRaises(self.m.Pending):self.m.prepare()

    def test_descriptor_and_settings_bounds_precede_json_decode(self):
        self.m.INPUT.write_bytes(b' '*(self.m.MAX_INPUT+1))
        with patch.object(self.m.json,'loads',side_effect=AssertionError('decode')):
            with self.assertRaises(self.m.Pending):self.m.document(self.m.INPUT,self.m.MAX_INPUT,self.m.KERNEL.now()+5)
        self.write();p=Path(self.descriptor['application_settings']);p.write_bytes(b' '*(self.m.MAX_SETTINGS+1))
        with patch.object(self.m.json,'loads',side_effect=AssertionError('decode')):
            with self.assertRaises(self.m.Pending):self.m.document(p,self.m.MAX_SETTINGS,self.m.KERNEL.now()+5)

    def test_settings_require_canonical_ascii_lf_no_duplicate_or_nonfinite_numbers(self):
        original=self.m.BASE.canonical(self.value);p=Path(self.descriptor['application_settings'])
        for raw in (original+b'\n',original[:-1],b'\xff\n',original.replace(b'"MaximumRequestBodyBytes":1048576',b'"MaximumRequestBodyBytes":NaN'),
            original.replace(b'"MaximumRequestBodyBytes":1048576',b'"MaximumRequestBodyBytes":1e999'),
            original.replace(b'"Sava":',b'"Sava":{},"Sava":')):
            p.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(self.m.Pending):self.m.prepare()

    def test_structural_depth_node_strings_integer_and_nonfinite_limits_are_source_only(self):
        for value in ({'x':'a'*65537},{'x':2**63},{'x':-(2**63)-1},{'x':float('inf')},{'x':'bad\nline'},{'é':1}):
            with self.subTest(value=type(value)),self.assertRaises(self.m.Pending):self.m.structural(value)
        value=0
        for _ in range(33):value=[value]
        with self.assertRaises(self.m.Pending):self.m.structural(value)
        with patch.object(self.m,'MAX_NODES',2):
            with self.assertRaises(self.m.Pending):self.m.structural({'a':[1]})

    def test_all_selected_policy_and_transport_fields_are_required_no_synthesized_defaults(self):
        for section,fields in (('Sava',self.m.POLICY_FIELDS),('ApplicationTransport',self.m.TRANSPORT_FIELDS)):
            for field in fields:
                value=copy.deepcopy(self.value);del value[section][field]
                with self.subTest(section=section,field=field),self.assertRaises(self.m.Pending):self.m.settings(value,self.descriptor['access_key'])
        value=copy.deepcopy(self.value);value['ApplicationTransport']['AccessKey']='inline'
        with self.assertRaises(self.m.Pending):self.m.settings(value,self.descriptor['access_key'])

    def test_transport_file_frame_and_duration_fields_have_true_types_and_finite_source_bounds(self):
        for field,bad in (('AccessKeyFile','/else/key'),('MaximumControlFrameBytes',True),('MaximumControlFrameBytes',4096.0),
            ('MaximumControlFrameBytes',4095),('MaximumControlFrameBytes',64*1024*1024+1),('ConnectTimeout','00:00:00'),
            ('ConnectTimeout','00:01:01'),('ConnectTimeout',5),('RequestTimeout','01:00:01'),('RequestTimeout','0:10:00')):
            value=copy.deepcopy(self.value);value['ApplicationTransport'][field]=bad
            with self.subTest(field=field,bad=bad),self.assertRaises(self.m.Pending):self.m.settings(value,self.descriptor['access_key'])

    def test_storage_account_material_capabilities_and_encryption_are_explicit_not_fallback(self):
        for field,bad in (('Accounts',{}),('Accounts',{'UPPER':self.account_key}),('Accounts',{'fixtureacct':'bad'}),
            ('DefaultAccount','missing'),('DataEncryptionKeys',{}),('DataEncryptionKeys',{'other':self.data_key}),
            ('AccountCapabilities',{}),('AccountCapabilities',{'fixtureacct':False}),('ObjectReplicationPolicies',{}),
            ('AllowAnonymousPublicAccess',True),('AllowAnonymousPublicAccess',0),('MaximumRequestBodyBytes',True),
            ('MaximumRequestBodyBytes',0),('BearerAuthentication',{}),('BearerAuthentication',{'Enabled':1})):
            value=copy.deepcopy(self.value);value['Sava'][field]=bad
            with self.subTest(field=field),self.assertRaises(self.m.Pending):self.m.settings(value,self.descriptor['access_key'])
        for path in ('relative','/','/srv','/srv/../x','/var/lib/x y','/srv/x/%n','/tmp/x'):
            value=copy.deepcopy(self.value);value['Sava']['DataPath']=path
            with self.assertRaises(self.m.Pending):self.m.settings(value,self.descriptor['access_key'])

    def test_whole_policy_and_transport_correspondence_refuses_even_opaque_value_type_changes(self):
        for section,field,bad in (('Sava','DataPath','/srv/other/data'),('ApplicationTransport','ConnectTimeout','00:00:06'),
                                 ('Sava','OpaqueNativeOption',1.0)):
            app=copy.deepcopy(self.value);gateway=copy.deepcopy(self.value)
            if field=='OpaqueNativeOption':app[section][field]=1
            gateway[section][field]=bad;self.write(app,gateway)
            with self.subTest(field=field),self.assertRaises(self.m.Pending):self.m.prepare()

    def test_unexamined_framework_sections_may_differ_without_a_native_configuration_certificate(self):
        app=copy.deepcopy(self.value);gateway=copy.deepcopy(self.value)
        app['ApplicationHosting']={'UnvalidatedNativeOption':'opaque'};gateway['Kestrel']={'Endpoints':{'Private':{'Url':'opaque'}}}
        self.write(app,gateway);r=json.loads(self.m.prepare())
        self.assertEqual(r['state'],'sava-split-transport-policy-source-only')
        self.assertNotEqual(r['settings']['application_source']['sha256'],r['settings']['gateway_source']['sha256'])
        self.assertNotIn('units',r)

    def test_key_material_exact_edges_canonical_lf_nonzero_and_no_whitespace_alias(self):
        for n in (32,512):
            key=b'k'*n;self.write(key=base64.b64encode(key)+b'\n')
            self.assertEqual(json.loads(self.m.prepare())['settings']['key_bytes'],n)
        for raw in (base64.b64encode(b'k'*31)+b'\n',base64.b64encode(b'k'*513)+b'\n',base64.b64encode(bytes(32))+b'\n',
            base64.b64encode(self.key),base64.b64encode(self.key)+b'\n\n',base64.b64encode(self.key)+b'\r\n',b'\xff\n',b'x'*(self.m.MAX_KEY_FILE+1),b' '+base64.b64encode(self.key)+b'\n'):
            self.write(key=raw)
            with self.subTest(rawlen=len(raw)),self.assertRaises(self.m.Pending):self.m.prepare()

    def test_encoding_precedes_second_every_source_file_and_identity_preparation(self):
        events=[];read=self.m.BASE.read_protected;identity=self.m.identity_bytes;canonical=self.m.BASE.canonical
        paths={self.m.INPUT,*map(Path,(self.descriptor[k] for k in self.m.FILES))}
        def observed(path,*args):
            if path in paths:events.append(path.name)
            return read(path,*args)
        def ids(end):events.append('identities');return identity(end)
        def encode(value):
            if type(value) is dict and value.get('state')=='sava-split-transport-policy-source-only':events.append('encode')
            return canonical(value)
        with patch.object(self.m.BASE,'read_protected',side_effect=observed),patch.object(self.m,'identity_bytes',side_effect=ids),patch.object(self.m.BASE,'canonical',side_effect=encode):self.m.prepare()
        four=['sava-transport.json','application.json','gateway.json','rpc.key']
        self.assertEqual(events,['identities']+four+['encode']+four+['identities'])

    def test_private_second_raw_buffers_are_compared_even_when_reported_hashes_are_held_equal(self):
        original=self.m.observe;calls=0
        def observe(end):
            nonlocal calls
            record,private=original(end);calls+=1
            if calls==2:private=(private[0],private[1]+b'x',private[2],private[3])
            return record,private
        with patch.object(self.m,'observe',side_effect=observe):
            with self.assertRaises(self.m.Pending):self.m.prepare()
        self.assertEqual(calls,2)

    def test_postencoding_settings_key_and_descriptor_byte_changes_withhold_receipt(self):
        canonical=self.m.BASE.canonical
        for path in (self.m.INPUT,*map(Path,(self.descriptor[k] for k in self.m.FILES))):
            def encode(value):
                raw=canonical(value)
                if type(value) is dict and value.get('state')=='sava-split-transport-policy-source-only':path.write_bytes(path.read_bytes()+b'\n')
                return raw
            with self.subTest(path=path),patch.object(self.m.BASE,'canonical',side_effect=encode):
                with self.assertRaises(self.m.Pending):self.m.prepare()
            self.write()

    def test_postencoding_same_byte_key_inode_replacement_withholds_receipt(self):
        canonical=self.m.BASE.canonical
        def encode(value):
            raw=canonical(value)
            if type(value) is dict and value.get('state')=='sava-split-transport-policy-source-only':
                path=Path(self.descriptor['access_key']);replacement=path.with_name('replace');replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);os.replace(replacement,path)
            return raw
        with patch.object(self.m.BASE,'canonical',side_effect=encode):
            with self.assertRaises(self.m.Pending):self.m.prepare()

    def test_postencoding_actual_release_inode_change_withholds_receipt(self):
        canonical=self.m.BASE.canonical
        def encode(value):
            raw=canonical(value)
            if type(value) is dict and value.get('state')=='sava-split-transport-policy-source-only':
                path=self.helper.helper.path();replacement=path.with_name('replace');replacement.write_bytes(path.read_bytes());replacement.chmod(0o755);os.replace(replacement,path)
            return raw
        with patch.object(self.m.BASE,'canonical',side_effect=encode):
            with self.assertRaises(self.m.Pending):self.m.prepare()

    def test_exact_output_bound_and_one_less_refuse_before_any_second_settings_or_identity(self):
        raw=self.m.prepare();observe=self.m.observe;ids=self.m.identity_bytes
        with patch.object(self.m,'MAX_OUTPUT',len(raw)):self.assertEqual(self.m.prepare(),raw)
        with patch.object(self.m,'MAX_OUTPUT',len(raw)-1),patch.object(self.m,'observe',wraps=observe) as settings,patch.object(self.m,'identity_bytes',wraps=ids) as identity:
            with self.assertRaises(self.m.Pending):self.m.prepare()
            self.assertEqual((settings.call_count,identity.call_count),(1,1))

    def test_invalid_deadline_and_initial_namespace_refuse_before_any_inputs(self):
        for value in (0,True,1.0,-1,2**64):
            with patch.object(self.m.KERNEL,'namespace',return_value=value),patch.object(self.m,'identity_bytes') as ids:
                with self.assertRaises(self.m.Pending):self.m.prepare()
                ids.assert_not_called()
        for deadline in (True,'10',float('nan'),float('inf'),self.m.KERNEL.now()-1):
            with patch.object(self.m,'identity_bytes') as ids:
                with self.assertRaises(self.m.Pending):self.m.prepare(deadline)
                ids.assert_not_called()

    def test_positive_inherited_cap_preserves_independent_identity_and_release_windows(self):
        read=self.m.BASE.read_protected
        for parent in (12,1000):
            seen=[]
            def observed(path,limit,private,end):seen.append((path,end));return read(path,limit,private,end)
            with patch.object(self.m.KERNEL,'now',return_value=10),patch.object(self.m.BASE,'read_protected',side_effect=observed):self.m.prepare(parent)
            self.assertEqual(len(seen),124)
            own={self.m.INPUT,*map(Path,(self.descriptor[k] for k in self.m.FILES))}
            idfiles={self.m.IDENTITIES.INPUT,self.m.IDENTITIES.PASSWD,self.m.IDENTITIES.GROUP}
            for path,end in seen:self.assertEqual(end,12 if parent==12 else 290 if path in own else 140 if path in idfiles else 70)

    def test_final_context_and_expiry_after_real_second_identity_return_withhold_receipt(self):
        with patch.object(self.m.KERNEL,'namespace',side_effect=[4711]*13+[4712]):
            with self.assertRaises(self.m.Pending):self.m.prepare()
        ids=self.m.identity_bytes;calls=0
        def identity(end):
            nonlocal calls
            raw=ids(end);calls+=1
            if calls==2:clock.return_value=end
            return raw
        with patch.object(self.m.KERNEL,'now',return_value=10) as clock,patch.object(self.m,'identity_bytes',side_effect=identity):
            with self.assertRaises(self.m.Pending):self.m.prepare()
        self.assertEqual(calls,2)

    def test_identity_delivery_requires_actual_immutable_bounded_bytes_and_equal_typed_context(self):
        raw=self.m.IDENTITIES.prepare();value=json.loads(raw);value['namespace']=4712
        for bad in (bytearray(raw),b'x'*(self.m.IDENTITIES.MAX_OUTPUT+1),self.m.BASE.canonical(value)):
            with patch.object(self.m.IDENTITIES,'prepare',return_value=bad):
                with self.assertRaises(self.m.Pending):self.m.prepare()

    def test_binary_cli_no_overrides_true_count_flush_and_no_secret_values(self):
        class Sink:
            def __init__(self,count=None,fail=False):self.buffer=self;self.count=count;self.fail=fail;self.raw=b''
            def write(self,raw):self.raw=raw;return len(raw) if self.count is None else self.count
            def flush(self):
                if self.fail:raise OSError('private flush')
        for count,fail,code in ((None,False,0),(True,False,75),(1,False,75),(None,True,75)):
            sink=Sink(count,fail)
            with patch.object(sys,'argv',['sava_transport.py']),patch.object(sys,'stdout',sink),patch.object(sys,'stderr',io.StringIO()),patch.object(self.m,'prepare',return_value=b'{}\n'):
                self.assertEqual(self.m.main(),code)
            self.assertEqual(sink.raw,b'{}\n')
        for args,sink in ((['sava_transport.py','extra'],Sink()),(['sava_transport.py'],io.StringIO())):
            with patch.object(sys,'argv',args),patch.object(sys,'stdout',sink),patch.object(sys,'stderr',io.StringIO()),patch.object(self.m,'prepare') as prepared:
                self.assertEqual(self.m.main(),75);prepared.assert_not_called()

    def test_actual_private_interpreter_pipe_has_encoding_independent_receipt_and_no_refused_output(self):
        program=("import importlib.util,os,sys;from pathlib import Path;"
            "s=importlib.util.spec_from_file_location('private_cli',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "r=Path(sys.argv[2]);i=m.IDENTITIES;i.BASE.TRUST_ROOT=r;i.BASE.TRUSTED_UID=os.geteuid();"
            "i.INPUT=r/'application-identities.json';i.PASSWD=r/'passwd';i.GROUP=r/'group';"
            "i.RELEASE.INPUT=r/'application-releases.json';i.RELEASE.RELEASE_ROOT=r/'opt/debian13s4-apps';i.KERNEL.namespace=lambda:4711;"
            "m.INPUT=r/'sava-transport.json';m.SETTINGS_ROOT=r/'etc/sava';sys.argv=['sava_transport.py'];sys.exit(m.main())")
        expected=self.m.prepare()
        for encoding in ('ascii:strict','utf-32:ignore'):
            env=dict(os.environ,PYTHONIOENCODING=encoding);env.pop('PYTHONPATH',None)
            child=subprocess.run([sys.executable,'-B','-c',program,str(ROOT/'Applications/sava_transport.py'),str(self.root)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertEqual((child.returncode,child.stdout,child.stderr),(0,expected,b''))
        Path(self.descriptor['access_key']).chmod(0o644)
        child=subprocess.run([sys.executable,'-B','-c',program,str(ROOT/'Applications/sava_transport.py'),str(self.root)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual((child.returncode,child.stdout),(75,b''))


if __name__=='__main__':
    unittest.main()
