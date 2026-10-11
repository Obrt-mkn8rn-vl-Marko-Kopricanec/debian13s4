"""Protected selected listing with PRIVATE dump/PG/listing delivery models."""
import copy
import importlib.util
import json
import os
import unittest
from unittest.mock import patch
import test_selected_stage as fixture


class SelectedInspectionTests(unittest.TestCase):
    def setUp(self):
        self.h=fixture.SelectedStageTests('test_whole_fresh_protected_intention_and_both_access_rounds_bind_selected_stage')
        self.h.setUp();self.addCleanup(self.h.doCleanups)
        spec=importlib.util.spec_from_file_location('private_selected_inspection',fixture.ROOT/'PostgreSQL/selected_inspection.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.m.HISTORY.SELECTED=self.h.m;self.m.HISTORY.BACKUP=self.h.m.BACKUP;self.m.HISTORY.PREP=self.h.m.PREP
        self.m.SELECTED=self.h.m;self.m.BACKUP=self.h.m.BACKUP;self.m.PREP=self.h.m.PREP;self.m.KERNEL=self.h.m.KERNEL
        self.m.INSPECT=self.h.m.INSPECT;self.m.STAGE=self.h.m.STAGE
        self.m.INSPECT.KERNEL.TRUST_ROOT=self.h.exe_root;self.m.INSPECT.KERNEL.TRUSTED_UID=os.geteuid()
        self.m.INSPECT.RESTORE=self.h.exe_root/'restore';self.m.BACKUP.RESTORE=str(self.m.INSPECT.RESTORE)
        self.ledger=self.h.exe_root/'listing-ledger';self.listing=b'OPAQUE MODEL listing\x00\xff\r\n'
        self.program();self.raw=self.h.stage();self.h.calls.clear()
        self.before=self.h.m.STAGE.file_identity(self.h.leaf().stat())

    def program(self,action='os.write(1,listing)'):
        self.m.INSPECT.RESTORE.write_text('#!/usr/bin/python3\nimport json,os,sys,time\nfrom pathlib import Path\n'+
            'listing='+repr(self.listing)+'\n'+
            'assert sys.argv[1:]==["--list",'+repr(str(self.h.leaf()))+']\n'+
            'assert Path(sys.argv[2]).read_bytes()=='+repr(self.h.data)+'\n'+
            'Path('+repr(str(self.ledger))+').open("a").write(json.dumps({"argv":sys.argv,"environment":dict(os.environ),"pid":os.getpid(),"sid":os.getsid(0)})+"\\n")\n'+action+'\n')
        self.m.INSPECT.RESTORE.chmod(0o700)

    def model(self,path,maximum,end):
        self.assertEqual(path,self.h.leaf());self.assertEqual(maximum,self.h.value['inventory_limit_bytes'])
        self.assertGreater(end,self.m.KERNEL.now());return self.listing

    def inspect(self,**kwargs):return self.m.inspect_selected(self.raw,**({'read':self.h.read,'listing':self.model}|kwargs))

    def test_complete_selection_fresh_both_peer_rounds_and_raw_listing_bind_without_promotion(self):
        raw=self.inspect();v=json.loads(raw)
        self.assertEqual(v['state'],'protected-selected-stage-listing-source-only');self.assertEqual(v['selection'],json.loads(self.raw))
        self.assertEqual(v['selection_sha256'],self.m.HISTORY.digest(self.raw))
        self.assertEqual(bytes.fromhex(v['inspection']['listing_hex']),self.listing)
        self.assertEqual(v['inspection']['listing_limit_bytes'],self.h.value['inventory_limit_bytes'])
        self.assertEqual(v['inspection']['argv'],[str(self.m.INSPECT.RESTORE),'--list',str(self.h.leaf())])
        self.assertEqual(len(self.h.calls),32);self.assertEqual(self.h.m.STAGE.file_identity(self.h.leaf().stat()),self.before)
        self.assertEqual(self.h.leaf().read_bytes(),self.h.data);self.assertFalse(self.h.leaf().with_suffix('').exists())

    def test_actual_private_fixed_listing_child_and_no_additional_dump_entry(self):
        v=json.loads(self.inspect(listing=None));row=json.loads(self.ledger.read_text())
        self.assertEqual(row['argv'],v['inspection']['argv']);self.assertEqual(row['environment'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
        self.assertEqual(row['pid'],row['sid']);self.assertEqual(len(self.h.ledger.read_text().splitlines()),1)
        self.assertEqual(bytes.fromhex(v['inspection']['listing_hex']),self.listing)
        self.assertEqual(self.h.m.STAGE.file_identity(self.h.leaf().stat()),self.before)

    def test_invalid_raw_byte_bound_closed_schema_and_canonical_before_fresh_query(self):
        value=json.loads(self.raw)
        for raw in (True,bytearray(self.raw),b'',b'x'*(self.m.SELECTED.MAX_OUTPUT+1),self.raw+b' ',self.m.PREP.canonical(value|{'extra':True}),self.m.PREP.canonical(value|{'schema':True})):
            with self.subTest(kind=type(raw).__name__),patch.object(self.m.SELECTED,'intention',side_effect=AssertionError('fresh')),self.assertRaises(ValueError):self.m.inspect_selected(raw,read=self.h.read,listing=self.model)
        self.assertFalse(self.ledger.exists());self.assertEqual(self.h.calls,[])

    def test_all_reported_stream_types_and_bindings_refuse_before_fresh_entry(self):
        for key,bad in (('root_exit',False),('namespace',True),('received_bytes',True),('received_sha256','a'*64),('limit_bytes',True),('stderr_limit_bytes',True),('stderr_hex','00'),('argv',[]),('executables',[[True]*8]*2)):
            v=json.loads(self.raw);v['stream'][key]=bad
            with self.subTest(key=key),patch.object(self.m.SELECTED,'intention',side_effect=AssertionError('fresh')),self.assertRaises(ValueError):self.m.inspect_selected(self.m.PREP.canonical(v),read=self.h.read,listing=self.model)

    def test_selected_leaf_directory_caps_and_application_cannot_be_repaired_by_hash(self):
        for field,bad in (('leaf','b'*64+'-mk8.dns.dump.partial'),('directory','/srv/foreign'),('limit_bytes',1024)):
            v=json.loads(self.raw);v['stage'][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.m.checked(self.m.PREP.canonical(v))
        v=json.loads(self.raw);v['application']='mk8.email'
        with self.assertRaises(ValueError):self.m.checked(self.m.PREP.canonical(v))

    def test_historical_job_and_pg_plan_corruption_refuse_before_fresh_entry(self):
        for which in ('job','plan'):
            v=json.loads(self.raw)
            if which=='job':v['backup_intention']['jobs']['mk8.dns']['inspection_argv'].append('--unsafe')
            else:v['backup_intention']['source_intention']['plan']['files']['pg_hba.conf']='host all all all trust\n'
            with self.subTest(which=which),patch.object(self.m.SELECTED,'intention',side_effect=AssertionError('fresh')),self.assertRaises(ValueError):self.m.inspect_selected(self.m.PREP.canonical(v),read=self.h.read,listing=self.model)

    def test_historical_context_mismatch_or_invalid_current_scope_precedes_query(self):
        with patch.object(self.m.KERNEL,'namespace',return_value=4712),patch.object(self.m.INSPECT.KERNEL,'namespace',return_value=4712),patch.object(self.m.SELECTED,'intention',side_effect=AssertionError('fresh')),self.assertRaises(ValueError):self.inspect()
        for scope in (0,True):
            with self.subTest(scope=scope),patch.object(self.m.KERNEL,'namespace',return_value=scope),self.assertRaises(ValueError):self.inspect()
        self.assertEqual(self.h.calls,[])

    def test_invalid_callbacks_and_deadlines_precede_pure_check_or_entry(self):
        with patch.object(self.m,'checked',side_effect=AssertionError('check')):
            for kwargs in ({'read':False},{'listing':False},{'deadline':True},{'deadline':float('inf')},{'deadline':float('nan')},{'deadline':self.m.KERNEL.now()-1}):
                with self.subTest(kwargs=str(kwargs)),self.assertRaises(ValueError):self.inspect(**kwargs)

    def test_positive_inherited_and_own_caps_reach_owned_inspection_without_widening(self):
        now=self.m.KERNEL.now();ends=[];original=self.m.INSPECT.inspect_stage
        def inspected(*args,**kwargs):ends.append(kwargs['deadline']);return original(*args,**kwargs)
        with patch.object(self.m.KERNEL,'now',return_value=now),patch.object(self.m.INSPECT,'inspect_stage',side_effect=inspected):
            self.inspect(deadline=now+2);self.inspect(deadline=now+1000)
        self.assertEqual(ends,[now+2,now+self.m.ATTEMPT_SECONDS])
        self.assertTrue(all(end<=now+2 for _,end in self.h.calls[:32]))

    def test_real_fresh_configuration_or_either_peer_refusal_precedes_listing(self):
        for which in ('config','peer:mk8.dns','peer:mk8.email'):
            def read(kind,end):
                raw=self.h.read(kind,end)
                if kind==which:
                    v=json.loads(raw);v['authentication']='trust';return json.dumps(v).encode()
                return raw
            if which=='config':self.h.fixture.write(self.m.BACKUP.INPUT,self.m.PREP.canonical({**self.h.value,'generation':'b'*64}))
            with self.subTest(which=which),self.assertRaises(self.m.Incomplete) as caught:self.inspect(read=read)
            self.assertIsNone(caught.exception.listing);self.assertEqual(caught.exception.selection,self.raw)
            self.h.fixture.write(self.m.BACKUP.INPUT,self.m.PREP.canonical(self.h.value))
        self.assertFalse(self.ledger.exists());self.assertEqual(len(self.h.ledger.read_text().splitlines()),1)

    def test_actual_stage_drift_refuses_before_listing_child(self):
        self.h.leaf().write_bytes(b'changed')
        with self.assertRaises(self.m.Incomplete) as caught:self.inspect(listing=None)
        self.assertIsNone(caught.exception.listing);self.assertFalse(self.ledger.exists())
        self.assertEqual(self.h.leaf().read_bytes(),b'changed')

    def test_listing_uses_protected_limit_and_fixed_binary_without_caller_override(self):
        self.m.INSPECT.RESTORE=self.h.exe_root/'other'
        with patch.object(self.m.SELECTED,'intention',side_effect=AssertionError('fresh')),self.assertRaises(ValueError):self.inspect()
        self.assertFalse(self.ledger.exists())

    def test_outer_encoding_precedes_second_complete_backup_and_final_whole_readback(self):
        events=[];encode=self.m.PREP.canonical;fresh=self.m.SELECTED.intention;readback=self.m.STAGE.readback
        def encoded(value):
            raw=encode(value)
            if isinstance(value,dict) and value.get('state')=='protected-selected-stage-listing-source-only':events.append('outer')
            return raw
        def prepare(*args,**kwargs):
            if events:events.append('fresh')
            return fresh(*args,**kwargs)
        def read(*args):
            if events:events.append('readback')
            return readback(*args)
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),patch.object(self.m.SELECTED,'intention',side_effect=prepare),patch.object(self.m.STAGE,'readback',side_effect=read):self.inspect()
        self.assertEqual(events,['outer','fresh','readback'])

    def test_outer_receipt_cap_preserves_known_listing_before_second_backup(self):
        with patch.object(self.m,'MAX_OUTPUT',1),self.assertRaises(self.m.Incomplete) as caught:self.inspect()
        self.assertEqual(len(self.h.calls),16);self.assertIsNotNone(caught.exception.listing)
        self.assertEqual(self.h.leaf().read_bytes(),self.h.data)

    def test_postlisting_real_backup_drift_refuses_without_deleting_stage(self):
        def listing(*args):
            self.h.fixture.write(self.m.BACKUP.INPUT,self.m.PREP.canonical({**self.h.value,'generation':'b'*64}));return self.listing
        with self.assertRaises(self.m.Incomplete) as caught:self.inspect(listing=listing)
        self.assertIsNotNone(caught.exception.listing);self.assertEqual(self.h.leaf().read_bytes(),self.h.data)
        self.assertEqual(len(self.h.ledger.read_text().splitlines()),1)

    def test_outer_encoding_file_mutation_refuses_actual_final_readback(self):
        encode=self.m.PREP.canonical
        def encoded(value):
            raw=encode(value)
            if isinstance(value,dict) and value.get('state')=='protected-selected-stage-listing-source-only':self.h.leaf().write_bytes(b'changed')
            return raw
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),self.assertRaises(self.m.Incomplete):self.inspect()
        self.assertEqual(self.h.leaf().read_bytes(),b'changed')

    def test_boolean_or_extra_field_substituted_listing_receipt_is_rejected(self):
        original=self.m.INSPECT.inspect_stage
        for field,bad in (('namespace',True),('schema',True),('listing_bytes',True),('extra',True)):
            def substituted(*args,**kwargs):v=json.loads(original(*args,**kwargs));v[field]=bad;return self.m.PREP.canonical(v)
            with self.subTest(field=field),patch.object(self.m.INSPECT,'inspect_stage',side_effect=substituted),self.assertRaises(self.m.Incomplete):self.inspect()

    def test_owned_listing_failure_keeps_original_cause_and_stage_without_dump_retry(self):
        cause=OSError('private listing delivery failed')
        def listing(*args):raise cause
        with self.assertRaises(self.m.Incomplete) as caught:self.inspect(listing=listing)
        self.assertIs(caught.exception.cause,cause);self.assertIsNone(caught.exception.listing)
        self.assertEqual(self.h.leaf().read_bytes(),self.h.data);self.assertEqual(len(self.h.ledger.read_text().splitlines()),1)

    def test_final_actual_readback_context_and_time_changes_refuse(self):
        readback=self.m.STAGE.readback;now=self.m.KERNEL.now()
        for which in ('context','time'):
            clock=[now];scope=[4711];count=[0]
            def read(*args):
                result=readback(*args);count[0]+=1
                if count[0]==3:
                    if which=='context':scope[0]=True
                    else:clock[0]=now+2
                return result
            with self.subTest(which=which),patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.INSPECT.KERNEL,'namespace',side_effect=lambda:scope[0]),patch.object(self.m.STAGE,'readback',side_effect=read),self.assertRaises(self.m.Incomplete) as caught:self.inspect(deadline=now+2)
            self.assertIsNotNone(caught.exception.listing);self.assertEqual(count[0],3)

    def test_outer_directory_close_failure_retires_fd_before_single_attempt(self):
        opened=self.m.os.open;closed=self.m.os.close;dirs=[];target=[None];replacement=[]
        def open_fd(path,flags,*args,**kwargs):
            fd=opened(path,flags,*args,**kwargs)
            if path==self.h.store:
                dirs.append(fd)
                if len(dirs)==2:target[0]=fd
            return fd
        def close_fd(fd):
            if fd==target[0] and not replacement:
                closed(fd);new=opened(self.h.fixture.root,os.O_RDONLY|os.O_DIRECTORY);self.assertEqual(new,fd);replacement.append(new);raise OSError('retired outer close')
            return closed(fd)
        try:
            with patch.object(self.m.os,'open',side_effect=open_fd),patch.object(self.m.os,'close',side_effect=close_fd),self.assertRaises(self.m.Incomplete) as caught:self.inspect()
            self.assertEqual(str(caught.exception.cause),'retired outer close');self.assertEqual(caught.exception.cleanup,())
            self.assertIsNotNone(caught.exception.listing);os.fstat(replacement[0])
        finally:
            for fd in replacement:closed(fd)

    def test_outer_encoded_cap_at_exact_size_and_one_less(self):
        raw=self.inspect()
        with patch.object(self.m,'MAX_OUTPUT',len(raw)):self.assertEqual(self.inspect(),raw)
        with patch.object(self.m,'MAX_OUTPUT',len(raw)-1),self.assertRaises(self.m.Incomplete) as caught:self.inspect()
        self.assertIsNotNone(caught.exception.listing);self.assertEqual(self.h.leaf().read_bytes(),self.h.data)

    def test_outer_postencoding_executable_drift_refuses_with_known_listing(self):
        encode=self.m.PREP.canonical
        def encoded(value):
            raw=encode(value)
            if isinstance(value,dict) and value.get('state')=='protected-selected-stage-listing-source-only':self.m.INSPECT.RESTORE.write_text('#!/usr/bin/python3\n')
            return raw
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),self.assertRaises(self.m.Incomplete) as caught:self.inspect()
        self.assertIsNotNone(caught.exception.listing);self.assertEqual(self.h.leaf().read_bytes(),self.h.data)

    def test_initial_real_query_expiry_blocks_next_query_and_listing(self):
        now=self.m.KERNEL.now();clock=[now];calls=[]
        def read(kind,end):
            calls.append(kind);raw=self.h.read(kind,end);clock[0]=now+2;return raw
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.INSPECT,'inspect_stage',side_effect=AssertionError('listing')),self.assertRaises(self.m.Incomplete):self.inspect(read=read,deadline=now+2)
        self.assertEqual(calls,['catalog']);self.assertEqual(self.h.leaf().read_bytes(),self.h.data)


if __name__=='__main__':unittest.main()
