"""Fresh intention/stage orchestration with PRIVATE PG/dump delivery only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from fixture_pg import PrivatePG, ROOT


class SelectedStageTests(unittest.TestCase):
    def setUp(self):
        self.fixture=PrivatePG();self.addCleanup(self.fixture.close)
        context=self.fixture.context();context.__enter__();self.addCleanup(context.close)
        spec=importlib.util.spec_from_file_location('private_selected_stage',ROOT/'PostgreSQL/selected_stage.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        b=self.m.BACKUP;b.ACCESS.LIVE=self.fixture.m;b.ACCESS.PREP=self.fixture.m.PREP;b.ACCESS.KERNEL=self.fixture.m.KERNEL
        b.PREP=self.fixture.m.PREP;b.KERNEL=self.fixture.m.KERNEL;b.Pending=self.fixture.m.Pending
        b.INPUT=self.fixture.root/'etc/backup.json'
        self.m.PREP=b.PREP;self.m.KERNEL=b.KERNEL;self.m.Pending=b.Pending
        self.value={'schema':1,'directory':'/srv/private-backups','generation':'a'*64,'archive_limit_bytes':1048576,
            'inventory_limit_bytes':65536,'dump_timeout_seconds':10,'lock_wait_ms':1000}
        self.fixture.write(b.INPUT,b.PREP.canonical(self.value))
        (self.fixture.root/'srv').mkdir(mode=0o700);self.store=self.fixture.root/'srv/private-backups';self.store.mkdir(mode=0o700)
        self.m.STAGE.TRUST_ROOT=self.fixture.root;self.m.STAGE.TRUSTED_UID=os.geteuid()
        self.m.DUMP.PREP=b.PREP
        self.executables=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.executables.cleanup)
        self.exe_root=Path(self.executables.name);self.exe_root.chmod(0o700)
        self.m.DUMP.KERNEL.TRUST_ROOT=self.exe_root;self.m.DUMP.KERNEL.TRUSTED_UID=os.geteuid()
        self.m.DUMP.KERNEL.namespace=lambda:4711;self.m.STAGE.KERNEL.namespace=lambda:4711
        self.m.DUMP.RUNUSER=self.exe_root/'runuser';self.m.DUMP.DUMP=self.exe_root/'pg_dump'
        self.m.DUMP.DUMP.write_text('inert private PG identity\n');self.m.DUMP.DUMP.chmod(0o700)
        b.RUNUSER=str(self.m.DUMP.RUNUSER);b.DUMP=str(self.m.DUMP.DUMP)
        self.ledger=self.exe_root/'ledger';self.data=b'INVALID-PG-ARCHIVE\x00\xff\r\n'*5000
        self.calls=[];self.streams=[];self.program()
        original=self.m.DUMP.DumpStream
        def owned(*args,**kwargs):
            s=original(*args,**kwargs);self.streams.append(s);return s
        self.delivery=patch.object(self.m.DUMP,'DumpStream',side_effect=owned);self.delivery.start();self.addCleanup(self.delivery.stop)
        self.addCleanup(self.cleanup_streams)

    def cleanup_streams(self):
        for s in self.streams:s.close()

    def leaf(self,app='mk8.dns'):return self.store/(self.value['generation']+'-'+app+'.dump.partial')

    def program(self,action='os.write(1,data)'):
        self.m.DUMP.RUNUSER.write_text('#!/usr/bin/python3\nimport json,os,sys,time\nfrom pathlib import Path\n'+
            'data='+repr(self.data)+'\n'+
            'Path('+repr(str(self.ledger))+').open("a").write(json.dumps({"argv":sys.argv,"environment":dict(os.environ),"pid":os.getpid(),"sid":os.getsid(0)})+"\\n")\n'+action+'\n')
        self.m.DUMP.RUNUSER.chmod(0o700)

    def read(self,kind,end):
        self.calls.append((kind,end))
        value=json.loads((self.fixture.root/('peer-'+self.fixture.value['applications'][kind[5:]]['role']+'.json')).read_bytes()) if kind.startswith('peer:') else self.fixture.reply
        return json.dumps(value).encode()

    def stage(self,app='mk8.dns',**kwargs):return self.m.stage_selected(app,4096,**({'read':self.read}|kwargs))

    def test_whole_fresh_protected_intention_and_both_access_rounds_bind_selected_stage(self):
        raw=self.stage();v=json.loads(raw)
        self.assertEqual(v['state'],'protected-selected-dump-stage-source-only');self.assertEqual(v['application'],'mk8.dns')
        self.assertEqual(v['backup_intention']['source_intention'],self.fixture.record)
        self.assertEqual(v['backup_intention']['configuration']['value'],self.value)
        self.assertEqual(v['stream']['argv'],v['backup_intention']['jobs']['mk8.dns']['dump_argv'])
        self.assertEqual(v['stage']['bytes'],v['stream']['received_bytes']);self.assertEqual(v['stage']['sha256'],v['stream']['received_sha256'])
        self.assertEqual(self.leaf().read_bytes(),self.data);self.assertEqual(raw,self.m.PREP.canonical(v))
        one=['catalog','catalog','peer:mk8.dns','peer:mk8.email','peer:mk8.dns','peer:mk8.email','catalog','catalog']
        self.assertEqual([kind for kind,_ in self.calls],one*4)
        self.assertEqual(len(self.streams),1);self.assertTrue(self.streams[0].closed and self.streams[0].done)
        self.assertFalse(self.leaf().with_suffix('').exists())

    def test_either_selected_application_uses_its_real_role_database_and_one_child(self):
        for app in ('mk8.dns','mk8.email'):
            self.program('assert Path('+repr(str(self.leaf(app)))+').is_file();os.write(1,data)')
            v=json.loads(self.stage(app));job=v['backup_intention']['jobs'][app];row=json.loads(self.ledger.read_text().splitlines()[-1])
            self.assertEqual(row['argv'],job['dump_argv']);self.assertEqual(row['pid'],row['sid'])
            self.assertEqual(row['environment'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
            self.assertEqual(job['role'],self.fixture.value['applications'][app]['role']);self.assertEqual(job['database'],self.fixture.value['applications'][app]['database'])
            self.assertEqual(self.leaf(app).read_bytes(),self.data)
        self.assertEqual(len(self.ledger.read_text().splitlines()),2)

    def test_invalid_selector_bounds_callable_and_deadlines_precede_prepare_or_child(self):
        with patch.object(self.m.BACKUP,'prepare',side_effect=AssertionError('prepare')):
            for app in (True,'mk8.sava','dns','mk8.dns\n'):
                with self.subTest(app=app),self.assertRaises(ValueError):self.stage(app)
            for cap in (True,0,self.m.DUMP.MAX_STDERR+1):
                with self.subTest(cap=cap),self.assertRaises(ValueError):self.m.stage_selected('mk8.dns',cap,read=self.read)
            with self.assertRaises(ValueError):self.stage(read=False)
            for end in (True,'later',float('inf'),float('nan'),self.m.KERNEL.now()-1):
                with self.subTest(end=str(end)),self.assertRaises(ValueError):self.stage(deadline=end)
        self.assertFalse(self.ledger.exists());self.assertFalse(self.leaf().exists())

    def test_missing_or_unsafe_protected_backup_input_refuses_before_stage_acquisition(self):
        self.m.BACKUP.INPUT.chmod(0o644)
        with self.assertRaises(ValueError):self.stage()
        self.m.BACKUP.INPUT.unlink()
        with self.assertRaises(OSError):self.stage()
        self.assertFalse(self.leaf().exists());self.assertFalse(self.ledger.exists())

    def test_real_admin_or_either_peer_refusal_precedes_stage_file_and_dump_child(self):
        for selected in ('catalog','peer:mk8.dns','peer:mk8.email'):
            def read(kind,end):
                raw=self.read(kind,end)
                if kind==selected:
                    value=json.loads(raw)
                    if kind=='catalog':value['roles'][1]['super']=True
                    else:value['authentication']='trust'
                    return json.dumps(value).encode()
                return raw
            with self.subTest(selected=selected),self.assertRaises(ValueError):self.stage(read=read)
        self.assertFalse(self.leaf().exists());self.assertFalse(self.ledger.exists())

    def test_existing_foreign_stage_never_enters_dump_and_preserves_bytes_inode(self):
        self.leaf().write_bytes(b'foreign');self.leaf().chmod(0o600);before=self.leaf().stat()
        with self.assertRaises(self.m.Incomplete) as caught:self.stage()
        self.assertIsInstance(caught.exception.cause,self.m.STAGE.Blocked)
        self.assertFalse(self.streams[0].started);self.assertTrue(self.streams[0].closed)
        self.assertEqual(self.leaf().read_bytes(),b'foreign');self.assertEqual(self.m.STAGE.file_identity(self.leaf().stat()),self.m.STAGE.file_identity(before))
        self.assertFalse(self.ledger.exists())

    def test_directory_absence_or_unsafe_mode_refuses_without_child_or_provisioning(self):
        self.store.rmdir()
        with self.assertRaises(self.m.Incomplete):self.stage()
        self.assertFalse(self.store.exists());self.assertFalse(self.ledger.exists())
        self.store.mkdir(mode=0o750)
        with self.assertRaises(self.m.Incomplete):self.stage()
        self.assertFalse(self.leaf().exists());self.assertFalse(self.ledger.exists())

    def test_stage_write_failure_explicitly_closes_active_child_preserves_original_cause(self):
        self.program('os.write(1,b"x");time.sleep(10)')
        with patch.object(self.m.STAGE.os,'write',side_effect=OSError('stage write failure')),self.assertRaises(self.m.Incomplete) as caught:self.stage()
        self.assertIsInstance(caught.exception.cause,self.m.STAGE.Blocked)
        self.assertEqual(str(caught.exception.cause.__cause__),'stage write failure')
        s=self.streams[0];self.assertTrue(s.closed);self.assertIsNotNone(s.child.poll())
        self.assertIsNone(caught.exception.stream_receipt);self.assertIsNone(caught.exception.stage_receipt)
        self.assertEqual(self.leaf().read_bytes(),b'')

    def test_original_stream_uncertainty_is_kept_through_stage_blocked_cause_chain(self):
        self.program('os.write(1,data);sys.exit(7)')
        with self.assertRaises(self.m.Incomplete) as caught:self.stage()
        s=self.streams[0];self.assertIs(caught.exception.uncertainty,s.poison)
        self.assertIs(caught.exception.cause.__cause__,s.poison)
        self.assertIsInstance(s.poison.cause,ValueError);self.assertTrue(s.closed);self.assertFalse(s.done)
        self.assertEqual(self.leaf().read_bytes(),self.data)

    def test_current_config_drift_during_dump_refuses_second_intention_without_deleting_stage(self):
        changed={**self.value,'generation':'b'*64};raw=self.m.PREP.canonical(changed)
        self.program('os.write(1,data);Path('+repr(str(self.m.BACKUP.INPUT))+').write_bytes('+repr(raw)+')')
        original=self.leaf()
        with self.assertRaises(self.m.Incomplete) as caught:self.stage()
        self.assertIsInstance(caught.exception.cause,ValueError);self.assertIsNotNone(caught.exception.stream_receipt)
        self.assertIsNotNone(caught.exception.stage_receipt);self.assertEqual(original.read_bytes(),self.data)
        self.assertFalse((self.store/('b'*64+'-mk8.dns.dump.partial')).exists())

    def test_outer_encoding_precedes_second_complete_backup_and_real_archive_readback(self):
        events=[];encode=self.m.PREP.canonical;prepare=self.m.BACKUP.prepare;readback=self.m.STAGE.readback
        def canonical(value):
            raw=encode(value)
            if isinstance(value,dict) and value.get('state')=='protected-selected-dump-stage-source-only':events.append('outer-encode')
            return raw
        def fresh(*args,**kw):
            if events:events.append('backup')
            return prepare(*args,**kw)
        def checked(*args):
            if events:events.append('readback')
            return readback(*args)
        with patch.object(self.m.PREP,'canonical',side_effect=canonical),patch.object(self.m.BACKUP,'prepare',side_effect=fresh),patch.object(self.m.STAGE,'readback',side_effect=checked):self.stage()
        self.assertEqual(events,['outer-encode','backup','readback'])

    def test_outer_receipt_cap_refuses_before_second_complete_access_and_keeps_known_receipts(self):
        with patch.object(self.m,'MAX_OUTPUT',1),self.assertRaises(self.m.Incomplete) as caught:self.stage()
        self.assertEqual(len(self.calls),16);self.assertIsNotNone(caught.exception.stream_receipt);self.assertIsNotNone(caught.exception.stage_receipt)
        self.assertEqual(self.leaf().read_bytes(),self.data)

    def test_postencoding_archive_drift_refuses_and_never_retries_or_promotes(self):
        original=self.m.PREP.canonical
        def encoded(value):
            raw=original(value)
            if isinstance(value,dict) and value.get('state')=='protected-selected-dump-stage-source-only':self.leaf().write_bytes(b'changed')
            return raw
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),self.assertRaises(self.m.Incomplete):self.stage()
        self.assertEqual(self.leaf().read_bytes(),b'changed');self.assertEqual(len(self.ledger.read_text().splitlines()),1)

    def test_module_delivery_argv_mismatch_refuses_before_target_or_child(self):
        self.m.DUMP.RUNUSER=self.exe_root/'different-delivery'
        with self.assertRaises(self.m.Incomplete):self.stage()
        self.assertFalse(self.leaf().exists());self.assertFalse(self.ledger.exists())

    def test_separate_stream_cleanup_error_does_not_mask_stage_write_failure(self):
        original=self.m.DUMP.DumpStream.side_effect
        def owned(*args,**kw):
            s=original(*args,**kw);close=s.close
            def cleanup():return close()+(OSError('separate cleanup failure'),)
            s.close=cleanup;return s
        self.program('os.write(1,b"x");time.sleep(10)')
        with patch.object(self.m.DUMP,'DumpStream',side_effect=owned),patch.object(self.m.STAGE.os,'write',side_effect=OSError('original write')),self.assertRaises(self.m.Incomplete) as caught:self.stage()
        self.assertEqual(str(caught.exception.cause.__cause__),'original write')
        self.assertEqual(str(caught.exception.cleanup[-1]),'separate cleanup failure')
        self.assertIsNotNone(self.streams[-1].child.poll())

    def test_writer_failure_after_entry_has_explicit_uncertainty_with_original_cause(self):
        self.program('os.write(1,b"x");time.sleep(10)')
        with patch.object(self.m.STAGE.os,'write',side_effect=OSError('writer fault')),self.assertRaises(self.m.Incomplete) as caught:self.stage()
        failure=caught.exception;self.assertIsInstance(failure.uncertainty,self.m.DUMP.Uncertain)
        self.assertIs(failure.uncertainty.cause,failure.cause)
        self.assertEqual(str(failure.cause.__cause__),'writer fault')
        self.assertTrue(self.streams[-1].closed);self.assertIsNone(failure.stream_receipt)

    def test_boolean_root_receipt_cannot_replace_actual_integer_completion(self):
        original=self.m.DUMP.DumpStream.side_effect
        def owned(*args,**kw):
            s=original(*args,**kw);finish=s.finish
            def completed():
                finish();value=json.loads(s.receipt);value['root_exit']=False;s.receipt=self.m.PREP.canonical(value)
            s.finish=completed;return s
        with patch.object(self.m.DUMP,'DumpStream',side_effect=owned),self.assertRaises(self.m.Incomplete):self.stage()
        self.assertEqual(self.leaf().read_bytes(),self.data)

    def test_positive_inherited_cap_and_outer_own_cap_reach_stream_without_widening(self):
        now=self.m.KERNEL.now();original=self.m.DUMP.DumpStream.side_effect;ends=[]
        def owned(*args,**kwargs):ends.append(kwargs['deadline']);return original(*args,**kwargs)
        with patch.object(self.m.KERNEL,'now',return_value=now),patch.object(self.m.DUMP,'DumpStream',side_effect=owned):
            self.stage(deadline=now+2);self.stage('mk8.email',deadline=now+10000)
        self.assertEqual(ends,[now+2,now+self.m.ATTEMPT_SECONDS])
        self.assertTrue(all(window<=now+2 for _,window in self.calls[:32]))

    def test_last_real_file_readback_context_and_time_changes_prevent_return(self):
        original=self.m.STAGE.readback
        for which,app in (('scope','mk8.dns'),('time','mk8.email')):
            now=self.m.KERNEL.now();clock=[now];scope=[4711];calls=[]
            def readback(*args):
                value=original(*args);calls.append(1)
                if len(calls)==2:
                    if which=='scope':scope[0]=True
                    else:clock[0]=now+2
                return value
            with self.subTest(which=which),patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.STAGE.KERNEL,'namespace',side_effect=lambda:scope[0]),patch.object(self.m.STAGE,'readback',side_effect=readback),self.assertRaises(self.m.Incomplete) as caught:self.stage(app,deadline=now+2)
            self.assertEqual(calls,[1,1]);self.assertIsNotNone(caught.exception.stream_receipt)
            self.assertIsNotNone(caught.exception.stage_receipt);self.assertEqual(self.leaf(app).read_bytes(),self.data)

    def test_final_directory_close_failure_retires_fd_before_one_attempt(self):
        real_open=self.m.os.open;real_close=self.m.os.close;opens=[];target=[None];replacement=[]
        def opened(path,flags,*args,**kwargs):
            fd=real_open(path,flags,*args,**kwargs)
            if path==self.store:
                opens.append(fd)
                if len(opens)==2:target[0]=fd
            return fd
        def closed(fd):
            if fd==target[0] and not replacement:
                real_close(fd);new=real_open(self.fixture.root,os.O_RDONLY|os.O_DIRECTORY)
                self.assertEqual(new,fd);replacement.append(new);raise OSError('retired directory close')
            return real_close(fd)
        try:
            with patch.object(self.m.os,'open',side_effect=opened),patch.object(self.m.os,'close',side_effect=closed),self.assertRaises(self.m.Incomplete) as caught:self.stage()
            self.assertEqual(str(caught.exception.cause),'retired directory close')
            self.assertEqual(len(replacement),1);os.fstat(replacement[0])
            self.assertIsNotNone(caught.exception.stream_receipt);self.assertIsNotNone(caught.exception.stage_receipt)
        finally:
            for fd in replacement:real_close(fd)

    def test_closed_stage_and_stream_bindings_refuse_cross_receipt_bytes(self):
        original=self.m.STAGE.stage
        def changed(*args,**kwargs):
            raw=original(*args,**kwargs);value=json.loads(raw);value['sha256']='b'*64
            return self.m.PREP.canonical(value)
        with patch.object(self.m.STAGE,'stage',side_effect=changed),self.assertRaises(self.m.Incomplete):self.stage()
        self.assertEqual(self.leaf().read_bytes(),self.data);self.assertEqual(len(self.ledger.read_text().splitlines()),1)


if __name__=='__main__':unittest.main()
