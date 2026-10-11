"""One reserved backup SOURCE attempt; PRIVATE native/account deliveries only."""
import importlib.util
import json
import os
import unittest
from unittest.mock import patch
import test_selected_inspection as fixture


class BackupLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.h=fixture.SelectedInspectionTests('test_complete_selection_fresh_both_peer_rounds_and_raw_listing_bind_without_promotion')
        self.h.setUp();self.addCleanup(self.h.doCleanups)
        # TEST-only removal of this fixture's seed stage, before lifecycle entry.
        self.h.h.leaf().unlink();self.h.h.ledger.unlink();self.h.h.calls.clear()
        spec=importlib.util.spec_from_file_location('private_backup_lifecycle',fixture.fixture.ROOT/'PostgreSQL/backup_lifecycle.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.m.MANIFEST.LISTING=self.h.m;self.m.MANIFEST.HISTORY=self.h.m.HISTORY;self.m.MANIFEST.PREP=self.h.m.PREP
        self.m.LISTING=self.h.m;self.m.UNCERTAINTY=self.h.m.HISTORY;self.m.SELECTED=self.h.h.m
        self.m.UNCERTAINTY.DUMP=self.m.SELECTED.DUMP # SAME private exception class delivery.
        self.m.BACKUP=self.h.m.BACKUP;self.m.PREP=self.h.m.PREP;self.m.KERNEL=self.h.m.KERNEL;self.m.STAGE=self.h.h.m.STAGE
        self.store=self.h.h.fixture.root/'lifecycle';self.store.mkdir(mode=0o700)
        for backend in (self.m.ATTEMPT._STORAGE,self.m.MANIFEST._STORAGE,self.m.UNCERTAINTY._STORAGE):
            backend.TRUST_ROOT=self.h.h.fixture.root;backend.TRUSTED_UID=os.geteuid()
        self.application='mk8.dns';self.points=[]

    def listing(self,path,maximum,end):
        self.assertEqual(path,self.h.h.leaf(self.application));self.assertEqual(maximum,self.h.h.value['inventory_limit_bytes'])
        self.points.append((str(path),maximum));return self.h.listing

    def run_once(self,**kwargs):return self.m.run_once(self.store,self.application,4096,**({'read':self.h.h.read,'listing':self.listing}|kwargs))

    def test_slot_exists_before_first_lazy_dump_and_success_binds_whole_source_history(self):
        slot=self.store/self.m.ATTEMPT.LEAF
        self.h.h.program('assert Path('+repr(str(slot))+').is_file();os.write(1,data)')
        raw=self.run_once();value=json.loads(raw)
        self.assertEqual(value['state'],'single-attempt-selected-backup-source-only');self.assertEqual(value['application'],self.application)
        self.assertEqual(value['reservation']['application'],self.application);self.assertEqual(value['selection'],value['listing']['selection'])
        self.assertEqual(value['manifest']['selected_listing'].encode(),self.m.PREP.canonical(value['listing']))
        self.assertEqual(value['manifest']['state'],'historical-selected-listing-manifest-only')
        self.assertEqual(self.m.ATTEMPT.load(self.store),self.m.PREP.canonical(value['reservation']))
        self.assertEqual(self.m.MANIFEST.load(self.store),self.m.PREP.canonical(value['manifest']))
        self.assertEqual(len(self.h.h.calls),80);self.assertEqual(len(self.points),1)
        self.assertEqual(self.h.h.leaf().read_bytes(),self.h.h.data);self.assertFalse(self.h.h.leaf().with_suffix('').exists())

    def test_email_job_selected_source_and_manifest_are_bound_in_one_attempt(self):
        self.application='mk8.email';v=json.loads(self.run_once())
        self.assertEqual(v['manifest']['application'],'mk8.email');self.assertEqual(v['listing']['inspection']['argv'][-1],str(self.h.h.leaf('mk8.email')))
        self.assertEqual(v['selection']['stream']['argv'],v['selection']['backup_intention']['jobs']['mk8.email']['dump_argv'])
        self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_every_existing_attempt_kind_blocks_before_fresh_or_dump(self):
        leaf=self.store/self.m.ATTEMPT.LEAF
        for kind in ('empty','directory','symlink'):
            if kind=='empty':leaf.write_bytes(b'');leaf.chmod(0o600)
            elif kind=='directory':leaf.mkdir()
            else:leaf.symlink_to(self.h.h.fixture.root/'missing')
            with self.subTest(kind=kind),patch.object(self.m.SELECTED,'stage_selected',side_effect=AssertionError('fresh')),self.assertRaises(self.m.ATTEMPT.Blocked):self.run_once()
            if kind=='directory':leaf.rmdir()
            else:leaf.unlink()
        self.assertFalse(self.h.h.ledger.exists());self.assertEqual(self.h.h.calls,[])

    def test_identical_reserved_slot_never_admits_another_attempt(self):
        with patch.object(self.m.ATTEMPT.secrets,'token_hex',return_value='a'*64):
            first=self.m.ATTEMPT.reserve(self.store,self.application,4711);leaf=self.store/self.m.ATTEMPT.LEAF;before=leaf.stat()
            with patch.object(self.m.SELECTED,'stage_selected',side_effect=AssertionError('fresh')),self.assertRaises(self.m.ATTEMPT.Blocked):self.run_once()
        self.assertEqual(leaf.read_bytes(),first);self.assertEqual(leaf.stat().st_ino,before.st_ino)

    def test_each_outcome_leaf_blocks_before_reservation_and_fresh_even_without_slot(self):
        for name in (self.m.MANIFEST.LEAF,self.m.UNCERTAINTY.LEAF):
            leaf=self.store/name;leaf.write_bytes(b'unknown');leaf.chmod(0o600)
            with self.subTest(name=name),patch.object(self.m.ATTEMPT,'reserve',side_effect=AssertionError('reserve')),self.assertRaises(ValueError):self.run_once()
            self.assertEqual(leaf.read_bytes(),b'unknown');leaf.unlink()
        self.assertFalse((self.store/self.m.ATTEMPT.LEAF).exists());self.assertFalse(self.h.h.ledger.exists())

    def test_partial_attempt_write_failure_leaves_closed_slot_without_fresh_entry(self):
        with patch.object(self.m.ATTEMPT.os,'write',return_value=False),patch.object(self.m.SELECTED,'stage_selected',side_effect=AssertionError('fresh')),self.assertRaises(self.m.ATTEMPT.Blocked):self.run_once()
        self.assertTrue((self.store/self.m.ATTEMPT.LEAF).exists())
        with self.assertRaises(self.m.ATTEMPT.Blocked):self.run_once()
        self.assertFalse(self.h.h.ledger.exists());self.assertEqual(self.h.h.calls,[])

    def test_fresh_source_refusal_keeps_reserved_slot_and_no_dump_or_history(self):
        self.h.h.m.BACKUP.INPUT.chmod(0o644)
        with self.assertRaises(self.m.Blocked) as caught:self.run_once()
        self.assertIsInstance(caught.exception.cause,ValueError);self.assertIsNone(caught.exception.selection)
        self.assertIsNone(caught.exception.history_error);self.assertTrue((self.store/self.m.ATTEMPT.LEAF).exists())
        self.assertFalse(self.h.h.ledger.exists());self.assertFalse((self.store/self.m.MANIFEST.LEAF).exists())

    def test_after_entry_stage_uncertainty_is_recorded_with_same_poison_and_no_retry(self):
        self.h.h.program('os.write(1,data);sys.exit(7)')
        with self.assertRaises(self.m.Blocked) as caught:self.run_once()
        error=caught.exception.cause;self.assertIs(type(error),self.m.SELECTED.Incomplete)
        self.assertIs(error.uncertainty,self.h.h.streams[-1].poison);self.assertIsNone(caught.exception.history_error)
        record=json.loads(self.m.UNCERTAINTY.load(self.store));self.assertEqual(record['state'],'historical-selected-stage-incomplete-no-retry')
        self.assertEqual(record['capture'][6],7);self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)
        with patch.object(self.m.SELECTED,'stage_selected',side_effect=AssertionError('retry')),self.assertRaises(ValueError):self.run_once()

    def test_uncertainty_history_failure_remains_separate_from_original_cause_poison(self):
        self.h.h.program('os.write(1,data);sys.exit(7)');history=OSError('history failed')
        with patch.object(self.m.UNCERTAINTY,'record',side_effect=history),self.assertRaises(self.m.Blocked) as caught:self.run_once()
        self.assertIs(caught.exception.history_error,history);self.assertIs(caught.exception.cause.uncertainty,self.h.h.streams[-1].poison)
        self.assertIs(caught.exception.__cause__,caught.exception.cause)
        with self.assertRaises(self.m.ATTEMPT.Blocked):self.run_once()
        self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_listing_failure_retains_known_selection_and_does_not_manufacture_manifest(self):
        cause=OSError('listing failed')
        def listing(*args):raise cause
        with self.assertRaises(self.m.Blocked) as caught:self.run_once(listing=listing)
        self.assertIs(type(caught.exception.cause),self.m.LISTING.Incomplete);self.assertIs(caught.exception.cause.cause,cause)
        self.assertIsNotNone(caught.exception.selection);self.assertIsNone(caught.exception.listing);self.assertIsNone(caught.exception.manifest)
        self.assertFalse((self.store/self.m.MANIFEST.LEAF).exists());self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_manifest_failure_retains_known_whole_listing_and_closed_slot(self):
        cause=OSError('manifest failure')
        with patch.object(self.m.MANIFEST,'record',side_effect=cause),self.assertRaises(self.m.Blocked) as caught:self.run_once()
        self.assertIs(caught.exception.cause,cause);self.assertIsNotNone(caught.exception.selection);self.assertIsNotNone(caught.exception.listing)
        self.assertIsNone(caught.exception.manifest);self.assertEqual(self.h.h.leaf().read_bytes(),self.h.h.data)
        with self.assertRaises(self.m.ATTEMPT.Blocked):self.run_once()

    def test_attempt_tampering_during_dump_refuses_before_listing(self):
        leaf=self.store/self.m.ATTEMPT.LEAF
        self.h.h.program('os.write(1,data);Path('+repr(str(leaf))+').write_bytes(b"changed")')
        with self.assertRaises(self.m.Blocked) as caught:self.run_once()
        self.assertIsNotNone(caught.exception.selection);self.assertIsNone(caught.exception.listing);self.assertEqual(self.points,[])
        self.assertEqual(leaf.read_bytes(),b'changed');self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_output_encoding_precedes_final_real_backup_archive_and_history_reads(self):
        events=[];encode=self.m.PREP.canonical;fresh=self.m.SELECTED.intention;readback=self.m.STAGE.readback;slot=self.m.ATTEMPT.load;history=self.m.MANIFEST.load
        def encoded(value):
            raw=encode(value)
            if isinstance(value,dict) and value.get('state')=='single-attempt-selected-backup-source-only':events.append('encode')
            return raw
        def prepared(*args,**kwargs):
            if events:events.append('fresh')
            return fresh(*args,**kwargs)
        def read(*args):
            if events:events.append('archive')
            return readback(*args)
        def loaded(*args,**kwargs):
            if events:events.append('slot')
            return slot(*args,**kwargs)
        def manifested(*args,**kwargs):
            if events:events.append('manifest')
            return history(*args,**kwargs)
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),patch.object(self.m.SELECTED,'intention',side_effect=prepared),patch.object(self.m.STAGE,'readback',side_effect=read),patch.object(self.m.ATTEMPT,'load',side_effect=loaded),patch.object(self.m.MANIFEST,'load',side_effect=manifested):self.run_once()
        self.assertEqual(events,['encode','fresh','archive','slot','manifest'])

    def test_result_cap_refuses_before_final_fresh_read_and_keeps_known_manifest(self):
        with patch.object(self.m,'MAX_OUTPUT',1),self.assertRaises(self.m.Blocked) as caught:self.run_once()
        self.assertEqual(len(self.h.h.calls),64);self.assertIsNotNone(caught.exception.manifest)
        self.assertTrue((self.store/self.m.MANIFEST.LEAF).exists());self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_postencoding_stage_drift_refuses_without_reset_or_second_dump(self):
        encode=self.m.PREP.canonical
        def encoded(value):
            raw=encode(value)
            if isinstance(value,dict) and value.get('state')=='single-attempt-selected-backup-source-only':self.h.h.leaf().write_bytes(b'changed')
            return raw
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),self.assertRaises(self.m.Blocked) as caught:self.run_once()
        self.assertIsNotNone(caught.exception.manifest);self.assertEqual(self.h.h.leaf().read_bytes(),b'changed')
        with self.assertRaises(ValueError):self.run_once()
        self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_invalid_public_inputs_scope_and_deadlines_precede_slot_or_fresh(self):
        with patch.object(self.m.ATTEMPT,'reserve',side_effect=AssertionError('reserve')):
            for app in (True,'mk8.sava','dns'):
                with self.subTest(app=app),self.assertRaises(ValueError):self.m.run_once(self.store,app,4096,read=self.h.h.read)
            for cap in (True,0,self.m.SELECTED.DUMP.MAX_STDERR+1):
                with self.subTest(cap=cap),self.assertRaises(ValueError):self.m.run_once(self.store,'mk8.dns',cap,read=self.h.h.read)
            for kwargs in ({'read':False},{'listing':False},{'deadline':True},{'deadline':float('inf')},{'deadline':float('nan')},{'deadline':self.m.KERNEL.now()-1}):
                with self.subTest(kwargs=str(kwargs)),self.assertRaises(ValueError):self.run_once(**kwargs)
        with patch.object(self.m.KERNEL,'namespace',return_value=0),self.assertRaises(ValueError):self.run_once()
        self.assertEqual(list(self.store.iterdir()),[]);self.assertFalse(self.h.h.ledger.exists())

    def test_positive_parent_and_own_caps_reach_reservation_without_widening(self):
        now=self.m.KERNEL.now();ends=[]
        def stop(*args,**kwargs):ends.append(kwargs['deadline']);raise OSError('admission probe')
        with patch.object(self.m.KERNEL,'now',return_value=now),patch.object(self.m.ATTEMPT,'reserve',side_effect=stop):
            for until in (now+2,now+10000):
                with self.assertRaises(OSError):self.run_once(deadline=until)
        self.assertEqual(ends,[now+2,now+self.m.ATTEMPT_SECONDS]);self.assertFalse(self.h.h.ledger.exists())

    def test_invalid_generated_marker_refuses_before_slot_acquisition(self):
        for marker in ('0'*64,'A'*64,'short',True):
            with self.subTest(marker=str(marker)[:8]),patch.object(self.m.ATTEMPT.secrets,'token_hex',return_value=marker),self.assertRaises(ValueError):self.run_once()
        self.assertEqual(list(self.store.iterdir()),[])

    def test_checked_slot_closed_schema_types_and_canonical_after_actual_reservation(self):
        raw=self.m.ATTEMPT.reserve(self.store,self.application,4711);v=json.loads(raw)
        for change in ({'namespace':True},{'application':'mk8.sava'},{'state':'completed'},{'correlation_id':'0'*64},{'extra':True}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.m.ATTEMPT.checked(self.m.PREP.canonical(v|change))
        with self.assertRaises(ValueError):self.m.ATTEMPT.checked(raw+b' ')
        self.assertEqual((self.store/self.m.ATTEMPT.LEAF).read_bytes(),raw)

    def test_owned_query_context_change_blocks_next_query_and_dump_entry(self):
        scope=[4711];calls=[]
        def read(kind,end):calls.append(kind);raw=self.h.h.read(kind,end);scope[0]=True;return raw
        with patch.object(self.m.KERNEL,'namespace',side_effect=lambda:scope[0]),self.assertRaises(self.m.Blocked):self.run_once(read=read)
        self.assertEqual(calls,['catalog']);self.assertFalse(self.h.h.ledger.exists());self.assertFalse(self.h.h.leaf().exists())
        self.assertTrue((self.store/self.m.ATTEMPT.LEAF).exists())

    def test_owned_listing_context_change_blocks_manifest_and_preserves_source_stage(self):
        scope=[4711]
        def listing(*args):scope[0]=True;return self.h.listing
        with patch.object(self.m.KERNEL,'namespace',side_effect=lambda:scope[0]),self.assertRaises(self.m.Blocked) as caught:self.run_once(listing=listing)
        self.assertIsNotNone(caught.exception.selection);self.assertIsNone(caught.exception.listing)
        self.assertFalse((self.store/self.m.MANIFEST.LEAF).exists());self.assertEqual(self.h.h.leaf().read_bytes(),self.h.h.data)

    def test_final_real_manifest_readback_context_change_refuses_return(self):
        original=self.m.MANIFEST.load;scope=[4711]
        def loaded(*args,**kwargs):raw=original(*args,**kwargs);scope[0]=True;return raw
        with patch.object(self.m.KERNEL,'namespace',side_effect=lambda:scope[0]),patch.object(self.m.MANIFEST,'load',side_effect=loaded),self.assertRaises(self.m.Blocked) as caught:self.run_once()
        self.assertIsNotNone(caught.exception.manifest);self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_actual_private_listing_argv_environment_and_one_dump_despite_second_call(self):
        v=json.loads(self.run_once(listing=None));row=json.loads(self.h.ledger.read_text())
        self.assertEqual(row['argv'],v['listing']['inspection']['argv']);self.assertEqual(row['environment'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'});self.assertEqual(row['pid'],row['sid'])
        with patch.object(self.m.SELECTED,'stage_selected',side_effect=AssertionError('fresh')),self.assertRaises(ValueError):self.run_once(listing=None)
        self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1);self.assertEqual(len(self.h.ledger.read_text().splitlines()),1)

    def test_postencoding_actual_manifest_drift_refuses_final_checked_history(self):
        encode=self.m.PREP.canonical
        def encoded(value):
            raw=encode(value)
            if isinstance(value,dict) and value.get('state')=='single-attempt-selected-backup-source-only':(self.store/self.m.MANIFEST.LEAF).write_bytes(b'changed')
            return raw
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),self.assertRaises(self.m.Blocked) as caught:self.run_once()
        self.assertIsNotNone(caught.exception.manifest);self.assertEqual((self.store/self.m.MANIFEST.LEAF).read_bytes(),b'changed')
        self.assertEqual(self.h.h.leaf().read_bytes(),self.h.h.data);self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_last_actual_manifest_load_time_expiry_prevents_return(self):
        now=self.m.KERNEL.now();clock=[now];original=self.m.MANIFEST.load
        def loaded(*args,**kwargs):raw=original(*args,**kwargs);clock[0]=now+1000;return raw
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.MANIFEST,'load',side_effect=loaded),self.assertRaises(self.m.Blocked) as caught:self.run_once(deadline=now+1000)
        self.assertIsNotNone(caught.exception.manifest);self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_final_archive_directory_close_retires_number_before_one_failed_close(self):
        opened=self.m.os.open;closed=self.m.os.close;encode=self.m.PREP.canonical;last=[None];target=[None];replacement=[]
        def open_fd(path,flags,*args,**kwargs):
            fd=opened(path,flags,*args,**kwargs)
            if path==self.h.h.store:last[0]=fd
            return fd
        def encoded(value):
            raw=encode(value)
            if isinstance(value,dict) and value.get('state')=='single-attempt-selected-backup-source-only':target[0]=last[0]
            return raw
        def close_fd(fd):
            if fd==target[0] and not replacement:
                closed(fd);new=opened(self.h.h.fixture.root,os.O_RDONLY|os.O_DIRECTORY);self.assertEqual(new,fd);replacement.append(new);raise OSError('retired lifecycle close')
            return closed(fd)
        try:
            with patch.object(self.m.os,'open',side_effect=open_fd),patch.object(self.m.os,'close',side_effect=close_fd),patch.object(self.m.PREP,'canonical',side_effect=encoded),self.assertRaises(self.m.Blocked) as caught:self.run_once()
            self.assertEqual(str(caught.exception.cause),'retired lifecycle close');self.assertEqual(caught.exception.cleanup,())
            self.assertIsNotNone(caught.exception.manifest);os.fstat(replacement[0])
        finally:
            for fd in replacement:closed(fd)


if __name__=='__main__':unittest.main()
