"""Historical failure custody with PRIVATE stage/dump/account deliveries only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import test_selected_stage as fixture


class SelectedUncertaintyTests(unittest.TestCase):
    def setUp(self):
        self.h=fixture.SelectedStageTests('test_existing_foreign_stage_never_enters_dump_and_preserves_bytes_inode')
        self.h.setUp();self.addCleanup(self.h.doCleanups)
        spec=importlib.util.spec_from_file_location('private_selected_uncertainty',fixture.ROOT/'PostgreSQL/selected_uncertainty.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.m.SELECTED=self.h.m;self.m.BACKUP=self.h.m.BACKUP;self.m.DUMP=self.h.m.DUMP
        self.m.PREP=self.h.m.PREP;self.m.KERNEL=self.h.m.KERNEL;self.m.Pending=self.h.m.Pending
        self.history=self.h.fixture.root/'history';self.history.mkdir(mode=0o700)
        self.m._STORAGE.TRUST_ROOT=self.h.fixture.root;self.m._STORAGE.TRUSTED_UID=os.geteuid()
        self.native={'popen':self.h.m.DUMP.subprocess.Popen,'dump':self.h.m.stage_selected}

    def failed(self,action='os.write(1,data);sys.exit(7)'):
        self.h.program(action)
        with self.assertRaises(self.h.m.Incomplete) as caught:self.h.stage()
        return caught.exception

    def record(self,error,**kwargs):return self.m.record(self.history,error,**kwargs)

    def no_entry(self):
        return patch.object(self.h.m,'stage_selected',side_effect=AssertionError('stage entry'))

    def test_actual_uncertainty_original_poison_and_after_cleanup_capture_are_preserved(self):
        error=self.failed();poison=self.h.streams[0].poison
        self.assertIs(error.uncertainty,poison);self.assertEqual(error.provenance[3],self.h.streams[0].evidence())
        raw=self.m.capture(error);value=json.loads(raw)
        self.assertEqual(value['state'],self.m.STATE);self.assertEqual(value['intention'],error.provenance[0].decode())
        self.assertEqual(value['capture'][6],7);self.assertTrue(value['capture'][7] and value['capture'][8])
        self.assertEqual(value['uncertainty']['capture'],value['capture'])
        self.assertEqual(value['stream_receipt_hex'],None);self.assertEqual(value['stage_receipt_hex'],None)
        self.assertEqual(self.h.leaf().read_bytes(),self.h.data)
        with self.no_entry(),patch.object(self.h.m.BACKUP,'prepare',side_effect=AssertionError('fresh prepare')):
            self.assertEqual(self.record(error),raw);self.assertEqual(self.m.load(self.history),raw)
        self.assertEqual(len(self.h.ledger.read_text().splitlines()),1);self.assertIs(error.uncertainty,poison)

    def test_existing_stage_failure_retains_pre_entry_empty_capture_without_new_child(self):
        self.h.leaf().write_bytes(b'foreign');self.h.leaf().chmod(0o600)
        with self.assertRaises(self.h.m.Incomplete) as caught:self.h.stage()
        error=caught.exception;value=json.loads(self.record(error))
        self.assertIsNone(value['uncertainty']);self.assertIsNone(value['capture'][1]);self.assertIsNone(value['capture'][2])
        self.assertFalse(value['capture'][7]);self.assertTrue(value['capture'][8]);self.assertEqual(value['capture'][3],0)
        self.assertFalse(self.h.ledger.exists());self.assertEqual(self.h.leaf().read_bytes(),b'foreign')

    def test_writer_failure_history_retains_uncertainty_and_original_nested_cause(self):
        self.h.program('os.write(1,b"x");time.sleep(10)')
        with patch.object(self.h.m.STAGE.os,'write',side_effect=OSError('original writer')),self.assertRaises(self.h.m.Incomplete) as caught:self.h.stage()
        error=caught.exception;raw=self.record(error);value=json.loads(raw)
        self.assertEqual(value['cause'][1],['OSError','original writer']);self.assertIs(error.uncertainty.cause,error.cause)
        self.assertEqual(value['uncertainty']['cause'],value['cause']);self.assertTrue(value['capture'][8])
        self.assertIsNotNone(self.h.streams[-1].child.poll());self.assertEqual(self.h.leaf().read_bytes(),b'')

    def test_known_zero_completion_remains_history_only_when_second_source_refuses(self):
        self.h.program('os.write(1,data);Path('+repr(str(self.h.m.BACKUP.INPUT))+').write_bytes('+repr(self.h.m.PREP.canonical({**self.h.value,'generation':'b'*64}))+')')
        with self.assertRaises(self.h.m.Incomplete) as caught:self.h.stage()
        error=caught.exception;value=json.loads(self.record(error))
        self.assertEqual(value['state'],self.m.STATE);self.assertEqual(value['capture'][6],0);self.assertIsNone(value['uncertainty'])
        self.assertEqual(bytes.fromhex(value['stream_receipt_hex']),error.stream_receipt)
        self.assertEqual(bytes.fromhex(value['stage_receipt_hex']),error.stage_receipt)
        self.assertEqual(json.loads(value['intention'])['configuration']['value']['generation'],'a'*64)
        self.assertEqual(self.h.leaf().read_bytes(),self.h.data)

    def test_separate_cleanup_diagnostics_do_not_replace_original_failure(self):
        error=self.failed();original=error.cause;poison=error.uncertainty
        error.cleanup=(OSError('separate cleanup'),);poison.cleanup=(RuntimeError('transport cleanup'),)
        value=json.loads(self.record(error))
        self.assertEqual(value['cleanup'],[['OSError','separate cleanup']])
        self.assertEqual(value['uncertainty']['cleanup'],[['RuntimeError','transport cleanup']])
        self.assertIs(error.cause,original);self.assertIs(error.uncertainty,poison)

    def test_binary_warning_prefix_is_losslessly_hex_encoded(self):
        error=self.failed('os.write(1,b"x");os.write(2,b"\\x00\\xff\\r\\n");sys.exit(9)')
        value=json.loads(self.record(error))
        self.assertEqual(bytes.fromhex(value['capture'][5]),b'\x00\xff\r\n')
        self.assertEqual(value['capture'][6],9);self.assertEqual(value['state'],self.m.STATE)

    def test_malformed_known_receipt_is_preserved_opaque_without_promotion(self):
        error=self.failed();error.stream_receipt=b'false-root-or-invalid-json\x00\xff'
        value=json.loads(self.record(error));self.assertEqual(bytes.fromhex(value['stream_receipt_hex']),error.stream_receipt)
        self.assertEqual(value['state'],self.m.STATE);self.assertEqual(value['capture'][6],7)

    def test_exact_delivery_class_and_immutable_provenance_refuse_other_profiles(self):
        error=self.failed()
        class Other(type(error)):pass
        wrong=Other(error.cause,error.uncertainty,error.stream_receipt,error.stage_receipt,error.cleanup,error.provenance)
        for item in (RuntimeError('generic'),error.uncertainty,wrong):
            with self.subTest(kind=type(item).__name__),self.assertRaises(ValueError):self.m.capture(item)
        original=error.provenance;error.provenance=list(original)
        with self.assertRaises(ValueError):self.m.capture(error)
        self.assertFalse((self.history/self.m.LEAF).exists())

    def test_intention_job_or_pg_plan_tampering_cannot_be_repaired_by_outer_hash(self):
        raw=self.m.capture(self.failed());value=json.loads(raw)
        for which in ('job','plan'):
            v=copy.deepcopy(value);plan=json.loads(v['intention'])
            if which=='job':plan['jobs']['mk8.dns']['dump_argv'].append('--unsafe')
            else:plan['source_intention']['plan']['files']['pg_hba.conf']='host all all all trust\n'
            original=self.m.encoded(plan);v['intention']=original.decode();v['intention_sha256']=self.m.digest(original)
            with self.subTest(which=which),self.assertRaises(ValueError):self.m.checked(self.m.encoded(v))

    def test_closed_schema_canonical_and_initial_byte_cap_precede_decoding(self):
        raw=self.m.capture(self.failed());value=json.loads(raw)
        for item in (True,b'',raw+b' ',self.m.encoded(value|{'extra':1}),raw.replace(b'"capture":',b'"capture":null,"capture":',1)):
            with self.subTest(item=type(item).__name__),self.assertRaises(ValueError):self.m.checked(item)
        with patch.object(self.m,'MAX_RECORD',len(raw)-1),self.assertRaises(ValueError):self.m.checked(raw)

    def test_every_capture_typed_field_and_prefix_bound_is_checked(self):
        value=json.loads(self.m.capture(self.failed()))
        for index,bad in ((0,[]),(1,True),(2,[[True]*8]*2),(3,True),(4,'bad'),(5,'FF'),(6,False),(7,1),(8,False)):
            for target in ('capture','uncertainty'):
                v=copy.deepcopy(value);row=v['capture'] if target=='capture' else v['uncertainty']['capture'];row[index]=bad
                with self.subTest(index=index,target=target),self.assertRaises(ValueError):self.m.checked(self.m.encoded(v))
        v=copy.deepcopy(value);v['capture'][5]='aa'*(v['stderr_limit_bytes']+2)
        with self.assertRaises(ValueError):self.m.checked(self.m.encoded(v))

    def test_missing_empty_hash_or_entered_identity_is_rejected(self):
        value=json.loads(self.m.capture(self.failed()))
        for fields in ({3:0,4:'a'*64},{1:None},{2:None}):
            v=copy.deepcopy(value)
            for index,item in fields.items():v['capture'][index]=item
            with self.subTest(fields=fields),self.assertRaises(ValueError):self.m.checked(self.m.encoded(v))

    def test_excessive_or_cyclic_cause_chain_refuses_without_erasing_original(self):
        error=self.failed();cause=error.cause;cause.__cause__=cause
        with self.assertRaises(ValueError):self.record(error)
        self.assertIs(error.cause,cause);self.assertFalse((self.history/self.m.LEAF).exists())

    def test_payload_and_envelope_integrity_closed_schema_cross_profile_refusal(self):
        raw=self.m.capture(self.failed());stored=self.m.envelope(raw);v=json.loads(stored)
        self.assertEqual(self.m.stored(stored),raw)
        for change in ({'payload_sha256':'0'*64},{'state':'completed'},{'schema':'debian13s4-nft-intent-history-1'},{'extra':True}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.m.stored(self.m.encoded(v|change))
        with self.assertRaises(ValueError):self.m._STORAGE.intent(raw)
        with patch.object(self.m,'MAX_BYTES',1),self.assertRaises(ValueError):self.m.envelope(raw)

    def test_real_private_record_load_mode_links_and_same_inode_history_idempotency(self):
        error=self.failed();raw=self.record(error);leaf=self.history/self.m.LEAF;before=leaf.stat()
        self.assertEqual(before.st_mode&0o777,0o600);self.assertEqual(before.st_nlink,1)
        self.assertEqual(self.record(error),raw);self.assertEqual(self.m.load(self.history),raw)
        self.assertEqual(leaf.stat().st_ino,before.st_ino);self.assertEqual(self.h.leaf().read_bytes(),self.h.data)

    def test_different_history_refuses_without_overwrite_or_second_stage(self):
        error=self.failed();first=self.record(error);leaf=self.history/self.m.LEAF;before=leaf.read_bytes()
        error.cleanup=(OSError('different'),)
        with self.assertRaises(ValueError):self.record(error)
        self.assertEqual(leaf.read_bytes(),before);self.assertEqual(self.m.load(self.history),first)
        self.assertEqual(len(self.h.ledger.read_text().splitlines()),1)

    def test_unsafe_history_path_modes_links_and_symlinks_refuse(self):
        error=self.failed();self.record(error);leaf=self.history/self.m.LEAF
        leaf.chmod(0o644)
        with self.assertRaises(ValueError):self.m.load(self.history)
        leaf.chmod(0o600);alias=self.history/'alias';os.link(leaf,alias)
        with self.assertRaises(ValueError):self.m.load(self.history)
        alias.unlink();raw=leaf.read_bytes();leaf.unlink();leaf.symlink_to(self.h.leaf())
        with self.assertRaises(ValueError):self.m.load(self.history)
        leaf.unlink();leaf.write_bytes(raw);leaf.chmod(0o600);self.history.chmod(0o750)
        with self.assertRaises(ValueError):self.m.load(self.history)

    def test_storage_failure_propagates_separately_from_original_uncertainty(self):
        error=self.failed();poison=error.uncertainty;cause=error.cause
        with patch.object(self.m._STORAGE,'create',side_effect=OSError('history failure')),self.assertRaises(OSError):self.record(error)
        self.assertIs(error.uncertainty,poison);self.assertIs(error.cause,cause)
        self.assertEqual(len(self.h.ledger.read_text().splitlines()),1)

    def test_invalid_deadlines_refuse_before_capture_or_storage(self):
        error=self.failed()
        with patch.object(self.m,'capture',side_effect=AssertionError('capture')):
            for end in (True,float('nan'),float('inf'),self.m._STORAGE.KERNEL.now()-1):
                with self.subTest(end=str(end)),self.assertRaises(ValueError):self.record(error,deadline=end)
        self.assertFalse((self.history/self.m.LEAF).exists())

    def test_positive_parent_and_own_caps_preserve_same_end_through_storage(self):
        error=self.failed();now=self.m._STORAGE.KERNEL.now();ends=[]
        with patch.object(self.m._STORAGE.KERNEL,'now',return_value=now),patch.object(self.m._STORAGE,'create',side_effect=lambda path,raw,deadline:ends.append(deadline) or raw):
            self.record(error,deadline=now+2);self.record(error,deadline=now+1000)
        self.assertEqual(ends,[now+2,now+self.m._STORAGE.ATTEMPT_SECONDS])

    def test_capture_expiry_blocks_storage_and_load_readback_expiry_blocks_return(self):
        error=self.failed();now=self.m._STORAGE.KERNEL.now();clock=[now];capture=self.m.capture
        def expired(value):raw=capture(value);clock[0]=now+2;return raw
        with patch.object(self.m._STORAGE.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m,'capture',side_effect=expired),patch.object(self.m._STORAGE,'create',side_effect=AssertionError('store')),self.assertRaises(ValueError):self.record(error,deadline=now+2)
        self.record(error);read=self.m._STORAGE.read_at;clock[0]=now
        def readback(*args,**kwargs):raw=read(*args,**kwargs);clock[0]=now+2;return raw
        with patch.object(self.m._STORAGE.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m._STORAGE,'read_at',side_effect=readback),self.assertRaises(ValueError):self.m.load(self.history,deadline=now+2)

    def test_original_backend_functions_and_other_storage_instances_are_unchanged(self):
        import ast
        raw=(fixture.ROOT/'Firewall/proposal_store.py').read_bytes();tree=ast.parse(raw)
        self.assertEqual(self.m._STORAGE.LEAF,self.m.LEAF)
        self.assertEqual(self.m._STORAGE.create.__code__.co_filename,str(fixture.ROOT/'Firewall/proposal_store.py'))
        self.assertTrue(any(isinstance(n,ast.FunctionDef) and n.name=='create' for n in tree.body))
        self.assertIsNot(self.m._STORAGE,self.h.m.STAGE)
        self.assertEqual(self.h.m.STAGE.MAX_RECEIPT,4096)

    def test_capture_inventory_caps_refuse_before_outer_encoding(self):
        error=self.failed();original=error.provenance
        for target in ('cleanup','argv','signature','receipt'):
            error.cleanup=();error.provenance=original;error.stream_receipt=None
            if target=='cleanup':error.cleanup=(OSError('x'),)*17
            elif target=='receipt':error.stream_receipt=b'x'*(self.m.DUMP.MAX_RECEIPT+1)
            else:
                row=list(original[3]);row[0]=row[0]+('extra',) if target=='argv' else row[0]
                if target=='signature':row[2]=(row[2][0]+(0,),row[2][1])
                error.provenance=original[:3]+(tuple(row),)
            encode=self.m.encoded
            def outer(value):
                if isinstance(value,dict) and value.get('schema')=='debian13s4-selected-stage-incomplete-1':raise AssertionError('outer encoding')
                return encode(value)
            with self.subTest(target=target),patch.object(self.m,'encoded',side_effect=outer),self.assertRaises(ValueError):self.m.capture(error)
        self.assertFalse((self.history/self.m.LEAF).exists())

    def test_exact_uncertainty_class_and_typed_stderr_cap_cannot_be_forged_aliases(self):
        error=self.failed();original=error.uncertainty;provenance=error.provenance
        error.uncertainty=RuntimeError('foreign uncertainty')
        with self.assertRaises(ValueError):self.m.capture(error)
        error.uncertainty=original;error.provenance=(provenance[0],provenance[1],True,provenance[3])
        with self.assertRaises(ValueError):self.m.capture(error)
        self.assertFalse((self.history/self.m.LEAF).exists())

    def test_real_storage_sync_failure_is_separate_and_retains_original_uncertainty(self):
        error=self.failed();poison=error.uncertainty
        with patch.object(self.m._STORAGE.os,'fsync',side_effect=OSError('private history sync')),self.assertRaises(OSError):self.record(error)
        self.assertIs(error.uncertainty,poison);self.assertEqual(list(self.history.iterdir()),[])
        self.assertEqual(len(self.h.ledger.read_text().splitlines()),1);self.assertEqual(self.h.leaf().read_bytes(),self.h.data)

    def test_history_window_starts_before_capture_and_does_not_observe_current_scope(self):
        error=self.failed();raw=self.m.capture(error)
        with patch.object(self.h.m.KERNEL,'namespace',side_effect=AssertionError('current namespace')),patch.object(self.h.m.PREP,'read_protected',side_effect=AssertionError('protected read')),patch.object(self.h.m.DUMP.KERNEL,'trusted_binary',side_effect=AssertionError('current executable')):
            self.assertEqual(self.record(error),raw);self.assertEqual(self.m.load(self.history),raw)
        self.assertEqual(len(self.h.ledger.read_text().splitlines()),1)


if __name__=='__main__':unittest.main()
