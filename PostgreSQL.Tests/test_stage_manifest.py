"""Historical source manifests; private models, never completed-backup proof."""
import copy
import importlib.util
import json
import os
import unittest
from unittest.mock import patch
import test_selected_inspection as fixture


class StageManifestTests(unittest.TestCase):
    def setUp(self):
        self.h=fixture.SelectedInspectionTests('test_complete_selection_fresh_both_peer_rounds_and_raw_listing_bind_without_promotion')
        self.h.setUp();self.addCleanup(self.h.doCleanups)
        spec=importlib.util.spec_from_file_location('private_stage_manifest',fixture.fixture.ROOT/'PostgreSQL/stage_manifest.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.m.LISTING=self.h.m;self.m.HISTORY=self.h.m.HISTORY;self.m.PREP=self.h.m.PREP
        self.store=self.h.h.fixture.root/'manifest';self.store.mkdir(mode=0o700)
        self.m._STORAGE.TRUST_ROOT=self.h.h.fixture.root;self.m._STORAGE.TRUSTED_UID=os.geteuid()
        self.raw=self.h.inspect()

    def record(self,raw=None,**kwargs):return self.m.record(self.store,self.raw if raw is None else raw,**kwargs)

    def test_complete_manifest_verbatim_listing_and_all_nested_receipts_remain_source_only(self):
        raw=self.record();v=json.loads(raw)
        self.assertEqual(v['state'],self.m.STATE);self.assertEqual(v['selected_listing'].encode(),self.raw)
        self.assertEqual(v['application'],'mk8.dns');self.assertEqual(v['generation'],'a'*64)
        self.assertEqual(v['selected_listing_sha256'],self.m.digest(self.raw))
        self.assertEqual(self.m.load(self.store),raw);self.assertEqual(self.h.h.leaf().read_bytes(),self.h.h.data)
        self.assertFalse(self.h.h.leaf().with_suffix('').exists())

    def test_successful_email_selected_listing_and_manifest_use_email_job_and_partial(self):
        email=self.h.h.stage('mk8.email');points=[]
        def listing(path,maximum,end):points.append((str(path),maximum));return self.h.listing
        raw=self.h.m.inspect_selected(email,read=self.h.h.read,listing=listing);v=json.loads(raw)
        manifest=json.loads(self.record(raw));job=v['selection']['backup_intention']['jobs']['mk8.email']
        self.assertEqual(manifest['application'],'mk8.email');self.assertEqual(manifest['state'],self.m.STATE)
        self.assertEqual(v['selection']['stream']['argv'],job['dump_argv'])
        self.assertEqual(v['inspection']['argv'],[str(self.h.m.INSPECT.RESTORE),'--list',str(self.h.h.leaf('mk8.email'))])
        self.assertEqual(points,[(str(self.h.h.leaf('mk8.email')),self.h.h.value['inventory_limit_bytes'])])
        self.assertEqual(self.h.h.leaf('mk8.email').read_bytes(),self.h.h.data)
        self.assertEqual(self.m.load(self.store),self.m.capture(raw))

    def test_capture_and_store_never_read_fresh_source_scope_binary_or_run_listing(self):
        with patch.object(self.h.m,'inspect_selected',side_effect=AssertionError('listing')),patch.object(self.h.m.SELECTED,'intention',side_effect=AssertionError('fresh')),patch.object(self.h.m.KERNEL,'namespace',side_effect=AssertionError('namespace')),patch.object(self.h.m.INSPECT.KERNEL,'trusted_binary',side_effect=AssertionError('binary')):
            raw=self.record();self.assertEqual(self.m.load(self.store),raw)
        self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)

    def test_initial_byte_bound_duplicate_nonfinite_float_and_closed_canonical_schema(self):
        v=json.loads(self.raw)
        for raw in (True,bytearray(self.raw),b'',self.raw+b' ',self.m.encoded(v|{'extra':1}),self.m.encoded(v|{'schema':True}),b'{"x":NaN}',b'{"x":1.1}',self.raw.replace(b'"inspection":',b'"inspection":null,"inspection":',1)):
            with self.subTest(kind=type(raw).__name__),self.assertRaises(ValueError):self.m.listing_checked(raw)
        with patch.object(self.m.LISTING,'MAX_OUTPUT',len(self.raw)-1),patch.object(self.m.LISTING.BACKUP.ACCESS.json,'loads',side_effect=AssertionError('JSON')),self.assertRaises(ValueError):self.m.listing_checked(self.raw)

    def test_outer_context_state_hashes_and_selection_repaired_job_tampering_refuse(self):
        for field,bad in (('namespace',True),('state','completed-backup'),('selection_sha256','0'*64),('inspection_sha256','0'*64)):
            v=json.loads(self.raw);v[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.m.listing_checked(self.m.encoded(v))
        v=json.loads(self.raw);v['selection']['backup_intention']['jobs']['mk8.dns']['dump_argv'].append('--unsafe')
        v['selection_sha256']=self.m.digest(self.m.encoded(v['selection']))
        with self.assertRaises(ValueError):self.m.listing_checked(self.m.encoded(v))

    def test_every_listing_field_closed_typed_and_whole_stage_correspondence(self):
        for field,bad in (('schema',True),('namespace',True),('state','valid'),('stage_sha256','a'*64),('argv',[]),('listing_limit_bytes',True),('listing_bytes',True),('listing_hex','FF'),('listing_hex',''),('listing_sha256','a'*64),('extra',True)):
            v=json.loads(self.raw);v['inspection'][field]=bad;v['inspection_sha256']=self.m.digest(self.m.encoded(v['inspection']))
            with self.subTest(field=field),self.assertRaises(ValueError):self.m.listing_checked(self.m.encoded(v))
        v=json.loads(self.raw);v['inspection']['stage']['leaf']='b'*64+'-mk8.dns.dump.partial';v['inspection_sha256']=self.m.digest(self.m.encoded(v['inspection']))
        with self.assertRaises(ValueError):self.m.listing_checked(self.m.encoded(v))

    def test_raw_listing_binary_is_losslessly_retained_but_not_an_archive_or_toc_verdict(self):
        value=self.m.listing_checked(self.raw);listing=bytes.fromhex(value['inspection']['listing_hex'])
        self.assertEqual(listing,self.h.listing);self.assertIn(b'\x00\xff\r\n',listing)
        self.assertEqual(json.loads(self.record())['state'],self.m.STATE)
        self.assertTrue(self.h.h.data.startswith(b'INVALID-PG-ARCHIVE'))

    def test_reported_executable_shape_type_owner_and_writable_modes_refuse(self):
        for index,bad in ((0,-1),(1,0),(2,0o100777),(3,os.geteuid()+1),(5,True),(7,False)):
            v=json.loads(self.raw);v['inspection']['executable'][index]=bad;v['inspection_sha256']=self.m.digest(self.m.encoded(v['inspection']))
            with self.subTest(index=index),self.assertRaises(ValueError):self.m.listing_checked(self.m.encoded(v))

    def test_manifest_closed_labels_whole_hash_and_no_completed_profile_aliases(self):
        raw=self.m.capture(self.raw);v=json.loads(raw)
        for change in ({'application':'mk8.email'},{'generation':'b'*64},{'state':'completed-backup'},{'schema':'debian13s4-selected-stage-incomplete-1'},{'selected_listing_sha256':'0'*64},{'extra':1}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.m.checked(self.m.encoded(v|change))
        with patch.object(self.m,'MAX_RECORD',len(raw)-1),self.assertRaises(ValueError):self.m.checked(raw)

    def test_envelope_closed_schema_canonical_hash_and_cross_profile_refusal(self):
        raw=self.m.capture(self.raw);envelope=self.m.envelope(raw);v=json.loads(envelope)
        self.assertEqual(self.m.stored(envelope),raw)
        for change in ({'payload_sha256':'0'*64},{'state':'historical-uncertain-no-retry'},{'schema':'debian13s4-nft-intent-history-1'},{'extra':1}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.m.stored(self.m.encoded(v|change))
        with self.assertRaises(ValueError):self.m._STORAGE.intent(raw)
        with patch.object(self.m,'MAX_BYTES',len(envelope)-1),self.assertRaises(ValueError):self.m.envelope(raw)

    def test_actual_private_manifest_leaf_single_link_mode_and_same_inode_resync(self):
        raw=self.record();leaf=self.store/self.m.LEAF;before=leaf.stat()
        self.assertEqual(before.st_mode&0o777,0o600);self.assertEqual(before.st_nlink,1)
        self.assertEqual(self.record(),raw);self.assertEqual(self.m.load(self.store),raw)
        self.assertEqual(leaf.stat().st_ino,before.st_ino);self.assertEqual(self.h.h.leaf().read_bytes(),self.h.h.data)

    def test_different_manifest_refuses_without_overwriting_or_touching_stage(self):
        raw=self.record();leaf=self.store/self.m.LEAF;before=leaf.read_bytes()
        v=json.loads(self.raw);v['inspection']['listing_hex']=b'other opaque bytes'.hex();v['inspection']['listing_bytes']=len(b'other opaque bytes');v['inspection']['listing_sha256']=self.m.digest(b'other opaque bytes');v['inspection_sha256']=self.m.digest(self.m.encoded(v['inspection']))
        with self.assertRaises(ValueError):self.record(self.m.encoded(v))
        self.assertEqual(leaf.read_bytes(),before);self.assertEqual(self.m.load(self.store),raw)
        self.assertEqual(self.h.h.leaf().read_bytes(),self.h.h.data)

    def test_private_directory_and_leaf_mode_link_symlink_refusals(self):
        self.record();leaf=self.store/self.m.LEAF;leaf.chmod(0o644)
        with self.assertRaises(ValueError):self.m.load(self.store)
        leaf.chmod(0o600);alias=self.store/'alias';os.link(leaf,alias)
        with self.assertRaises(ValueError):self.m.load(self.store)
        alias.unlink();raw=leaf.read_bytes();leaf.unlink();leaf.symlink_to(self.h.h.leaf())
        with self.assertRaises(ValueError):self.m.load(self.store)
        leaf.unlink();leaf.write_bytes(raw);leaf.chmod(0o600);self.store.chmod(0o750)
        with self.assertRaises(ValueError):self.m.load(self.store)

    def test_initial_invalid_deadline_refuses_before_capture_or_store(self):
        with patch.object(self.m,'capture',side_effect=AssertionError('capture')):
            for end in (True,float('nan'),float('inf'),self.m._STORAGE.KERNEL.now()-1):
                with self.subTest(end=str(end)),self.assertRaises(ValueError):self.record(deadline=end)
        self.assertFalse((self.store/self.m.LEAF).exists())

    def test_positive_inherited_and_own_window_pass_same_end_to_storage(self):
        now=self.m._STORAGE.KERNEL.now();ends=[]
        with patch.object(self.m._STORAGE.KERNEL,'now',return_value=now),patch.object(self.m._STORAGE,'create',side_effect=lambda path,payload,deadline:ends.append(deadline) or payload):
            self.record(deadline=now+2);self.record(deadline=now+1000)
        self.assertEqual(ends,[now+2,now+self.m._STORAGE.ATTEMPT_SECONDS])

    def test_capture_expiry_and_real_load_readback_expiry_prevent_success(self):
        now=self.m._STORAGE.KERNEL.now();clock=[now];capture=self.m.capture
        def expired(raw):value=capture(raw);clock[0]=now+2;return value
        with patch.object(self.m._STORAGE.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m,'capture',side_effect=expired),patch.object(self.m._STORAGE,'create',side_effect=AssertionError('store')),self.assertRaises(ValueError):self.record(deadline=now+2)
        self.record();read=self.m._STORAGE.read_at;clock[0]=now
        def readback(*args,**kwargs):raw=read(*args,**kwargs);clock[0]=now+2;return raw
        with patch.object(self.m._STORAGE.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m._STORAGE,'read_at',side_effect=readback),self.assertRaises(ValueError):self.m.load(self.store,deadline=now+2)

    def test_storage_sync_failure_propagates_without_rollback_or_stage_retry(self):
        with patch.object(self.m._STORAGE.os,'fsync',side_effect=OSError('private history sync')),self.assertRaises(OSError):self.record()
        self.assertEqual(list(self.store.iterdir()),[]);self.assertEqual(self.h.h.leaf().read_bytes(),self.h.h.data)
        self.assertEqual(len(self.h.h.ledger.read_text().splitlines()),1)


if __name__=='__main__':unittest.main()
