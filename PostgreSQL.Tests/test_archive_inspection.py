"""Private listing delivery models; no native PostgreSQL/archive-validity proof."""
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ArchiveInspectionTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0: raise RuntimeError('ordinary UID models required')
        self.temp = tempfile.TemporaryDirectory(dir='/dev/shm'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.store = self.root/'stage'; self.store.mkdir(mode=0o700)
        self.exec_temp = tempfile.TemporaryDirectory(dir='/tmp'); self.addCleanup(self.exec_temp.cleanup)
        self.exec_root = Path(self.exec_temp.name); self.exec_root.chmod(0o700)
        spec = importlib.util.spec_from_file_location('private_archive_inspection', ROOT/'PostgreSQL/archive_inspection.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.STAGE.TRUST_ROOT = self.root; self.m.STAGE.TRUSTED_UID = os.geteuid()
        self.m.KERNEL.TRUST_ROOT = self.exec_root; self.m.KERNEL.TRUSTED_UID = os.geteuid()
        self.scope = patch.object(self.m.KERNEL, 'namespace', return_value=4711); self.scope.start(); self.addCleanup(self.scope.stop)
        self.name = 'f'*64+'-mk8.dns.dump.partial'; self.leaf = self.store/self.name
        self.data = b'OPAQUE\x00\xff\r\nNOT a valid PostgreSQL archive'*2000
        self.receipt = self.m.STAGE.stage(self.store, self.name, io.BytesIO(self.data), len(self.data))
        self.listing = b'; private model TOC\n1; 0 0 TABLE public example private\n\x00\xff\r\n'
        self.m.RESTORE = self.exec_root/'restore'; self.ledger = self.exec_root/'ledger'
        self.children = []; self.addCleanup(self.cleanup_children)
        self.program()

    def cleanup_children(self):
        for child in self.children:
            if child.poll() is None:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(timeout=1)

    def program(self, action="os.write(1, listing)"):
        self.m.RESTORE.write_text("#!/usr/bin/python3\nimport json,os,sys,time\nfrom pathlib import Path\n"+
            'listing='+repr(self.listing)+'\n'+
            'assert sys.argv[1:]==["--list", '+repr(str(self.leaf))+']\n'+
            'assert Path(sys.argv[2]).read_bytes()=='+repr(self.data)+'\n'+
            'Path('+repr(str(self.ledger))+').write_text(json.dumps({"argv":sys.argv,"environment":dict(os.environ),"pid":os.getpid(),"sid":os.getsid(0)}))\n'+action+'\n')
        self.m.RESTORE.chmod(0o700)

    def inspect(self, **kwargs):
        return self.m.inspect_stage(self.receipt, 4096, **kwargs)

    def model(self, path, maximum, end):
        self.assertEqual(path, self.leaf); self.assertEqual(maximum, 4096)
        self.assertGreater(end, self.m.KERNEL.now()); return self.listing

    def test_complete_opaque_stage_and_raw_listing_are_bound_without_promotion(self):
        before = self.leaf.stat(); raw = self.inspect(read=self.model); value = json.loads(raw)
        self.assertEqual(value['state'], 'private-archive-listing-source-only')
        self.assertEqual(value['stage'], json.loads(self.receipt))
        self.assertEqual(value['stage_sha256'], hashlib.sha256(self.receipt).hexdigest())
        self.assertEqual(bytes.fromhex(value['listing_hex']), self.listing)
        self.assertEqual(value['listing_sha256'], hashlib.sha256(self.listing).hexdigest())
        self.assertEqual(value['listing_bytes'], len(self.listing)); self.assertEqual(value['namespace'], 4711)
        self.assertEqual(value['argv'], [str(self.m.RESTORE), '--list', str(self.leaf)])
        self.assertEqual(value['executable'], list(self.m.KERNEL.trusted_binary(self.m.RESTORE)))
        self.assertEqual(raw, self.m.PREP.canonical(value)); self.assertEqual(self.leaf.stat(), before)
        self.assertEqual(self.leaf.read_bytes(), self.data)
        self.assertEqual([p.name for p in self.store.iterdir()], [self.name])

    def test_actual_private_child_fixed_argv_environment_session_and_unmodified_file(self):
        value = json.loads(self.inspect()); point = json.loads(self.ledger.read_bytes())
        self.assertEqual(point['argv'], [str(self.m.RESTORE), '--list', str(self.leaf)])
        self.assertEqual(point['environment'], {'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
        self.assertEqual(point['pid'], point['sid']); self.assertEqual(bytes.fromhex(value['listing_hex']), self.listing)
        self.assertEqual(self.leaf.read_bytes(), self.data)

    def test_receipt_true_bytes_bound_canonical_json_and_closed_schema_before_delivery(self):
        for raw in (True, bytearray(self.receipt), b'', b'x'*(self.m.STAGE.MAX_RECEIPT+1), b'{}',
                    self.receipt+b'\n', self.receipt.replace(b'"schema":1', b'"schema":true'),
                    self.receipt.replace(b'"schema":1', b'"schema":1,"schema":1'), b'{"x":NaN}\n', b'\xff'):
            with self.subTest(kind=type(raw).__name__), patch.object(self.m, 'native', side_effect=AssertionError('entry')), self.assertRaises(ValueError):
                self.m.inspect_stage(raw, 4096)
        value=json.loads(self.receipt); value['extra']=1
        with self.assertRaises(ValueError): self.m.checked(self.m.PREP.canonical(value))

    def test_receipt_identity_shape_types_modes_links_size_owner_and_hash_are_closed(self):
        original=json.loads(self.receipt)
        changes=[('state','ready'),('schema',2),('leaf','../'+self.name),('leaf','0'*64+'-mk8.dns.dump.partial'),
                 ('directory','relative'),('bytes',True),('bytes',0),('limit_bytes',1),('sha256','G'*64),
                 ('identity',[1]),('directory_identity',[1]*4)]
        for key,value in changes:
            altered=dict(original);altered[key]=value
            with self.subTest(key=key,value=str(value)[:40]),self.assertRaises(ValueError):self.m.checked(self.m.PREP.canonical(altered))
        for field,indices in (('identity',(0,2,3,5,8)),('directory_identity',(0,2,3))):
            for index in indices:
                altered=json.loads(self.receipt);altered[field][index]=True
                with self.subTest(field=field,index=index),self.assertRaises(ValueError):self.m.checked(self.m.PREP.canonical(altered))
        for index,value in ((2,stat.S_IFREG|0o644),(3,os.geteuid()+1),(5,1),(8,2)):
            altered=json.loads(self.receipt);altered['identity'][index]=value
            with self.subTest(index=index),self.assertRaises(ValueError):self.m.checked(self.m.PREP.canonical(altered))

    def test_historical_hash_is_not_authority_actual_bytes_are_read_before_entry(self):
        value=json.loads(self.receipt);value['sha256']='a'*64
        with patch.object(self.m,'native',side_effect=AssertionError('entry')),self.assertRaises(ValueError):
            self.m.inspect_stage(self.m.PREP.canonical(value),4096)
        self.assertEqual(self.leaf.read_bytes(),self.data)

    def test_all_input_bounds_deliveries_and_deadlines_refuse_before_native(self):
        for maximum in (True,0,-1,1.0,'1',self.m.MAX_LISTING+1):
            with self.subTest(maximum=maximum),self.assertRaises(ValueError):self.m.inspect_stage(self.receipt,maximum)
        for deadline in (True,float('inf'),float('nan'),'later',self.m.KERNEL.now()-1,10**10000):
            with self.subTest(kind=type(deadline).__name__),self.assertRaises(ValueError):self.inspect(deadline=deadline)
        with self.assertRaises(ValueError):self.inspect(read=object())
        self.assertFalse(self.ledger.exists())

    def test_changed_directory_permissions_ancestry_and_path_refuse_before_entry(self):
        for path,mode in ((self.store,0o750),(self.root,0o770)):
            path.chmod(mode)
            with self.subTest(path=path),self.assertRaises(ValueError):self.inspect()
            path.chmod(0o700)
        self.assertFalse(self.ledger.exists())
        value=json.loads(self.receipt);value['directory']=str(self.store/'..'/'stage')
        with self.assertRaises(ValueError):self.m.inspect_stage(self.m.PREP.canonical(value),4096)

    def test_changed_file_bytes_size_mode_link_and_replacement_refuse_before_entry(self):
        before=self.leaf.read_bytes();self.leaf.write_bytes(before[:-1])
        with self.assertRaises(ValueError):self.inspect()
        self.leaf.write_bytes(before);self.leaf.chmod(0o644)
        with self.assertRaises(ValueError):self.inspect()
        self.leaf.chmod(0o600);os.link(self.leaf,self.root/'external')
        with self.assertRaises(ValueError):self.inspect()
        (self.root/'external').unlink();self.leaf.unlink();self.leaf.symlink_to(self.m.RESTORE)
        with self.assertRaises(ValueError):self.inspect()
        self.assertFalse(self.ledger.exists())

    def test_nonblocking_exclusive_cooperating_lock_refuses_before_child(self):
        fd=os.open(self.store,os.O_RDONLY|os.O_DIRECTORY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.inspect()
            self.assertFalse(self.ledger.exists())
        finally:os.close(fd)

    def test_native_zero_exit_warning_and_nonzero_refuse_without_success(self):
        for action in ("os.write(1,listing);os.write(2,b'warning')", "os.write(1,listing);sys.exit(7)"):
            self.program(action)
            with self.subTest(action=action),self.assertRaises(ValueError):self.inspect()
            self.assertEqual(self.leaf.read_bytes(),self.data)

    def test_native_stdout_and_stderr_overflow_are_bounded_concurrent_captures(self):
        for channel in (1,2):
            self.program('os.write('+str(channel)+',b"x"*8192)')
            with self.subTest(channel=channel),self.assertRaises(ValueError):self.inspect()
        self.program('os.write(1,b"x"*4096);os.write(2,b"x"*4096)')
        with self.assertRaises(ValueError):self.inspect()

    def test_exact_listing_cap_is_admitted_without_extra_truncation(self):
        self.listing=b'x'*4096;self.program()
        value=json.loads(self.inspect());self.assertEqual(value['listing_bytes'],4096)
        self.assertEqual(bytes.fromhex(value['listing_hex']),self.listing)

    def test_empty_mutable_nonbyte_and_oversized_model_results_refuse(self):
        for value in (b'',bytearray(b'x'),'x',None,b'x'*4097):
            with self.subTest(kind=type(value).__name__),self.assertRaises(ValueError):self.inspect(read=lambda *args:value)

    def test_private_capture_timeout_reaps_its_owned_child_and_closes_channels(self):
        original=self.m.subprocess.Popen
        def entered(*args,**kwargs):
            child=original(*args,**kwargs);self.children.append(child);return child
        self.program('time.sleep(10)')
        with patch.object(self.m.KERNEL,'QUERY_SECONDS',0.2),patch.object(self.m.subprocess,'Popen',side_effect=entered),self.assertRaises(ValueError):self.inspect()
        self.assertEqual(len(self.children),1);self.assertIsNotNone(self.children[0].poll())
        self.assertTrue(self.children[0].stdout.closed);self.assertTrue(self.children[0].stderr.closed)

    def test_closed_capture_pipes_do_not_waive_child_completion_timeout(self):
        original=self.m.subprocess.Popen
        def entered(*args,**kwargs):
            child=original(*args,**kwargs);self.children.append(child);return child
        self.program('os.close(1);os.close(2);time.sleep(10)')
        now=self.m.KERNEL.now()
        with patch.object(self.m.KERNEL,'now',return_value=now),patch.object(self.m.KERNEL,'QUERY_SECONDS',0.2),patch.object(self.m.subprocess,'Popen',side_effect=entered),self.assertRaises(subprocess.TimeoutExpired):self.inspect()
        self.assertEqual(len(self.children),1);self.assertIsNotNone(self.children[0].poll())
        self.assertTrue(self.children[0].stdout.closed);self.assertTrue(self.children[0].stderr.closed)

    def test_listing_callback_expiry_refuses_before_encoding_and_readback(self):
        now=self.m.KERNEL.now();clock=[now]
        def read(*args):clock[0]=now+2;return self.listing
        original=self.m.PREP.canonical
        def encoded(value):
            if value['state']=='private-archive-listing-source-only':raise AssertionError('output encode')
            return original(value)
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.PREP,'canonical',side_effect=encoded),self.assertRaises(ValueError):
            self.inspect(read=read,deadline=now+1)

    def test_positive_inherited_and_own_caps_reach_delivery_unchanged(self):
        now=self.m.KERNEL.now();seen=[]
        def read(path,maximum,end):seen.append(end);return self.listing
        with patch.object(self.m.KERNEL,'now',return_value=now):
            self.inspect(read=read,deadline=now+1);self.inspect(read=read,deadline=now+1000)
        self.assertEqual(seen,[now+1,now+self.m.ATTEMPT_SECONDS])

    def test_changed_file_after_listing_and_after_receipt_encoding_refuses(self):
        def read(*args):self.leaf.write_bytes(b'changed');return self.listing
        with self.assertRaises(ValueError):self.inspect(read=read)
        self.assertEqual(self.leaf.read_bytes(),b'changed')

    def test_encoding_precedes_second_full_readback_and_final_admission(self):
        events=[];canonical=self.m.PREP.canonical;readback=self.m.STAGE.readback;admission=self.m.STAGE.admission
        def encoded(value):events.append('encode');return canonical(value)
        def checked_file(*args):events.append('readback');return readback(*args)
        def fence(end):events.append('fence');return admission(end)
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),patch.object(self.m.STAGE,'readback',side_effect=checked_file),patch.object(self.m.STAGE,'admission',side_effect=fence):self.inspect(read=self.model)
        self.assertEqual(events.count('readback'),2)
        self.assertEqual([e for e in events if e in ('readback','encode')],['encode','readback','encode','readback'])
        self.assertEqual(events[-1],'fence')

    def test_receipt_cap_refuses_before_second_readback(self):
        original=self.m.STAGE.readback;calls=[]
        def readback(*args):calls.append(1);return original(*args)
        with patch.object(self.m,'MAX_OUTPUT',1),patch.object(self.m.STAGE,'readback',side_effect=readback),self.assertRaises(ValueError):self.inspect(read=self.model)
        self.assertEqual(calls,[1]);self.assertEqual(self.leaf.read_bytes(),self.data)

    def test_final_real_readback_scope_and_time_changes_refuse(self):
        original=self.m.STAGE.readback;now=self.m.KERNEL.now()
        for which in ('context','time'):
            count=[0];clock=[now];context=[4711]
            def readback(*args):
                result=original(*args);count[0]+=1
                if count[0]==2:
                    if which=='context':context[0]=4712
                    else:clock[0]=now+2
                return result
            with self.subTest(which=which),patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.KERNEL,'namespace',side_effect=lambda:context[0]),patch.object(self.m.STAGE,'readback',side_effect=readback),self.assertRaises(ValueError):self.inspect(read=self.model,deadline=now+1)
            self.assertEqual(count[0],2)

    def test_repeated_executable_identity_refuses_model_drift(self):
        def read(*args):self.m.RESTORE.write_text('#!/usr/bin/python3\n');return self.listing
        with self.assertRaises(ValueError):self.inspect(read=read)

    def test_preentry_context_drift_and_untrusted_executable_prevent_delivery(self):
        with patch.object(self.m.KERNEL,'namespace',side_effect=[4711,4712]),self.assertRaises(ValueError):self.inspect()
        self.assertFalse(self.ledger.exists());self.m.RESTORE.chmod(0o770)
        with self.assertRaises(ValueError):self.inspect()
        self.assertFalse(self.ledger.exists())

    def test_directory_close_retires_number_before_single_failed_close(self):
        original=self.m.os.close;replacement=[];target=[];real_open=self.m.os.open
        def opened(path,flags,*args,**kwargs):
            fd=real_open(path,flags,*args,**kwargs)
            if path==self.store:target.append(fd)
            return fd
        def close(fd):
            if target and fd==target[0] and not replacement:
                original(fd);new=real_open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.assertEqual(new,fd);replacement.append(new);raise OSError('retired close')
            return original(fd)
        try:
            with patch.object(self.m.os,'open',side_effect=opened),patch.object(self.m.os,'close',side_effect=close),self.assertRaises(OSError):self.inspect(read=self.model)
            self.assertEqual(len(replacement),1);os.fstat(replacement[0])
        finally:
            for fd in replacement:original(fd)

    def test_after_output_encoding_file_and_directory_changes_refuse(self):
        original=self.m.PREP.canonical
        for which in ('file','directory'):
            def encoded(value):
                raw=original(value)
                if value['state']=='private-archive-listing-source-only':
                    (self.leaf if which=='file' else self.store).chmod(0o644 if which=='file' else 0o750)
                return raw
            with self.subTest(which=which),patch.object(self.m.PREP,'canonical',side_effect=encoded),self.assertRaises(ValueError):self.inspect(read=self.model)
            self.leaf.chmod(0o600);self.store.chmod(0o700)
            # TEST-only fresh stage receipt after metadata mutation; no production reset.
            value=json.loads(self.receipt);value['identity']=list(self.m.STAGE.file_identity(self.leaf.stat()))
            self.receipt=original(value)

    def test_private_native_postcapture_executable_and_context_fences_refuse(self):
        self.program('os.write(1,listing);Path(__file__).chmod(0o600)')
        with self.assertRaises(ValueError):self.inspect()
        self.assertTrue(self.ledger.exists());self.program()
        with patch.object(self.m.KERNEL,'namespace',side_effect=[4711,4711,4711,4712]),self.assertRaises(ValueError):self.inspect()

    def test_receipt_size_at_exact_encoded_cap_and_one_less(self):
        raw=self.inspect(read=self.model)
        with patch.object(self.m,'MAX_OUTPUT',len(raw)):
            self.assertEqual(self.inspect(read=self.model),raw)
        with patch.object(self.m,'MAX_OUTPUT',len(raw)-1),self.assertRaises(ValueError):self.inspect(read=self.model)

    def test_oversized_receipt_refuses_before_json_decoder_entry(self):
        with patch.object(self.m.json,'loads',side_effect=AssertionError('JSON entry')),self.assertRaises(ValueError):
            self.m.checked(b'x'*(self.m.STAGE.MAX_RECEIPT+1))

    def test_direct_native_path_and_positive_context_refuse_before_child(self):
        paths=(Path('--file=output'),Path('relative'),str(self.leaf),self.store/'..'/'stage'/self.name,
               self.store/'other.dump',self.store/('0'*64+'-mk8.dns.dump.partial'))
        for path in paths:
            with self.subTest(path=str(path)),patch.object(self.m.subprocess,'Popen',side_effect=AssertionError('child entry')),self.assertRaises(ValueError):
                self.m.native(path,4096,self.m.KERNEL.now()+1)
        with patch.object(self.m.KERNEL,'namespace',return_value=0),patch.object(self.m.subprocess,'Popen',side_effect=AssertionError('child entry')),self.assertRaises(ValueError):
            self.m.native(self.leaf,4096,self.m.KERNEL.now()+1)


if __name__=='__main__':unittest.main()
