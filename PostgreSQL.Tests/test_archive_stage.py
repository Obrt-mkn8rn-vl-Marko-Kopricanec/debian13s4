"""Ordinary-UID private byte-stage models; no valid PG archive/native backup."""
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ArchiveStageTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid()==0:raise RuntimeError('private fixtures require ordinary UID')
        self.temp=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.store=self.root/'stage';self.store.mkdir(mode=0o700)
        spec=importlib.util.spec_from_file_location('private_archive_stage',ROOT/'PostgreSQL/archive_stage.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.m.TRUST_ROOT=self.root;self.m.TRUSTED_UID=os.geteuid()
        self.name='f'*64+'-mk8.dns.dump.partial';self.leaf=self.store/self.name
        self.data=b'OPAQUE\x00\xff\r\n-not-a-PG-archive\n'*5000

    def stage(self,raw=None,**kw):
        raw=self.data if raw is None else raw
        return self.m.stage(self.store,self.name,io.BytesIO(raw),len(raw) or 1,**kw)

    def test_complete_binary_stream_private_size_hash_identity_and_no_promotion(self):
        raw=self.stage();value=json.loads(raw)
        self.assertEqual(value['state'],'private-unverified-archive-stage-only')
        self.assertEqual(value['bytes'],len(self.data));self.assertEqual(value['sha256'],hashlib.sha256(self.data).hexdigest())
        self.assertEqual(self.leaf.read_bytes(),self.data)
        self.assertEqual(value['identity'],list(self.m.file_identity(self.leaf.stat())))
        self.assertEqual(stat.S_IMODE(self.leaf.stat().st_mode),0o600);self.assertEqual(self.leaf.stat().st_nlink,1)
        self.assertEqual(raw,self.m.PREP.canonical(value))
        self.assertEqual({p.name for p in self.store.iterdir()},{self.name})
        self.assertFalse((self.store/self.name.removesuffix('.partial')).exists())

    def test_arbitrary_nonarchive_bytes_are_admitted_only_as_opaque_unverified_stage(self):
        raw=self.stage(b'NOT A VALID BACKUP')
        self.assertEqual(json.loads(raw)['state'],'private-unverified-archive-stage-only')
        self.assertEqual(self.leaf.read_bytes(),b'NOT A VALID BACKUP')

    def test_reads_are_bounded_and_exact_limit_requires_one_more_eof_observation(self):
        calls=[];source=io.BytesIO(self.data)
        class Stream:
            def read(inner,n):calls.append(n);return source.read(n)
        self.m.stage(self.store,self.name,Stream(),len(self.data))
        self.assertEqual(calls[-1],1);self.assertTrue(all(0<n<=self.m.CHUNK for n in calls))

    def test_identical_second_call_blocks_before_stream_entry_preserving_inode_and_bytes(self):
        self.stage();before=self.leaf.stat()
        class Stream:
            def read(inner,n):raise AssertionError('second stream entry')
        with self.assertRaises(self.m.Blocked):self.m.stage(self.store,self.name,Stream(),len(self.data))
        self.assertEqual(self.leaf.stat().st_ino,before.st_ino);self.assertEqual(self.leaf.read_bytes(),self.data)

    def test_every_existing_empty_partial_or_foreign_leaf_is_never_overwritten_or_deleted(self):
        for raw in (b'',b'partial',b'foreign'):
            self.leaf.write_bytes(raw);self.leaf.chmod(0o600);before=self.leaf.stat()
            with self.subTest(raw=raw),patch.object(self.m.os,'unlink',side_effect=AssertionError('delete')),self.assertRaises(self.m.Blocked):self.stage()
            self.assertEqual(self.leaf.read_bytes(),raw);self.assertEqual(self.leaf.stat().st_ino,before.st_ino)
            self.leaf.unlink() # TEST reset only; no production removal API.

    def test_symlink_fifo_directory_and_external_hardlink_targets_block_without_following(self):
        target=self.root/'target';target.write_bytes(b'keep');target.chmod(0o600)
        self.leaf.symlink_to(target)
        with self.assertRaises(self.m.Blocked):self.stage()
        self.assertEqual(target.read_bytes(),b'keep');self.leaf.unlink();os.mkfifo(self.leaf,0o600)
        with self.assertRaises(self.m.Blocked):self.stage()
        self.leaf.unlink();self.leaf.mkdir()
        with self.assertRaises(self.m.Blocked):self.stage()
        self.leaf.rmdir();os.link(target,self.leaf)
        with self.assertRaises(self.m.Blocked):self.stage()
        self.assertEqual(target.read_bytes(),b'keep');self.assertEqual(target.stat().st_nlink,2)

    def test_names_bounds_readers_and_deadlines_refuse_before_open_or_stream(self):
        for name in ('x','0'*64+'-mk8.dns.dump.partial','A'*64+'-mk8.dns.dump.partial',
                'f'*64+'-mk8.sava.dump.partial',self.name.removesuffix('.partial'),'../'+self.name,True):
            with self.subTest(name=name),patch.object(self.m.os,'open',side_effect=AssertionError('open')),self.assertRaises(ValueError):
                self.m.stage(self.store,name,io.BytesIO(b'x'),1)
        for limit in (True,0,-1,self.m.MAX_BYTES+1,1.0,'1'):
            with self.subTest(limit=limit),self.assertRaises(ValueError):self.m.stage(self.store,self.name,io.BytesIO(b'x'),limit)
        with self.assertRaises(ValueError):self.m.stage(self.store,self.name,object(),1)
        for deadline in (True,float('inf'),float('nan'),'later',self.m.KERNEL.now()-1,10**10000):
            with self.subTest(kind=type(deadline).__name__),self.assertRaises(ValueError):self.stage(deadline=deadline)
        self.assertFalse(self.leaf.exists())

    def test_private_directory_ancestry_owner_alias_and_link_refuse_before_creation(self):
        self.store.chmod(0o750)
        with self.assertRaises(ValueError):self.stage()
        self.store.chmod(0o700);self.root.chmod(0o770)
        with self.assertRaises(ValueError):self.stage()
        self.root.chmod(0o700)
        with patch.object(self.m,'TRUSTED_UID',os.geteuid()+1),self.assertRaises(ValueError):self.stage()
        alias=self.root/'alias';alias.symlink_to(self.store,target_is_directory=True)
        with self.assertRaises(ValueError):self.m.stage(alias,self.name,io.BytesIO(b'x'),1)
        for path in (Path('relative'),self.store/'..'/'stage',str(self.store)):
            with self.subTest(path=path),self.assertRaises(ValueError):self.m.stage(path,self.name,io.BytesIO(b'x'),1)
        self.assertFalse(self.leaf.exists())

    def test_nonblocking_cooperating_directory_lock_withholds_creation(self):
        fd=os.open(self.store,os.O_RDONLY|os.O_DIRECTORY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.stage()
            self.assertFalse(self.leaf.exists())
        finally:os.close(fd)

    def test_actual_short_writes_complete_identical_bytes(self):
        real=os.write;counts=[]
        def short(fd,data):count=real(fd,data[:37]);counts.append(count);return count
        with patch.object(self.m.os,'write',side_effect=short):self.stage(b'x'*257)
        self.assertEqual(sum(counts),257);self.assertGreater(len(counts),1);self.assertEqual(self.leaf.read_bytes(),b'x'*257)

    def test_bad_boolean_zero_negative_unknown_and_oversized_write_results_block_slot(self):
        for count in (True,0,-1,None,self.m.CHUNK+1):
            with self.subTest(count=count),patch.object(self.m.os,'write',return_value=count),self.assertRaises(self.m.Blocked):self.stage(b'abc')
            self.assertTrue(self.leaf.exists());self.assertEqual(self.leaf.read_bytes(),b'')
            with self.assertRaises(self.m.Blocked):self.stage(b'abc')
            self.leaf.unlink()

    def test_partial_actual_write_error_retains_exact_prefix_and_original_cause(self):
        real=os.write;calls=[];error=OSError('private write')
        def interrupted(fd,data):
            calls.append(fd)
            if len(calls)==1:return real(fd,data[:7])
            raise error
        with patch.object(self.m.os,'write',side_effect=interrupted),self.assertRaises(self.m.Blocked) as failure:self.stage(b'abcdefghijklmnop')
        self.assertIs(failure.exception.__cause__,error);self.assertEqual(self.leaf.read_bytes(),b'abcdefg')
        with self.assertRaises(self.m.Blocked):self.stage()

    def test_empty_oversized_nonbytes_and_over_requested_delivery_retain_blocking_stage(self):
        for delivery in (b'',bytearray(b'a'),None,True,b'xx'):
            class Stream:
                def read(inner,n):return delivery
            with self.subTest(kind=type(delivery).__name__),self.assertRaises(self.m.Blocked):self.m.stage(self.store,self.name,Stream(),1)
            self.assertTrue(self.leaf.exists());self.assertEqual(self.leaf.read_bytes(),b'')
            self.leaf.unlink()
        class Stream:
            def read(inner,n):return b'x'*(n+1)
        with self.assertRaises(self.m.Blocked):self.m.stage(self.store,self.name,Stream(),self.m.MAX_BYTES)
        self.assertEqual(self.leaf.read_bytes(),b'')

    def test_late_stream_error_keeps_preceding_chunks_without_receipt_or_retry(self):
        error=OSError('private source');calls=[]
        class Stream:
            def read(inner,n):
                calls.append(n)
                if len(calls)==1:return b'prefix'
                raise error
        with self.assertRaises(self.m.Blocked) as failure:self.m.stage(self.store,self.name,Stream(),100)
        self.assertIs(failure.exception.__cause__,error);self.assertEqual(self.leaf.read_bytes(),b'prefix')
        with self.assertRaises(self.m.Blocked):self.stage()

    def test_over_limit_detection_never_writes_the_excess_byte(self):
        with self.assertRaises(self.m.Blocked):self.m.stage(self.store,self.name,io.BytesIO(b'123456'),5)
        self.assertEqual(self.leaf.read_bytes(),b'') # one bounded six-byte delivery refused BEFORE write

    def test_file_directory_sync_and_mode_errors_withhold_receipt_and_keep_target(self):
        real=os.fsync
        for directory in (False,True):
            def sync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode)==directory:raise OSError('private sync')
                return real(fd)
            with self.subTest(directory=directory),patch.object(self.m.os,'fsync',side_effect=sync),self.assertRaises(self.m.Blocked):self.stage(b'bytes')
            self.assertTrue(self.leaf.exists());self.leaf.unlink()
        with patch.object(self.m.os,'fchmod',side_effect=OSError('mode')),self.assertRaises(self.m.Blocked):self.stage(b'bytes')
        self.assertTrue(self.leaf.exists())

    def test_readback_corruption_or_extra_link_refuses_success_without_cleanup(self):
        real=self.m.readback
        for fault in ('bytes','link'):
            extra=self.root/'external'
            def readback(*args):
                if fault=='bytes':self.leaf.write_bytes(b'changed')
                else:os.link(self.leaf,extra)
                return real(*args)
            with self.subTest(fault=fault),patch.object(self.m,'readback',side_effect=readback),self.assertRaises(self.m.Blocked):self.stage(b'bytes')
            self.assertTrue(self.leaf.exists())
            if extra.exists():extra.unlink()
            self.leaf.unlink()

    def test_readback_wrong_digest_and_size_are_rejected(self):
        raw=self.stage(b'opaque');record=json.loads(raw);fd=os.open(self.store,os.O_RDONLY|os.O_DIRECTORY)
        try:
            for count,digest in ((record['bytes']+1,record['sha256']),(record['bytes'],'0'*64)):
                with self.subTest(count=count),self.assertRaises(ValueError):self.m.readback(fd,self.name,tuple(record['identity']),count,digest,self.m.KERNEL.now()+2)
        finally:os.close(fd)

    def test_receipt_encoding_occurs_before_close_directory_sync_and_real_readback(self):
        encode=self.m.PREP.canonical;close=os.close;readback=self.m.readback;events=[]
        def canonical(value):events.append('encode');return encode(value)
        def closing(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):events.append('file-close')
            return close(fd)
        def reread(*args):events.append('readback');return readback(*args)
        with patch.object(self.m.PREP,'canonical',side_effect=canonical),patch.object(self.m.os,'close',side_effect=closing),patch.object(self.m,'readback',side_effect=reread):self.stage(b'opaque')
        self.assertEqual(events,['encode','file-close','readback','file-close'])

    def test_receipt_cap_precedes_readback_and_withholds_success(self):
        with patch.object(self.m,'MAX_RECEIPT',1),patch.object(self.m,'readback',side_effect=AssertionError('readback')),self.assertRaises(self.m.Blocked):self.stage(b'opaque')
        self.assertEqual(self.leaf.read_bytes(),b'opaque')

    def test_retired_write_descriptor_is_not_reclosed_after_number_reuse(self):
        realclose=os.close;realopen=os.open;calls=[];reused=[];other=self.root/'other';other.write_bytes(b'keep')
        def close(fd):
            fact=os.fstat(fd)
            if self.leaf.exists() and (fact.st_dev,fact.st_ino)==(self.leaf.stat().st_dev,self.leaf.stat().st_ino) and not calls:
                calls.append(fd);realclose(fd);new=realopen(other,os.O_RDONLY);reused.append(new)
                self.assertEqual(new,fd);raise OSError('after retirement')
            return realclose(fd)
        try:
            with patch.object(self.m.os,'close',side_effect=close),self.assertRaises(self.m.Blocked):self.stage(b'opaque')
            self.assertEqual(len(calls),1);self.assertEqual(os.read(reused[0],4),b'keep')
        finally:
            for fd in reused:realclose(fd)
        with self.assertRaises(self.m.Blocked):self.stage()

    def test_readback_and_directory_close_errors_cannot_return_success_or_close_reused_number(self):
        realclose=os.close;realopen=os.open;other=self.root/'other';other.write_bytes(b'keep')
        for mode in ('readback','directory'):
            calls=[];reused=[];opens=[];original=self.m.readback
            def readback(*args):opens.append('readback');return original(*args)
            def close(fd):
                kind=stat.S_ISDIR(os.fstat(fd).st_mode)
                if ((mode=='directory' and kind) or (mode=='readback' and not kind and opens)) and not calls:
                    calls.append(fd);realclose(fd);new=realopen(other,os.O_RDONLY);reused.append(new)
                    self.assertEqual(new,fd);raise OSError('after retirement')
                return realclose(fd)
            try:
                with self.subTest(mode=mode),patch.object(self.m,'readback',side_effect=readback),patch.object(self.m.os,'close',side_effect=close),self.assertRaises((self.m.Blocked,OSError)):self.stage(b'opaque')
                self.assertEqual(len(calls),1);self.assertEqual(os.read(reused[0],4),b'keep')
            finally:
                for fd in reused:realclose(fd)
            self.leaf.unlink()

    def test_deadline_cap_and_expiry_immediately_after_stream_precede_any_write(self):
        start=self.m.KERNEL.now();clock=[start];requests=[]
        class Stream:
            def read(inner,n):requests.append(n);clock[0]=start+2;return b'x'
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.os,'write',side_effect=AssertionError('write')),self.assertRaises(self.m.Blocked):
            self.m.stage(self.store,self.name,Stream(),1,deadline=start+2)
        self.assertEqual(len(requests),1);self.assertEqual(self.leaf.read_bytes(),b'')

    def test_expiry_after_receipt_and_actual_readback_withholds_success(self):
        start=self.m.KERNEL.now();clock=[start];real=self.m.readback
        def readback(*args):value=real(*args);clock[0]=start+2;return value
        with patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m,'readback',side_effect=readback),self.assertRaises(self.m.Blocked):self.stage(b'opaque',deadline=start+2)
        self.assertEqual(self.leaf.read_bytes(),b'opaque')

    def test_directory_or_file_identity_change_after_encoding_refuses_receipt(self):
        real=self.m.PREP.canonical
        for fault in ('directory','file'):
            def encode(value):
                raw=real(value)
                if fault=='directory':self.store.chmod(0o750)
                else:self.leaf.chmod(0o640)
                return raw
            with self.subTest(fault=fault),patch.object(self.m.PREP,'canonical',side_effect=encode),self.assertRaises(self.m.Blocked):self.stage(b'opaque')
            self.store.chmod(0o700);self.leaf.unlink()

    def test_positive_parent_cap_and_own_upper_cap_reach_all_admission_points(self):
        start=self.m.KERNEL.now();real=self.m.admission
        for inherited,expected in ((start+2,start+2),(start+7200,start+self.m.ATTEMPT_SECONDS)):
            ends=[]
            def admission(end):ends.append(end);return real(end)
            with self.subTest(inherited=inherited),patch.object(self.m.KERNEL,'now',return_value=start),patch.object(self.m,'admission',side_effect=admission):self.stage(b'opaque',deadline=inherited)
            self.assertTrue(ends);self.assertEqual(set(ends),{expected});self.leaf.unlink()

    def test_cross_chunk_overflow_preserves_only_previous_complete_chunks(self):
        raw=b'x'*self.m.CHUNK+b'overflow'
        with self.assertRaises(self.m.Blocked):self.m.stage(self.store,self.name,io.BytesIO(raw),self.m.CHUNK+3)
        self.assertEqual(self.leaf.read_bytes(),b'x'*self.m.CHUNK)
        with self.assertRaises(self.m.Blocked):self.stage()

    def test_named_leaf_replacement_during_stream_refuses_without_touching_foreign_bytes(self):
        moved=self.store/'moved';calls=[];source=io.BytesIO(b'opaque')
        class Stream:
            def read(inner,n):
                calls.append(n)
                if len(calls)==1:
                    self.leaf.rename(moved);self.leaf.write_bytes(b'foreign');self.leaf.chmod(0o600)
                return source.read(n)
        with self.assertRaises(self.m.Blocked):self.m.stage(self.store,self.name,Stream(),20)
        self.assertEqual(self.leaf.read_bytes(),b'foreign');self.assertEqual(moved.read_bytes(),b'opaque')
        with self.assertRaises(self.m.Blocked):self.stage()


if __name__=='__main__':unittest.main()
