"""Private fixed dump-child models; no actual PG/runuser/SQL/backup validation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


class DumpStreamTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid()==0:raise RuntimeError('ordinary UID fixture required')
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.storage=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(self.storage.cleanup)
        self.store=Path(self.storage.name);self.store.chmod(0o700)
        spec=importlib.util.spec_from_file_location('private_dump_stream',ROOT/'PostgreSQL/dump_stream.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.m.KERNEL.TRUST_ROOT=self.root;self.m.KERNEL.TRUSTED_UID=os.geteuid()
        self.scope=patch.object(self.m.KERNEL,'namespace',return_value=4711);self.scope.start();self.addCleanup(self.scope.stop)
        self.m.RUNUSER=self.root/'runuser';self.m.DUMP=self.root/'pg_dump'
        self.m.DUMP.write_text('PRIVATE inert product identity\n');self.m.DUMP.chmod(0o700)
        self.ledger=self.root/'ledger';self.data=b'INVALID-PG\x00\xff\r\n'*7000
        self.program();self.streams=[];self.addCleanup(self.cleanup)
        spec=importlib.util.spec_from_file_location('private_dump_stage',ROOT/'PostgreSQL/archive_stage.py')
        self.stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.stage)
        self.stage.TRUST_ROOT=self.store;self.stage.TRUSTED_UID=os.geteuid()
        self.name='f'*64+'-mk8.dns.dump.partial';self.leaf=self.store/self.name

    def cleanup(self):
        for stream in self.streams:stream.close()

    def program(self,action='os.write(1,data)'):
        self.m.RUNUSER.write_text('#!/usr/bin/python3\nimport json,os,sys,time\nfrom pathlib import Path\n'+
            'data='+repr(self.data)+'\n'+
            'Path('+repr(str(self.ledger))+').open("a").write(json.dumps({"argv":sys.argv,"environment":dict(os.environ),"pid":os.getpid(),"sid":os.getsid(0)})+"\\n")\n'+action+'\n')
        self.m.RUNUSER.chmod(0o700)

    def stream(self,**kw):
        args={'role':'dns_demo','database':'dns_demo','limit':len(self.data),'stderr_limit':4096,'seconds':2,'lock_wait_ms':1000}
        args.update(kw);s=self.m.DumpStream(**args);self.streams.append(s);return s

    def consume(self,s,n=65536):
        parts=[]
        while True:
            part=s.read(n)
            if not part:return b''.join(parts)
            self.assertIs(type(part),bytes);self.assertLessEqual(len(part),n);parts.append(part)

    def test_constructor_is_lazy_and_close_before_entry_prevents_every_child(self):
        s=self.stream();self.assertFalse(self.ledger.exists());self.assertFalse(s.started)
        self.assertEqual(s.close(),());self.assertEqual(s.close(),())
        with self.assertRaises(ValueError):s.read(1)
        self.assertFalse(self.ledger.exists())

    def test_complete_binary_stream_fixed_argv_env_session_and_receipt_only(self):
        s=self.stream();self.assertEqual(self.consume(s),self.data);v=json.loads(s.receipt)
        self.assertEqual(v['state'],'dump-stream-receipt-only');self.assertEqual(v['received_bytes'],len(self.data))
        self.assertEqual(v['received_sha256'],hashlib.sha256(self.data).hexdigest());self.assertEqual(v['root_exit'],0)
        self.assertEqual(v['stderr_hex'],'');self.assertTrue(s.closed and s.done)
        rows=[json.loads(line) for line in self.ledger.read_text().splitlines()];self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['argv'],list(s.argv));self.assertEqual(rows[0]['pid'],rows[0]['sid'])
        self.assertEqual(rows[0]['environment'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
        self.assertEqual(list(s.argv),[str(self.m.RUNUSER),'-u','dns_demo','--',str(self.m.DUMP),'--format=custom','--no-password','--host',self.m.PREP.SOCKET_DIRECTORY,'--port','5432','--username','dns_demo','--dbname','dns_demo','--lock-wait-timeout=1000'])
        self.assertEqual(s.read(1),b'');self.assertEqual(len(self.ledger.read_text().splitlines()),1)

    def test_every_explicit_bound_identity_and_deadline_is_validated_before_entry(self):
        for field,bads in {'role':('root','postgres','pg_x','x;bad',True),'database':('template0','root','--dbname=x',True),
             'limit':(True,1023,(1<<40)+1),'stderr_limit':(True,0,self.m.MAX_STDERR+1),'seconds':(True,0,3601),
             'lock_wait_ms':(True,0,60001),'deadline':(True,'later',float('nan'),float('inf'),self.m.KERNEL.now()-1)}.items():
            for value in bads:
                with self.subTest(field=field,value=str(value)),self.assertRaises(ValueError):self.stream(**{field:value})
        self.assertFalse(self.ledger.exists())

    def test_existing_stage_blocks_before_lazy_child_and_preserves_foreign_bytes(self):
        self.leaf.write_bytes(b'foreign');self.leaf.chmod(0o600);before=self.leaf.stat();s=self.stream()
        with self.assertRaises(self.stage.Blocked):self.stage.stage(self.store,self.name,s,s.limit)
        self.assertFalse(s.started);self.assertFalse(self.ledger.exists())
        self.assertEqual(self.leaf.read_bytes(),b'foreign');self.assertEqual(self.leaf.stat(),before)

    def test_real_create_only_writer_acquires_target_before_single_entry_and_known_eof(self):
        self.program('assert Path('+repr(str(self.leaf))+').is_file();os.write(1,data)')
        s=self.stream();raw=self.stage.stage(self.store,self.name,s,s.limit)
        self.assertEqual(self.leaf.read_bytes(),self.data);self.assertEqual(json.loads(raw)['state'],'private-unverified-archive-stage-only')
        self.assertTrue(s.done);self.assertEqual(json.loads(s.receipt)['received_bytes'],len(self.data))
        self.assertEqual(len(self.ledger.read_text().splitlines()),1)
        with self.assertRaises(self.stage.Blocked):self.stage.stage(self.store,self.name,self.stream(),s.limit)
        self.assertEqual(len(self.ledger.read_text().splitlines()),1)

    def test_nonzero_and_zero_warning_leave_acquired_partial_and_original_cause(self):
        for action in ('os.write(1,data);sys.exit(7)','os.write(1,data);os.write(2,b"warning")'):
            self.program(action);s=self.stream()
            with self.subTest(action=action),self.assertRaises(self.stage.Blocked) as caught:self.stage.stage(self.store,self.name,s,s.limit)
            self.assertIsInstance(caught.exception.__cause__,self.m.Uncertain)
            self.assertIs(caught.exception.__cause__,s.poison);self.assertIsInstance(s.poison.cause,ValueError)
            self.assertTrue(s.closed);self.assertFalse(s.done);self.assertIsNone(s.receipt)
            self.assertEqual(self.leaf.read_bytes(),self.data)
            self.leaf.unlink() # TEST-only cleanup, no production reset.

    def test_stdout_overflow_refuses_before_excess_chunk_delivery_and_poison_blocks_retry(self):
        self.program('os.write(1,data+b"excess")');s=self.stream()
        with self.assertRaises(self.m.Uncertain) as caught:self.consume(s)
        self.assertIs(caught.exception,s.poison);self.assertGreater(s.received,s.limit)
        self.assertLessEqual(s.received,s.limit+1);self.assertTrue(s.closed)
        with self.assertRaises(self.m.Uncertain) as again:s.read(1)
        self.assertIs(again.exception,caught.exception);self.assertEqual(len(self.ledger.read_text().splitlines()),1)

    def test_bounded_stderr_is_drained_alongside_stdout_and_warned_zero_is_uncertain(self):
        self.program('os.write(2,b"w"*4096);os.write(1,data)');s=self.stream()
        with self.assertRaises(self.m.Uncertain):self.consume(s,1000)
        self.assertEqual(bytes(s.stderr),b'w'*4096);self.assertEqual(s.received,len(self.data))
        self.assertEqual(s.child.returncode,0);self.assertFalse(s.done)

    def test_stderr_overflow_is_bounded_prefix_and_owned_child_is_retired(self):
        self.program('os.write(2,b"w"*8192);time.sleep(10)');s=self.stream()
        with self.assertRaises(self.m.Uncertain):s.read(1)
        self.assertEqual(len(s.stderr),4097);self.assertTrue(s.closed);self.assertIsNotNone(s.child.poll())
        self.assertLessEqual(s.received,s.limit)

    def test_empty_child_zero_never_supplies_successful_eof_or_stage_receipt(self):
        self.program('pass');s=self.stream()
        with self.assertRaises(self.stage.Blocked):self.stage.stage(self.store,self.name,s,s.limit)
        self.assertEqual(self.leaf.read_bytes(),b'');self.assertIsNone(s.receipt);self.assertIsNotNone(s.poison)

    def test_child_closes_pipes_but_stalls_completion_and_is_cleaned_without_eof(self):
        self.program('os.write(1,b"x");os.close(1);os.close(2);time.sleep(10)');now=self.m.KERNEL.now()
        with patch.object(self.m.KERNEL,'now',return_value=now):
            s=self.stream(seconds=1);self.assertEqual(s.read(1),b'x')
            with self.assertRaises(self.m.Uncertain) as caught:s.read(1)
        self.assertIsInstance(caught.exception.cause,subprocess.TimeoutExpired)
        self.assertTrue(s.closed);self.assertIsNotNone(s.child.poll());self.assertFalse(s.done)

    def test_capture_expiry_retires_its_own_child_and_poison_has_prefix_not_total_production(self):
        self.program('time.sleep(10)');s=self.stream(seconds=1)
        with self.assertRaises(self.m.Uncertain):s.read(1)
        self.assertEqual(s.received,0);self.assertTrue(s.closed);self.assertIsNotNone(s.child.poll())

    def test_final_executable_drift_and_namespace_change_withhold_eof(self):
        self.program('os.write(1,data);Path('+repr(str(self.m.DUMP))+').chmod(0o600)');s=self.stream()
        with self.assertRaises(self.m.Uncertain):self.consume(s)
        self.assertFalse(s.done);self.assertIsNone(s.receipt)
        self.m.DUMP.chmod(0o700);self.program();s=self.stream();first=s.read(1)
        self.assertEqual(first,self.data[:1])
        with patch.object(self.m.KERNEL,'namespace',return_value=True),self.assertRaises(self.m.Uncertain):s.read(1)
        self.assertTrue(s.closed)

    def test_positive_inherited_cap_and_invalid_initial_namespace_precede_child(self):
        now=self.m.KERNEL.now()
        with patch.object(self.m.KERNEL,'now',return_value=now):
            self.assertEqual(self.stream(seconds=3600,deadline=now+2).end,now+2)
        for context in (0,True,-1,1<<64,'1'):
            with patch.object(self.m.KERNEL,'namespace',return_value=context),self.assertRaises(ValueError):self.stream().read(1)
        self.assertFalse(self.ledger.exists())

    def test_receipt_encoding_precedes_final_executable_context_fences_and_checked_close(self):
        s=self.stream();events=[];canonical=self.m.PREP.canonical;trusted=self.m.KERNEL.trusted_binary;close=s.close
        def encoded(value):events.append('encode');return canonical(value)
        def binary(path):events.append('binary');return trusted(path)
        def retired():events.append('close');return close()
        with patch.object(self.m.PREP,'canonical',side_effect=encoded),patch.object(self.m.KERNEL,'trusted_binary',side_effect=binary),patch.object(s,'close',side_effect=retired):self.consume(s)
        self.assertEqual(events[-4:],['encode','binary','binary','close'])

    def test_receipt_cap_refuses_without_eof_and_preserves_single_entry(self):
        s=self.stream()
        with patch.object(self.m,'MAX_RECEIPT',1),self.assertRaises(self.m.Uncertain):self.consume(s)
        self.assertIsNone(s.receipt);self.assertFalse(s.done);self.assertTrue(s.closed)
        self.assertEqual(len(self.ledger.read_text().splitlines()),1)

    def test_invalid_read_after_entry_poison_closes_child_before_any_second_attempt(self):
        self.program('os.write(1,b"x");time.sleep(10)');s=self.stream();self.assertEqual(s.read(1),b'x')
        with self.assertRaises(self.m.Uncertain):s.read(True)
        self.assertTrue(s.closed);self.assertIsNotNone(s.child.poll())
        with self.assertRaises(self.m.Uncertain):s.read(1)
        self.assertEqual(len(self.ledger.read_text().splitlines()),1)

    def test_original_failure_remains_separate_from_cleanup_failure_and_retirement(self):
        self.program('os.write(2,b"w"*8192);time.sleep(10)');s=self.stream();original=s.close
        def close():
            errors=original();return errors+(OSError('separate cleanup'),)
        with patch.object(s,'close',side_effect=close),self.assertRaises(self.m.Uncertain) as caught:s.read(1)
        self.assertIsInstance(caught.exception.cause,ValueError);self.assertEqual(str(caught.exception.cleanup[-1]),'separate cleanup')
        self.assertTrue(s.closed);self.assertIsNotNone(s.child.poll())

    def test_completed_pipe_close_failure_refuses_eof_and_retires_once(self):
        s=self.stream();original=s.close;calls=[]
        def close():calls.append(1);return original()+(OSError('close failure'),)
        with patch.object(s,'close',side_effect=close),self.assertRaises(self.m.Uncertain):self.consume(s)
        self.assertEqual(calls,[1]);self.assertFalse(s.done);self.assertIsNone(s.receipt)
        with self.assertRaises(self.m.Uncertain):s.read(1)
        self.assertEqual(calls,[1])

    def test_invalid_initial_read_sizes_retire_without_process_entry(self):
        for size in (True,0,-1,1.0,'1',self.m.CHUNK+1):
            s=self.stream()
            with self.subTest(size=size),self.assertRaises(ValueError):s.read(size)
            self.assertTrue(s.closed);self.assertFalse(s.started)
            with self.assertRaises(ValueError):s.read(1)
        self.assertFalse(self.ledger.exists())

    def test_actual_poison_is_preserved_even_for_later_malformed_read(self):
        self.program('os.write(2,b"w"*8192);time.sleep(10)');s=self.stream()
        with self.assertRaises(self.m.Uncertain) as first:s.read(1)
        with self.assertRaises(self.m.Uncertain) as later:s.read(True)
        self.assertIs(first.exception,later.exception)
        self.assertEqual(len(self.ledger.read_text().splitlines()),1)

    def test_final_receipt_encoding_context_or_clock_change_refuses_eof(self):
        original=self.m.PREP.canonical
        for which in ('scope','time'):
            now=self.m.KERNEL.now();clock=[now];scope=[4711]
            def encoded(value):
                raw=original(value)
                if value['state']=='dump-stream-receipt-only':
                    if which=='scope':scope[0]=True
                    else:clock[0]=now+2
                return raw
            with self.subTest(which=which),patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),patch.object(self.m.KERNEL,'namespace',side_effect=lambda:scope[0]),patch.object(self.m.PREP,'canonical',side_effect=encoded):
                s=self.stream(seconds=1)
                with self.assertRaises(self.m.Uncertain):self.consume(s)
                self.assertTrue(s.closed);self.assertFalse(s.done);self.assertIsNone(s.receipt)

    def test_setup_after_popen_failure_preserves_uncertainty_and_owns_cleanup(self):
        self.program('time.sleep(10)');s=self.stream()
        with patch.object(self.m.selectors,'DefaultSelector',side_effect=OSError('selector acquisition')),self.assertRaises(self.m.Uncertain) as caught:s.read(1)
        self.assertEqual(str(caught.exception.cause),'selector acquisition')
        self.assertTrue(s.closed);self.assertIsNotNone(s.child.poll());self.assertEqual(s.streams,{})

    def test_known_popen_channels_close_even_when_setup_registry_is_lost(self):
        self.program('time.sleep(10)');s=self.stream();channels=[]
        def acquisition():
            channels.extend((s.child.stdout,s.child.stderr))
            s.streams.clear() # MODEL the post-Popen registry acquisition failure.
            raise OSError('lost channel registry')
        def cleanup():
            for channel in channels:
                if not channel.closed:channel.close()
        self.addCleanup(cleanup)
        with patch.object(self.m.selectors,'DefaultSelector',side_effect=acquisition),self.assertRaises(self.m.Uncertain) as caught:s.read(1)
        self.assertEqual(str(caught.exception.cause),'lost channel registry')
        self.assertTrue(s.closed);self.assertIsNotNone(s.child.poll())
        self.assertEqual(len(channels),2);self.assertTrue(all(channel.closed for channel in channels))


    def test_signal_failure_does_not_skip_owned_wait_or_repeat_retired_cleanup(self):
        self.program('time.sleep(10)');s=self.stream();s.start()
        channels=tuple(s.streams.values());original=OSError('original delivery failure')
        signal_error,wait_error=OSError('signal reported failure'),OSError('wait reported failure')
        kill,wait=os.killpg,s.child.wait;events=[]
        def signalled(pid,value):
            self.assertTrue(s.closed);self.assertEqual(pid,s.child.pid)
            events.append('signal');kill(pid,value);raise signal_error
        def waited(*args,**kwargs):
            self.assertTrue(s.closed);self.assertEqual(kwargs['timeout'],self.m.KERNEL.CLEANUP_SECONDS)
            events.append('wait');wait(*args,**kwargs);raise wait_error
        with patch.object(self.m.os,'killpg',side_effect=signalled),patch.object(s.child,'wait',side_effect=waited),self.assertRaises(self.m.Uncertain) as caught:
            s.fail(original)
        self.assertIs(caught.exception.cause,original);self.assertIs(caught.exception.__cause__,original)
        self.assertEqual(caught.exception.cleanup,(signal_error,wait_error))
        self.assertEqual(events,['signal','wait']);self.assertIsNotNone(s.child.returncode)
        self.assertTrue(all(channel.closed for channel in channels))
        self.assertEqual(s.streams,{});self.assertIsNone(s.child.stdout);self.assertIsNone(s.child.stderr)
        with patch.object(self.m.os,'killpg',side_effect=AssertionError('second signal')),patch.object(s.child,'wait',side_effect=AssertionError('second wait')):
            self.assertEqual(s.close(),())
            with self.assertRaises(self.m.Uncertain) as repeated:s.read(1)
        self.assertIs(repeated.exception,caught.exception)


if __name__=='__main__':unittest.main()
