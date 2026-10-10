"""Checked native delivery predicates using ordinary-UID private executables."""
import copy
import hashlib
import json
import os
import subprocess
import time
import unittest
from unittest.mock import patch
from fixture_web import PrivateWeb


class WebLiveTests(unittest.TestCase):
    def setUp(self):self.fixture=PrivateWeb();self.addCleanup(self.fixture.close);self.m=self.fixture.m
    def model(self,kind,item,end,epoch=None):
        if kind in ('certificate-key','private-key'):return b'-----BEGIN PUBLIC KEY-----\nbW9kZWw=\n-----END PUBLIC KEY-----\n'
        if kind=='key-check':return b'Key is valid\n'
        if kind=='verify':return (item['certificate']+': OK\n').encode()
        if kind=='nginx':return b''
        raise AssertionError(kind)

    def test_real_private_capture_checks_all_fixed_crypto_and_syntax_argv(self):
        self.m.check()
        rows=[json.loads(row) for row in (self.fixture.root/'native.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows),16)
        self.assertEqual(sum(row['binary']=='openssl' for row in rows),15)
        self.assertEqual(rows[-1]['binary'],'nginx')
        for row in rows:
            self.assertEqual(row['pid'],row['sid']);self.assertEqual(row['environment']['LC_ALL'],'C')
            self.assertEqual(row['environment']['PATH'],'/usr/bin:/usr/sbin')
            self.assertNotIn('PYTHONPATH',row['environment'])
        epochs=[int(row['argv'][10]) for row in rows if 'verify' in row['argv']]
        self.assertEqual(epochs[1]-epochs[0],3600)

    def test_key_pair_validity_chain_and_unexpected_syntax_output_refuse(self):
        for fault in ('key_mismatch','invalid_key','verify','syntax','warning','exit'):
            with self.subTest(fault=fault):
                self.fixture.faults(**{fault:True})
                with self.assertRaises((self.m.Pending,subprocess.TimeoutExpired)):self.m.check()
                self.fixture.faults(**{fault:False})

    def test_unavailable_or_unsafe_worker_inventory_refuses_before_native_entry(self):
        path=self.m.PASSWD;good=path.read_bytes()
        for bad in (good.replace(b'www-data',b'absent'),good.replace(b':33:33:',b':0:33:'),
            good.replace(b':33:33:',b':33:0:'),good.replace(b'/usr/sbin/nologin',b'/bin/bash'),
            good.replace(b'\n',b'\r\n'),good.replace(b'\n',b'\v'),good+b'root:x:5:5::/:/bin/false\n'):
            path.write_bytes(bad)
            with patch.object(self.m,'native') as native, self.assertRaises(self.m.Pending):self.m.check(read=native)
            native.assert_not_called()
        path.write_bytes(good)

    def test_every_non_lf_account_control_byte_refuses(self):
        raw=self.m.PASSWD.read_bytes()
        for separator in (b'\r',b'\r\n',b'\v',b'\f',b'\x1c',b'\x1d',b'\x1e',b'\0',b'\x7f'):
            with self.subTest(separator=separator), self.assertRaises(self.m.Pending):self.m.worker(raw.replace(b'\n',separator,1))

    def test_group_identity_and_supplementary_memberships_are_closed(self):
        account={'uid':33,'gid':33,'name':'www-data'}
        self.m.groups(b'root:x:0:\nwww-data:x:33:\n',account)
        for raw in (b'root:x:0:\n',b'www-data:x:34:\n',b'www-data:x:33:foreign\n',
            b'www-data:x:33:\nadm:x:4:www-data\n',b'www-data:x:33:\r\n',
            b'www-data:x:33:www-data,www-data\n'):
            with self.subTest(raw=raw),self.assertRaises(self.m.Pending):self.m.groups(raw,account)

    def test_installed_config_and_system_ca_are_mandatory_protected_inputs(self):
        self.m.CONFIG.write_bytes(b'worker_processes auto;\n')
        with self.assertRaises(self.m.Pending):self.m.check(read=self.model)
        self.m.CONFIG.write_bytes(self.m.PREP.render(self.fixture.value).encode())
        self.m.CA.write_bytes(b'')
        with self.assertRaises(self.m.Pending):self.m.check(read=self.model)
        self.m.CA.unlink()
        with self.assertRaises(OSError):self.m.check(read=self.model)

    def test_plain_identity_has_no_native_entry_and_binds_every_startup_material(self):
        with patch.object(subprocess,'Popen',side_effect=AssertionError('identity must not spawn')):
            before=self.m.identity()
        value=json.loads(before);self.assertEqual(value['namespace'],4711)
        self.assertEqual(len(value['startup_sha256']),64)
        key=self.fixture.value['applications']['mk8.sava']['private_key']
        from pathlib import Path
        Path(key).write_bytes(self.fixture.pem(True,b'changed key MODEL'))
        self.assertNotEqual(self.m.identity(),before)

    def test_same_path_material_change_after_native_admission_withholds_check(self):
        calls=[]
        def read(kind,item,end,epoch=None):
            calls.append(kind)
            result=self.model(kind,item,end,epoch)
            if kind=='nginx':self.m.CA.write_bytes(self.fixture.pem(body=b'changed CA model'))
            return result
        with self.assertRaises(self.m.Pending):self.m.check(read=read)
        self.assertEqual(calls[-1],'nginx')

    def test_current_and_one_hour_verification_are_both_mandatory(self):
        calls=[]
        def read(kind,item,end,epoch=None):
            if kind=='verify':calls.append(epoch)
            return self.model(kind,item,end,epoch)
        with patch.object(self.m.time,'time',return_value=1700000000):self.m.check(read=read)
        self.assertEqual(calls,[1700000000,1700003600]*3)
        calls=[]
        def second_refuses(kind,item,end,epoch=None):
            if kind=='verify':
                calls.append(epoch)
                if len(calls)==2:return b'not OK\n'
            return self.model(kind,item,end,epoch)
        with self.assertRaises(self.m.Pending):self.m.check(read=second_refuses)
        self.assertEqual(len(calls),2)

    def test_wallclock_invalid_backward_or_admission_drift_refuses(self):
        for value in (True,float('nan'),float('inf'),0,2**31):
            with patch.object(self.m.time,'time',return_value=value), self.assertRaises(self.m.Pending):self.m.check(read=self.model)
        for final in (1699999999,1700000060,float('nan')):
            with patch.object(self.m.time,'time',side_effect=[1700000000,final]),self.assertRaises(self.m.Pending):self.m.check(read=self.model)

    def test_invalid_master_pid_refuses_before_all_protected_and_native_reads(self):
        for pid in (0,True,1.0,2**31,'10'):
            with patch.object(self.m,'inputs') as inputs,self.assertRaises(self.m.Pending):self.m.check(read=self.model,pid=pid)
            inputs.assert_not_called()

    def test_fixed_command_builder_has_no_signal_install_connection_or_caller_argv(self):
        item=self.fixture.value['applications']['mk8.sava']
        for kind in ('start','reload','create','s_client','http','-g'):
            with self.assertRaises(self.m.Pending):self.m.arguments(kind,item)
        binary,args=self.m.arguments('verify',item,1700000000)
        self.assertEqual(binary,self.m.OPENSSL);self.assertIn('-no-CAstore',args);self.assertIn('-auth_level',args)
        self.assertNotIn('-crl_download',args);self.assertNotIn('-no_check_time',args)

    def test_reported_owner_inventory_binds_master_workers_and_four_complete_listeners(self):
        raw=b''.join(('LISTEN 0 511 '+address+' *:* users:(("nginx",pid=100,fd=6),("nginx",pid=101,fd=6))\n').encode()
            for address in ('0.0.0.0:80','[::]:80','0.0.0.0:443','[::]:443'))
        proc=lambda pid:{'uid':0 if pid==100 else 33,'gid':0 if pid==100 else 33,'ppid':1 if pid==100 else 100,'start':500}
        self.m.sockets(raw,100,{'uid':33,'gid':33},proc)
        for bad in (raw[:-1],raw.replace(b'"nginx"',b'"foreign"'),raw.split(b'\n',1)[1],raw+raw.split(b'\n')[0]+b'\n',
                    raw.replace(b'0.0.0.0:80',b'127.0.0.1:80'),raw.replace(b'pid=100',b'pid=102')):
            with self.subTest(raw=bad),self.assertRaises(self.m.Pending):self.m.sockets(bad,100,{'uid':33,'gid':33},proc)
        with self.assertRaises(self.m.Pending):self.m.sockets(raw,100,{'uid':33,'gid':33},lambda pid:{'uid':33,'gid':33,'ppid':1,'start':500})
        with self.assertRaises(self.m.Pending):self.m.sockets(raw,100,{'uid':33,'gid':33},lambda pid:{'uid':0 if pid==100 else 33,'gid':0 if pid==100 else 33,'ppid':99,'start':500})

    def test_reported_process_identity_drift_refuses(self):
        raw=b''.join(('LISTEN 0 511 '+address+' *:* users:(("nginx",pid=100,fd=6))\n').encode()
            for address in ('0.0.0.0:80','[::]:80','0.0.0.0:443','[::]:443'))
        counts=[]
        def proc(pid):counts.append(pid);return {'uid':0,'gid':0,'ppid':1,'start':len(counts)}
        with self.assertRaises(self.m.Pending):self.m.sockets(raw,100,{'uid':33,'gid':33},proc)

    def test_native_stdout_stderr_limits_and_timeout_do_not_admit(self):
        self.fixture.faults(large=True)
        with self.assertRaises(self.m.Pending):self.m.native('nginx',None,self.m.KERNEL.now()+3)
        self.fixture.faults(large=False,sleep=True)
        with self.assertRaises((self.m.Pending,subprocess.TimeoutExpired)):
            self.m.native('nginx',None,self.m.KERNEL.now()+0.3)

    def test_retired_capture_fd_is_closed_once_even_when_close_reports_error(self):
        original=self.m.subprocess.Popen;closed=[];reused=[]
        class Stream:
            def __init__(self,owned):self.owned=owned
            def fileno(self):return self.owned.fileno()
            def close(self):
                fd=self.owned.fileno();closed.append(fd);self.owned.close()
                other=os.open('/dev/null',os.O_RDONLY)
                if other!=fd:os.dup2(other,fd);os.close(other)
                reused.append(fd);raise OSError('retired pipe close delivery')
        def spawn(*args,**kwargs):
            child=original(*args,**kwargs);child.stdout=Stream(child.stdout);return child
        try:
            with patch.object(self.m.subprocess,'Popen',side_effect=spawn),self.assertRaises(OSError):
                self.m.native('nginx',None,self.m.KERNEL.now()+3)
            self.assertEqual(len(closed),1);self.assertEqual(reused,closed)
            self.assertEqual(os.read(reused[0],1),b'');os.fstat(reused[0])
        finally:
            for fd in reused:os.close(fd)

    def test_native_public_key_bytes_are_typed_bounded_canonical(self):
        for raw in (b'',True,b'bad\n',b'x'*16385,b'-----BEGIN PUBLIC KEY-----\nAB==\n-----END PUBLIC KEY-----\n'):
            with self.subTest(raw=raw),self.assertRaises(self.m.Pending):self.m.public_key(raw)

    def test_process_cpu_counter_changes_are_not_identity_but_start_changes_refuse(self):
        from pathlib import Path
        self.m.PROC=self.fixture.root/'proc';(self.m.PROC/'100').mkdir(parents=True)
        root=self.m.PROC/'100';fields=['S','1']+['0']*30;fields[19]='500'
        def stat_raw(cpu,start='500'):
            changed=list(fields);changed[11]=str(cpu);changed[19]=start
            return ('100 (nginx) '+' '.join(changed)+'\n').encode()
        (root/'stat').write_bytes(stat_raw(1))
        (root/'status').write_bytes(b'Name:\tnginx\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n')
        (root/'exe').symlink_to(self.m.NGINX)
        original=Path.read_bytes;calls=[]
        def changing(path):
            if path==root/'stat':calls.append(1);return stat_raw(len(calls))
            return original(path)
        with patch.object(Path,'read_bytes',changing):
            self.assertEqual(self.m.process(100),{'uid':0,'gid':0,'ppid':1,'start':500})
        calls=[]
        def reused(path):
            if path==root/'stat':calls.append(1);return stat_raw(1,'500' if len(calls)==1 else '501')
            return original(path)
        with patch.object(Path,'read_bytes',reused),self.assertRaises(self.m.Pending):self.m.process(100)

    def test_file_projection_is_encoded_before_second_complete_preparation_and_final_scope(self):
        calls=[]
        class Text(str):
            def encode(self,*args,**kw):calls.append('encode');return super().encode(*args,**kw)
        def prepare(**kw):calls.append('prepare');return b'whole trusted intention MODEL'
        def scope():calls.append('scope');return 4711
        with patch.object(self.m.PREP,'prepare',side_effect=prepare),patch.object(self.m.json,'loads',return_value={'nginx':Text('config\n'),'namespace':4711}),patch.object(self.m.KERNEL,'namespace',side_effect=scope):
            self.assertEqual(self.m.file_payload(),b'config\n')
        self.assertEqual(calls,['prepare','encode','prepare','scope'])
        with patch.object(self.m.PREP,'prepare',side_effect=[b'first',b'changed']),patch.object(self.m.json,'loads',return_value={'nginx':'config\n','namespace':4711}),self.assertRaises(self.m.Pending):
            self.m.file_payload()


if __name__=='__main__':unittest.main()
