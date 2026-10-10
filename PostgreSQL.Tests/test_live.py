"""Real admission/capture predicates with explicit private native deliveries."""
import copy
import io
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch
from fixture_pg import PrivatePG


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.fixture=PrivatePG();self.addCleanup(self.fixture.close)
        self.context=self.fixture.context();self.context.__enter__();self.addCleanup(self.context.close)
        self.m=self.fixture.m

    def test_two_complete_native_catalogs_and_reported_context_are_bound(self):
        raw=self.m.check();value=json.loads(raw)
        self.assertEqual(value['state'],'enrolled-local-postgresql-source-only')
        self.assertEqual(value['namespace'],4711)
        self.assertEqual(value['catalog'],self.fixture.reply)
        ledger=[json.loads(x) for x in self.fixture.ledger.read_text().splitlines()]
        self.assertEqual([x['kind'] for x in ledger],['catalog','catalog'])
        for row in ledger:
            self.assertEqual(row['pid'],row['sid'])
            self.assertEqual(row['environment'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
            self.assertEqual(row['argv'][-1],self.m.SQL)

    def test_clean_stopped_checksummed_enrollment_is_required(self):
        self.assertEqual(self.m.prestart(self.fixture.read),self.fixture.record)
        for replacement in (b'Database cluster state: shut down',b'Data page checksum version: 1',
                            b'Database system identifier: 7341234567890123456'):
            with self.subTest(field=replacement):
                self.fixture.control=self.fixture.control.replace(replacement,replacement+b'x')
                with self.assertRaises(self.m.Pending):self.m.prestart(self.fixture.read)
                self.fixture.control=self.fixture.control.replace(replacement+b'x',replacement)

    def test_existing_postmaster_or_symlink_is_never_removed(self):
        path=self.m.DATA/'postmaster.pid'
        for symbolic in (False,True):
            if symbolic:path.symlink_to(self.m.DATA/'missing')
            else:path.write_bytes(b'123\n')
            with self.subTest(symbolic=symbolic),patch.object(self.m,'native',side_effect=AssertionError('entry prohibited')):
                with self.assertRaises(self.m.Pending):self.m.prestart(self.fixture.read)
                self.assertTrue(path.exists() or path.is_symlink())
            path.unlink()

    def test_enrollment_is_private_canonical_and_required_before_native_entry(self):
        path=self.m.ENROLLMENT;original=path.read_bytes()
        values=(b'{"schema":1,"system_identifier":0}\n',b'{"schema":true,"system_identifier":5}\n',
                b'{"schema":1,"system_identifier":true}\n',b'{"schema":1,"system_identifier":5,"foreign":0}\n',
                b'{"schema":1,"schema":1,"system_identifier":5}\n',original.rstrip())
        for raw in values:
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaises((self.m.Pending,ValueError)):self.m.check(lambda *_:self.fail('native reached'))
        path.write_bytes(original);path.chmod(0o644)
        with self.assertRaises(self.m.Pending):self.m.check(lambda *_:self.fail('native reached'))

    def test_data_mode_version_and_automatic_overrides_refuse(self):
        version=self.m.DATA/'PG_VERSION';auto=self.m.DATA/'postgresql.auto.conf'
        for raw in (b'16\n',b'17\r\n',b'17'):
            version.write_bytes(raw)
            with self.subTest(version=raw),self.assertRaises(self.m.Pending):self.m.check(self.fixture.read)
        version.write_bytes(b'17\n');version.chmod(0o644)
        with self.assertRaises(self.m.Pending):self.m.check(self.fixture.read)
        version.chmod(0o600)
        for raw in (b'listen_addresses = \'*\'\n',b' # not an admitted comment\n'):
            auto.write_bytes(raw)
            with self.subTest(auto=raw),self.assertRaises(self.m.Pending):self.m.check(self.fixture.read)

    def test_server_session_identity_and_true_integer_facts_refuse(self):
        cases={'version':True,'identifier':'different','user':'dns_demo','database':'template1',
               'client':'127.0.0.1','authentication':'trust','recovery':True,'memberships':True,'start':'a\n'}
        for field,value in cases.items():
            reply=copy.deepcopy(self.fixture.reply);reply[field]=value
            with self.subTest(field=field),self.assertRaises(self.m.Pending):
                self.m.check(lambda *_:json.dumps(reply).encode())

    def test_every_setting_value_unit_and_pending_restart_is_checked(self):
        for name in self.m.SETTING_NAMES:
            for field,value in (('value','wrong'),('unit','wrong'),('pending_restart',True)):
                reply=copy.deepcopy(self.fixture.reply);reply['settings'][name][field]=value
                with self.subTest(name=name,field=field),self.assertRaises(self.m.Pending):
                    self.m.check(lambda *_:json.dumps(reply).encode())

    def test_role_privileges_authentication_and_closed_inventory_refuse(self):
        for field,value in (('super',True),('inherit',True),('createdb',True),('createrole',True),
                            ('replication',True),('bypass',True),('login',False),('limit',True),
                            ('password','hash'),('valid_until','tomorrow')):
            reply=copy.deepcopy(self.fixture.reply);reply['roles'][1][field]=value
            with self.subTest(field=field),self.assertRaises(self.m.Pending):self.m.check(lambda *_:json.dumps(reply).encode())
        for change in ('missing','extra','duplicate'):
            reply=copy.deepcopy(self.fixture.reply)
            if change=='missing':reply['roles'].pop()
            else:reply['roles'].append(copy.deepcopy(reply['roles'][1]))
            with self.subTest(change=change),self.assertRaises(self.m.Pending):self.m.check(lambda *_:json.dumps(reply).encode())

    def test_database_and_role_setting_overrides_cannot_hide_application_settings(self):
        for value in (1,-1,True,False,0.0,None):
            reply=copy.deepcopy(self.fixture.reply);reply['overrides']=value
            with self.subTest(value=value),self.assertRaises(self.m.Pending):
                self.m.check(lambda *_:json.dumps(reply).encode())
        self.assertIn('pg_catalog.pg_db_role_setting',self.m.SQL)
        self.assertEqual(self.m.SQL.count('pg_catalog.left(rolname,3)'),2)
        self.assertEqual(self.m.settings_expected(self.fixture.record)['default_transaction_read_only'],'off')

    def test_all_database_owners_and_public_grants_are_bound(self):
        for field,value in (('owner','postgres'),('encoding','SQL_ASCII'),('limit',True),
                            ('allow',False),('template',True),('public_access',True)):
            reply=copy.deepcopy(self.fixture.reply);reply['databases'][3][field]=value
            with self.subTest(field=field),self.assertRaises(self.m.Pending):self.m.check(lambda *_:json.dumps(reply).encode())
        reply=copy.deepcopy(self.fixture.reply);reply['databases'][0]['name']='foreign'
        with self.assertRaises(self.m.Pending):self.m.check(lambda *_:json.dumps(reply).encode())

    def test_catalog_drift_and_duplicate_json_fields_refuse(self):
        calls=[]
        def read(*_):
            value=copy.deepcopy(self.fixture.reply);calls.append(1)
            if len(calls)==2:value['start']='new postmaster'
            return json.dumps(value).encode()
        with self.assertRaises(self.m.Pending):self.m.check(read)
        self.assertEqual(len(calls),2)
        raw=json.dumps(self.fixture.reply).encode().replace(b'{',b'{"version":170006,',1)
        with self.assertRaises(self.m.Pending):self.m.check(lambda *_:raw)

    def test_final_enrollment_configuration_and_context_changes_refuse(self):
        for change in ('enrollment','config','context'):
            count=[];original=self.m.ENROLLMENT.read_bytes();config=self.m.CONFIG/'pg_hba.conf';prior=config.read_bytes()
            def read(*_):
                count.append(1)
                if len(count)==2:
                    if change=='enrollment':self.m.ENROLLMENT.write_bytes(self.m.PREP.canonical({'schema':1,'system_identifier':5}))
                    elif change=='config':config.write_bytes(b'local all all trust\n')
                    else:self.m.KERNEL.namespace=lambda:4712
                return json.dumps(self.fixture.reply).encode()
            with self.subTest(change=change),self.assertRaises(self.m.Pending):self.m.check(read)
            self.m.ENROLLMENT.write_bytes(original);config.write_bytes(prior);self.m.KERNEL.namespace=lambda:4711

    def test_startup_identity_binds_executable_and_configuration_bytes(self):
        first=json.loads(self.m.startup());path=self.m.SERVER
        path.write_bytes(b'#!/bin/sh\nexit 1\n');second=json.loads(self.m.startup())
        self.assertNotEqual(first['executables'][str(path)],second['executables'][str(path)])
        path.chmod(0o600)
        with self.assertRaises(self.m.Pending):self.m.startup()

    def test_startup_whole_passwd_and_final_context_are_bound(self):
        before=json.loads(self.m.startup());path=self.m.PREP.PASSWD
        path.write_bytes(path.read_bytes().replace(b'PostgreSQL:/nonexistent:/bin/bash',b'PostgreSQL:/changed:/bin/bash'))
        after=json.loads(self.m.startup());self.assertNotEqual(before['account_source'],after['account_source'])
        original=self.m.enrollment;calls=[]
        def read(end):
            value=original(end);calls.append(1)
            if len(calls)==2:self.m.KERNEL.namespace=lambda:False
            return value
        with patch.object(self.m,'enrollment',side_effect=read),self.assertRaises(self.m.Pending):self.m.startup()
        self.assertEqual(len(calls),2)

    def test_native_warnings_nonzero_and_channel_overflow_withhold_receipt(self):
        for fault in ('native_warning','native_exit'):
            self.fixture.faults(**{fault:True})
            with self.subTest(fault=fault),self.assertRaises(self.m.Pending):self.m.check()
            self.fixture.faults(**{fault:False})
        self.fixture.faults(native_large=True)
        with self.assertRaises(self.m.Pending):self.m.check()

    def test_native_timeout_keeps_owned_session_cleanup_bounded(self):
        self.fixture.faults(sleep=True)
        # The private child records entry before sleeping. Clock DELIVERY waits
        # for that explicit handshake, then reports expiry; startup scheduling
        # does not determine whether the intended post-entry control is reached.
        original=self.m.KERNEL.now;end=original()+3
        def clock():
            if self.fixture.ledger.exists():return end+1
            return original()
        with patch.object(self.m.KERNEL,'now',side_effect=clock),self.assertRaises((self.m.Pending,subprocess.TimeoutExpired)):
            self.m.native('catalog',end)
        ledger=[json.loads(x) for x in self.fixture.ledger.read_text().splitlines()]
        self.assertEqual(len(ledger),1);self.assertEqual(ledger[0]['pid'],ledger[0]['sid'])

    def test_native_close_error_still_closes_other_pipe_without_retrying_retired_fd(self):
        original=self.m.subprocess.Popen;opened=[];closed=[];replacement=[]
        def create(*args,**kw):
            child=original(*args,**kw);opened.append(child)
            stdout=child.stdout;close=stdout.close;old=stdout.fileno();stderr_close=child.stderr.close
            def fail_close():
                closed.append(old);close()
                fd=os.open('/dev/null',os.O_RDONLY)
                if fd!=old:os.dup2(fd,old);os.close(fd);fd=old
                replacement.append(fd);self.assertEqual(fd,old)
                raise OSError('injected after descriptor retirement')
            stdout.close=fail_close
            def close_stderr():closed.append('stderr');stderr_close()
            child.stderr.close=close_stderr
            return child
        try:
            with patch.object(self.m.subprocess,'Popen',side_effect=create),self.assertRaises(OSError):
                self.m.native('catalog',self.m.KERNEL.now()+3)
            self.assertEqual(closed,[replacement[0],'stderr'])
            self.assertEqual(os.read(replacement[0],1),b'')
            self.assertIsNotNone(opened[0].returncode)
        finally:
            for fd in replacement:os.close(fd)

    def test_cli_retains_binary_sink_before_observation_and_checks_count(self):
        for sink in (None,object()):
            with patch.object(sys,'argv',['live.py','--check']),patch.object(sys,'stdout',sink),patch.object(sys,'stderr',io.StringIO()),patch.object(self.m,'check',side_effect=AssertionError('not admitted')):
                self.assertEqual(self.m.main(),75)
        class Output:
            def __init__(self,count):self.buffer=self;self.count=count;self.payload=None;self.flushed=False
            def write(self,value):self.payload=value;return self.count if self.count!='full' else len(value)
            def flush(self):self.flushed=True
        for count in (True,None,0,'full'):
            out=Output(count)
            with patch.object(sys,'argv',['live.py','--check']),patch.object(sys,'stdout',out),patch.object(sys,'stderr',io.StringIO()):
                self.assertEqual(self.m.main(),0 if count=='full' else 75)
            self.assertIs(type(out.payload),bytes);self.assertEqual(out.flushed,count=='full')


if __name__=='__main__':unittest.main()
