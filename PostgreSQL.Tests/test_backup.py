"""Protected private backup intentions; no dump, restore or archive is executed."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from fixture_pg import PrivatePG, ROOT


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivatePG(); self.addCleanup(self.fixture.close)
        context = self.fixture.context(); context.__enter__(); self.addCleanup(context.close)
        spec = importlib.util.spec_from_file_location('private_pg_backup', ROOT/'PostgreSQL/backup.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.ACCESS.LIVE = self.fixture.m; self.m.ACCESS.PREP = self.fixture.m.PREP
        self.m.ACCESS.KERNEL = self.fixture.m.KERNEL; self.m.ACCESS.Pending = self.fixture.m.Pending
        self.m.PREP = self.fixture.m.PREP; self.m.KERNEL = self.fixture.m.KERNEL
        self.m.Pending = self.fixture.m.Pending; self.m.INPUT = self.fixture.root/'etc/backup.json'
        self.value = {'schema':1, 'directory':'/srv/private-backups', 'generation':'a'*64,
            'archive_limit_bytes':1048576, 'inventory_limit_bytes':65536,
            'dump_timeout_seconds':120, 'lock_wait_ms':1000}
        self.publish(); self.calls = []

    def publish(self):
        self.fixture.write(self.m.INPUT, self.m.PREP.canonical(self.value))

    def peer(self, app):
        role = self.fixture.value['applications'][app]['role']
        return json.loads((self.fixture.root/('peer-'+role+'.json')).read_bytes())

    def read(self, kind, end):
        self.calls.append((kind,end))
        value = self.peer(kind[5:]) if kind.startswith('peer:') else self.fixture.reply
        return json.dumps(value).encode()

    def prepare(self, **kw):
        return self.m.prepare(**({'read':self.read}|kw))

    def test_complete_real_access_twice_binds_both_databases_and_original_intention(self):
        raw = self.prepare(); value = json.loads(raw)
        self.assertEqual(raw,self.m.PREP.canonical(value))
        self.assertEqual(value['state'],'postgresql-logical-backup-intention-only')
        self.assertEqual(value['namespace'],4711)
        self.assertEqual(value['source_intention'],self.fixture.record)
        self.assertEqual(value['enrollment']['value'],self.fixture.enrolled)
        self.assertEqual(set(value['jobs']),{'mk8.dns','mk8.email'})
        one = ['catalog','catalog','peer:mk8.dns','peer:mk8.email','peer:mk8.dns','peer:mk8.email','catalog','catalog']
        self.assertEqual([kind for kind,_ in self.calls],one*2)

    def test_dump_and_inspection_argv_have_fixed_tools_peer_identity_and_no_shell_or_restore_connection(self):
        result = json.loads(self.prepare())
        for app,job in result['jobs'].items():
            item = self.fixture.value['applications'][app]
            self.assertEqual(job['dump_argv'],['/usr/sbin/runuser','-u',item['role'],'--',
                '/usr/lib/postgresql/17/bin/pg_dump','--format=custom','--no-password',
                '--host',self.m.PREP.SOCKET_DIRECTORY,'--port','5432','--username',item['role'],
                '--dbname',item['database'],'--lock-wait-timeout=1000'])
            self.assertEqual(job['dump_environment'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
            self.assertEqual(job['inspection_argv'],['/usr/lib/postgresql/17/bin/pg_restore','--list',job['archive']])
            self.assertNotIn('--file',job['dump_argv']); self.assertNotIn('--dbname',job['inspection_argv'])
            self.assertEqual(job['archive'],self.value['directory']+'/'+self.value['generation']+'-'+app+'.dump')

    def test_no_backup_archive_directory_or_child_is_created_by_intention(self):
        before = sorted(str(p.relative_to(self.fixture.root)) for p in self.fixture.root.rglob('*'))
        with patch('subprocess.Popen',side_effect=AssertionError('backup child')):
            self.prepare()
        self.assertEqual(before,sorted(str(p.relative_to(self.fixture.root)) for p in self.fixture.root.rglob('*')))
        self.assertFalse(self.fixture.ledger.exists())

    def test_every_field_is_required_closed_and_schema_is_a_true_integer(self):
        for field in self.value:
            bad = copy.deepcopy(self.value); del bad[field]
            with self.subTest(field=field),self.assertRaises(ValueError):self.m.checked(bad)
        for bad in ({**self.value,'foreign':1},{**self.value,'schema':True},{**self.value,'schema':1.0},[],None):
            with self.subTest(kind=type(bad).__name__),self.assertRaises(ValueError):self.m.checked(bad)

    def test_directory_aliases_system_paths_unicode_and_injections_refuse(self):
        for path in ('/srv','/var/backups','/etc/x','/proc/x','/srv/../etc/x','/srv/./x','/srv//x',
                '/srv/x/','relative','/srv/with space','/srv/x\nExecStart=bad','/srv/é','/srv/$HOME',True):
            with self.subTest(path=path),self.assertRaises(ValueError):self.m.checked({**self.value,'directory':path})
        self.assertEqual(self.m.checked({**self.value,'directory':'/var/backups/explicit'})['directory'],'/var/backups/explicit')

    def test_public_generation_is_exact_nonzero_lower_hex_not_a_shell_argument(self):
        for generation in ('0'*64,'A'*64,'f'*63,'f'*65,'x'*64,'f'*63+'\n',True,None):
            with self.subTest(generation=generation),self.assertRaises(ValueError):self.m.checked({**self.value,'generation':generation})

    def test_each_explicit_resource_bound_rejects_boolean_float_missing_and_out_of_range(self):
        for field,low,high in (('archive_limit_bytes',1024,1<<40),('inventory_limit_bytes',1024,1<<26),
                ('dump_timeout_seconds',1,3600),('lock_wait_ms',1,60000)):
            for bad in (low-1,high+1,True,float(low),None,'1'):
                with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):self.m.checked({**self.value,field:bad})
            self.assertEqual(self.m.checked({**self.value,field:low})[field],low)
            self.assertEqual(self.m.checked({**self.value,field:high})[field],high)

    def test_missing_unsafe_or_nonprivate_configuration_precedes_native_entry(self):
        for mode in (0o644,0o666):
            self.m.INPUT.chmod(mode)
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.m.prepare(read=lambda *args:self.fail('native'))
        self.m.INPUT.chmod(0o600); self.m.INPUT.unlink()
        with self.assertRaises(OSError):self.m.prepare(read=lambda *args:self.fail('native'))

    def test_symbolic_and_multiple_link_configuration_refuse_before_native_entry(self):
        target = self.fixture.root/'etc/original'; self.m.INPUT.rename(target); self.m.INPUT.symlink_to(target)
        with self.assertRaises(ValueError):self.m.prepare(read=lambda *args:self.fail('native'))
        self.m.INPUT.unlink(); target.rename(self.m.INPUT)
        import os
        os.link(self.m.INPUT,target)
        with self.assertRaises(ValueError):self.m.prepare(read=lambda *args:self.fail('native'))

    def test_json_duplicate_nonfinite_float_noncanonical_and_oversized_inputs_refuse(self):
        good = self.m.PREP.canonical(self.value)
        raws = (b'{}\n',b'[]\n',b'\xff',good[:-1],b' '+good,
            good.replace(b'{',b'{"schema":1,',1),good.replace(b'1048576',b'NaN'),
            good.replace(b'1048576',b'1e999'),good.replace(b'1048576',b'1048576.0'),b'x'*(self.m.MAX_INPUT+1))
        for raw in raws:
            self.fixture.write(self.m.INPUT,raw)
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):self.m.prepare(read=lambda *args:self.fail('native'))

    def test_real_admin_and_either_peer_refusal_prevents_backup_intention(self):
        for selected in ('catalog','peer:mk8.dns','peer:mk8.email'):
            def read(kind,end):
                raw=self.read(kind,end)
                if kind==selected:
                    value=json.loads(raw)
                    if kind=='catalog':value['roles'][1]['super']=True
                    else:value['authentication']='trust'
                    return json.dumps(value).encode()
                return raw
            with self.subTest(kind=selected),self.assertRaises(ValueError):self.m.prepare(read=read)

    def test_second_complete_access_may_not_change_to_another_admitted_schema_owner(self):
        count=[]
        def read(kind,end):
            raw=self.read(kind,end);count.append(kind)
            if len(count)>8 and kind=='peer:mk8.dns':
                value=json.loads(raw);value['schema_access']['owner']='dns_demo';return json.dumps(value).encode()
            return raw
        with self.assertRaisesRegex(ValueError,'access source changed'):self.m.prepare(read=read)
        self.assertEqual(len(count),16)

    def test_encoding_precedes_second_configuration_access_and_final_original_intention(self):
        real=self.m.PREP.canonical;configuration=self.m.configuration;intention=self.m.ACCESS.LIVE.intention;events=[]
        def encode(value):
            raw=real(value)
            if type(value) is dict and value.get('state')=='postgresql-logical-backup-intention-only':events.append('backup')
            return raw
        def config(end):
            if events:events.append('configuration')
            return configuration(end)
        def original(end):
            if events:events.append('intention')
            return intention(end)
        with patch.object(self.m.PREP,'canonical',side_effect=encode),patch.object(self.m,'configuration',side_effect=config), \
                patch.object(self.m.ACCESS.LIVE,'intention',side_effect=original):self.prepare()
        self.assertEqual(events[0:2],['backup','configuration']);self.assertEqual(events[-1],'intention')

    def test_configuration_drift_after_encoding_cannot_return_prepared_bytes(self):
        real=self.m.PREP.canonical
        def encode(value):
            raw=real(value)
            if type(value) is dict and value.get('state')=='postgresql-logical-backup-intention-only':
                self.value['generation']='b'*64;self.publish()
            return raw
        with patch.object(self.m.PREP,'canonical',side_effect=encode),self.assertRaisesRegex(ValueError,'configuration changed'):self.prepare()

    def test_output_bound_refuses_before_any_second_access_attempt(self):
        with patch.object(self.m,'MAX_OUTPUT',1),self.assertRaisesRegex(ValueError,'intention exceeds'):self.prepare()
        self.assertEqual(len(self.calls),8)

    def test_invalid_window_callable_and_typed_context_refuse_before_input_or_native(self):
        for deadline in (True,'later',float('nan'),float('inf'),self.m.KERNEL.now()-1,10**10000):
            with self.subTest(kind=type(deadline).__name__),self.assertRaises(ValueError):self.prepare(deadline=deadline)
        for namespace in (0,True,-1,1<<64,'1'):
            with patch.object(self.m.KERNEL,'namespace',return_value=namespace),self.assertRaises(ValueError):self.prepare()
        with self.assertRaises(ValueError):self.m.prepare(read=False)

    def test_positive_parent_cap_is_retained_by_all_sixteen_deliveries(self):
        start=self.m.KERNEL.now();end=start+2
        with patch.object(self.m.KERNEL,'now',return_value=start):self.prepare(deadline=end)
        self.assertEqual({window for _,window in self.calls},{end})

    def test_expiry_during_first_and_second_access_withholds_intention(self):
        for position in (1,16):
            start=self.m.KERNEL.now();clock=[start];count=[]
            def read(kind,end):
                raw=self.read(kind,end);count.append(kind)
                if len(count)==position:clock[0]=start+61
                return raw
            with self.subTest(position=position),patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]),self.assertRaises(ValueError):self.m.prepare(read=read)
            self.assertEqual(len(count),position)

    def test_final_typed_context_and_clock_drift_after_encoding_refuse(self):
        for change in ('scope','clock'):
            start=self.m.KERNEL.now();clock=[start];scope=[4711];real=self.m.PREP.canonical
            def encode(value):
                raw=real(value)
                if type(value) is dict and value.get('state')=='postgresql-logical-backup-intention-only':
                    if change=='scope':scope[0]=True
                    else:clock[0]=start+61
                return raw
            with self.subTest(change=change),patch.object(self.m.PREP,'canonical',side_effect=encode), \
                    patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]), \
                    patch.object(self.m.KERNEL,'namespace',side_effect=lambda:scope[0]),self.assertRaises(ValueError):self.prepare()

    def test_real_private_native_access_captures_are_not_backup_children(self):
        value=json.loads(self.m.prepare())
        rows=[json.loads(line) for line in self.fixture.ledger.read_text().splitlines()]
        self.assertEqual(len(rows),16);self.assertEqual(value['access']['applications']['mk8.dns'],self.peer('mk8.dns'))
        for row in rows:
            self.assertEqual(row['pid'],row['sid']);self.assertEqual(row['environment'],{'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
            self.assertNotIn('pg_dump',row['argv']);self.assertNotIn('pg_restore',row['argv'])

    def test_cli_extra_arguments_and_missing_binary_sink_precede_preparation(self):
        for argv in (['backup.py'],['backup.py','--prepare','extra'],['backup.py','--dump']):
            with patch.object(sys,'argv',argv),patch.object(sys,'stderr',io.StringIO()), \
                    patch.object(self.m,'prepare',side_effect=AssertionError('entry')):self.assertEqual(self.m.main(),75)
        for stdout in (None,object(),io.StringIO()):
            with patch.object(sys,'argv',['backup.py','--prepare']),patch.object(sys,'stdout',stdout), \
                    patch.object(sys,'stderr',io.StringIO()),patch.object(self.m,'prepare',side_effect=AssertionError('entry')):
                self.assertEqual(self.m.main(),75)

    def test_cli_retains_same_immutable_payload_requires_true_full_write_and_flush(self):
        raw=self.prepare()
        class Sink:
            def __init__(self,count):self.buffer=self;self.count=count;self.raw=None;self.flushed=False
            def write(self,data):self.raw=data;return len(data) if self.count=='full' else self.count
            def flush(self):self.flushed=True
        for count in ('full',True,0,None):
            sink=Sink(count)
            with patch.object(sys,'argv',['backup.py','--prepare']),patch.object(sys,'stdout',sink), \
                    patch.object(sys,'stderr',io.StringIO()),patch.object(self.m,'prepare',return_value=raw):
                self.assertEqual(self.m.main(),0 if count=='full' else 75)
            self.assertIs(sink.raw,raw);self.assertEqual(sink.flushed,count=='full')

    def test_actual_final_fences_refuse_change_after_last_real_protected_intention(self):
        for change in ('scope','clock'):
            start=self.m.KERNEL.now();clock=[start];scope=[4711];outer=[];real=self.m.ACCESS.LIVE.intention
            def intention(end):
                value=real(end)
                if end==start+self.m.ATTEMPT_SECONDS:
                    outer.append(end)
                    if len(outer)==2:
                        if change=='scope':scope[0]=True
                        else:clock[0]=end
                return value
            self.calls=[]
            with self.subTest(change=change),patch.object(self.m.ACCESS.LIVE,'intention',side_effect=intention), \
                    patch.object(self.m.KERNEL,'now',side_effect=lambda:clock[0]), \
                    patch.object(self.m.KERNEL,'namespace',side_effect=lambda:scope[0]),self.assertRaises(ValueError):self.prepare()
            self.assertEqual(len(outer),2);self.assertEqual(len(self.calls),16)


if __name__=='__main__':unittest.main()
