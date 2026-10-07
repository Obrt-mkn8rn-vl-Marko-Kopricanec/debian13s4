import contextlib
import copy
import importlib.util
import io
import json
import os
import signal
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_tc', ROOT / 'Firewall/tc.py')
TC = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(TC)
KERNEL = TC.KERNEL


def link_rows():
    return [{'ifindex':1,'ifname':'lo','flags':['LOOPBACK','UP','LOWER_UP'],'qdisc':'noqueue','link_type':'loopback'},
            {'ifindex':2,'ifname':'eth0','flags':['BROADCAST','UP','LOWER_UP'],'qdisc':'noqueue','link_type':'ether'}]


def message():
    return [{'kind':'noqueue','handle':'0:','dev':name,'root':True,'refcnt':2,'options':{}} for name in ('lo','eth0')]


class PrivateNative(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-tc-', dir='/dev/shm');self.root = Path(self.directory.name);self.binary = self.root / 'tc';self.ledger = self.root / 'ledger'
        self.settings = [patch.object(TC, 'BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def executable(self, body):
        self.binary.write_text('#!/usr/bin/python3 -B\n' + body + '\n');self.binary.chmod(0o700)

    def query(self):return TC.native_query(KERNEL.now() + 10)


class NativeTests(PrivateNative):
    def test_fixed_read_only_argv_clears_environment_closes_inherited_descriptors(self):
        fd = os.open(self.root / 'fd', os.O_CREAT | os.O_WRONLY, 0o600);os.set_inheritable(fd, True)
        self.executable(f"import json,os,sys\ntry:\n os.fstat({fd});leaked=True\nexcept OSError:\n leaked=False\nopen({str(self.ledger)!r},'w').write(json.dumps([sys.argv[1:],dict(os.environ),leaked]))\nprint({json.dumps(message())!r})")
        try:
            with patch.dict(os.environ, {'TC_LIB_DIR': 'bad', 'LD_PRELOAD': 'bad', 'TASK_SECRET': 'bad'}):self.assertEqual(self.query(), message())
            args, environment, leaked = json.loads(self.ledger.read_text());self.assertEqual(args, list(TC.COMMAND));self.assertFalse(leaked);self.assertFalse(set(environment)&{'TC_LIB_DIR','LD_PRELOAD','TASK_SECRET'})
        finally:os.close(fd)

    def test_invalid_deadline_and_unavailable_binary_do_not_execute(self):
        self.executable(f"open({str(self.ledger)!r},'w').write('unexpected')")
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(TC.Pending):TC.native_query(deadline)
        self.assertFalse(self.ledger.exists());self.binary.unlink()
        with self.assertRaises(FileNotFoundError):self.query()

    def test_nonzero_stderr_invalid_utf8_duplicate_json_and_truncation_are_failures(self):
        for body in ('raise SystemExit(1)', f"import sys;print({json.dumps(message())!r});print('warning',file=sys.stderr)",
                     "import os;os.write(1,b'\\xff')", "print('{\"qdiscs\":[],\"qdiscs\":[]}')", "print('{')"):
            self.executable(body)
            with self.subTest(body=body), self.assertRaises(TC.Pending):self.query()

    def test_each_channel_has_an_independent_checked_limit(self):
        for channel in (1, 2):
            self.executable(f"import os;os.write({channel},b'x'*{TC.MAX_BYTES + 1})")
            with self.subTest(channel=channel), self.assertRaises(TC.Pending):self.query()

    def test_pipe_eof_does_not_count_as_native_root_completion(self):
        self.executable('import os,time\nos.close(1);os.close(2);time.sleep(60)')
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.1), self.assertRaises(TC.Pending):self.query()

    def test_unreaped_leader_child_holding_capture_is_killed_in_its_owned_group(self):
        marker = self.root / 'child'
        self.executable(f"import json,os,time\npid=os.fork()\nif pid:\n fields=open('/proc/'+str(pid)+'/stat').read().rsplit(')',1)[1].split()\n open({str(marker)!r},'w').write(json.dumps({{'pid':pid,'start':fields[19],'group':os.getpgid(pid),'session':os.getsid(pid)}}))\n print({json.dumps(message())!r},flush=True)\n os._exit(0)\ntime.sleep(60)")
        signals = [];killpg = TC.os.killpg
        def recorded(group, value):signals.append((group,value));return killpg(group,value)
        try:
            with patch.object(TC.os, 'killpg', side_effect=recorded), self.assertRaises(TC.Pending):self.query()
            self.assertTrue(marker.exists());owned = json.loads(marker.read_text())
            self.assertEqual(owned['group'], owned['session']);self.assertIn((owned['group'], signal.SIGKILL), signals)
            for _ in range(100):
                try:
                    fields=Path('/proc/'+str(owned['pid'])+'/stat').read_text().rsplit(')',1)[1].split()
                except FileNotFoundError:break
                if fields[19]!=owned['start'] or fields[0]=='Z':break
                time.sleep(0.01)
            else:self.fail('owned child stayed live after captured group termination')
        finally:
            if marker.exists():
                owned = json.loads(marker.read_text())
                try:
                    entry=Path('/proc/'+str(owned['pid']));fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
                    if entry.stat().st_uid==os.geteuid() and fields[19]==owned['start'] and fields[0]!='Z' and int(fields[2])==owned['group'] and int(fields[3])==owned['session']:os.kill(owned['pid'], signal.SIGKILL)
                except (FileNotFoundError,ProcessLookupError):pass

    def test_symbolic_wrong_kind_owner_and_writable_path_refuse_before_execution(self):
        self.executable(f"open({str(self.ledger)!r},'w').write('unexpected')")
        with patch.object(KERNEL, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(TC.Pending):self.query()
        self.binary.chmod(0o720)
        with self.assertRaises(TC.Pending):self.query()
        self.binary.chmod(0o700);original = self.root / 'original';self.binary.rename(original);self.binary.symlink_to(original)
        with self.assertRaises(TC.Pending):self.query()
        self.binary.unlink();os.mkfifo(self.binary)
        with self.assertRaises(TC.Pending):self.query()
        self.assertFalse(self.ledger.exists())

    def test_native_binary_replacement_after_capture_cannot_certify_a_read(self):
        self.executable(f"from pathlib import Path\nPath({str(self.binary)!r}).write_text('replaced')\nprint({json.dumps(message())!r})")
        with self.assertRaisesRegex(TC.Pending, 'binary changed'):self.query()

    def test_real_private_complete_noqueue_observation_is_positive(self):
        self.executable(f"print({json.dumps(message())!r})")
        result = TC.observe(links=lambda name, deadline: link_rows());self.assertEqual(result['profile'], 'all-links-zero-handle-noqueue-only-1');self.assertEqual(result['source']['tc'], str(self.binary))

    def test_real_private_clsact_or_warning_cli_has_no_healthy_stdout(self):
        foreign = message();foreign.append({'kind':'clsact','handle':'ffff:','dev':'eth0','parent':'ffff:fff1','options':{}})
        real_observe = TC.observe
        for body in (f"print({json.dumps(foreign)!r})", f"import sys;print({json.dumps(message())!r});print('warning',file=sys.stderr)"):
            self.executable(body);out, err = io.StringIO(), io.StringIO()
            with self.subTest(body=body), patch.object(TC.sys, 'argv', ['tc.py']), patch.object(TC, 'observe', side_effect=lambda: real_observe(links=lambda name, deadline:link_rows())), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(TC.main(), 75)
            self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())

    def test_cli_success_and_argument_refusal_use_only_fixed_native_read(self):
        self.executable(f"print({json.dumps(message())!r})");out = io.StringIO();real_observe = TC.observe
        with patch.object(TC.sys, 'argv', ['tc.py']), patch.object(TC, 'observe', side_effect=lambda: real_observe(links=lambda name, deadline:link_rows())), contextlib.redirect_stdout(out):self.assertEqual(TC.main(), 0)
        self.assertEqual(json.loads(out.getvalue())['profile'], 'all-links-zero-handle-noqueue-only-1')
        out = io.StringIO()
        with patch.object(TC.sys, 'argv', ['tc.py', 'flush']), contextlib.redirect_stdout(out):self.assertEqual(TC.main(), 64)
        self.assertEqual(out.getvalue(), '')

    def test_no_caller_operator_interface_or_input_profile_can_execute(self):
        self.executable(f"open({str(self.ledger)!r},'w').write('unexpected')")
        for extra in (('replace',), ('dev','eth0'), ('-batch','file')):
            with self.subTest(extra=extra), self.assertRaises(TypeError):TC.native_query(KERNEL.now()+10, *extra)
        self.assertFalse(self.ledger.exists())

    def test_zero_exit_after_completion_deadline_refuses_before_json_use(self):
        self.executable(f"print({json.dumps(message())!r})");clock = [KERNEL.now()];start = clock[0]
        native = TC.subprocess.Popen
        def delayed(*args, **kwargs):
            process = native(*args, **kwargs);wait = process.wait
            def complete(*args, **kwargs):
                result = wait(*args, **kwargs);clock[0] = start + KERNEL.QUERY_SECONDS + 1;return result
            process.wait = complete
            return process
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), patch.object(TC.subprocess, 'Popen', side_effect=delayed), \
                self.assertRaisesRegex(TC.Pending, 'completed after'):TC.native_query(start + 10)


class ProfileTests(unittest.TestCase):
    def test_numeric_and_mixed_native_link_types_preserve_original_private_rows(self):
        for loopback,ethernet in (('[772]','[1]'),('loopback','[1]'),('[772]','ether')):
            value = link_rows();value[0]['link_type'] = loopback;value[1]['link_type'] = ethernet
            original = copy.deepcopy(value)
            with self.subTest(loopback=loopback, ethernet=ethernet):
                result = TC.link_inventory(value)
                self.assertEqual(result, original)
                self.assertEqual(len(TC.noqueue_roots(message(), result)), 2)
                value[1]['ifindex'] += 1
                self.assertEqual(result, original)

    def test_unknown_numeric_wrong_kind_and_numeric_loopback_consistency_refuse(self):
        for index,bad in ((0,'[1]'),(1,'[772]'),(0,'[0]'),(1,'[9999]'),(1,'[01]'),(1,'[1 ]'),
                          (1,1),(0,772),(1,None),(1,True)):
            value = link_rows();value[0]['link_type'] = '[772]';value[1]['link_type'] = '[1]';value[index]['link_type'] = bad
            with self.subTest(index=index,bad=bad), self.assertRaises(TC.Pending):TC.link_inventory(value)
        for index,flags in ((0,['UP','LOWER_UP']),(1,['LOOPBACK','UP','LOWER_UP'])):
            value = link_rows();value[0]['link_type'] = '[772]';value[1]['link_type'] = '[1]';value[index]['flags'] = flags
            with self.subTest(index=index,flags=flags), self.assertRaises(TC.Pending):TC.link_inventory(value)

    def test_complete_noqueue_roots_include_loopback_and_are_privately_copied(self):
        links = link_rows();qdiscs = message();before = TC.link_inventory(links)
        result = TC.noqueue_roots(qdiscs, before);links[1]['ifindex'] = 99;qdiscs[1]['refcnt'] = 3
        self.assertEqual(before[1]['ifindex'], 2);self.assertEqual(result[1]['refcnt'], 2)

    def test_empty_or_missing_link_and_qdisc_rows_never_prove_positive_absence(self):
        for value in (None, [], {}, [None], link_rows()[:1]):
            with self.subTest(value=value):
                if value == link_rows()[:1]:
                    with self.assertRaises(TC.Pending):TC.noqueue_roots(message(), TC.link_inventory(value))
                else:
                    with self.assertRaises(TC.Pending):TC.link_inventory(value)
        for value in (None, [], {}, [None], message()[:1]):
            with self.subTest(value=value), self.assertRaises(TC.Pending):TC.noqueue_roots(value, link_rows())

    def test_each_required_link_and_qdisc_field_is_positive_not_defaulted(self):
        for key in link_rows()[0]:
            value = link_rows();del value[0][key]
            with self.subTest(kind='link', key=key), self.assertRaises(TC.Pending):TC.link_inventory(value)
        for key in ('kind','handle','dev','root','options'):
            value = message();del value[0][key]
            with self.subTest(kind='qdisc', key=key), self.assertRaises(TC.Pending):TC.noqueue_roots(value, link_rows())

    def test_duplicate_names_indexes_qdiscs_and_unknown_devices_refuse(self):
        for field,bad in (('ifname','lo'),('ifindex',1),('ifindex',True),('ifindex',0),('ifname','eth 0')):
            value = link_rows();value[1][field] = bad
            with self.subTest(field=field), self.assertRaises(TC.Pending):TC.link_inventory(value)
        for value in (message()+[message()[0]], message()+[message()[0]|{'dev':'foreign'}]):
            with self.subTest(value=value), self.assertRaises(TC.Pending):TC.noqueue_roots(value, link_rows())

    def test_loopback_type_flags_and_link_queue_disagreement_refuse(self):
        for index,field,bad in ((0,'link_type','ether'),(0,'flags',['UP','LOWER_UP']),(1,'link_type','loopback'),
                                (1,'flags',['LOOPBACK','UP']),(1,'flags',['UNKNOWN']),(1,'qdisc','fq_codel')):
            value = link_rows();value[index][field] = bad
            with self.subTest(field=field), self.assertRaises(TC.Pending):TC.link_inventory(value)

    def test_common_schedulers_with_possible_classifiers_are_never_whitelisted(self):
        for kind in ('fq_codel','fq','mq','pfifo_fast','htb','tbf','netem','cake','prio','bpf','unknown','noop'):
            value = message();value[1]['kind'] = kind
            with self.subTest(kind=kind), self.assertRaises(TC.Pending):TC.noqueue_roots(value, link_rows())

    def test_ingress_clsact_child_shared_blocks_offload_and_unknown_state_refuse(self):
        for kind in ('ingress','clsact'):
            value = message()+[{'kind':kind,'handle':'ffff:','dev':'eth0','parent':'ffff:fff1','options':{}}]
            with self.subTest(kind=kind), self.assertRaises(TC.Pending):TC.noqueue_roots(value, link_rows())
        for key,bad in (('parent','1:1'),('ingress_block',1),('egress_block',1),('offloaded',True),
                         ('deleted',True),('added',True),('replaced',True),('unknown',{})):
            value = message();value[1][key] = bad
            with self.subTest(key=key), self.assertRaises(TC.Pending):TC.noqueue_roots(value, link_rows())

    def test_nonzero_handle_boolean_root_options_and_reference_types_refuse(self):
        for key,bad in (('handle','1:'),('handle',0),('root',False),('root',1),('options',[]),
                         ('options',{'unknown':1}),('refcnt',True),('refcnt',0),('refcnt',-1)):
            value = message();value[1][key] = bad
            with self.subTest(key=key), self.assertRaises(TC.Pending):TC.noqueue_roots(value, link_rows())
        value = message();del value[1]['refcnt']
        self.assertEqual(len(TC.noqueue_roots(value, link_rows())), 2)

    def test_unknown_link_attributes_and_excessive_inventory_refuse(self):
        value = link_rows();value[1]['xdp'] = {}
        with self.assertRaises(TC.Pending):TC.link_inventory(value)
        with self.assertRaises(TC.Pending):TC.link_inventory(link_rows() * KERNEL.MAX_LINKS)
        with self.assertRaises(TC.Pending):TC.noqueue_roots(message() * KERNEL.MAX_ITEMS, link_rows())

    def test_snapshot_encoding_structure_scalar_size_and_private_copy_are_checked(self):
        data = {'value':[1,None,True,'name']};result = TC.snapshot(data);data['value'][0] = 2
        self.assertEqual(result['value'][0], 1)
        cycle = [];cycle.append(cycle)
        for bad in (cycle, {'bad':float('nan')}, {1:'key'}, {'bad':'\ud800'}, {'bad':'\x00'},
                     {'bad':'x'*(TC.MAX_BYTES+1)}, {'bad':[None]*(TC.MAX_NODES+1)}):
            with self.subTest(type=type(bad).__name__), self.assertRaises(TC.Pending):TC.snapshot(bad)


class ObservationTests(unittest.TestCase):
    def observe(self, **overrides):
        values = {'query': lambda deadline:message(), 'links': lambda name,deadline:link_rows()}
        values.update(overrides);return TC.observe(**values)

    def test_two_complete_unfiltered_deliveries_share_one_window_namespace_and_fixed_link_query(self):
        calls = []
        result = self.observe(query=lambda deadline:calls.append(('tc',deadline)) or message(),
                              links=lambda name,deadline:calls.append((name,deadline)) or link_rows())
        self.assertEqual([name for name,_ in calls], ['links','tc']*2);self.assertEqual(len({d for _,d in calls}), 1)
        self.assertEqual(result['namespace'], KERNEL.namespace());self.assertEqual(result['source']['tc'], str(TC.BINARY))
        self.assertNotIn('empty', result);self.assertEqual(result['profile'], 'all-links-zero-handle-noqueue-only-1')

    def test_invalid_and_inherited_deadlines_do_not_execute_or_widen(self):
        for value in (True,'future',float('nan'),float('inf'),KERNEL.now()-1,10**10000):
            with self.subTest(type=type(value).__name__), self.assertRaises(TC.Pending):
                self.observe(deadline=value, scope=lambda:self.fail('scope'), query=lambda deadline:self.fail('query'))
        start = KERNEL.now()
        for budget in (5,1000):
            seen = []
            with patch.object(KERNEL, 'now', return_value=start):
                self.observe(deadline=start+budget, query=lambda deadline:seen.append(deadline) or message())
            self.assertEqual(seen, [start+min(budget,TC.ATTEMPT_SECONDS)]*2)

    def test_namespace_type_and_initial_final_change_refuse(self):
        for value in (0,True,'1',None):
            with self.subTest(value=value), self.assertRaises(TC.Pending):self.observe(scope=lambda:value)
        for value in (2,True,'1',None):
            scopes = iter([1,value])
            with self.subTest(value=value), self.assertRaises(TC.Pending):self.observe(scope=lambda:next(scopes))

    def test_changed_complete_link_or_reference_inventory_cannot_publish(self):
        for kind in ('links','tc'):
            seen = []
            def changed(deadline):
                seen.append(deadline);value = link_rows() if kind=='links' else message()
                if len(seen)==2:
                    if kind=='links':value[1]['ifindex'] += 1
                    else:value[1]['refcnt'] += 1
                return value
            with self.subTest(kind=kind), self.assertRaisesRegex(TC.Pending, 'changed'):
                self.observe(**({'links':lambda name,deadline:changed(deadline)} if kind=='links' else {'query':changed}))

    def test_mutation_after_the_first_link_snapshot_cannot_change_its_admission(self):
        links = link_rows();seen = []
        def read(deadline):
            seen.append(deadline)
            if len(seen)==1:links[1]['ifindex'] = 3
            return message()
        with self.assertRaisesRegex(TC.Pending, 'changed'):self.observe(links=lambda name,deadline:links, query=read)

    def test_expired_delivery_and_scope_cannot_publish_or_admit_next_query(self):
        start = KERNEL.now();clock = [start];calls = []
        def links(name,deadline):clock[0] = deadline;return link_rows()
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(TC.Pending):
            self.observe(links=links, query=lambda deadline:self.fail('expired links admitted tc'))
        clock[0] = start
        def query(deadline):clock[0] = deadline;calls.append(deadline);return message()
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(TC.Pending):self.observe(query=query)
        self.assertEqual(len(calls), 1)

    def test_failed_query_or_second_incomplete_inventory_is_not_absence(self):
        def failed(deadline):raise OSError('fixture')
        with self.assertRaises(OSError):self.observe(query=failed)
        turns = iter([message(),[]])
        with self.assertRaises(TC.Pending):self.observe(query=lambda deadline:next(turns))


class CompleteNativeTests(PrivateNative):
    def test_complete_numeric_fixed_ip_tc_capture_and_cli_preserve_raw_types(self):
        ip = self.root / 'ip';rows = link_rows();rows[0]['link_type'] = '[772]';rows[1]['link_type'] = '[1]'
        ip.write_text('#!/usr/bin/python3 -B\nimport json,os,sys\nassert sys.argv[1:]=='+repr(['-j','-N',*KERNEL.COMMANDS['links']])+
                      '\nwith open('+repr(str(self.ledger))+',"a") as f:f.write(json.dumps(["ip",sys.argv[1:],dict(os.environ)])+"\\n")'+
                      '\nprint('+repr(json.dumps(rows))+')\n');ip.chmod(0o700)
        self.executable(f"import json,os,sys\nassert sys.argv[1:]=={list(TC.COMMAND)!r}\nwith open({str(self.ledger)!r},'a') as f:f.write(json.dumps(['tc',sys.argv[1:],dict(os.environ)])+'\\n')\nprint({json.dumps(message())!r})")
        out,err = io.StringIO(),io.StringIO()
        with patch.object(KERNEL, 'IP_BINARY', ip), patch.object(TC.sys, 'argv', ['tc.py']), \
                patch.dict(os.environ, {'IP_LIB_DIR':'bad','TC_LIB_DIR':'bad','NUMERIC_SECRET':'bad'}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):status = TC.main()
        self.assertEqual(status, 0, err.getvalue());self.assertEqual(err.getvalue(), '')
        value = json.loads(out.getvalue());self.assertEqual(value['links'], rows)
        self.assertEqual(value['source'], {'tc':str(self.binary),'ip':str(ip)})
        self.assertEqual(len(value['qdiscs']), 2)
        ledger = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual([name for name,_,_ in ledger], ['ip','tc']*2)
        for name,args,environment in ledger:
            self.assertEqual(args, ['-j','-N',*KERNEL.COMMANDS['links']] if name=='ip' else list(TC.COMMAND))
            self.assertFalse(set(environment)&{'IP_LIB_DIR','TC_LIB_DIR','NUMERIC_SECRET'})

    def test_complete_numeric_unknown_and_wrong_kind_cli_refuses_before_tc_query(self):
        ip = self.root / 'ip'
        for index,bad in ((0,'[1]'),(1,'[772]'),(1,'[9999]'),(1,'[01]')):
            rows = link_rows();rows[0]['link_type'] = '[772]';rows[1]['link_type'] = '[1]';rows[index]['link_type'] = bad
            ip.write_text('#!/usr/bin/python3 -B\nimport sys\nassert sys.argv[1:]=='+repr(['-j','-N',*KERNEL.COMMANDS['links']])+
                          '\nprint('+repr(json.dumps(rows))+')\n');ip.chmod(0o700)
            self.executable(f"open({str(self.ledger)!r},'w').write('unexpected tc query')\nraise SystemExit(1)")
            out,err = io.StringIO(),io.StringIO()
            with self.subTest(index=index,bad=bad), patch.object(KERNEL, 'IP_BINARY', ip), patch.object(TC.sys, 'argv', ['tc.py']), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(TC.main(), 75)
            self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue());self.assertFalse(self.ledger.exists())

    def test_real_private_ip_tc_capture_parser_binding_and_cli_path_is_positive(self):
        ip = self.root / 'ip';data = json.dumps(link_rows())
        ip.write_text('#!/usr/bin/python3 -B\nimport json,os,sys\nassert sys.argv[1:]=='+repr(['-j','-N',*KERNEL.COMMANDS['links']])+
                      '\nprint('+repr(data)+')\n');ip.chmod(0o700)
        self.executable(f"import json,os,sys\nassert sys.argv[1:]=={list(TC.COMMAND)!r}\nprint({json.dumps(message())!r})")
        out = io.StringIO()
        with patch.object(KERNEL, 'IP_BINARY', ip), patch.object(TC.sys, 'argv', ['tc.py']), contextlib.redirect_stdout(out):
            self.assertEqual(TC.main(), 0)
        value = json.loads(out.getvalue());self.assertEqual(value['source'], {'tc':str(self.binary),'ip':str(ip)})
        self.assertEqual(len(value['links']), 2);self.assertEqual(len(value['qdiscs']), 2)


if __name__ == '__main__':unittest.main()
