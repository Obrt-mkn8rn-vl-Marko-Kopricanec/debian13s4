import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_classifiers', ROOT / 'Firewall/classifiers.py')
CLASSIFIERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLASSIFIERS)
KERNEL = CLASSIFIERS.KERNEL


def links():
    return [{'ifindex': 1, 'ifname': 'lo', 'flags': ['LOOPBACK', 'UP', 'LOWER_UP'], 'qdisc': 'noqueue', 'link_type': '[772]'},
            {'ifindex': 2, 'ifname': 'eth0', 'flags': ['BROADCAST', 'UP', 'LOWER_UP'], 'qdisc': 'fq_codel', 'link_type': '[1]'}]


def options():
    return {'limit': 10240, 'flows': 1024, 'quantum': 1514, 'target': 4999, 'interval': 99999,
            'memory_limit': 33554432, 'ecn': True, 'drop_batch': 64}


def roots():
    return [{'kind': 'noqueue', 'handle': '0:', 'dev': 'lo', 'root': True, 'refcnt': 2, 'options': {}},
            {'kind': 'fq_codel', 'handle': '0:', 'dev': 'eth0', 'root': True, 'refcnt': 2, 'options': options()}]


class ProfileTests(unittest.TestCase):
    def test_numeric_and_textual_link_kinds_preserve_full_private_rows(self):
        for lo, ether in (('[772]', '[1]'), ('loopback', 'ether'), ('[772]', 'ether')):
            value = links();value[0]['link_type'] = lo;value[1]['link_type'] = ether
            value[1]['mtu'] = 1500;original = copy.deepcopy(value)
            with self.subTest(lo=lo, ether=ether):
                result = CLASSIFIERS.link_inventory(value)
                value[1]['ifindex'] += 1
                self.assertEqual(result, original)

    def test_noqueue_down_and_ethernet_fq_codel_links_are_supported(self):
        value = links();value[1]['flags'] = ['BROADCAST'];value.append(dict(value[1], ifindex=7, ifname='2', qdisc='noqueue'))
        self.assertEqual(CLASSIFIERS.link_inventory(value), value)

    def test_unknown_wrong_numeric_kind_loopback_and_flags_refuse(self):
        for index, key, value in ((0, 'link_type', '[1]'), (1, 'link_type', '[772]'), (1, 'link_type', '[01]'),
                                  (1, 'link_type', '[9999]'), (1, 'link_type', 1), (0, 'qdisc', 'fq_codel'),
                                  (0, 'flags', ['UP']), (1, 'flags', ['UP', 'LOOPBACK']), (1, 'flags', ['UNKNOWN'])):
            rows = links();rows[index][key] = value
            with self.subTest(index=index, key=key, value=value), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.link_inventory(rows)

    def test_all_links_including_loopback_and_unique_names_indexes_are_required(self):
        cases = [[], links()[1:], links() + [links()[1]], links() + [dict(links()[1], ifname='other')],
                 links() + [dict(links()[1], ifindex=3)], links() * (KERNEL.MAX_LINKS + 1)]
        for rows in cases:
            with self.subTest(rows=len(rows)), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.link_inventory(rows)
        for key, value in (('ifname', '../eth0'), ('ifname', '-batch'), ('ifname', 'a' * 16), ('ifindex', True), ('ifindex', 0),
                           ('qdisc', 'mq'), ('xdp', {}), ('ingress_block', 1)):
            rows = links();rows[1][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.link_inventory(rows)

    def test_noqueue_and_fq_codel_root_identity_options_remain_private(self):
        value = roots();result = CLASSIFIERS.root_inventory(value, CLASSIFIERS.link_inventory(links()))
        value[1]['options']['limit'] += 1
        self.assertEqual(result, roots())
        for handle in ('0:', '1:', '8001:', 'fffe:'):
            value = roots();value[1]['handle'] = handle
            with self.subTest(handle=handle):self.assertEqual(CLASSIFIERS.root_inventory(value, links()), value)

    def test_missing_foreign_duplicate_child_and_unsupported_roots_refuse(self):
        for rows in ([], roots()[:1], roots() + [roots()[1]], roots() + [dict(roots()[1], dev='foreign')],
                     roots() + [{'kind': 'clsact', 'handle': 'ffff:', 'dev': 'eth0', 'parent': 'ffff:fff1', 'options': {}}]):
            with self.subTest(rows=rows), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.root_inventory(rows, links())
        for key, value in (('root', False), ('root', 1), ('kind', 'mq'), ('kind', 'noqueue'), ('parent', '1:1'),
                           ('ingress_block', 1), ('egress_block', 1), ('offloaded', True), ('stats', {}), ('refcnt', 0), ('refcnt', True)):
            rows = roots();rows[1][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.root_inventory(rows, links())

    def test_noncanonical_reserved_and_noqueue_nonzero_handles_refuse(self):
        for handle in ('ffff:', '01:', 'A:', '1:1', '0x1:', '', 0, True, '10000:'):
            rows = roots();rows[1]['handle'] = handle
            with self.subTest(handle=handle), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.root_inventory(rows, links())
        rows = roots();rows[0]['handle'] = '1:'
        with self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.root_inventory(rows, links())

    def test_positive_fq_codel_options_use_native_integer_and_optional_encodings(self):
        value = options();del value['ecn'];del value['drop_batch']
        CLASSIFIERS.fq_options(value)
        value.update(ce_threshold=0, ce_threshold_selector=0, ce_threshold_mask=255)
        CLASSIFIERS.fq_options(value)
        for key in ('limit', 'quantum', 'target', 'interval', 'memory_limit'):
            current = options();current[key] = 0
            with self.subTest(key=key):CLASSIFIERS.fq_options(current)

    def test_fq_codel_missing_unknown_boolean_string_and_partial_ce_options_refuse(self):
        for key in CLASSIFIERS.FQ_REQUIRED:
            value = options();del value[key]
            with self.subTest(missing=key), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.fq_options(value)
        for key, value in (('flows', 0), ('flows', 65537), ('target', True), ('interval', -1), ('memory_limit', '32Mb'),
                           ('limit', 1 << 32), ('ecn', False), ('ecn', 1), ('drop_batch', 0), ('drop_batch', '64'),
                           ('unknown', 1), ('ce_threshold_selector', 1), ('ce_threshold_mask', 1)):
            current = options();current[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.fq_options(current)
        for selector, mask in ((0, 0), (256, 1), (1, True)):
            value = options();value.update(ce_threshold=1, ce_threshold_selector=selector, ce_threshold_mask=mask)
            with self.subTest(selector=selector, mask=mask), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.fq_options(value)

    def test_noqueue_nonempty_options_or_fq_codel_unverifiable_options_refuse(self):
        for index, value in ((0, {'foo': 1}), (0, []), (1, {}), (1, None), (1, [])):
            rows = roots();rows[index]['options'] = value
            with self.subTest(index=index, value=value), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.root_inventory(rows, links())

    def test_shared_snapshot_bounds_apply_to_link_and_root_input(self):
        value = links();value[1]['parentdev'] = 'x' * CLASSIFIERS.MAX_BYTES
        with self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.link_inventory(value)
        value = roots();value[1]['options']['target'] = 1.0
        with self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.root_inventory(value, links())


class ObservationTests(unittest.TestCase):
    def observe(self, **kwargs):
        def query(operation, deadline, interface=None):return roots() if operation == 'qdiscs' else []
        defaults = {'query': query, 'links': lambda operation, deadline: links(), 'scope': lambda: 123}
        defaults.update(kwargs)
        return CLASSIFIERS.observe(**defaults)

    def test_complete_mixed_roots_require_two_positive_filter_reads(self):
        ledger = []
        def query(operation, deadline, interface=None):
            ledger.append((operation, interface, deadline));return roots() if operation == 'qdiscs' else []
        result = self.observe(query=query)
        self.assertEqual(result['fq_codel_filters'], {'eth0': []})
        self.assertEqual(result['links'], links());self.assertEqual(result['qdiscs'], roots());self.assertNotIn('empty', result)
        self.assertEqual([(op, name) for op, name, _ in ledger], [('qdiscs', None), ('filters', 'eth0')] * 2)
        self.assertEqual(len({deadline for _, _, deadline in ledger}), 1)

    def test_all_noqueue_does_not_claim_a_classifier_query_for_no_block_roots(self):
        rows, qdiscs = links(), roots();rows[1]['qdisc'] = 'noqueue';qdiscs[1].update(kind='noqueue', options={})
        def query(operation, deadline, interface=None):
            self.assertEqual(operation, 'qdiscs');self.assertIsNone(interface);return qdiscs
        result = self.observe(query=query, links=lambda operation, deadline: rows)
        self.assertEqual(result['fq_codel_filters'], {})

    def test_every_fq_codel_root_including_down_link_gets_each_round(self):
        rows, qdiscs = links(), roots();rows.append(dict(rows[1], ifname='offline', ifindex=3, flags=['BROADCAST']))
        qdiscs.append(dict(qdiscs[1], dev='offline', handle='8001:'));seen = []
        def query(operation, deadline, interface=None):
            if operation == 'qdiscs':return qdiscs
            seen.append(interface);return []
        result = self.observe(query=query, links=lambda operation, deadline: rows)
        self.assertEqual(seen, ['eth0', 'offline'] * 2);self.assertEqual(result['fq_codel_filters'], {'eth0': [], 'offline': []})

    def test_any_nonempty_malformed_or_absent_filter_delivery_refuses(self):
        for value in (None, {}, [None], [{'kind': 'bpf', 'chain': 7}], [{'kind': 'u32', 'protocol': 'all'}], '', True):
            def query(operation, deadline, interface=None):return roots() if operation == 'qdiscs' else value
            with self.subTest(value=value), self.assertRaises(CLASSIFIERS.Pending):self.observe(query=query)

    def test_failed_filter_read_is_not_empty_and_prevents_completion(self):
        def query(operation, deadline, interface=None):
            if operation == 'qdiscs':return roots()
            raise OSError('private read failed')
        with self.assertRaises(OSError):self.observe(query=query)

    def test_full_link_root_and_option_identity_changes_refuse(self):
        for kind in ('link', 'root', 'options'):
            turns = [0]
            def read(operation, deadline, interface=None):
                if operation == 'filters':return []
                turns[0] += 1;value = links() if kind == 'link' else roots()
                if turns[0] == 2:
                    if kind == 'link':value[1]['ifindex'] += 1
                    elif kind == 'root':value[1]['refcnt'] += 1
                    else:value[1]['options']['target'] += 1
                return value
            arguments = {'links': read} if kind == 'link' else {'query': read}
            with self.subTest(kind=kind), self.assertRaisesRegex(CLASSIFIERS.Pending, 'changed'):self.observe(**arguments)

    def test_private_link_root_filter_snapshots_cannot_be_changed_by_later_callbacks(self):
        rows, qdiscs, filters = links(), roots(), []
        def query(operation, deadline, interface=None):
            if operation == 'qdiscs':return qdiscs
            rows[1]['ifindex'] = 7;qdiscs[1]['refcnt'] = 4;return filters
        with self.assertRaisesRegex(CLASSIFIERS.Pending, 'changed'):self.observe(query=query, links=lambda operation, deadline: rows)

    def test_inherited_deadlines_never_widen_and_exhaustion_blocks_next_delivery(self):
        start = KERNEL.now();clock = [start];seen = []
        def query(operation, deadline, interface=None):
            seen.append((operation, deadline));clock[0] = deadline;return roots()
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(CLASSIFIERS.Pending):self.observe(query=query, deadline=start + 2)
        self.assertEqual(seen, [('qdiscs', start + 2)])
        seen.clear();clock[0] = start
        def read(operation, deadline):clock[0] = deadline;return links()
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaises(CLASSIFIERS.Pending):self.observe(links=read, query=lambda *args, **kwargs:self.fail('expired links admitted native tc'))

    def test_final_filter_and_namespace_exhaustion_cannot_publish(self):
        start = KERNEL.now();clock = [start];calls = [0]
        def query(operation, deadline, interface=None):
            if operation == 'qdiscs':return roots()
            calls[0] += 1
            if calls[0] == 2:clock[0] = deadline
            return []
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(CLASSIFIERS.Pending):self.observe(query=query)
        clock[0] = start;scopes = [0]
        def scope():
            scopes[0] += 1
            if scopes[0] == 2:clock[0] = start + CLASSIFIERS.ATTEMPT_SECONDS
            return 123
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), self.assertRaises(CLASSIFIERS.Pending):self.observe(scope=scope)

    def test_bad_scope_deadline_and_namespace_change_refuse(self):
        for value in (True, 0, -1, '123', 1 << 64):
            with self.subTest(scope=value), self.assertRaises(CLASSIFIERS.Pending):self.observe(scope=lambda: value)
        for deadline in (True, 'future', float('nan'), float('inf'), KERNEL.now() - 1):
            with self.subTest(deadline=deadline), self.assertRaises(CLASSIFIERS.Pending):self.observe(deadline=deadline)
        for final in (124, True, '123'):
            scopes = iter((123, final))
            with self.subTest(final=final), self.assertRaises(CLASSIFIERS.Pending):self.observe(scope=lambda:next(scopes))

    def test_finite_budget_covers_bounded_maximum_native_reads_and_cleanup(self):
        self.assertEqual(CLASSIFIERS.ATTEMPT_SECONDS, 2 * (KERNEL.MAX_LINKS + 2) * (KERNEL.QUERY_SECONDS + KERNEL.CLEANUP_SECONDS) + CLASSIFIERS.LOCAL_SECONDS)
        rows = [links()[0]] + [dict(links()[1], ifname='eth' + str(index), ifindex=index + 2) for index in range(KERNEL.MAX_LINKS - 1)]
        qdiscs = [roots()[0]] + [dict(roots()[1], dev=row['ifname']) for row in rows[1:]];seen = []
        def query(operation, deadline, interface=None):seen.append((operation, interface));return qdiscs if operation == 'qdiscs' else []
        result = self.observe(query=query, links=lambda operation, deadline:rows)
        self.assertEqual(len(seen), 2 * KERNEL.MAX_LINKS);self.assertEqual(len(result['fq_codel_filters']), KERNEL.MAX_LINKS - 1)


class PrivateNative(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-classifiers-', dir='/dev/shm')
        self.root = Path(self.directory.name);self.root.chmod(0o700);self.binary = self.root / 'tc';self.ip = self.root / 'ip';self.ledger = self.root / 'ledger'
        self.settings = [patch.object(CLASSIFIERS, 'BINARY', self.binary), patch.object(KERNEL, 'TRUST_ROOT', self.root),
                         patch.object(KERNEL, 'TRUSTED_UID', os.geteuid()), patch.object(KERNEL, 'IP_BINARY', self.ip)]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def executable(self, body):
        self.binary.write_text('#!/usr/bin/python3 -B\n' + body + '\n');self.binary.chmod(0o700)

    def query(self, operation='filters', **kwargs):return CLASSIFIERS.native_query(operation, KERNEL.now() + 10, **({'interface':'eth0'} if operation == 'filters' else {}) | kwargs)

    def complete(self, rows=None, qdiscs=None, filter_body="print('[]')"):
        rows = links() if rows is None else rows;qdiscs = roots() if qdiscs is None else qdiscs
        self.ip.write_text('#!/usr/bin/python3 -B\nimport json,os,sys\nassert sys.argv[1:]=='+repr(['-j','-N',*KERNEL.COMMANDS['links']])+
            '\nwith open('+repr(str(self.ledger))+',"a") as f:f.write(json.dumps(["ip",sys.argv[1:],dict(os.environ)])+"\\n")\nprint('+repr(json.dumps(rows))+')\n')
        self.ip.chmod(0o700)
        body = f"import json,os,sys\nargs=sys.argv[1:]\nwith open({str(self.ledger)!r},'a') as f:f.write(json.dumps(['tc',args,dict(os.environ)])+'\\n')\nif args=={list(CLASSIFIERS.QDISCS)!r}:\n print({json.dumps(qdiscs)!r})\nelse:\n assert args in {([['-json','filter','show','dev',row['ifname']] for row in rows if row['qdisc']=='fq_codel'])!r}\n"
        body += '\n'.join(' ' + line for line in filter_body.splitlines())
        self.executable(body)

    def cli(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(CLASSIFIERS.sys, 'argv', ['classifiers.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):status = CLASSIFIERS.main()
        return status, out.getvalue(), err.getvalue()


class NativeTests(PrivateNative):
    def test_fixed_unfiltered_device_query_clears_environment_and_inherited_fds(self):
        fd = os.open(self.root / 'fd', os.O_CREAT | os.O_WRONLY, 0o600);os.set_inheritable(fd, True)
        self.executable(f"import json,os,sys\ntry:\n os.fstat({fd});leaked=True\nexcept OSError:\n leaked=False\nopen({str(self.ledger)!r},'w').write(json.dumps([sys.argv[1:],dict(os.environ),leaked]))\nprint('[]')")
        try:
            with patch.dict(os.environ, {'TC_LIB_DIR':'bad','LD_PRELOAD':'bad','CLASSIFIER_SECRET':'bad'}):self.assertEqual(self.query(), [])
            args, environment, leaked = json.loads(self.ledger.read_text())
            self.assertEqual(args, ['-json','filter','show','dev','eth0']);self.assertFalse(leaked)
            self.assertFalse(set(environment)&{'TC_LIB_DIR','LD_PRELOAD','CLASSIFIER_SECRET'});self.assertEqual(environment['LC_ALL'], 'C')
        finally:os.close(fd)

    def test_all_invalid_operations_interfaces_deadlines_and_extra_selectors_refuse_before_exec(self):
        self.executable(f"open({str(self.ledger)!r},'w').write('unexpected')")
        for operation, interface in (('replace',None), ('filters',None), ('filters','../eth0'), ('filters','-batch'),
                                     ('filters','a'*16), ('filters',2), ('qdiscs','eth0'), (True,None)):
            with self.subTest(operation=operation, interface=interface), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.native_query(operation,KERNEL.now()+10,interface)
        for deadline in (True, 'future', float('nan'), float('inf'), KERNEL.now()-1):
            with self.subTest(deadline=deadline), self.assertRaises(CLASSIFIERS.Pending):CLASSIFIERS.native_query('filters', deadline, 'eth0')
        with self.assertRaises(TypeError):CLASSIFIERS.native_query('filters', KERNEL.now()+10, 'eth0', 'root')
        self.assertFalse(self.ledger.exists())

    def test_nonzero_warning_partial_invalid_encoding_and_duplicate_json_refuse(self):
        for body in ("print('[]');raise SystemExit(1)", "import sys;print('[]');print('warning',file=sys.stderr)",
                     "print('[')", "import os;os.write(1,b'\\xff')", "print('[{\"chain\":1,\"chain\":2}]')"):
            self.executable(body)
            with self.subTest(body=body), self.assertRaises(CLASSIFIERS.Pending):self.query()

    def test_independent_capture_limits_refuse_for_each_channel(self):
        for channel in (1, 2):
            self.executable(f"import os;os.write({channel},b'x'*{CLASSIFIERS.MAX_BYTES+1})")
            with self.subTest(channel=channel), self.assertRaises(CLASSIFIERS.Pending):self.query()

    def test_zero_exit_after_completion_deadline_refuses_before_parse(self):
        self.executable("print('[]')");start = KERNEL.now();clock = [start];native = CLASSIFIERS.subprocess.Popen
        def delayed(*args, **kwargs):
            process = native(*args, **kwargs);wait = process.wait
            def complete(*args, **kwargs):value = wait(*args, **kwargs);clock[0] = start + KERNEL.QUERY_SECONDS + 1;return value
            process.wait = complete;return process
        with patch.object(KERNEL, 'now', side_effect=lambda:clock[0]), patch.object(CLASSIFIERS.subprocess, 'Popen', side_effect=delayed), self.assertRaisesRegex(CLASSIFIERS.Pending, 'completed after'):self.query()

    def test_pipe_eof_without_root_exit_cannot_certify_empty_filters(self):
        self.executable('import os,time\nos.close(1);os.close(2);time.sleep(60)')
        with patch.object(KERNEL, 'QUERY_SECONDS', 0.1), self.assertRaises(CLASSIFIERS.Pending):self.query()

    def test_owned_unreaped_group_is_killed_on_descendant_held_pipe(self):
        marker = self.root / 'child'
        self.executable(f"import json,os,time\npid=os.fork()\nif pid:\n fields=open('/proc/'+str(pid)+'/stat').read().rsplit(')',1)[1].split()\n open({str(marker)!r},'w').write(json.dumps({{'pid':pid,'start':fields[19],'group':os.getpgid(pid),'session':os.getsid(pid)}}))\n print('[]',flush=True)\n os._exit(0)\ntime.sleep(60)")
        killpg = CLASSIFIERS.os.killpg;signals = []
        def recorded(group, value):signals.append((group,value));return killpg(group,value)
        try:
            with patch.object(CLASSIFIERS.os, 'killpg', side_effect=recorded), self.assertRaises(CLASSIFIERS.Pending):self.query()
            owned = json.loads(marker.read_text());self.assertEqual(owned['group'], owned['session']);self.assertIn((owned['group'],signal.SIGKILL),signals)
            for _ in range(100):
                try:fields = Path('/proc/'+str(owned['pid'])+'/stat').read_text().rsplit(')',1)[1].split()
                except FileNotFoundError:break
                if fields[19] != owned['start'] or fields[0] == 'Z':break
                time.sleep(0.01)
            else:self.fail('owned descendant remained live after group termination')
        finally:
            if marker.exists():
                owned = json.loads(marker.read_text())
                try:
                    entry = Path('/proc/'+str(owned['pid']));fields = (entry/'stat').read_text().rsplit(')',1)[1].split()
                    if entry.stat().st_uid == os.geteuid() and fields[19] == owned['start'] and fields[0] != 'Z' and int(fields[2]) == owned['group'] and int(fields[3]) == owned['session']:os.kill(owned['pid'],signal.SIGKILL)
                except (FileNotFoundError,ProcessLookupError):pass

    def test_wrong_owner_symbolic_fifo_and_writable_trust_refuse_before_exec(self):
        self.executable(f"open({str(self.ledger)!r},'w').write('unexpected')")
        with patch.object(KERNEL, 'TRUSTED_UID', os.geteuid()+1), self.assertRaises(CLASSIFIERS.Pending):self.query()
        self.binary.chmod(0o720)
        with self.assertRaises(CLASSIFIERS.Pending):self.query()
        self.binary.chmod(0o700);original = self.root / 'original';self.binary.rename(original);self.binary.symlink_to(original)
        with self.assertRaises(CLASSIFIERS.Pending):self.query()
        self.binary.unlink();os.mkfifo(self.binary)
        with self.assertRaises(CLASSIFIERS.Pending):self.query()
        self.assertFalse(self.ledger.exists())

    def test_replaced_native_binary_cannot_certify_a_read(self):
        self.executable(f"from pathlib import Path\nPath({str(self.binary)!r}).write_text('replaced')\nprint('[]')")
        with self.assertRaisesRegex(CLASSIFIERS.Pending, 'binary changed'):self.query()


class CompleteNativeTests(PrivateNative):
    def test_complete_cli_utf8_serialization_preserves_the_checked_output_bound(self):
        rows = links();rows[1]['parentdev'] = '\u00e9' * 60000
        self.complete(rows=rows)
        status, out, err = self.cli()
        self.assertEqual(status, 0, err);self.assertEqual(err, '')
        self.assertEqual(json.loads(out)['links'], rows)
        self.assertLessEqual(len(out.encode('utf-8')), CLASSIFIERS.MAX_BYTES + 1)
        self.assertIn('\u00e9', out)

    def test_complete_numeric_ip_qdisc_filter_parser_namespace_and_cli_path(self):
        self.complete()
        with patch.dict(os.environ, {'IP_LIB_DIR':'bad','TC_LIB_DIR':'bad','CLASSIFIER_SECRET':'bad'}):status, out, err = self.cli()
        self.assertEqual(status, 0, err);self.assertEqual(err, '')
        value = json.loads(out);self.assertEqual(value['links'], links());self.assertEqual(value['qdiscs'], roots());self.assertEqual(value['fq_codel_filters'], {'eth0':[]})
        self.assertEqual(value['source'], {'tc':str(self.binary),'ip':str(self.ip)})
        ledger = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual([name for name, _, _ in ledger], ['ip','tc','tc'] * 2)
        self.assertEqual([args for _, args, _ in ledger], [['-j','-N',*KERNEL.COMMANDS['links']],list(CLASSIFIERS.QDISCS),['-json','filter','show','dev','eth0']] * 2)
        for _, _, environment in ledger:self.assertFalse(set(environment)&{'IP_LIB_DIR','TC_LIB_DIR','CLASSIFIER_SECRET'})

    def test_complete_zero_or_nonzero_handle_and_numeric_device_use_unselected_dump(self):
        for handle in ('0:', '8001:'):
            if self.ledger.exists():self.ledger.unlink()
            rows, qdiscs = links(), roots();rows[1].update(ifname='2',ifindex=7);qdiscs[1].update(dev='2',handle=handle)
            self.complete(rows, qdiscs);status,out,err = self.cli()
            self.assertEqual(status, 0, err);self.assertEqual(json.loads(out)['fq_codel_filters'], {'2':[]})
            ledger = [json.loads(line) for line in self.ledger.read_text().splitlines()]
            self.assertEqual([args for _, args, _ in ledger if args[1:3] == ['filter','show']], [['-json','filter','show','dev','2']] * 2)

    def test_complete_nonempty_bpf_classifier_in_any_chain_has_no_healthy_stdout(self):
        self.complete(filter_body="print('[{\"kind\":\"bpf\",\"chain\":77,\"protocol\":\"ipv6\",\"pref\":100}]')")
        status, out, err = self.cli();self.assertEqual(status, 75);self.assertEqual(out, '');self.assertIn('not positively empty', err)

    def test_complete_empty_stdout_warning_and_failed_filter_are_not_absence(self):
        for body in ("pass", "print('[]');raise SystemExit(1)", "print('[]');print('warning',file=sys.stderr)"):
            self.complete(filter_body=body)
            with self.subTest(body=body):
                status,out,err = self.cli();self.assertEqual(status, 75);self.assertEqual(out, '');self.assertIn('pending', err)

    def test_complete_unknown_links_and_partial_foreign_or_offloaded_roots_refuse(self):
        for kind in ('unknown-link','missing-root','shared-block','offload','clsact'):
            rows, qdiscs = links(), roots()
            if kind == 'unknown-link':rows[1]['link_type'] = '[9999]'
            elif kind == 'missing-root':qdiscs.pop()
            elif kind == 'shared-block':qdiscs[1]['egress_block'] = 9
            elif kind == 'offload':qdiscs[1]['offloaded'] = True
            else:qdiscs.append({'kind':'clsact','dev':'eth0','handle':'ffff:','parent':'ffff:fff1','options':{}})
            self.complete(rows, qdiscs)
            with self.subTest(kind=kind):
                status,out,err = self.cli();self.assertEqual(status, 75);self.assertEqual(out, '');self.assertIn('pending', err)

    def test_cli_usage_refuses_before_any_private_native_execution(self):
        self.complete()
        for args in (['replace'], ['dev','eth0'], ['root'], ['-batch','file']):
            with self.subTest(args=args), patch.object(CLASSIFIERS.sys, 'argv', ['classifiers.py',*args]):self.assertEqual(CLASSIFIERS.main(), 64)
        self.assertFalse(self.ledger.exists())


if __name__ == '__main__':
    unittest.main()
