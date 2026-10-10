"""Protected private file/structured SOURCE delivery models, never host observers.

All site-like settings are finite TEST DATA. Real EMPTY admission, protected
readers, account checks and compiler/translator run; replies do not authenticate
native state, allocation, catalogs, ownership or delivery permission.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_assemble as fixture
import test_dns_policy as compiler_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_dns_empty_prepare', ROOT / 'Firewall/dns_prepare.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class DNSEmptyPreparationTests(unittest.TestCase):
    def setUp(self):
        private = tempfile.TemporaryDirectory(dir='/dev/shm'); self.addCleanup(private.cleanup)
        self.root = Path(private.name); self.root.chmod(0o700)
        self.records = fixture.records(); self.namespace = self.records['dhcp4']['kernel']['namespace']
        for owner, field, value in ((M, 'ASSEMBLY', fixture.ASSEMBLY), (M, 'KERNEL', fixture.KERNEL),
            (M.DNS.BASE, 'TRUST_ROOT', self.root), (M.DNS.BASE, 'TRUSTED_UID', os.getuid()),
            (M.DNS, 'INPUT', self.root/'dns.json'), (M.DNS, 'PASSWD', self.root/'passwd'),
            (M.DNS, 'GROUP', self.root/'group')):
            adapter = patch.object(owner, field, value); adapter.start(); self.addCleanup(adapter.stop)
        self.value = compiler_fixture.settings()
        self.data = compiler_fixture.reported()['snapshot']
        self.passwd = (b'root:x:0:0:root:/root:/bin/bash\n'
            b'dns_app_demo:x:401:401::/:/usr/sbin/nologin\n'
            b'dns_gateway_demo:x:402:402::/:/bin/false\n')
        self.group = (b'root:x:0:\ndns_app_demo:x:401:\ndns_gateway_demo:x:402:\n'
            b'dns_ipc_demo:x:403:dns_app_demo,dns_gateway_demo\n')
        self.write()
        for path, raw in ((M.DNS.PASSWD, self.passwd), (M.DNS.GROUP, self.group)):
            path.write_bytes(raw); path.chmod(0o644)

    def write(self):
        M.DNS.INPUT.write_bytes(M.DNS.BASE.canonical(self.value)); M.DNS.INPUT.chmod(0o600)

    def readers(self):
        return {'dhcp': lambda deadline: self.records['dhcp4'],
            'dns': lambda deadline: self.records['dns'], 'ntp': lambda deadline: self.records['ntp'],
            'nft': lambda deadline: fixture.nft_receipt(self.namespace),
            'legacy': lambda deadline: fixture.legacy_receipt(self.namespace),
            'classifiers': lambda deadline: fixture.classifier_receipt(self.records['dhcp4']['kernel']),
            'bpf': lambda deadline: fixture.bpf_receipt(self.namespace),
            'bpf_links': lambda deadline: fixture.bpf_link_receipt(self.namespace),
            'kernel': lambda name, deadline: copy.deepcopy(self.data[name])}

    def prepare(self, **kw):
        return M.prepare(**(self.readers() | kw))

    def test_real_protected_service_and_complete_kernel_compiler_manifest_are_bound(self):
        payload = self.prepare(); record = json.loads(payload)
        self.assertEqual(payload, M.DNS.BASE.canonical(record))
        self.assertEqual(record['state'], 'prepared-public-dns-empty-source-intention-only')
        self.assertEqual(record['namespace'], self.namespace)
        service = record['service_intention'].encode('ascii')
        self.assertEqual(record['service_sha256'], hashlib.sha256(service).hexdigest())
        self.assertEqual(json.loads(service)['configuration']['value'], self.value)
        self.assertEqual(record['dns_configuration'].encode(), M.DNS.INPUT.read_bytes())
        expected = M.MANIFEST.expected(record['topology'].encode(), record['dns_configuration'].encode(), record['kernel_snapshot'].encode())
        self.assertEqual(record['intention'], expected)
        self.assertEqual(len(expected['nft_policy']['sets']), 17)
        self.assertEqual(expected['nft_policy']['rules']['forward'], [])
        self.assertTrue(expected['compiler']['policy'].startswith('destroy table inet debian13s4\n'))
        self.assertNotIn('correlation_id', record); self.assertNotIn('owned', record)

    def test_receipt_encoding_and_second_real_service_read_precede_every_final_fence(self):
        events = []; real_prepare = M.DNS.prepare; real_canonical = M.DNS.BASE.canonical
        def service(**kw):
            events.append('service'); return real_prepare(**kw)
        def encoded(value):
            if type(value) is dict and value.get('state') == 'prepared-public-dns-empty-source-intention-only':
                events.append('receipt')
            return real_canonical(value)
        readers = self.readers()
        for name, fn in tuple(readers.items()):
            if name == 'kernel':
                readers[name] = lambda key, deadline, fn=fn: events.append('kernel:'+key) or fn(key, deadline)
            else:
                readers[name] = lambda deadline, name=name, fn=fn: events.append(name) or fn(deadline)
        with patch.object(M.DNS, 'prepare', side_effect=service), patch.object(M.DNS.BASE, 'canonical', side_effect=encoded):
            M.prepare(**readers)
        self.assertEqual(events[0], 'service')
        self.assertEqual(events[1:17], ['nft','legacy','classifiers','bpf','bpf_links','dhcp','dns','ntp']*2)
        self.assertEqual(events[17:37], ['kernel:'+name for name in M.KERNEL.COMMANDS]*2)
        self.assertEqual(events[37:], ['receipt','service','nft','legacy','classifiers','bpf','bpf_links'])

    def test_missing_or_unprotected_input_refuses_before_any_source_entry(self):
        for action in ('missing', 'public', 'symlink'):
            self.write()
            if action == 'missing': M.DNS.INPUT.unlink()
            elif action == 'public': M.DNS.INPUT.chmod(0o644)
            else:
                target = self.root/'target'; target.write_bytes(M.DNS.INPUT.read_bytes()); target.chmod(0o600)
                M.DNS.INPUT.unlink(); M.DNS.INPUT.symlink_to(target)
            with self.subTest(action=action), patch.object(M.ASSEMBLY, 'observe', side_effect=AssertionError('source')):
                with self.assertRaises((ValueError, OSError)): self.prepare()
            if M.DNS.INPUT.is_symlink(): M.DNS.INPUT.unlink()

    def test_complete_account_primary_and_ipc_group_refusals_precede_source_entry(self):
        for path, raw in ((M.DNS.PASSWD, self.passwd+b'other:x:404:401::/:/bin/false\n'),
            (M.DNS.GROUP, self.group.replace(b'dns_app_demo,dns_gateway_demo', b'dns_app_demo')),
            (M.DNS.PASSWD, self.passwd.replace(b'\n', b'\r')+b'\n')):
            M.DNS.PASSWD.write_bytes(self.passwd); M.DNS.GROUP.write_bytes(self.group); path.write_bytes(raw)
            with self.subTest(path=path), patch.object(M.ASSEMBLY, 'observe', side_effect=AssertionError('source')):
                with self.assertRaises(ValueError): self.prepare()

    def test_unsupported_caller_overrides_and_noncallables_refuse_before_context(self):
        for kw in ({'compiler':lambda:None}, {'scope':lambda:1}, {'configuration':{}}, {'topology':{}},
            {'identifier':'x'}, {'healthy':True}, {'kernel':None}, {'nft':False}):
            with self.subTest(kw=kw), patch.object(M.KERNEL, 'namespace', side_effect=AssertionError('context')):
                with self.assertRaises(ValueError): M.prepare(**kw)

    def test_invalid_parent_deadlines_refuse_before_protected_service(self):
        for deadline in (True, float('nan'), float('inf'), 'later', M.KERNEL.now()-1, 10**10000):
            with self.subTest(kind=type(deadline).__name__), patch.object(M.DNS, 'prepare', side_effect=AssertionError('service')):
                with self.assertRaises(ValueError): self.prepare(deadline=deadline)

    def test_initial_context_requires_true_positive_uint64(self):
        for namespace in (0, True, -1, '1', 1<<64):
            with self.subTest(namespace=namespace), patch.object(M.KERNEL, 'namespace', return_value=namespace), patch.object(M.DNS, 'prepare', side_effect=AssertionError('service')):
                with self.assertRaises(ValueError): self.prepare()

    def test_existing_even_matching_nft_objects_never_become_empty_admission(self):
        for source in (fixture.nft_receipt(self.namespace)|{'empty':False}, {},
            {'schema':'debian13s4-nft-candidate-1','namespace':self.namespace,'policy':{}}):
            with self.subTest(source=source), patch.object(M, 'kernel_pair', side_effect=AssertionError('kernel')):
                with self.assertRaises(ValueError): self.prepare(nft=lambda deadline: source)

    def test_missing_legacy_tc_program_or_link_inventory_refuses_before_compilation(self):
        for name in ('legacy','classifiers','bpf','bpf_links'):
            with self.subTest(name=name), patch.object(M.MANIFEST, 'expected', side_effect=AssertionError('compiler')):
                with self.assertRaises(ValueError): self.prepare(**{name:lambda deadline:{}})

    def test_changed_infrastructure_between_rounds_and_instantiated_dhcp6_refuse(self):
        self.records['dhcp4']['interfaces'][0].update(dhcp6=True, state6='stopped')
        with self.assertRaisesRegex(ValueError, 'DHCPv6'): self.prepare()
        self.records = fixture.records(); calls = [0]
        def dns(deadline):
            calls[0] += 1; value = copy.deepcopy(self.records['dns'])
            if calls[0] == 2: value['source']['sha256'] = 'a'*64
            return value
        with self.assertRaisesRegex(ValueError, 'between rounds'): self.prepare(dns=dns)

    def test_all_ten_queries_are_copied_twice_with_one_capped_shared_window(self):
        calls = []; start = M.KERNEL.now()
        def query(name, deadline):
            calls.append((name, deadline)); return self.data[name]
        with patch.object(M.KERNEL, 'now', return_value=start): self.prepare(deadline=start+1000, kernel=query)
        self.assertEqual([name for name,_ in calls], list(M.KERNEL.COMMANDS)*2)
        self.assertEqual({end for _,end in calls}, {start+10})
        with patch.object(M.KERNEL, 'now', return_value=start):
            calls.clear(); self.prepare(deadline=start+5, kernel=query)
        self.assertEqual({end for _,end in calls}, {start+5})

    def test_complete_raw_drift_refuses_even_when_normalized_interfaces_are_equal(self):
        calls = [0]
        def query(name, deadline):
            calls[0] += 1; value = copy.deepcopy(self.data[name])
            if calls[0] == 11: value[1]['mtu'] = 1500
            return value
        with self.assertRaisesRegex(ValueError, 'between samples'): self.prepare(kernel=query)
        self.assertEqual(calls[0], 20)

    def test_later_queries_cannot_mutate_already_copied_source_rows(self):
        calls = [0]
        def query(name, deadline):
            calls[0] += 1
            if calls[0] == 2: self.data['links'][1]['mtu'] = 1500
            return self.data[name]
        with self.assertRaisesRegex(ValueError, 'between samples'): self.prepare(kernel=query)

    def test_missing_malformed_proxy_and_rule_inventories_refuse(self):
        for name, value in (('links', []), ('addresses', None), ('proxy4',[{}]), ('rules6',[])):
            saved = self.data[name]; self.data[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): self.prepare()
            self.data[name] = saved

    def test_static_selected_assignments_require_full_forever_lifetimes_and_exact_addresses(self):
        entry = self.data['addresses'][1]['addr_info'][0]; saved = copy.deepcopy(entry)
        for change in ({'valid_life_time':3600}, {'preferred_life_time':True}, {'dynamic':True},
            {'scope':'link'}, {'local':'192.168.50.101'}):
            entry.clear(); entry.update(saved|change)
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare()
        entry.clear(); entry.update(saved)
        for family in ('4','6'):
            self.data['proxy'+family] = [{}]
            with self.subTest(family=family), self.assertRaises(ValueError): self.prepare()
            self.data['proxy'+family] = []

    def test_raw_kernel_topology_must_equal_all_automatic_interface_facts(self):
        self.data['neighbors4'][1]['lladdr'] = '02:00:00:00:00:21'
        with self.assertRaisesRegex(ValueError, 'kernel facts disagree'): self.prepare()

    def test_changed_protected_settings_during_kernel_reads_withholds_receipt(self):
        calls = [0]
        def query(name, deadline):
            calls[0] += 1
            if calls[0] == 20: self.value['node'] = 'changed'; self.write()
            return copy.deepcopy(self.data[name])
        with self.assertRaisesRegex(ValueError, 'service intention changed'): self.prepare(kernel=query)

    def test_changed_accounts_or_groups_before_second_real_service_read_refuse(self):
        real = M.MANIFEST.expected
        for path, raw in ((M.DNS.PASSWD,self.passwd.replace(b':401:401:',b':405:401:')),
            (M.DNS.GROUP,self.group+b'unrelated:x:444:\n')):
            M.DNS.PASSWD.write_bytes(self.passwd); M.DNS.GROUP.write_bytes(self.group)
            def expected(*args):
                result = real(*args); path.write_bytes(raw); return result
            with self.subTest(path=path), patch.object(M.MANIFEST, 'expected', side_effect=expected):
                with self.assertRaisesRegex(ValueError, 'service intention changed'): self.prepare()

    def test_expiry_from_second_protected_read_precedes_final_nft_admission(self):
        now = M.KERNEL.now(); real = M.DNS.prepare; calls = [0]; nft_calls = []
        def service(**kw):
            calls[0] += 1; raw = real(**kw)
            if calls[0] == 2: clock.return_value = now+61
            return raw
        def nft(deadline):
            nft_calls.append(deadline); return fixture.nft_receipt(self.namespace)
        with patch.object(M.KERNEL, 'now', return_value=now) as clock, patch.object(M.DNS, 'prepare', side_effect=service):
            with self.assertRaises(ValueError): self.prepare(nft=nft)
        self.assertEqual(calls[0],2); self.assertEqual(len(nft_calls),2)

    def test_final_source_drift_for_each_nft_legacy_tc_program_and_link_withholds_receipt(self):
        for name in ('nft','legacy','classifiers','bpf','bpf_links'):
            fn = self.readers()[name]; calls = [0]
            def reader(deadline):
                calls[0] += 1; return fn(deadline) if calls[0] < 3 else {}
            with self.subTest(name=name), self.assertRaises(ValueError): self.prepare(**{name:reader})
            self.assertEqual(calls[0],3)

    def test_kernel_query_failure_and_context_change_do_not_publish_a_receipt(self):
        def failure(name, deadline): raise OSError('private query failed')
        with self.assertRaises(OSError): self.prepare(kernel=failure)
        def changed(name, deadline):
            context.return_value = self.namespace+1; return self.data[name]
        with patch.object(M.KERNEL, 'namespace', return_value=self.namespace) as context:
            with self.assertRaisesRegex(ValueError,'context changed'): self.prepare(kernel=changed)

    def test_complete_receipt_byte_bound_precedes_second_service_preparation(self):
        real = M.DNS.prepare
        with patch.object(M, 'MAX_OUTPUT', 1), patch.object(M.DNS, 'prepare', wraps=real) as service:
            with self.assertRaisesRegex(ValueError,'receipt exceeds'): self.prepare()
        self.assertEqual(service.call_count,1)

    def test_final_return_requires_exact_schema_profile_context_and_same_policy_object(self):
        real = M.ASSEMBLY.observe
        for change in ({'schema':'bad'}, {'profile':'bad'}, {'namespace':True}, {'namespace':self.namespace+1}, {'policy':None}):
            def assembly(**kw):
                value = real(**kw)
                if 'policy' in change:
                    value['policy'] = value['policy'].encode().decode()
                else: value.update(change)
                return value
            with self.subTest(change=change), patch.object(M.ASSEMBLY, 'observe', side_effect=assembly):
                with self.assertRaisesRegex(ValueError,'same complete'): self.prepare()

    def test_no_encoding_compilation_or_protected_io_after_assembly_final_return(self):
        real = M.ASSEMBLY.observe; done = [False]
        def assembly(**kw):
            value = real(**kw); done[0] = True; return value
        def checked(fn):
            def call(*args, **kw):
                self.assertFalse(done[0]); return fn(*args, **kw)
            return call
        with patch.object(M.ASSEMBLY, 'observe', side_effect=assembly), \
            patch.object(M.DNS.BASE, 'canonical', side_effect=checked(M.DNS.BASE.canonical)), \
            patch.object(M.DNS.BASE, 'read_protected', side_effect=checked(M.DNS.BASE.read_protected)), \
            patch.object(M.MANIFEST, 'expected', side_effect=checked(M.MANIFEST.expected)):
            payload = self.prepare()
        self.assertTrue(done[0]); self.assertTrue(payload.endswith(b'\n'))

    def test_final_context_and_window_refuse_after_complete_assembly_return(self):
        real = M.ASSEMBLY.observe
        for kind in ('context', 'window'):
            with patch.object(M.KERNEL, 'namespace', return_value=self.namespace) as scope, \
                patch.object(M.KERNEL, 'now', return_value=M.KERNEL.now()) as clock:
                def assembly(**kw):
                    value = real(**kw)
                    if kind == 'context': scope.return_value = self.namespace+1
                    else: clock.return_value += 61
                    return value
                with self.subTest(kind=kind), patch.object(M.ASSEMBLY, 'observe', side_effect=assembly):
                    with self.assertRaisesRegex(ValueError,'context changed'): self.prepare()

    def test_raw_structure_and_total_frame_bounds_precede_real_expected_compilation(self):
        with patch.object(M.COMPILER, 'MAX_KERNEL', 1), \
            patch.object(M.MANIFEST, 'expected', side_effect=AssertionError('compile')):
            with self.assertRaisesRegex(ValueError,'frame exceeds'): self.prepare()
        def excessive(name, deadline): return ['x'*(M.KERNEL.MAX_BYTES+1)]
        with self.assertRaises(ValueError): self.prepare(kernel=excessive)

    def test_slow_kernel_delivery_is_checked_on_return_before_following_query(self):
        start = M.KERNEL.now(); calls = []
        with patch.object(M.KERNEL, 'now', return_value=start) as clock:
            def query(name, deadline):
                calls.append(name); clock.return_value = start+11; return self.data[name]
            with self.assertRaisesRegex(ValueError,'admission expired'): self.prepare(kernel=query)
        self.assertEqual(calls,['links'])

    def private_kernel(self, warning=False, exit_code=0, drift=False):
        binary = self.root/'ip'; ledger = self.root/'queries.ndjson'
        commands = {tuple(value):name for name,value in M.KERNEL.COMMANDS.items()}
        body = ('#!/usr/bin/python3 -B\nimport json,os,sys\nfrom pathlib import Path\n'
            f'ledger=Path({str(ledger)!r})\ncommands={commands!r}\ndata={self.data!r}\n'
            "args=sys.argv[1:]\nif args[:2]!=['-j','-N']:raise SystemExit(64)\n"
            "key=commands.get(tuple(args[2:]))\nif key is None:raise SystemExit(64)\n"
            "count=len(ledger.read_text().splitlines()) if ledger.exists() else 0\n"
            "with ledger.open('a') as f:f.write(json.dumps({'argv':args,'env':dict(os.environ),'pid':os.getpid(),'sid':os.getsid(0)})+'\\n')\n"
            f"if {warning!r}:print('private warning',file=sys.stderr)\n"
            f"if {drift!r} and count==10:data['links'][1]['mtu']=1500\n"
            f'print(json.dumps(data[key]))\nraise SystemExit({exit_code!r})\n')
        binary.write_text(body); binary.chmod(0o700)
        for field, value in (('IP_BINARY',binary), ('TRUST_ROOT',self.root), ('TRUSTED_UID',os.getuid())):
            adapter = patch.object(M.KERNEL,field,value); adapter.start(); self.addCleanup(adapter.stop)
        return binary,ledger

    def test_twenty_private_fixed_native_captures_retain_argv_cleared_env_and_owned_sessions(self):
        binary,ledger = self.private_kernel(); readers = self.readers(); del readers['kernel']
        payload = M.prepare(**readers); rows = [json.loads(line) for line in ledger.read_text().splitlines()]
        self.assertEqual([row['argv'] for row in rows], [['-j','-N',*args] for args in M.KERNEL.COMMANDS.values()]*2)
        self.assertEqual(len(rows),20)
        for row in rows:
            self.assertEqual(row['env'], {'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'})
            self.assertEqual(row['pid'], row['sid']); self.assertGreater(row['pid'],0)
        self.assertEqual(json.loads(payload)['state'],'prepared-public-dns-empty-source-intention-only')
        self.assertNotEqual(str(binary),'/usr/bin/ip')

    def test_private_capture_warning_nonzero_and_second_sample_drift_withhold_receipt(self):
        for warning,code,drift in ((True,0,False),(False,9,False),(False,0,True)):
            binary,ledger = self.private_kernel(warning,code,drift)
            if ledger.exists(): ledger.unlink()
            readers = self.readers(); del readers['kernel']
            with self.subTest(warning=warning,code=code,drift=drift), self.assertRaises(ValueError): M.prepare(**readers)
            self.assertEqual(len(ledger.read_text().splitlines()),20 if drift else 1)
