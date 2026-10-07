import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_dhcp import xml
from test_dhcp_servers import document, inventory, kernel_data, encoded
from test_timesync import packet
from test_policy import PacketModel

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('firewall_assemble', ROOT / 'Firewall/assemble.py')
ASSEMBLY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSEMBLY)
SERVERS, DHCP, TIME, DNS, KERNEL, POLICY = ASSEMBLY.SERVERS, ASSEMBLY.DHCP, ASSEMBLY.TIMESYNC, ASSEMBLY.RESOLVER, ASSEMBLY.KERNEL, ASSEMBLY.POLICY
NFT = ASSEMBLY.NFT


def nft_receipt(namespace):
    return {'schema': 'debian13s4-nft-empty-1', 'namespace': namespace, 'empty': True,
            'source': {'binary': str(NFT.BINARY), 'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}}


def records():
    kernel = SERVERS.assigned_topology(KERNEL.now() + 30, query=lambda name, deadline: copy.deepcopy(kernel_data()[name]))
    clients = inventory(families=(4,))['interfaces']
    attribution = SERVERS.descriptions(encoded(document(infinite=True)), clients[0], kernel)
    common = {key: kernel[key] for key in ('schema', 'namespace', 'interfaces')}
    return {'dhcp4': {'schema': 'debian13s4-networkd-dhcp4-servers-1', 'kernel': kernel,
                     'source': {'service': DHCP.SERVICE, 'owner': ':1.88', 'pid': os.getpid()},
                     'interfaces': clients, 'attributions': attribution, 'dhcp4': [{'interface': 'eth0', 'address': '192.168.50.1'}]},
            'dns': {'schema': 'debian13s4-resolver-1', 'kernel': common | {'scope_names': {'lo': 1, 'eth0': 2}},
                    'source': {'path': '/etc/resolv.conf', 'sha256': hashlib.sha256(b'nameserver 192.168.50.1\n').hexdigest()},
                    'dns': [{'interface': 'eth0', 'address': '192.168.50.1'}]},
            'ntp': {'schema': 'debian13s4-timesync-1', 'kernel': common,
                    'source': {'service': TIME.SERVICE, 'owner': ':1.77', 'pid': os.getpid(), 'name': 'time.example.test'},
                    'ntp': [{'interface': 'eth0', 'address': '192.168.50.3'}]}}


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.records = records()
        self.namespace = self.records['dhcp4']['kernel']['namespace']

    def observe(self, **overrides):
        settings = {name: (lambda deadline, key=key: copy.deepcopy(self.records[key])) for name, key in (('dhcp', 'dhcp4'), ('dns', 'dns'), ('ntp', 'ntp'))}
        settings['nft'] = lambda deadline: nft_receipt(self.namespace)
        settings.update(overrides)
        return ASSEMBLY.observe(**settings)

    def test_two_complete_rounds_share_one_deadline_and_feed_the_real_compiler(self):
        calls = []
        def reader(name):
            def read(deadline):
                calls.append((name, deadline))
                return self.records[name]
            return read
        result = self.observe(dhcp=reader('dhcp4'), dns=reader('dns'), ntp=reader('ntp'))
        self.assertEqual([name for name, _ in calls], ['dhcp4', 'dns', 'ntp'] * 2)
        self.assertEqual(len({deadline for _, deadline in calls}), 1)
        self.assertEqual(result['schema'], 'debian13s4-assembled-policy-1')
        self.assertEqual(result['topology']['dhcp6'], [])
        self.assertEqual(result['policy'], POLICY.compile_policy(json.dumps(result['topology']).encode()))
        self.assertIn('"eth0" . 192.168.50.20 . 02:00:00:00:00:20', result['policy'])
        self.assertNotIn('"eth0" . 192.168.50.1 . 02:00:00:00:00:01', result['policy'])

    def test_invalid_inherited_deadline_refuses_before_any_observer(self):
        for deadline in (KERNEL.now() - 1, True, float('nan'), float('inf'), 'future', 10 ** 10000):
            with self.subTest(type=type(deadline).__name__), self.assertRaises(ASSEMBLY.Pending):
                self.observe(deadline=deadline, dhcp=lambda **kw: self.fail('unexpected reader'))

    def test_inherited_window_never_widens_and_expiration_prevents_later_admission(self):
        start = KERNEL.now()
        for budget in (10, 1000):
            seen = []
            with self.subTest(budget=budget), patch.object(KERNEL, 'now', return_value=start):
                self.observe(deadline=start + budget, dhcp=lambda deadline: seen.append(deadline) or self.records['dhcp4'])
            self.assertEqual(seen, [start + min(budget, ASSEMBLY.ATTEMPT_SECONDS)] * 2)
        with patch.object(ASSEMBLY, 'ATTEMPT_SECONDS', 0), self.assertRaises(ASSEMBLY.Pending):
            self.observe(dhcp=lambda **kw: self.fail('unexpected expired admission'))

    def test_all_instantiated_dhcp6_states_refuse_before_dns_or_compile(self):
        for state in DHCP.STATES[6]:
            self.records['dhcp4']['interfaces'][0].update(dhcp6=True, state6=state)
            with self.subTest(state=state), self.assertRaisesRegex(ASSEMBLY.Pending, 'DHCPv6 reply'):
                self.observe(dns=lambda **kw: self.fail('unsupported profile advanced'), compiler=lambda raw: self.fail('unexpected compile'))

    def test_independently_valid_different_namespace_interface_index_mac_or_prefix_cannot_combine(self):
        for field, changed in (('index', 3), ('mac', '02:00:00:00:00:11'), ('prefixes', ['192.168.60.0/24'])):
            self.records = records()
            self.records['dns']['kernel']['interfaces'] = copy.deepcopy(self.records['dns']['kernel']['interfaces'])
            self.records['dns']['kernel']['interfaces'][0][field] = changed
            with self.subTest(field=field), self.assertRaises(ASSEMBLY.Pending):
                self.observe()
        self.records = records()
        self.records['ntp']['kernel']['namespace'] += 1
        with self.assertRaises(ASSEMBLY.Pending):
            self.observe()

    def test_second_complete_round_source_owner_peer_state_or_endpoint_change_is_pending(self):
        for service, field, changed in (('dns', 'sha256', 'a' * 64), ('ntp', 'owner', ':1.78'), ('ntp', 'name', 'other.test'), ('dhcp4', 'owner', ':1.89')):
            count = 0
            def read(deadline):
                nonlocal count
                count += 1
                value = copy.deepcopy(self.records[service])
                if count == 2:
                    value['source'][field] = changed
                return value
            name = 'dhcp' if service == 'dhcp4' else service
            with self.subTest(service=service, field=field), self.assertRaises(ASSEMBLY.Pending):
                self.observe(**{name: read})
        count = 0
        def dns(deadline):
            nonlocal count
            count += 1
            value = copy.deepcopy(self.records['dns'])
            if count == 2:value['dns'][0]['address'] = '192.168.50.2'
            return value
        with self.assertRaises(ASSEMBLY.Pending):self.observe(dns=dns)

    def test_reader_reusing_and_mutating_an_object_cannot_rewrite_the_first_round(self):
        value = copy.deepcopy(self.records['dns']);count = 0
        def dns(deadline):
            nonlocal count
            count += 1
            if count == 2:value['source']['sha256'] = 'a' * 64
            return value
        with self.assertRaises(ASSEMBLY.Pending):self.observe(dns=dns)

    def test_missing_unknown_schema_malformed_client_or_empty_infrastructure_refuse(self):
        for service in self.records:
            original = records()
            for mutation in ('schema', 'extra', 'missing'):
                self.records = copy.deepcopy(original)
                record = self.records[service]
                if mutation == 'schema':record['schema'] = 'unknown'
                elif mutation == 'extra':record['extra'] = True
                else:del record['kernel']
                with self.subTest(service=service, mutation=mutation), self.assertRaises(ASSEMBLY.Pending):self.observe()
        for service in ('dns', 'ntp'):
            self.records = records();self.records[service][service] = []
            with self.subTest(service=service), self.assertRaises(ASSEMBLY.Pending):self.observe()
        for field, bad in (('dhcp4', 1), ('dhcp6', None), ('state4', []), ('state6', 'bound'), ('path', '/wrong'), ('administrative', 'unmanaged')):
            self.records = records();self.records['dhcp4']['interfaces'][0][field] = bad
            with self.subTest(field=field), self.assertRaises(ASSEMBLY.Pending):self.observe()

    def test_live_client_endpoint_attribution_and_exact_assignment_are_required(self):
        for mutation in ('missing-attribution', 'missing-endpoint', 'missing-assignment', 'wrong-mask', 'unusable', 'duplicate-assignment', 'non-live'):
            self.records = records();dhcp = self.records['dhcp4']
            if mutation == 'missing-attribution':dhcp['attributions'] = []
            elif mutation == 'missing-endpoint':dhcp['dhcp4'] = []
            elif mutation == 'missing-assignment':dhcp['kernel']['assigned4'] = []
            elif mutation == 'wrong-mask':dhcp['kernel']['assigned4'][0]['prefixlen'] = 25
            elif mutation == 'unusable':dhcp['kernel']['assigned4'][0]['usable'] = False
            elif mutation == 'duplicate-assignment':dhcp['kernel']['assigned4'].append(copy.deepcopy(dhcp['kernel']['assigned4'][0]))
            else:dhcp['interfaces'][0]['state4'] = 'selecting'
            with self.subTest(mutation=mutation), self.assertRaises(ASSEMBLY.Pending):self.observe()
        self.records = records();self.records['dhcp4']['attributions'] = [];self.records['dhcp4']['dhcp4'] = []
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'complete server'):self.observe()

    def test_static_and_bootstrap_dhcp4_state_need_no_unicast_server_guess(self):
        for state in (None, 'stopped', 'selecting', 'requesting'):
            self.records = records();client = self.records['dhcp4']['interfaces'][0]
            client.update(dhcp4=state is not None, state4=state)
            self.records['dhcp4']['dhcp4'] = [];self.records['dhcp4']['attributions'] = []
            with self.subTest(state=state):
                result = self.observe()
                self.assertEqual(result['topology']['dhcp4'], [])
                self.assertEqual(result['topology']['interfaces'][0]['dhcp4'], state is not None)

    def test_expiry_during_other_observers_or_compiler_cannot_publish(self):
        start = KERNEL.now();until = int((start + 5) * 1000000)
        for name in ('preferred_until', 'valid_until'):self.records['dhcp4']['attributions'][0][name] = until
        clock = [start]
        def compiler(raw):
            text = POLICY.compile_policy(raw);clock[0] = start + 6;return text
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaisesRegex(ASSEMBLY.Pending, 'attribution expired'):
            self.observe(compiler=compiler)
        self.records = records()
        def compiler(raw):
            text = POLICY.compile_policy(raw);clock[0] = start + 61;return text
        clock[0] = start
        with patch.object(KERNEL, 'now', side_effect=lambda: clock[0]), self.assertRaisesRegex(ASSEMBLY.Pending, 'expired before publication'):
            self.observe(compiler=compiler)

    def test_final_namespace_change_or_native_observer_failure_cannot_publish(self):
        with patch.object(KERNEL, 'namespace', return_value=KERNEL.namespace() + 1), self.assertRaises(ASSEMBLY.Pending):self.observe()
        for name in ('dhcp', 'dns', 'ntp'):
            def failure(**kw):raise OSError('fixture failed delivery')
            with self.subTest(name=name), self.assertRaises(OSError):self.observe(**{name: failure}, compiler=lambda raw: self.fail('compiled failed observation'))

    def test_down_static_interfaces_keep_blocked_prefixes_without_cached_ssh_admission(self):
        extra = copy.deepcopy(self.records['dhcp4']['kernel']['interfaces'][0])
        extra.update(name='eth1', index=3, up=False, flags=['BROADCAST', 'MULTICAST'])
        for service in self.records:
            self.records[service]['kernel']['interfaces'] = copy.deepcopy(self.records[service]['kernel']['interfaces']) + [copy.deepcopy(extra)]
        client = copy.deepcopy(self.records['dhcp4']['interfaces'][0])
        client.update(name='eth1', index=3, path=DHCP.link_path(3), dhcp4=False, state4=None)
        self.records['dhcp4']['interfaces'].append(client)
        result = self.observe()
        self.assertEqual(result['topology']['interfaces'][1]['neighbors'], [])
        self.assertEqual(result['topology']['interfaces'][1]['prefixes'], extra['prefixes'])
        self.assertNotIn('"eth1" . 192.168.50.20 .', result['policy'])
        self.records['dns']['dns'][0]['interface'] = 'eth1'
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'active common'):self.observe()

    def test_real_compiler_rejects_invalid_endpoints_masks_and_aggregate_limits(self):
        for service in ('dns', 'ntp'):
            self.records = records();self.records[service][service][0]['address'] = '::ffff:192.168.50.1'
            with self.subTest(service=service), self.assertRaises(POLICY.InvalidTopology):self.observe()
        self.records = records()
        with patch.object(POLICY, 'MAX_INPUT', 1), self.assertRaises(POLICY.InvalidTopology):self.observe()

    def test_snapshot_encoding_structure_bounds_and_private_copy_are_positive(self):
        for value in ({'bad': 1.0}, {'bad': float('nan')}, {'bad': '\ud800'}, {'bad': b'bytes'}, {1: 'nonstring'}, {'bad': '\x00'}):
            with self.subTest(value=repr(value)), self.assertRaises(ASSEMBLY.Pending):ASSEMBLY.snapshot(value)
        with patch.object(ASSEMBLY, 'MAX_NODES', 1), self.assertRaises(ASSEMBLY.Pending):ASSEMBLY.snapshot({'a': ['b']})
        value = {};current = value
        for _ in range(18):current['next'] = {};current = current['next']
        with self.assertRaises(ASSEMBLY.Pending):ASSEMBLY.snapshot(value)
        value = {'a': ['b']};copied = ASSEMBLY.snapshot(value);value['a'].append('c')
        self.assertEqual(copied, {'a': ['b']})

    def test_final_compiler_output_type_and_byte_bound_are_checked(self):
        for text in (None, '', b'nft', 'x' * (POLICY.MAX_OUTPUT + 1)):
            with self.subTest(type=type(text).__name__), self.assertRaises(ASSEMBLY.Pending):self.observe(compiler=lambda raw: text)

    def test_nft_refusal_or_invalid_receipt_prevents_infrastructure_and_compiler_admission(self):
        def failure(deadline):raise NFT.Pending('existing nft objects')
        with self.assertRaises(NFT.Pending):
            self.observe(nft=failure, dhcp=lambda **kw: self.fail('unadmitted infrastructure'), compiler=lambda raw: self.fail('unadmitted compiler'))
        for empty in (False, 1, None, 'true'):
            receipt = nft_receipt(self.records['dhcp4']['kernel']['namespace']);receipt['empty'] = empty
            with self.subTest(empty=empty), self.assertRaises(ValueError):self.observe(nft=lambda deadline: receipt, dhcp=lambda **kw: self.fail('unverified receipt admitted'))

    def test_nft_and_infrastructure_namespace_mismatch_refuses_before_dns(self):
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'nft and infrastructure'):
            self.observe(nft=lambda deadline: nft_receipt(self.records['dhcp4']['kernel']['namespace'] + 1), dns=lambda **kw: self.fail('foreign namespace advanced'))

    def test_nft_source_changes_in_second_round_or_after_compile_cannot_publish(self):
        for turn in (2, 3):
            calls = []
            def read(deadline):
                calls.append(deadline);result = nft_receipt(self.records['dhcp4']['kernel']['namespace'])
                if len(calls)==turn:result['source']['version'] = '1.1.4'
                return result
            with self.subTest(turn=turn), self.assertRaises(ASSEMBLY.Pending):self.observe(nft=read)

    def test_nft_rounds_and_final_barrier_share_the_existing_inherited_window(self):
        seen = [];deadline = KERNEL.now() + 20
        def read(deadline):seen.append(deadline);return nft_receipt(self.namespace)
        result = self.observe(nft=read, deadline=deadline)
        self.assertEqual(seen, [deadline] * 3)
        self.assertEqual(result['sources']['nft']['binary'], str(NFT.BINARY))


class CLITests(unittest.TestCase):
    def test_arguments_and_refusal_do_not_emit_a_partial_policy(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py', 'extra']), contextlib.redirect_stdout(out):self.assertEqual(ASSEMBLY.main(), 64)
        self.assertEqual(out.getvalue(), '')
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), patch.object(ASSEMBLY, 'observe', side_effect=ASSEMBLY.Pending('fixture')), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(ASSEMBLY.main(), 75)
        self.assertEqual(out.getvalue(), '');self.assertIn('pending', err.getvalue())

    def test_success_emits_only_checked_compiler_text_and_write_errors_fail(self):
        out = io.StringIO()
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), patch.object(ASSEMBLY, 'observe', return_value={'policy': 'fixture\n'}), contextlib.redirect_stdout(out):self.assertEqual(ASSEMBLY.main(), 0)
        self.assertEqual(out.getvalue(), 'fixture\n')
        class FailedOutput:
            def write(self, value):raise OSError('fixture write')
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), patch.object(ASSEMBLY, 'observe', return_value={'policy': 'fixture\n'}), patch.object(ASSEMBLY.sys, 'stdout', FailedOutput()), contextlib.redirect_stderr(io.StringIO()):self.assertEqual(ASSEMBLY.main(), 75)


class PrivateNative(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='debian13s4-assembly-', dir='/dev/shm')
        self.root = Path(self.directory.name)
        self.bus, self.ip, self.ledger = self.root / 'busctl', self.root / 'ip', self.root / 'ledger'
        self.nft = self.root / 'nft'
        self.source = self.root / 'resolv.conf'
        self.settings = [patch.object(DHCP, 'BUS_BINARY', self.bus), patch.object(TIME, 'BUS_BINARY', self.bus),
                         patch.object(KERNEL, 'IP_BINARY', self.ip), patch.object(KERNEL, 'TRUST_ROOT', self.root), patch.object(KERNEL, 'TRUSTED_UID', os.geteuid()),
                         patch.object(DNS, 'RESOLV_CONF', self.source), patch.object(DNS, 'TRUST_ROOT', self.root), patch.object(DNS, 'TRUSTED_UID', os.geteuid())]
        self.settings += [patch.object(NFT, 'BINARY', self.nft), patch.object(NFT.KERNEL, 'TRUST_ROOT', self.root), patch.object(NFT.KERNEL, 'TRUSTED_UID', os.geteuid())]
        for setting in self.settings:setting.start()

    def tearDown(self):
        for setting in reversed(self.settings):setting.stop()
        self.directory.cleanup()

    def executable(self, path, body):
        path.write_text('#!/usr/bin/python3 -B\n' + body + '\n');path.chmod(0o700)

    def fixtures(self, state='bound', families=(4,), change_provider=False, change_time=False, change_dns=False, warning=False, corrupt=False, dns='8.8.8.8'):
        self.source.write_text('nameserver ' + dns + '\n')
        self.source.chmod(0o600)
        node_path, peer_path = self.root / 'description.json', self.root / 'peer.json'
        node = document(infinite=True)
        if corrupt:node['Addresses'][0]['ConfigProvider'] = [0, 0, 0, 0]
        node_path.write_text(json.dumps(node));peer_path.write_text(json.dumps(packet('192.168.50.3')))
        desc_count, peer_count = self.root / 'descriptions', self.root / 'peers'
        for path in (desc_count, peer_count):
            if path.exists():path.unlink()
        self.ledger.write_text('')
        self.executable(self.nft, f"import json,os,sys\nargs=sys.argv[1:]\nwith open({str(self.ledger)!r},'a') as log:log.write(json.dumps(['nft',args,dict(os.environ)])+'\\n')\nif args!={list(NFT.COMMAND)!r}:raise SystemExit(1)\nprint({json.dumps({'nftables': [{'metainfo': {'version': '1.1.3', 'release_name': 'fixture', 'json_schema_version': 1}}]})!r})")
        self.executable(self.bus, f"""import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['bus',args,dict(os.environ)])+'\\n')
if args[:8]!=['--system','--no-pager','--json=short','--auto-start=no','--allow-interactive-authorization=no','--expect-reply=yes','--timeout=3s','call']: raise SystemExit(1)
a=args[8:]
namespace=int(os.readlink('/proc/self/ns/net')[5:-1])
if a=={[*DHCP.BUS,'GetNameOwner','s',DHCP.SERVICE]!r}: result={{'type':'s','data':[':1.88']}}
elif a=={[*TIME.BUS,'GetNameOwner','s',TIME.SERVICE]!r}: result={{'type':'s','data':[':1.77']}}
elif len(a)==6 and a[:4]=={[*DHCP.BUS,'GetConnectionUnixProcessID']!r} and a[4]=='s' and a[5] in (':1.88',':1.77'): result={{'type':'u','data':[os.getppid()]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.MANAGER,'ListLinks']!r}: result={{'type':'a(iso)','data':[[[1,'lo',{DHCP.link_path(1)!r}],[2,'eth0',{DHCP.link_path(2)!r}]]]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.PROPERTIES,'Get','ss',DHCP.MANAGER,'NamespaceId']!r}: result={{'type':'v','data':[{{'type':'t','data':namespace}}]}}
elif a=={[':1.88',DHCP.link_path(2),DHCP.INTROSPECT,'Introspect']!r}: result={{'type':'s','data':[{xml(families)!r}]}}
elif a=={[':1.88',DHCP.link_path(2),DHCP.PROPERTIES,'Get','ss',DHCP.LINK,'AdministrativeState']!r}: result={{'type':'v','data':[{{'type':'s','data':'configured'}}]}}
elif len(a)==7 and a[:4]=={[':1.88',DHCP.link_path(2),DHCP.PROPERTIES,'Get']!r} and a[4]=='ss' and a[6]=='State':
 family=4 if a[5]=={DHCP.CLIENTS[4]!r} else 6 if a[5]=={DHCP.CLIENTS[6]!r} else 0
 if family not in {families!r}: raise SystemExit(1)
 result={{'type':'v','data':[{{'type':'s','data':{state!r} if family==4 else 'bound'}}]}}
elif a=={[':1.88',DHCP.OBJECT,DHCP.MANAGER,'DescribeLink','i','2']!r}:
 path=Path({str(desc_count)!r});turn=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(turn))
 node=json.loads(Path({str(node_path)!r}).read_text())
 if {change_provider!r} and turn>=3: node['Addresses'][0]['ConfigProvider']=[192,168,50,2]
 if {change_dns!r} and turn>=3: Path({str(self.source)!r}).write_text('nameserver 9.9.9.9\\n')
 result={{'type':'s','data':[json.dumps(node)]}}
elif a=={[':1.77',TIME.OBJECT,'org.freedesktop.DBus.Properties','GetAll','s',TIME.INTERFACE]!r}:
 path=Path({str(peer_count)!r});turn=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(turn))
 result=json.loads(Path({str(peer_path)!r}).read_text())
 if {change_time!r} and turn>=4: result['data'][0]['ServerName']['data']='changed.test'
 if {warning!r}: print('fixture warning',file=sys.stderr)
else: raise SystemExit(1)
print(json.dumps(result))""")
        data = kernel_data()
        self.executable(self.ip, f"""import json,sys
args=sys.argv[1:]
with open({str(self.ledger)!r},'a') as log: log.write(json.dumps(['ip',args,{{}}])+'\\n')
if args[:2]!=['-j','-N']: raise SystemExit(1)
a=args[2:]
commands={KERNEL.COMMANDS!r}
data={data!r}
if len(a)==4 and a[0]=='-4' and a[1:3]==['route','get'] and a[3] in ('8.8.8.8','9.9.9.9','192.168.50.1','192.168.50.2','192.168.50.3'):
 row={{'dst':a[3],'dev':'eth0'}}
 if a[3] in ('8.8.8.8','9.9.9.9'): row['gateway']='192.168.50.1'
 result=[row]
else:
 keys=[key for key,value in commands.items() if list(value)==a]
 if len(keys)!=1: raise SystemExit(1)
 result=data[keys[0]]
print(json.dumps(result))""")


class NativeAssemblyTests(PrivateNative):
    def test_full_private_capture_observation_join_and_compiler_path_is_positive(self):
        self.fixtures()
        with patch.dict(os.environ, {'DBUS_SYSTEM_BUS_ADDRESS': 'bad', 'ASSEMBLY_SECRET': 'bad'}):result = ASSEMBLY.observe()
        self.assertEqual(result['topology']['dns'], [{'interface': 'eth0', 'address': '8.8.8.8'}])
        self.assertEqual(result['topology']['ntp'], [{'interface': 'eth0', 'address': '192.168.50.3'}])
        self.assertEqual(result['topology']['dhcp4'], [{'interface': 'eth0', 'address': '192.168.50.1'}])
        self.assertEqual(result['sources']['dhcp4']['pid'], os.getpid())
        self.assertEqual(result['sources']['ntp']['pid'], os.getpid())
        rows = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual(sum(kind=='bus' for kind, _, _ in rows), 100)
        self.assertEqual(sum(kind=='ip' for kind, _, _ in rows), 252)
        self.assertEqual(sum('DescribeLink' in args for _, args, _ in rows), 4)
        self.assertEqual(sum('get' in args for kind, args, _ in rows if kind=='ip'), 12)
        for _, _, environment in rows:self.assertFalse(set(environment) & {'DBUS_SYSTEM_BUS_ADDRESS', 'ASSEMBLY_SECRET'})
        model = PacketModel(result['policy'])
        self.assertEqual(model.verdict('input', iifname='eth0', saddr='192.168.50.20', mac='02:00:00:00:00:20', dport=22), 'accept')
        self.assertEqual(model.verdict('input', iifname='eth0', saddr='192.168.50.1', mac='02:00:00:00:00:01', dport=22), 'drop')
        self.assertEqual(model.verdict('output', oifname='eth0', daddr='192.168.50.20', dport=445), 'drop')

    def test_private_static_and_bootstrap_clients_need_no_invented_server(self):
        for families, state in (((), 'bound'), ((4,), 'selecting')):
            self.fixtures(families=families, state=state)
            with self.subTest(families=families, state=state):
                result = ASSEMBLY.observe()
                self.assertEqual(result['topology']['dhcp4'], [])
                self.assertEqual(result['topology']['interfaces'][0]['dhcp4'], bool(families))
                self.assertFalse(any('DescribeLink' in json.loads(line)[1] for line in self.ledger.read_text().splitlines()))

    def test_private_instantiated_dhcp6_remains_pending_without_compiling(self):
        self.fixtures(families=(4, 6))
        with self.assertRaisesRegex(ASSEMBLY.Pending, 'DHCPv6 reply'):
            ASSEMBLY.observe(compiler=lambda raw: self.fail('unsupported profile compiled'))
        self.assertFalse(any(TIME.SERVICE in json.loads(line)[1] for line in self.ledger.read_text().splitlines()))

    def test_independently_healthy_native_second_round_changes_cannot_publish(self):
        for options in ({'change_provider': True}, {'change_time': True}, {'change_dns': True}):
            self.fixtures(**options)
            with self.subTest(options=options), self.assertRaisesRegex(ASSEMBLY.Pending, 'complete infrastructure observations changed'):
                ASSEMBLY.observe(compiler=lambda raw: self.fail('changed complete round compiled'))

    def test_private_native_warning_bad_provider_and_local_dns_stub_refuse(self):
        for options, message in (({'warning': True}, 'time query failed or warned'), ({'corrupt': True}, 'non-unicast'), ({'dns': '127.0.0.53'}, 'local resolver stub')):
            self.fixtures(**options)
            with self.subTest(options=options), self.assertRaisesRegex(ASSEMBLY.Pending, message):
                ASSEMBLY.observe(compiler=lambda raw: self.fail('failed native predicate compiled'))

    def test_private_cli_prepares_text_only_after_real_observer_and_compiler_predicates(self):
        self.fixtures();out, err = io.StringIO(), io.StringIO()
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(ASSEMBLY.main(), 0)
        self.assertTrue(out.getvalue().startswith('destroy table inet debian13s4\n'))
        self.assertEqual(err.getvalue(), '')
        self.fixtures(warning=True);out = io.StringIO()
        with patch.object(ASSEMBLY.sys, 'argv', ['assemble.py']), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):self.assertEqual(ASSEMBLY.main(), 75)
        self.assertEqual(out.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
