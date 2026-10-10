"""Private protected-input/TLS API delivery models; no real socket or crypto."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import ssl
import unittest
from unittest.mock import patch
from fixture_web import PrivateWeb, ROOT


def sava_report():
    return {'status':'ready','component':'gateway','application':'ready','metadata':'ready',
        'integrity':{'status':'healthy','complete':False,'checkedChunks':0,'missingChunks':0,
                     'corruptChunks':0,'customerKeyChunks':0,'checkedAt':None}}


def http(app, body=None, headers=None, status=b'HTTP/1.0 200 OK'):
    if body is None:
        body=b'running' if app=='mk8.drava' else json.dumps(sava_report() if app=='mk8.sava' else {'status':'ready'}).encode()
    media=b'text/plain; charset=utf-8' if app=='mk8.drava' else b'application/json; charset=utf-8'
    rows=[b'Content-Type: '+media,b'Content-Length: '+str(len(body)).encode()]
    if headers is not None:rows=headers
    return status+b'\r\n'+b'\r\n'.join(rows)+b'\r\n\r\n'+body


class UpstreamTests(unittest.TestCase):
    def setUp(self):
        self.fixture=PrivateWeb();self.addCleanup(self.fixture.close)
        spec=importlib.util.spec_from_file_location('private_upstream',ROOT/'Web/upstream.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.m.PREP=self.fixture.m.PREP;self.m.KERNEL=self.fixture.m.KERNEL
        self.m.Pending=self.fixture.m.Pending
        self.calls=[]
    def delivery(self, app, item, ca, end):
        self.calls.append((app,item.copy(),ca,end))
        return {'tls':'TLSv1.3','certificate':b'PRIVATE CERTIFICATE DELIVERY NOT CRYPTO',
                'response':http(app)}
    def test_all_three_protected_gateways_and_distinct_readiness_liveness_reports(self):
        raw=self.m.check(self.delivery);record=json.loads(raw)
        self.assertEqual(record['state'],'upstream-readiness-liveness-source-only')
        self.assertEqual([call[0] for call in self.calls],list(self.m.PREP.APPLICATIONS))
        self.assertEqual(record['observations']['mk8.drava']['report'],{'kind':'gateway-liveness-only','status':'running'})
        self.assertFalse(record['observations']['mk8.sava']['report']['report']['integrity']['complete'])
        for app,item,ca,end in self.calls:
            self.assertEqual(ca,Path(item['upstream_ca']).read_bytes())
            report=record['observations'][app]
            self.assertEqual(report['response_sha256'],hashlib.sha256(http(app)).hexdigest())
            self.assertEqual(report['endpoint'],['127.0.0.1',item['upstream_port']])
    def test_request_is_fixed_get_with_explicit_host_no_forwarded_identity_or_credentials(self):
        for app in self.m.PREP.APPLICATIONS:
            item=self.fixture.value['applications'][app];raw=self.m.request(app,item)
            self.assertEqual(raw,(f'GET {self.m.ROUTES[app]} HTTP/1.0\r\nHost: {item["hostname"]}\r\nConnection: close\r\nAccept: application/json, text/plain\r\nAccept-Encoding: identity\r\n\r\n').encode())
            self.assertNotIn(b'Authorization:',raw);self.assertNotIn(b'Forwarded',raw)
    def test_noncallable_delivery_refuses_before_protected_preparation(self):
        with patch.object(self.m.PREP,'prepare',side_effect=AssertionError('entry')):
            with self.assertRaises(self.m.Pending):self.m.check(False)
    def test_missing_protected_input_refuses_before_probe(self):
        self.m.PREP.INPUT.unlink()
        with self.assertRaises(FileNotFoundError):self.m.check(self.delivery)
        self.assertEqual(self.calls,[])
    def test_untrusted_ca_refuses_before_probe(self):
        Path(self.fixture.value['applications']['mk8.sava']['upstream_ca']).chmod(0o666)
        with self.assertRaises(self.m.Pending):self.m.check(self.delivery)
        self.assertEqual(self.calls,[])
    def test_initial_context_requires_positive_true_uint64(self):
        for context in (0,False,-1,2**64):
            with self.subTest(context=context),patch.object(self.m.KERNEL,'namespace',return_value=context):
                with self.assertRaises(self.m.Pending):self.m.check(self.delivery)
        self.assertEqual(self.calls,[])
    def test_invalid_and_expired_inherited_windows_refuse_before_preparation(self):
        for end in (False,float('nan'),float('inf'),0):
            with self.subTest(end=end),patch.object(self.m.PREP,'prepare',side_effect=AssertionError('entry')):
                with self.assertRaises(self.m.Pending):self.m.check(self.delivery,end)
        self.assertEqual(self.calls,[])
    def test_positive_inherited_window_is_passed_unchanged_to_all_readers(self):
        end=self.m.KERNEL.now()+5
        self.m.check(self.delivery,end)
        self.assertEqual([call[3] for call in self.calls],[end]*3)
    def test_later_parent_cannot_extend_own_thirty_second_window(self):
        with patch.object(self.m.KERNEL,'now',return_value=10):self.m.check(self.delivery,100)
        self.assertEqual([call[3] for call in self.calls],[40]*3)
    def test_each_probe_expiry_refuses_later_entries(self):
        for selected in self.m.PREP.APPLICATIONS:
            self.calls=[]
            def read(app,item,ca,end):
                result=self.delivery(app,item,ca,end)
                if app==selected:self.clock.return_value=end
                return result
            with patch.object(self.m.KERNEL,'now',return_value=10) as self.clock:
                with self.assertRaises(self.m.Pending):self.m.check(read)
            expected=list(self.m.PREP.APPLICATIONS);self.assertEqual([c[0] for c in self.calls],expected[:expected.index(selected)+1])
    def test_configuration_change_during_probe_withholds_receipt(self):
        def read(app,item,ca,end):
            result=self.delivery(app,item,ca,end)
            if app=='mk8.email':
                self.fixture.value['applications']['mk8.sava']['body_bytes']=2048;self.fixture.settings()
            return result
        with self.assertRaises(self.m.Pending):self.m.check(read)
    def test_ca_change_between_preparation_and_direct_read_refuses_before_probe(self):
        original=self.m.PREP.prepare
        def prepare(**kwargs):
            result=original(**kwargs)
            path=Path(self.fixture.value['applications']['mk8.sava']['upstream_ca']);path.write_bytes(self.fixture.pem(body=b'changed CA MODEL'))
            return result
        with patch.object(self.m.PREP,'prepare',side_effect=prepare):
            with self.assertRaises(self.m.Pending):self.m.check(self.delivery)
        self.assertEqual(self.calls,[])
    def test_final_context_drift_withholds_prepared_receipt(self):
        original=self.m.PREP.prepare;count=0
        def prepare(**kwargs):
            nonlocal count
            count+=1;value=original(**kwargs)
            if count==2:self.m.KERNEL.namespace=lambda:4712
            return value
        with patch.object(self.m.PREP,'prepare',side_effect=prepare):
            with self.assertRaises(self.m.Pending):self.m.check(self.delivery)
        self.assertEqual(len(self.calls),3)
    def test_receipt_encoding_precedes_final_protected_preparation(self):
        original=self.m.PREP.prepare;canonical=self.m.PREP.BASE.canonical;calls=0;encoded=[]
        def encode(value):
            if isinstance(value,dict) and value.get('state')=='upstream-readiness-liveness-source-only':encoded.append(calls)
            return canonical(value)
        def prepare(**kwargs):
            nonlocal calls
            calls+=1
            if calls==2:self.assertEqual(encoded,[1])
            return original(**kwargs)
        with patch.object(self.m.PREP,'prepare',side_effect=prepare),patch.object(self.m.PREP.BASE,'canonical',side_effect=encode):
            raw=self.m.check(self.delivery)
        self.assertEqual(calls,2);self.assertEqual(encoded,[1]);self.assertIs(type(raw),bytes)
    def test_receipt_output_bound_precedes_second_preparation(self):
        original=self.m.PREP.prepare
        with patch.object(self.m,'MAX_OUTPUT',1),patch.object(self.m.PREP,'prepare',wraps=original) as prepare:
            with self.assertRaises(self.m.Pending):self.m.check(self.delivery)
            self.assertEqual(prepare.call_count,1)
    def test_tls_delivery_requires_closed_fields_modern_version_and_true_certificate_bytes(self):
        variants=[{'tls':'TLSv1.1'}, {'certificate':bytearray(b'cert')}, {'certificate':b''},
                  {'certificate':b'x'*(self.m.MAX_CERTIFICATE+1)}, {'extra':True}]
        for values in variants:
            def read(app,item,ca,end):return {**self.delivery(app,item,ca,end),**values}
            with self.subTest(values=list(values)):
                with self.assertRaises(self.m.Pending):self.m.check(read)
    def test_http_success_accepts_fixed_or_connection_close_length(self):
        for app in self.m.PREP.APPLICATIONS:
            raw=http(app)
            self.assertEqual(self.m.response(raw,app),self.m.response(raw.replace(b'HTTP/1.0',b'HTTP/1.1'),app))
            head,body=raw.split(b'\r\n\r\n');head=b'\r\n'.join(row for row in head.split(b'\r\n') if not row.startswith(b'Content-Length:'))
            self.assertEqual(self.m.response(raw,app),self.m.response(head+b'\r\n\r\n'+body,app))
    def test_http_refuses_redirect_informational_failure_protocol_and_embedded_controls(self):
        for status in (b'HTTP/1.0 301 Moved',b'HTTP/1.1 100 Continue',b'HTTP/1.0 503 Unavailable',b'HTTP/2 200 OK',b'HTTP/1.1 200 OK\nBad'):
            with self.subTest(status=status):
                with self.assertRaises(self.m.Pending):self.m.response(http('mk8.email',status=status),'mk8.email')
    def test_header_duplicates_folded_controls_encodings_and_redirects_refuse(self):
        media=b'Content-Type: application/json'
        for rows in ([media,media],[media,b' content: fold'],[media,b'X-Test: \x00'],[media,b'X-Test: \t'],
                     [media,b'Transfer-Encoding: chunked'],[media,b'Content-Encoding: gzip'],[media,b'Location: https://other.invalid']):
            with self.subTest(rows=rows):
                with self.assertRaises(self.m.Pending):self.m.response(http('mk8.email',headers=rows),'mk8.email')
    def test_exact_content_length_rejects_partial_extra_negative_and_multiple_lengths(self):
        for value in (b'0',b'1',b'999999',b'-1',b'01',b'1, 1'):
            with self.subTest(value=value):
                with self.assertRaises(self.m.Pending):self.m.response(http('mk8.email',headers=[b'Content-Type: application/json',b'Content-Length: '+value]),'mk8.email')
    def test_header_body_and_total_capture_bounds_refuse(self):
        for raw in (http('mk8.email',headers=[b'X: '+b'x'*self.m.MAX_HEADERS]),http('mk8.email',body=b'x'*(self.m.MAX_BODY+1)),b'x'*(self.m.MAX_RESPONSE+1),bytearray(http('mk8.email'))):
            with self.subTest(size=len(raw)):
                with self.assertRaises(self.m.Pending):self.m.response(raw,'mk8.email')
    def test_email_readiness_rejects_unknown_duplicate_nonfinite_invalid_encoding_and_not_ready(self):
        for body in (b'{"status":"unavailable"}',b'{"status":"ready","extra":1}',b'{"status":"ready","status":"ready"}',b'{"status":NaN}',b'\xff',b'[]'):
            with self.subTest(body=body):
                with self.assertRaises(self.m.Pending):self.m.response(http('mk8.email',body=body),'mk8.email')
    def test_sava_selected_readiness_and_integrity_are_positive_typed_reports(self):
        cases=[('status','unavailable'),('component','application'),('application','unavailable'),('metadata','unavailable')]
        for field,value in cases:
            body=sava_report();body[field]=value
            with self.subTest(field=field):
                with self.assertRaises(self.m.Pending):self.m.response(http('mk8.sava',json.dumps(body).encode()),'mk8.sava')
        for field,value in (('status','corrupt'),('complete',0),('checkedChunks',True),('missingChunks',1),('corruptChunks',1),('customerKeyChunks',-1),('checkedAt','\n')):
            body=sava_report();body['integrity'][field]=value
            with self.subTest(field=field):
                with self.assertRaises(self.m.Pending):self.m.response(http('mk8.sava',json.dumps(body).encode()),'mk8.sava')
    def test_drava_liveness_never_substitutes_a_json_readiness_assertion(self):
        for body in (b'ready',b'running\n',b'{"status":"ready"}'):
            with self.subTest(body=body):
                with self.assertRaises(self.m.Pending):self.m.response(http('mk8.drava',body),'mk8.drava')
    def test_cli_missing_binary_sink_refuses_before_probe(self):
        with patch.object(self.m.sys,'argv',['upstream.py']),patch.object(self.m.sys,'stdout',io.StringIO()),patch.object(self.m,'check',side_effect=AssertionError('entry')):
            self.assertEqual(self.m.main(),75)
    def test_cli_cached_bytes_full_true_count_and_flush_are_required(self):
        class Sink:
            def __init__(self,count=None):self.buffer=self;self.raw=b'';self.flushed=False;self.count=count
            def write(self,raw):self.raw=raw;return len(raw) if self.count is None else self.count
            def flush(self):self.flushed=True
        for count,code in ((None,0),(False,75),(1,75)):
            sink=Sink(count)
            with patch.object(self.m.sys,'argv',['upstream.py']),patch.object(self.m.sys,'stdout',sink),patch.object(self.m,'check',return_value=b'receipt\n'):
                self.assertEqual(self.m.main(),code)
            self.assertEqual(sink.raw,b'receipt\n');self.assertEqual(sink.flushed,code==0)


class NativeDeliveryTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('native_upstream_model',ROOT/'Web/upstream.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.item={'hostname':'public.example.invalid','upstream_name':'gateway.example.invalid','upstream_port':9100}
        self.events=[];self.fail=None;self.parts=[http('mk8.email'),b'']
        outer=self
        class Raw:
            def settimeout(self,value):outer.events.append(('raw-timeout',value))
            def close(self):outer.events.append(('raw-close',))
        class Channel:
            def operation(self,name,*args):
                outer.events.append((name,*args))
                if outer.fail==name:raise OSError('private injected '+name)
            def settimeout(self,value):self.operation('timeout',value)
            def connect(self,target):self.operation('connect',target)
            def do_handshake(self):self.operation('handshake')
            def getpeercert(self,**kwargs):self.operation('certificate',kwargs);return b'CERTIFICATE MODEL'
            def version(self):return outer.version
            def selected_alpn_protocol(self):return outer.alpn
            def sendall(self,value):self.operation('send',value)
            def recv(self,limit):self.operation('recv',limit);return outer.parts.pop(0)
            def close(self):self.operation('channel-close')
        class Context:
            def __init__(self,protocol):outer.events.append(('context',protocol));self.verify_flags=0;outer.context=self
            def set_alpn_protocols(self,value):outer.events.append(('alpn',value))
            def load_verify_locations(self,**kwargs):outer.events.append(('ca',kwargs))
            def wrap_socket(self,raw,**kwargs):
                outer.events.append(('wrap',kwargs))
                if outer.fail=='wrap':raise OSError('private injected wrap')
                return Channel()
        self.version='TLSv1.3';self.alpn='http/1.1'
        self.patches=[patch.object(self.m.KERNEL,'now',return_value=10),patch.object(self.m.ssl,'SSLContext',Context),patch.object(self.m.socket,'socket',side_effect=lambda *args:(self.events.append(('socket',args)),Raw())[1])]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def run_native(self):return self.m.native('mk8.email',self.item,b'PRIVATE CA MODEL',20)
    def test_fixed_literal_endpoint_verified_san_ca_tls_and_http_request(self):
        result=self.run_native()
        self.assertEqual(result['response'],http('mk8.email'))
        self.assertIn(('socket',(socket.AF_INET,socket.SOCK_STREAM)),self.events)
        self.assertIn(('connect',('127.0.0.1',9100)),self.events)
        self.assertIn(('ca',{'cadata':'PRIVATE CA MODEL'}),self.events)
        self.assertIn(('wrap',{'server_hostname':'gateway.example.invalid','do_handshake_on_connect':False,'suppress_ragged_eofs':False}),self.events)
        self.assertEqual(self.context.verify_mode,ssl.CERT_REQUIRED);self.assertTrue(self.context.check_hostname)
        self.assertFalse(self.context.hostname_checks_common_name)
        self.assertEqual(self.context.minimum_version,ssl.TLSVersion.TLSv1_2);self.assertEqual(self.context.maximum_version,ssl.TLSVersion.TLSv1_3)
        self.assertTrue(self.context.verify_flags&ssl.VERIFY_X509_STRICT)
        self.assertIn(('send',self.m.request('mk8.email',self.item)),self.events)
        self.assertEqual(self.events.count(('channel-close',)),1);self.assertNotIn(('raw-close',),self.events)
        self.assertTrue(all(row[1]==3 for row in self.events if row[0] in ('timeout','raw-timeout')))
    def test_inherited_native_cap_is_smaller_than_own_three_second_window(self):
        self.m.native('mk8.email',self.item,b'CA MODEL',10.25)
        self.assertTrue(all(row[1]==.25 for row in self.events if row[0] in ('timeout','raw-timeout')))
    def test_wrap_failure_closes_only_the_owned_raw_socket(self):
        self.fail='wrap'
        with self.assertRaises(OSError):self.run_native()
        self.assertEqual(self.events.count(('raw-close',)),1);self.assertNotIn(('channel-close',),self.events)
    def test_each_failed_connection_handshake_send_receive_retires_channel_once(self):
        for operation in ('connect','handshake','send','recv'):
            self.events=[];self.fail=operation;self.parts=[http('mk8.email'),b'']
            with self.subTest(operation=operation):
                with self.assertRaises(OSError):self.run_native()
                self.assertEqual(self.events.count(('channel-close',)),1);self.assertNotIn(('raw-close',),self.events)
    def test_invalid_tls_version_or_alpn_cannot_send_request(self):
        for version,alpn in (('TLSv1.1','http/1.1'),('TLSv1.3','h2')):
            self.version=version;self.alpn=alpn;self.events=[]
            with self.subTest(version=version,alpn=alpn):
                with self.assertRaises(self.m.Pending):self.run_native()
                self.assertFalse(any(row[0]=='send' for row in self.events));self.assertEqual(self.events.count(('channel-close',)),1)
    def test_capture_bound_refuses_before_receipt_and_retires_channel(self):
        self.parts=[b'x'*(self.m.MAX_RESPONSE+1)]
        with self.assertRaises(self.m.Pending):self.run_native()
        self.assertEqual(self.events.count(('channel-close',)),1)
    def test_final_native_expiry_withholds_captured_response(self):
        values=[10]*100
        original=self.parts
        class EndParts(list):
            def pop(inner,index=0):
                value=super().pop(index)
                if not value:self.clock.return_value=13
                return value
        self.parts=EndParts(original)
        with patch.object(self.m.KERNEL,'now',return_value=10) as self.clock:
            with self.assertRaises(self.m.Pending):self.run_native()
        self.assertEqual(self.events.count(('channel-close',)),1)


if __name__=='__main__':unittest.main()
