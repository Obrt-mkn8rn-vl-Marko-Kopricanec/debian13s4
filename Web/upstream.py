#!/usr/bin/python3
"""Bound protected private HTTPS readiness/liveness SOURCE observations.

Default invocation CONNECTS to three configured loopback gateways. It is not
authorized by source acceptance or private delivery tests. TLS verifies the
supplied CA and SAN hostname under honest Python/OpenSSL; it does not prove
process ownership, app release/catalog identity, CRUD or future readiness.
Drava supplies liveness ONLY. This standalone entry is not a controller join.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import socket
import ssl
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_upstream_prepare',
    Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
ROUTES = {'mk8.sava': '/health/ready', 'mk8.drava': '/_drava/live',
          'mk8.email': '/health/ready'}
MAX_HEADERS = 8192
MAX_BODY = 65536
MAX_RESPONSE = MAX_HEADERS + MAX_BODY + 4
MAX_CERTIFICATE = 65536
MAX_OUTPUT = PREP.MAX_OUTPUT + 32768
ATTEMPT_SECONDS = 30


def timeout(end):
    PREP.BASE.fence(end)
    remaining = end - KERNEL.now()
    if remaining <= 0:
        raise Pending('upstream operation admission expired')
    return remaining


def request(app, item):
    if app not in ROUTES:
        raise Pending('unsupported upstream application')
    PREP.hostname(item['hostname']); PREP.hostname(item['upstream_name'])
    if type(item['upstream_port']) is not int or not 1024 <= item['upstream_port'] <= 65535:
        raise Pending('invalid explicit upstream port')
    return (f'GET {ROUTES[app]} HTTP/1.0\r\nHost: {item["hostname"]}\r\n'
            'Connection: close\r\nAccept: application/json, text/plain\r\n'
            'Accept-Encoding: identity\r\n\r\n').encode('ascii')


def native(app, item, ca, end):
    # No DNS, proxy, environment CA defaults, redirects, client credential,
    # retry, key logging or unchecked CA pathname reopen. Every blocking socket
    # operation inherits the SAME capped BOOTTIME admission, not a hard timer.
    payload = request(app, item)
    if type(ca) is not bytes or not ca or len(ca) > PREP.MAX_PEM:
        raise Pending('invalid protected upstream CA bytes')
    until = min(end, KERNEL.now() + KERNEL.QUERY_SECONDS)
    timeout(until)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.hostname_checks_common_name = False
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.set_alpn_protocols(['http/1.1'])
    context.load_verify_locations(cadata=ca.decode('ascii'))
    # Ownership transfers only after wrap_socket succeeds. The retired raw
    # descriptor must not be closed a second time by this module.
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout(until))
        channel = context.wrap_socket(raw, server_hostname=item['upstream_name'],
            do_handshake_on_connect=False, suppress_ragged_eofs=False)
    except BaseException:
        raw.close()
        raise
    try:
        channel.settimeout(timeout(until))
        channel.connect(('127.0.0.1', item['upstream_port']))
        channel.settimeout(timeout(until)); channel.do_handshake()
        certificate = channel.getpeercert(binary_form=True)
        version, alpn = channel.version(), channel.selected_alpn_protocol()
        if (type(certificate) is not bytes or not 1 <= len(certificate) <= MAX_CERTIFICATE or
            version not in ('TLSv1.2', 'TLSv1.3') or alpn not in (None, 'http/1.1')):
            raise Pending('unsupported upstream TLS observation')
        channel.settimeout(timeout(until)); channel.sendall(payload)
        parts = bytearray()
        while True:
            channel.settimeout(timeout(until))
            part = channel.recv(min(4096, MAX_RESPONSE + 1 - len(parts)))
            if not part:
                break
            parts.extend(part)
            if len(parts) > MAX_RESPONSE:
                raise Pending('upstream response exceeds capture bound')
        timeout(until)
        return {'tls': version, 'certificate': certificate, 'response': bytes(parts)}
    finally:
        channel.close()


def response(raw, app):
    if type(raw) is not bytes or not raw or len(raw) > MAX_RESPONSE:
        raise Pending('invalid immutable upstream response')
    header, separator, body = raw.partition(b'\r\n\r\n')
    if not separator or len(header) > MAX_HEADERS or len(body) > MAX_BODY:
        raise Pending('upstream header/body bound or delimiter')
    lines = header.split(b'\r\n')
    if re.fullmatch(rb'HTTP/1\.[01] 200 [\x20-\x7e]*', lines[0]) is None:
        raise Pending('upstream response is not final success')
    fields = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        if (not colon or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None or
            any(byte < 32 or byte > 126 for byte in value)):
            raise Pending('unsupported upstream header grammar')
        name = name.lower()
        if name in fields:
            raise Pending('duplicate upstream header')
        fields[name] = value.strip(b' ')
    if any(name in fields for name in (b'transfer-encoding', b'content-encoding', b'location')):
        raise Pending('encoded/redirected upstream response is outside profile')
    if b'content-length' in fields:
        value = fields[b'content-length']
        if re.fullmatch(rb'0|[1-9][0-9]{0,5}', value) is None or int(value) != len(body):
            raise Pending('upstream content length differs')
    media = fields.get(b'content-type', b'').lower().replace(b' ', b'')
    if app == 'mk8.drava':
        if media not in (b'text/plain', b'text/plain;charset=utf-8') or body != b'running':
            raise Pending('Drava liveness response differs')
        return {'kind': 'gateway-liveness-only', 'status': 'running'}
    if media not in (b'application/json', b'application/json;charset=utf-8'):
        raise Pending('upstream readiness JSON media type differs')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite readiness JSON')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid upstream readiness JSON') from error
    if app == 'mk8.email':
        KERNEL.known(value, {'status'}, {'status'})
        if value['status'] != 'ready':
            raise Pending('Email application transport is not reported ready')
    elif app == 'mk8.sava':
        fields = {'status', 'component', 'application', 'metadata', 'integrity'}
        KERNEL.known(value, fields, fields)
        if (value['status'] != 'ready' or value['component'] != 'gateway' or
            value['application'] != 'ready' or value['metadata'] != 'ready'):
            raise Pending('Sava gateway/application/metadata is not reported ready')
        integrity = value['integrity']
        fields = {'status', 'complete', 'checkedChunks', 'missingChunks', 'corruptChunks',
                  'customerKeyChunks', 'checkedAt'}
        KERNEL.known(integrity, fields, fields)
        if integrity['status'] != 'healthy' or type(integrity['complete']) is not bool:
            raise Pending('unsupported reported Sava integrity')
        for name in ('checkedChunks', 'missingChunks', 'corruptChunks', 'customerKeyChunks'):
            KERNEL.uint(integrity[name], 0x7fffffffffffffff)
        if integrity['missingChunks'] or integrity['corruptChunks']:
            raise Pending('reported Sava chunk failures')
        at = integrity['checkedAt']
        if at is not None and (type(at) is not str or len(at) > 64 or
                              re.fullmatch(r'[0-9T:+.Z-]+', at) is None):
            raise Pending('unsupported reported Sava integrity timestamp')
    else:
        raise Pending('unsupported readiness application')
    return {'kind': 'gateway-reported-readiness', 'report': value}


def check(read=None, deadline=None):
    if read is None:
        read = native
    if not callable(read):
        raise Pending('unsupported HTTPS observation delivery')
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited upstream window')
        end = min(end, deadline)
    timeout(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing upstream caller context')
    original = PREP.prepare(deadline=end)
    intention = json.loads(original)
    if intention['namespace'] != context:
        raise Pending('upstream preparation caller differs')
    observations = {}
    for app in PREP.APPLICATIONS:
        item = intention['configuration']['value']['applications'][app]
        ca, fact = PREP.BASE.read_protected(Path(item['upstream_ca']), PREP.MAX_PEM, False, end)
        if fact != intention['materials'][item['upstream_ca']]['source']:
            raise Pending('protected upstream CA changed before entry')
        timeout(end)
        observed = read(app, item, ca, end)
        KERNEL.known(observed, {'tls', 'certificate', 'response'}, {'tls', 'certificate', 'response'})
        certificate = observed['certificate']
        if (observed['tls'] not in ('TLSv1.2', 'TLSv1.3') or type(certificate) is not bytes or
            not 1 <= len(certificate) <= MAX_CERTIFICATE):
            raise Pending('invalid upstream TLS delivery')
        report = response(observed['response'], app)
        observations[app] = {'endpoint': ['127.0.0.1', item['upstream_port']],
            'server_name': item['upstream_name'], 'host': item['hostname'], 'path': ROUTES[app],
            'tls': observed['tls'], 'certificate_sha256': hashlib.sha256(certificate).hexdigest(),
            'response_sha256': hashlib.sha256(observed['response']).hexdigest(), 'report': report}
        timeout(end)
    payload = PREP.BASE.canonical({'schema': 1, 'profile': 'private-https-three-gateway-probes-v1',
        'state': 'upstream-readiness-liveness-source-only', 'namespace': context,
        'intention': intention, 'observations': observations})
    if len(payload) > MAX_OUTPUT:
        raise Pending('upstream receipt output bound')
    if PREP.prepare(deadline=end) != original:
        raise Pending('protected upstream inputs changed during probes')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('upstream caller context changed')
    timeout(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('upstream probes accept no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('upstream probes require binary stdout')
        payload = check()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete upstream receipt publication')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('debian13s4 upstream pending: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
