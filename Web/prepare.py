#!/usr/bin/python3
"""Prepare a PARTIAL nginx HTTPS ingress intention; never run or publish it.

Three existing private HTTPS gateways are required. DNS UDP/TCP service, mail
TCP protocols, application provisioning, certificate cryptography/validity,
nginx syntax/loaded generation and client locality are outside this profile.
Protected file bytes are bound, not authenticated or certified usable.
"""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_web_inputs',
    Path(__file__).resolve().parents[1] / 'PostgreSQL/prepare.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
KERNEL = BASE.KERNEL
Pending = BASE.Pending
INPUT = Path('/etc/debian13s4/web.json')
APPLICATIONS = ('mk8.sava', 'mk8.drava', 'mk8.email')
MAX_INPUT = 8192
MAX_PEM = 65536
MAX_OUTPUT = 131073
ATTEMPT_SECONDS = 10
# These are product protocol routes, not deployment domains or allocations.
MAIL_EXACT = ('/.well-known/jmap', '/jmap/session', '/jmap/api', '/jmap/event',
    '/.well-known/caldav', '/.well-known/carddav', '/dav',
    '/ews/exchange.asmx', '/autodiscover/autodiscover.xml',
    '/.well-known/oauth-authorization-server', '/.well-known/openid-configuration',
    '/oauth/jwks', '/oauth/userinfo', '/oauth/authorize', '/oauth/token', '/oauth/revoke')
MAIL_PREFIX = ('/jmap/upload/', '/jmap/download/', '/dav/')


def hostname(value):
    if (type(value) is not str or not 3 <= len(value) <= 253 or value != value.lower() or
        '.' not in value or re.fullmatch(r'[a-z0-9.-]+', value) is None):
        raise Pending('unsupported explicit ingress hostname')
    labels = value.split('.')
    if (any(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) is None
            for part in labels) or re.fullmatch(r'[a-z][a-z0-9-]*', labels[-1]) is None):
        raise Pending('noncanonical ingress DNS name')
    return value


def material_path(value):
    if (type(value) is not str or not 2 <= len(value) <= 240 or
        re.fullmatch(r'/[A-Za-z0-9_./-]+', value) is None or
        any(part in ('', '.', '..') for part in value.split('/')[1:]) or
        os.path.normpath(value) != value):
        raise Pending('unsupported explicit ingress material path')
    return value


def checked(value):
    fields = {'schema', 'applications'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported ingress input schema')
    KERNEL.known(value['applications'], set(APPLICATIONS), set(APPLICATIONS))
    names, ports, keys, public = set(), set(), set(), set()
    fields = {'hostname', 'certificate', 'private_key', 'upstream_port',
              'upstream_name', 'upstream_ca', 'body_bytes', 'idle_seconds'}
    for app in APPLICATIONS:
        item = value['applications'][app]
        KERNEL.known(item, fields, fields)
        name = hostname(item['hostname']); hostname(item['upstream_name'])
        for field, minimum, maximum in (('upstream_port', 1024, 65535),
            ('body_bytes', 1024, 1073741824), ('idle_seconds', 10, 600)):
            if type(item[field]) is not int or not minimum <= item[field] <= maximum:
                raise Pending('unsupported explicit ingress bound')
        port = item['upstream_port']
        if name in names or port in ports or port == 5432:
            raise Pending('shared or reserved ingress identity')
        names.add(name); ports.add(port)
        for field in ('certificate', 'private_key', 'upstream_ca'):
            material_path(item[field])
        keys.add(item['private_key'])
        public.update((item['certificate'], item['upstream_ca']))
    if keys & public:
        raise Pending('private key reused as public ingress material')
    return json.loads(BASE.canonical(value))


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite ingress input')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid ingress JSON') from error
    if raw != BASE.canonical(value):
        raise Pending('ingress input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def pem(raw, private):
    # A narrow PEM delivery grammar ONLY. This deliberately does not decode
    # ASN.1, verify signatures/names/dates/key pairing, or trust the issuer.
    label = b'PRIVATE KEY' if private else b'CERTIFICATE'
    begin = b'-----BEGIN ' + label + b'-----\n'
    end = b'-----END ' + label + b'-----\n'
    remaining, blocks = raw, 0
    while remaining:
        if not remaining.startswith(begin) or end not in remaining:
            raise Pending('unsupported ingress PEM framing')
        body, remaining = remaining[len(begin):].split(end, 1)
        lines = body[:-1].split(b'\n') if body.endswith(b'\n') else []
        if (not lines or any(len(line) != 64 for line in lines[:-1]) or
            not 1 <= len(lines[-1]) <= 64):
            raise Pending('unsupported ingress PEM line grammar')
        encoded = b''.join(lines)
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise Pending('invalid ingress PEM base64') from error
        if not decoded or base64.b64encode(decoded) != encoded:
            raise Pending('noncanonical or empty ingress PEM')
        blocks += 1
        if blocks > (1 if private else 16):
            raise Pending('ingress PEM block count exceeds profile')
    if blocks == 0:
        raise Pending('missing ingress PEM')
    return blocks


def materials(settings, end):
    inputs = {}
    for app in APPLICATIONS:
        item = settings['applications'][app]
        for field in ('certificate', 'private_key', 'upstream_ca'):
            name = item[field]
            if name in inputs:
                continue
            raw, source = BASE.read_protected(Path(name), MAX_PEM, field == 'private_key', end)
            count = pem(raw, field == 'private_key')
            inputs[name] = {'source': source, 'pem_blocks': count,
                            'kind': 'private-key' if field == 'private_key' else 'certificate'}
    return inputs


def proxy(item):
    return (f"            proxy_pass https://127.0.0.1:{item['upstream_port']};\n"
        '            proxy_http_version 1.1;\n'
        f"            proxy_set_header Host {item['hostname']};\n"
        '            proxy_set_header X-Forwarded-Host $host;\n'
        '            proxy_set_header X-Forwarded-Proto https;\n'
        '            proxy_set_header X-Forwarded-For $remote_addr;\n'
        '            proxy_set_header X-Real-IP $remote_addr;\n'
        '            proxy_set_header Forwarded "";\n'
        '            proxy_set_header Proxy "";\n'
        '            proxy_set_header Upgrade $http_upgrade;\n'
        '            proxy_set_header Connection $s4_connection;\n'
        '            proxy_ssl_server_name on;\n'
        f"            proxy_ssl_name {item['upstream_name']};\n"
        f"            proxy_ssl_trusted_certificate {item['upstream_ca']};\n"
        '            proxy_ssl_verify on;\n            proxy_ssl_verify_depth 4;\n'
        '            proxy_ssl_protocols TLSv1.2 TLSv1.3;\n'
        '            proxy_next_upstream off;\n            proxy_redirect off;\n'
        '            proxy_buffering off;\n            proxy_request_buffering off;\n'
        '            proxy_ignore_headers X-Accel-Redirect X-Accel-Buffering;\n'
        '            proxy_max_temp_file_size 0;\n            proxy_connect_timeout 5s;\n'
        f"            proxy_read_timeout {item['idle_seconds']}s;\n"
        f"            proxy_send_timeout {item['idle_seconds']}s;\n")


def render(settings):
    settings = checked(settings)
    text = ('user www-data;\nworker_processes auto;\npid /run/debian13s4-web/nginx.pid;\n'
        'error_log stderr warn;\nevents { worker_connections 1024; }\nhttp {\n'
        '    server_tokens off;\n    access_log off;\n    merge_slashes on;\n'
        '    client_header_timeout 10s;\n    client_body_timeout 30s;\n'
        '    send_timeout 30s;\n    keepalive_timeout 30s;\n'
        '    client_body_temp_path /run/debian13s4-web/body;\n'
        '    map $http_upgrade $s4_connection { default upgrade; "" close; }\n'
        '    server { listen 80 default_server; listen [::]:80 default_server;\n'
        '        server_name ""; return 444; }\n'
        '    server { listen 443 ssl default_server; listen [::]:443 ssl default_server;\n'
        '        ssl_reject_handshake on; return 444; }\n')
    for index, app in enumerate(APPLICATIONS):
        name = settings['applications'][app]['hostname']
        text += (f'    map $http_host $s4_host_{index} {{ default 0; '
                 f'{name} 1; {name}:443 1; }}\n')
    for index, app in enumerate(APPLICATIONS):
        item = settings['applications'][app]; name = item['hostname']
        text += (f'    server {{ listen 80; listen [::]:80; server_name {name};\n'
                 f'        return 308 https://{name}$request_uri; }}\n'
                 f'    server {{ listen 443 ssl; listen [::]:443 ssl; server_name {name};\n'
                 f'        ssl_certificate {item["certificate"]};\n'
                 f'        ssl_certificate_key {item["private_key"]};\n'
                 '        ssl_protocols TLSv1.2 TLSv1.3;\n'
                 '        ssl_session_tickets off;\n'
                 f'        client_max_body_size {item["body_bytes"]};\n'
                 f'        if ($ssl_server_name != {name}) {{ return 421; }}\n'
                 f'        if ($host != {name}) {{ return 421; }}\n'
                 f'        if ($s4_host_{index} = 0) {{ return 421; }}\n'
                 '        add_header Strict-Transport-Security "max-age=86400" always;\n'
                 '        add_header X-Content-Type-Options nosniff always;\n')
        if app == 'mk8.email':
            # Block double decoding and encoded separators before the allowlist.
            # nginx location matching normalizes URI, while proxy_pass without a
            # URI preserves the client's URI. No public admin catch-all exists.
            text += '        if ($request_uri ~* "%25|%2f|%5c|%00") { return 400; }\n'
            for path in MAIL_EXACT:
                text += f'        location = {path} {{\n' + proxy(item) + '        }\n'
            for path in MAIL_PREFIX:
                text += f'        location ^~ {path} {{\n' + proxy(item) + '        }\n'
            text += '        location / { return 404; }\n'
        else:
            if app == 'mk8.drava':
                text += ('        location ^~ /mk8.drava.proxy.v1.ServiceRegistry/ { return 404; }\n')
            text += ('        location ~* ^/(health|metrics|internal|admin|_drava)(/|$) { return 404; }\n'
                     '        location / {\n' + proxy(item) + '        }\n')
        text += '    }\n'
    return text + '}\n'


def prepare(deadline=None, scope=KERNEL.namespace):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited ingress deadline')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(scope(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing ingress caller context')
    settings = configuration(end)
    inputs = materials(settings['value'], end)
    config = render(settings['value'])
    record = {'schema': 1, 'profile': 'nginx-private-https-three-gateway-intention-v1',
        'state': 'ingress-configuration-intention-only', 'namespace': context,
        'configuration': settings, 'materials': inputs, 'nginx': config,
        'nginx_sha256': hashlib.sha256(config.encode('ascii')).hexdigest()}
    payload = BASE.canonical(record)
    if len(payload) > MAX_OUTPUT:
        raise Pending('ingress intention exceeds output bound')
    if configuration(end) != settings or materials(settings['value'], end) != inputs:
        raise Pending('ingress configuration or TLS material changed')
    if KERNEL.uint(scope(), 0xffffffffffffffff) != context:
        raise Pending('ingress caller context changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('ingress preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('ingress preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete ingress intention publication')
        sink.flush()
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == '__main__':
    sys.exit(main())
