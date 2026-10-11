#!/usr/bin/python3
"""Bind selected Sava Gateway HTTPS FILE intentions to real nginx intentions.

This checks a narrow explicit Kestrel JSON/PEM profile and repeated protected
bytes. It neither runs CLR/TLS nor authenticates certificates, loaded listeners,
service-readable credentials, release ownership or application readiness.
"""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys


def owned(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
SAVA = owned('debian13s4_sava_ingress_transport', ROOT/'Applications/sava_transport.py')
WEB = owned('debian13s4_sava_ingress_web', ROOT/'Web/prepare.py')
BASE, KERNEL, Pending = SAVA.BASE, SAVA.KERNEL, SAVA.Pending
MAX_OUTPUT = 8388609
ATTEMPT_SECONDS = 600
SAVA_FIELDS = {'schema', 'profile', 'state', 'namespace', 'identities', 'identity_sha256', 'settings'}
WEB_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration', 'materials', 'nginx', 'nginx_sha256'}


def finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise Pending('nonfinite ingress correspondence number')
    return value


def prepared(module, end, context):
    if module is not SAVA and module is not WEB:
        raise Pending('unsupported owned Sava ingress dependency')
    BASE.fence(end)
    try:
        raw = (SAVA.prepare(deadline=end) if module is SAVA else
            WEB.prepare(deadline=end, scope=WEB.KERNEL.namespace))
    except (SAVA.Pending, WEB.Pending) as error:
        raise Pending('Sava ingress dependency refused') from error
    if type(raw) is not bytes or len(raw) > module.MAX_OUTPUT:
        raise Pending('unsupported complete Sava ingress dependency bytes')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_float=finite, parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite dependency')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid Sava ingress dependency JSON') from error
    fields, profile, state = ((SAVA_FIELDS, 'sava-paired-transport-policy-files-v1',
        'sava-split-transport-policy-source-only') if module is SAVA else
        (WEB_FIELDS, 'nginx-private-https-three-gateway-intention-v1', 'ingress-configuration-intention-only'))
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['profile'] != profile or value['state'] != state or
        KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or raw != BASE.canonical(value)):
        raise Pending('Sava ingress dependency schema, scope or canonical bytes differ')
    BASE.fence(end)
    return raw, value


def material_path(value):
    path = WEB.material_path(value)
    try:
        name = str(Path(path).relative_to(SAVA.SETTINGS_ROOT))
    except ValueError as error:
        raise Pending('Gateway TLS files must be explicit product settings descendants') from error
    SAVA.IDENTITIES.RELEASE.relative(name)
    if not name.endswith('.pem'):
        raise Pending('Gateway TLS material requires explicit PEM files')
    return path


def listener(gateway, ingress, rpc):
    """Selected file syntax/correspondence, not the native Kestrel validator."""
    port = KERNEL.uint(ingress['upstream_port'], 65535)
    if port < 1024 or port == 5432:
        raise Pending('unsupported explicit Gateway ingress port')
    KERNEL.known(gateway, {'Sava', 'ApplicationTransport', 'Kestrel'},
        {'Sava', 'ApplicationTransport', 'Kestrel'})
    kestrel = gateway['Kestrel']
    KERNEL.known(kestrel, {'Endpoints'}, {'Endpoints'})
    KERNEL.known(kestrel['Endpoints'], {'Private'}, {'Private'})
    selected = kestrel['Endpoints']['Private']
    KERNEL.known(selected, {'Url', 'Protocols', 'Certificate'}, {'Url', 'Protocols', 'Certificate'})
    certificate = selected['Certificate']
    KERNEL.known(certificate, {'Path', 'KeyPath', 'Password'}, {'Path', 'KeyPath', 'Password'})
    if (type(selected['Url']) is not str or
        selected['Url'] != 'https://127.0.0.1:'+str(port) or
        type(selected['Protocols']) is not str or selected['Protocols'] != 'Http1' or
        type(certificate['Password']) is not str or certificate['Password'] != ''):
        raise Pending('Gateway requires one explicit loopback HTTPS/HTTP1 unencrypted PEM intention')
    public, private = material_path(certificate['Path']), material_path(certificate['KeyPath'])
    if public == private or private == ingress['upstream_ca'] or port == KERNEL.uint(rpc['port'], 65535):
        raise Pending('Gateway TLS material or RPC/listener ports conflict')
    return {'address': '127.0.0.1', 'port': port, 'scheme': 'https',
        'protocol': 'Http1', 'certificate': public, 'private_key': private,
        'server_name_intention': ingress['upstream_name']}


def observe(sava, web, end):
    descriptor_raw, descriptor, descriptor_source = SAVA.document(SAVA.INPUT, SAVA.MAX_INPUT, end)
    descriptor = SAVA.checked(descriptor)
    gateway_raw, gateway, gateway_source = SAVA.document(
        Path(descriptor['gateway_settings']), SAVA.MAX_SETTINGS, end)
    settings = sava['settings']
    if (BASE.canonical(descriptor_source) != BASE.canonical(settings['configuration_source']) or
        BASE.canonical(gateway_source) != BASE.canonical(settings['gateway_source'])):
        raise Pending('Gateway files differ from the complete owned Sava preparation')
    rpc = SAVA.settings(gateway, descriptor['access_key'])
    if (BASE.canonical(rpc) != BASE.canonical(settings['rpc']) or
        hashlib.sha256(BASE.canonical(gateway['Sava'])).hexdigest() != settings['policy_sha256'] or
        hashlib.sha256(BASE.canonical(gateway['ApplicationTransport'])).hexdigest() != settings['transport_sha256']):
        raise Pending('whole Gateway policy/transport differ from owned Sava preparation')
    try:
        config = WEB.checked(web['configuration']['value'])
        nginx = WEB.render(config)
        ingress = config['applications']['mk8.sava']
        selected = listener(gateway, ingress, rpc)
    except (SAVA.Pending, WEB.Pending) as error:
        raise Pending('Sava listener or real ingress renderer refused') from error
    if (type(web['nginx']) is not str or web['nginx'] != nginx or
        web['nginx_sha256'] != hashlib.sha256(nginx.encode('ascii')).hexdigest()):
        raise Pending('whole ingress intention differs from the real renderer')
    body = gateway['Sava']['MaximumRequestBodyBytes']
    if type(body) is not int or ingress['body_bytes'] > body:
        raise Pending('public ingress body intention exceeds selected Sava policy')
    key = selected['private_key']
    public_files = {row[field] for row in config['applications'].values()
        for field in ('certificate', 'upstream_ca')}
    if key in public_files or key == descriptor['access_key']:
        raise Pending('Gateway private key is reused as public or RPC material')
    certificate_raw, certificate_source = BASE.read_protected(
        Path(selected['certificate']), WEB.MAX_PEM, False, end)
    private_raw, private_source = BASE.read_protected(Path(key), WEB.MAX_PEM, True, end)
    try:
        certificate_blocks = WEB.pem(certificate_raw, False)
        private_blocks = WEB.pem(private_raw, True)
    except WEB.Pending as error:
        raise Pending('Gateway TLS material grammar refused') from error
    row = web['materials'][ingress['upstream_ca']]
    KERNEL.known(row, {'source', 'pem_blocks', 'kind'}, {'source', 'pem_blocks', 'kind'})
    if row['kind'] != 'certificate':
        raise Pending('ingress CA must remain reported public material')
    record = {'configuration_source': descriptor_source, 'gateway_source': gateway_source,
        'listener': selected, 'certificate_source': certificate_source,
        'private_key_source': private_source, 'certificate_blocks': certificate_blocks,
        'private_key_blocks': private_blocks, 'upstream_ca': row,
        'ingress_body_bytes': ingress['body_bytes'], 'policy_body_bytes': body}
    # Secret whole-file/key bytes stay private and are compared after encoding.
    return record, (descriptor_raw, gateway_raw, certificate_raw, private_raw)


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited Sava ingress window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing Sava ingress namespace')
    sava_raw, sava = prepared(SAVA, end, context)
    web_raw, web = prepared(WEB, end, context)
    observed, private = observe(sava, web, end)
    payload = BASE.canonical({'schema': 1, 'profile': 'sava-gateway-nginx-file-correspondence-v1',
        'state': 'protected-sava-gateway-ingress-source-only', 'namespace': context,
        'sava': sava, 'ingress': web, 'sava_sha256': hashlib.sha256(sava_raw).hexdigest(),
        'ingress_sha256': hashlib.sha256(web_raw).hexdigest(), 'gateway': observed})
    if len(payload) > MAX_OUTPUT:
        raise Pending('whole Sava ingress correspondence exceeds its output bound')
    if prepared(SAVA, end, context)[0] != sava_raw or prepared(WEB, end, context)[0] != web_raw:
        raise Pending('complete owned Sava or ingress preparation changed')
    after, after_private = observe(sava, web, end)
    if after != observed or after_private != private:
        raise Pending('whole Gateway settings or TLS material changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('Sava ingress namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('Sava ingress correspondence accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('Sava ingress correspondence requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete Sava ingress output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
