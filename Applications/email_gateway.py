#!/usr/bin/python3
"""Prepare partial Email Gateway/Worker configuration correspondence.

This reads existing protected files only. Gateway database authorization is
absent from the current local-peer plan, so no runnable unit is emitted. Native
configuration, cryptography, credentials, listeners and health remain unverified.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys


def owned(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
EMAIL = owned('debian13s4_email_gateway_worker', Path(__file__).resolve().with_name('email_worker.py'))
WEB_PATH = ROOT/'Web/prepare.py'
if not WEB_PATH.is_file(): WEB_PATH = ROOT/'web/prepare.py'
WEB = owned('debian13s4_email_gateway_web', WEB_PATH)
BASE, KERNEL, Pending = EMAIL.BASE, EMAIL.KERNEL, EMAIL.Pending
INPUT = Path('/etc/debian13s4/email-gateway.json')
MAX_INPUT, MAX_OUTPUT, ATTEMPT_SECONDS = 8192, 262144, 650
PROFILE = 'email-gateway-worker-file-correspondence-v1'
STATE = 'protected-email-gateway-file-correspondence-only'


def descriptor(value):
    fields = {'schema', 'settings', 'https_settings', 'credentials', 'state_directory'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported Email Gateway descriptor schema')
    credentials = value['credentials']
    if type(credentials) is not dict or not 5 <= len(credentials) <= 13:
        raise Pending('Email Gateway requires bounded explicit credential sources')
    paths = [value['settings'], value['https_settings'], *credentials.values()]
    for name in paths:
        if not EMAIL.literal(name).startswith(str(EMAIL.SETTINGS_ROOT)+'/'):
            raise Pending('Email Gateway files must be product settings descendants')
    if len(set(paths)) != len(paths) or set(paths) & {str(INPUT), str(EMAIL.INPUT)}:
        raise Pending('Email Gateway descriptor/settings/credential paths must remain distinct')
    state = EMAIL.literal(value['state_directory'])
    if not state.startswith(('/var/lib/debian13s4-email/', '/srv/debian13s4-email/')):
        raise Pending('Email Gateway state requires an explicit product directory intention')
    return value


def web_prepared(end, context):
    BASE.fence(end)
    try:
        raw = WEB.prepare(deadline=end, scope=WEB.KERNEL.namespace)
    except WEB.Pending as error:
        raise Pending('Email ingress preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > WEB.MAX_OUTPUT:
        raise Pending('unsupported complete Email ingress receipt')
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
        fields = {'schema', 'profile', 'state', 'namespace', 'configuration', 'materials', 'nginx', 'nginx_sha256'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or
            value['profile'] != 'nginx-private-https-three-gateway-intention-v1' or
            value['state'] != 'ingress-configuration-intention-only' or
            KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or raw != BASE.canonical(value)):
            raise Pending('Email ingress profile, context or canonical bytes differ')
        nginx = WEB.render(value['configuration']['value'])
        if value['nginx'] != nginx or value['nginx_sha256'] != hashlib.sha256(nginx.encode('ascii')).hexdigest():
            raise Pending('Email ingress differs from the complete real renderer')
    except WEB.Pending as error:
        raise Pending('Email ingress renderer refused') from error
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete Email ingress receipt') from error
    BASE.fence(end)
    return raw, value


def public_options(row, private):
    return {name: value for name, value in row.items() if name not in private}


def configuration(value, worker, role, ingress, state):
    """A private HTTPS/JMAP-only profile; no extra mail TCP listeners selected."""
    required = EMAIL.REQUIRED | {'Imap', 'Pop3', 'Sieve', 'Jmap', 'Dav', 'Tls', 'Admin'}
    KERNEL.known(value, EMAIL.SECTIONS, required)
    expected = EMAIL.transport_configuration(value, {'user': role['name'], 'database': worker['Database']['Name']})
    if value['Database']['Username'] == worker['Database']['Username']:
        raise Pending('Email Gateway must not borrow the Application database identity')
    for section, ignored in (
        ('Messaging', {'WorkerId'}), ('ObjectStorage', set()), ('Limits', set()),
        ('OAuth', {'SigningKey', 'SigningKeyFile'}), ('Mfa', {'EncryptionKey', 'EncryptionKeyFile'}),
        ('Dkim', {'PrivateKeyPath'})):
        if BASE.canonical(public_options(value[section], ignored)) != BASE.canonical(public_options(worker[section], ignored)):
            raise Pending('Email Gateway and Worker '+section+' intentions differ')
    if value['Messaging']['WorkerId'] == worker['Messaging']['WorkerId']:
        raise Pending('Email Gateway and Worker require distinct explicit process identifiers')
    for section, names in (('OAuth', ('SigningKey', 'SigningKeyFile')),
                           ('Mfa', ('EncryptionKey', 'EncryptionKeyFile')),
                           ('Dkim', ('PrivateKeyPath',))):
        if any(value[section].get(name, '') != '' for name in names):
            raise Pending('Worker-only signing/MFA material must not enter Gateway inputs')
    for section, names in (
        ('Smtp', ('EnableSmtp', 'EnableSubmission', 'EnableImplicitTls', 'EnableStartTls', 'RequireTls', 'AllowRelay')),
        ('Imap', ('EnableImap', 'EnableImplicitTls')),
        ('Pop3', ('EnablePop3', 'EnableImplicitTls', 'EnableStartTls')),
        ('Sieve', ('EnableManageSieve', 'EnableStartTls')),
        ('Dav', ('EnableDav',))):
        if any(EMAIL.flag(value[section], name) for name in names):
            raise Pending('Email Gateway profile selects private HTTPS/JMAP only')
    if value['Smtp'].get('ListenAddress') != '127.0.0.1' or value['Smtp'].get('Hostname') != worker['Smtp']['Hostname']:
        raise Pending('Email SMTP source identity or explicit loopback intention differs')
    KERNEL.known(value['Tls'], {'CertificatePath', 'CertificateKeyPath'}, set())
    if any(value['Tls'].get(name, '') != '' for name in ('CertificatePath', 'CertificateKeyPath')):
        raise Pending('disabled mail TCP listeners must not reference separate TLS material')
    jmap = value['Jmap']
    if (not EMAIL.flag(jmap, 'EnableJmap') or type(jmap.get('Port')) is not int or
        jmap['Port'] != ingress['upstream_port'] or jmap.get('PublicBaseUrl') != 'https://'+ingress['hostname']):
        raise Pending('Email JMAP listener/public URL differ from the ingress intention')
    for name, minimum, maximum in (('MaxUploadSizeBytes', 1048576, 1073741824),
                                  ('MaxRequestSizeBytes', 65536, 104857600)):
        if KERNEL.uint(jmap.get(name), maximum) < minimum:
            raise Pending('unsupported Email JMAP body bound')
    body = max(65536, jmap['MaxUploadSizeBytes'], jmap['MaxRequestSizeBytes'])
    if ingress['body_bytes'] > body:
        raise Pending('Email ingress body exceeds the selected Gateway body intention')
    for name in ('EnableOAuth', 'EnableOpenIdConnect'):
        EMAIL.flag(value['OAuth'], name)
    if value['OAuth']['EnableOAuth'] and value['OAuth'].get('PublicBaseUrl') != 'https://'+ingress['hostname']:
        raise Pending('Email OAuth public URL differs from ingress')
    admin = value['Admin']
    fields = {'AllowedNetworks', 'DataProtectionKeyPath', 'AuditLogPath', 'HealthStatusPath', 'SessionMinutes'}
    KERNEL.known(admin, fields, fields)
    if KERNEL.uint(admin['SessionMinutes'], 480) < 5:
        raise Pending('unsupported Email admin session bound')
    networks = admin['AllowedNetworks']
    if type(networks) is not list or not 1 <= len(networks) <= 32:
        raise Pending('Email admin networks must be explicit and bounded')
    try:
        if any(type(net) is not str or str(ipaddress.ip_network(net, strict=True)) != net for net in networks):
            raise ValueError('noncanonical network')
    except ValueError as error:
        raise Pending('unsupported explicit Email admin network') from error
    if len(set(networks)) != len(networks): raise Pending('duplicate Email admin network')
    for name, leaf in (('DataProtectionKeyPath', 'data-protection'), ('AuditLogPath', 'audit.jsonl'), ('HealthStatusPath', 'health.json')):
        if admin[name] != state+'/'+leaf: raise Pending('Email admin paths differ from explicit Gateway state')
    return expected, {'body_bytes': body, 'admin_networks': networks,
                      'admin_session_minutes': admin['SessionMinutes']}


def https(value, ingress):
    KERNEL.known(value, {'Kestrel'}, {'Kestrel'})
    KERNEL.known(value['Kestrel'], {'Endpoints'}, {'Endpoints'})
    endpoints = value['Kestrel']['Endpoints']
    KERNEL.known(endpoints, {'Private'}, {'Private'})
    endpoint = endpoints['Private']
    KERNEL.known(endpoint, {'Url', 'Protocols', 'Certificate'}, {'Url', 'Protocols', 'Certificate'})
    certificate = endpoint['Certificate']
    KERNEL.known(certificate, {'Path', 'KeyPath', 'Password'}, {'Path', 'KeyPath', 'Password'})
    if (endpoint['Url'] != 'https://127.0.0.1:'+str(ingress['upstream_port']) or endpoint['Protocols'] != 'Http1' or
        certificate != {'Path': 'certificate.pem', 'KeyPath': 'private-key.pem', 'Password': ''}):
        raise Pending('Email HTTPS requires one loopback HTTP1 listener and fixed credential leaves')
    return {'address': '127.0.0.1', 'port': ingress['upstream_port'], 'scheme': 'https',
            'protocol': 'Http1', 'server_name_intention': ingress['upstream_name']}


def observe(joined, web, end):
    worker_inputs, worker_private = EMAIL.observe(joined['role_bindings']['mk8.email'], end)
    worker = json.loads(worker_private[1])
    descriptor_raw, inputs, descriptor_source = EMAIL.document(INPUT, MAX_INPUT, end)
    inputs = descriptor(inputs)
    settings_raw, settings, settings_source = EMAIL.document(Path(inputs['settings']), EMAIL.MAX_SETTINGS, end)
    https_raw, https_settings, https_source = EMAIL.document(Path(inputs['https_settings']), EMAIL.MAX_SETTINGS, end)
    role = joined['identities']['execution_bindings']['mk8.email']['gateway']
    ingress = web['configuration']['value']['applications']['mk8.email']
    expected, options = configuration(settings, worker, role, ingress, inputs['state_directory'])
    listener = https(https_settings, ingress)
    expected.update({'certificate.pem': 'certificate', 'private-key.pem': 'private-key'})
    if set(inputs['credentials']) != set(expected):
        raise Pending('Email Gateway credential sources differ from selected references')
    worker_sources = {row['id']: row['source'] for row in worker_inputs['credentials']}
    forbidden = {worker_sources[name]['path'] for name in worker_sources
                 if name in ('environment.json', 'database.password', 'oauth-signing.pem', 'mfa.key', 'dkim.pem')}
    public_files = {row[field] for row in web['configuration']['value']['applications'].values()
                    for field in ('certificate', 'upstream_ca')}
    credentials = [{'id': 'environment.json', 'source': settings_source, 'bytes': len(settings_raw)},
                   {'id': 'appsettings.json', 'source': https_source, 'bytes': len(https_raw)}]
    private = [descriptor_raw, settings_raw, https_raw]
    for name, kind in sorted(expected.items()):
        filename = inputs['credentials'][name]
        if filename in forbidden or kind != 'certificate' and filename in public_files:
            raise Pending('Email Gateway reuses Worker-private or public ingress material')
        raw, source = BASE.read_protected(Path(filename), EMAIL.MAX_SECRET, True, end)
        if kind in ('certificate', 'private-key'):
            try: WEB.pem(raw, kind == 'private-key')
            except WEB.Pending as error: raise Pending('Email Gateway PEM grammar refused') from error
        else:
            EMAIL.secret_bytes(raw, kind)
        if name == 'objects.connection' or name.startswith('messaging.'):
            if source['sha256'] != worker_sources[name]['sha256']:
                raise Pending('Email Gateway and Worker shared transport material bytes differ')
        credentials.append({'id': name, 'source': source, 'bytes': len(raw)})
        private.append(raw)
    if sum(row['bytes'] for row in credentials) > EMAIL.MAX_CREDENTIAL_BYTES:
        raise Pending('combined Email Gateway credentials exceed their bounded capacity')
    record = {'configuration_source': descriptor_source, 'credentials': credentials,
        'gateway_identity': role, 'listener': listener, 'presentation': options,
        'required_state': {'path': inputs['state_directory'], 'owner_uid': role['uid'],
            'owner_gid': role['primary_gid'], 'mode': '0700', 'observed': False, 'created': False},
        'database': {'host': settings['Database']['Host'], 'port': 5432, 'name': settings['Database']['Name'],
            'user': role['name'], 'authorized_by_current_local_peer_plan': False},
        'unit_available': False, 'full_native_configuration_validated': False,
        'worker_files': worker_inputs}
    return record, tuple(private)+worker_private


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Email Gateway window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing Email Gateway namespace')
    joined_raw, joined = EMAIL.prerequisite(end, context)
    web_raw, web = web_prepared(end, context)
    gateway, private = observe(joined, web, end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'application_pg_sha256': hashlib.sha256(joined_raw).hexdigest(),
        'identity_sha256': hashlib.sha256(BASE.canonical(joined['identities'])).hexdigest(),
        'release_sha256': hashlib.sha256(BASE.canonical(joined['identities']['releases'])).hexdigest(),
        'ingress_sha256': hashlib.sha256(web_raw).hexdigest(), 'gateway': gateway})
    if len(raw) > MAX_OUTPUT: raise Pending('complete Email Gateway observation exceeds its output bound')
    if EMAIL.prerequisite(end, context)[0] != joined_raw or web_prepared(end, context)[0] != web_raw:
        raise Pending('complete Email identity/PG or ingress preparation changed')
    after, after_private = observe(joined, web, end)
    if BASE.canonical(after) != BASE.canonical(gateway) or after_private != private:
        raise Pending('Email Gateway or Worker protected files changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('Email Gateway namespace changed')
    BASE.fence(end)
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        raw = prepare()
        count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete Email Gateway output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
