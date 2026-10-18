#!/usr/bin/python3
"""Prepare Email Worker file bindings and credential/service intentions only.

No account, database, credential, service or application is changed. The retained
Worker performs schema/restore-queue work on startup; rendering this plan does not
authorize that work or establish full CLR configuration or native readiness.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_email_worker_pg',
    Path(__file__).resolve().with_name('postgresql_identity.py'))
JOIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(JOIN)
BASE, KERNEL, Pending = JOIN.PG, JOIN.KERNEL, JOIN.Pending
INPUT = Path('/etc/debian13s4/email-worker.json')
SETTINGS_ROOT = Path('/etc/debian13s4-email')
MAX_INPUT, MAX_SETTINGS, MAX_SECRET = 8192, 524288, 131072
MAX_OUTPUT, MAX_CREDENTIAL_BYTES, ATTEMPT_SECONDS = 131072, 1_000_000, 600
PROFILE = 'email-worker-credential-service-intentions-v1'
STATE = 'protected-email-worker-service-intention-only'
UNIT = 'debian13s4-email-application.service'
SECTIONS = {'Database', 'Smtp', 'Imap', 'Pop3', 'Sieve', 'Jmap', 'Dav', 'OAuth',
    'Mfa', 'Tls', 'Dkim', 'Security', 'Filtering', 'Queue', 'Limits', 'General',
    'Admin', 'Messaging', 'ObjectStorage'}
REQUIRED = {'Database', 'Smtp', 'OAuth', 'Mfa', 'Dkim', 'Limits', 'Messaging', 'ObjectStorage'}


def literal(value):
    if (type(value) is not str or not 1 < len(value) <= 512 or
        re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value) is None or
        os.path.normpath(value) != value or any(p in ('.', '..') for p in value.split('/'))):
        raise Pending('unsupported literal Email file/service operand')
    return value


def structure(value):
    """Bounded unambiguous JSON, not a replacement for EnvironmentConfig.Validate."""
    stack = [(value, 0)]; count = 0
    while stack:
        item, depth = stack.pop(); count += 1
        if depth > 32 or count > 16384:
            raise Pending('Email configuration exceeds its structural bound')
        if type(item) is dict:
            seen = set()
            for key, child in item.items():
                if (not 1 <= len(key) <= 128 or any(not 32 <= ord(c) <= 126 for c in key)
                    or ':' in key or key.casefold() in seen):
                    raise Pending('ambiguous Email configuration property')
                seen.add(key.casefold()); stack.append((child, depth+1))
        elif type(item) is list:
            stack.extend((child, depth+1) for child in item)
        elif type(item) is str:
            if len(item) > 65536 or any(not 32 <= ord(c) <= 126 for c in item):
                raise Pending('unsupported Email configuration string')
        elif type(item) is int:
            if not -(2**63) <= item < 2**63: raise Pending('Email integer exceeds signed64')
        elif type(item) is float:
            if not math.isfinite(item): raise Pending('nonfinite Email number')
        elif item is not None and type(item) is not bool:
            raise Pending('unsupported Email configuration value')


def document(path, limit, end):
    raw, source = BASE.read_protected(path, limit, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite Email JSON')))
        structure(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected Email JSON') from error
    if type(value) is not dict or raw != BASE.canonical(value):
        raise Pending('Email input requires canonical ASCII JSON object plus LF')
    return raw, value, source


def descriptor(value):
    KERNEL.known(value, {'schema', 'settings', 'credentials'}, {'schema', 'settings', 'credentials'})
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported Email Worker descriptor schema')
    sources = value['credentials']
    if type(sources) is not dict or not 3 <= len(sources) <= 14:
        raise Pending('Email Worker requires explicit bounded credential sources')
    for name in sources:
        if re.fullmatch(r'[a-z][a-z0-9.-]{0,63}', name) is None or name == 'environment.json':
            raise Pending('unsupported Email credential name')
    paths = [value['settings'], *sources.values()]
    for filename in paths:
        literal(filename)
        if not filename.startswith(str(SETTINGS_ROOT)+'/'):
            raise Pending('Email inputs must be descendants of the product settings directory')
    if len(set(paths)) != len(paths) or str(INPUT) in paths:
        raise Pending('Email descriptor/settings/credential sources must be distinct')
    return value


def flag(row, name):
    value = row.get(name)
    if type(value) is not bool: raise Pending('Email feature selections must be explicit Booleans')
    return value


def secret_reference(row, field, credential, kind, expected, required=True):
    if row.get(field, '') != '' or type(row.get(field, '')) is not str:
        raise Pending('Email secrets must use separate credential files')
    filename = row.get(field+'File', '')
    if required:
        if filename != credential: raise Pending('Email secret must use its fixed credential leaf')
        expected[credential] = kind
    elif filename not in ('', None):
        raise Pending('disabled Email feature still references secret material')


def transport_configuration(value, peer):
    """Selected shared database/messaging/object-store file intentions."""
    KERNEL.known(value, SECTIONS, REQUIRED)
    if any(type(row) is not dict for row in value.values()):
        raise Pending('Email configuration sections must be objects')
    db, msg, objects = (value[name] for name in ('Database', 'Messaging', 'ObjectStorage'))
    KERNEL.known(db, {'Host', 'Port', 'Name', 'Username', 'Password', 'PasswordFile'},
                    {'Host', 'Port', 'Name', 'Username', 'Password', 'PasswordFile'})
    if (db['Host'] != BASE.SOCKET_DIRECTORY or type(db['Port']) is not int or db['Port'] != 5432
        or db['Name'] != peer['database'] or db['Username'] != peer['user']):
        raise Pending('Email database differs from its selected role/database file intention')
    expected = {}
    secret_reference(db, 'Password', 'database.password', 'password', expected)
    msg_fields = {'Enabled', 'EncryptionKeyId', 'EncryptionKey', 'EncryptionKeyFile', 'DecryptionKeys',
        'MaxPayloadBytes', 'InlinePayloadThresholdBytes', 'LeaseSeconds', 'NotificationFallbackSeconds', 'WorkerId'}
    KERNEL.known(msg, msg_fields, msg_fields)
    if not flag(msg, 'Enabled'): raise Pending('Email transport requires distributed messaging')
    identifier = r'[A-Za-z0-9][A-Za-z0-9._:-]{0,63}'
    if type(msg['EncryptionKeyId']) is not str or re.fullmatch(identifier, msg['EncryptionKeyId']) is None:
        raise Pending('unsupported Email messaging encryption key identifier')
    if (type(msg['WorkerId']) is not str or
        re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}', msg['WorkerId']) is None):
        raise Pending('Email transport requires an explicit bounded identity, without machine-name fallback')
    secret_reference(msg, 'EncryptionKey', 'messaging.key', 'key32', expected)
    previous = msg['DecryptionKeys']; ids = {msg['EncryptionKeyId']}
    if type(previous) is not list or len(previous) > 8: raise Pending('too many Email decryption keys')
    for number, row in enumerate(previous):
        KERNEL.known(row, {'Id', 'Key', 'KeyFile'}, {'Id', 'Key', 'KeyFile'})
        if type(row['Id']) is not str or re.fullmatch(identifier, row['Id']) is None or row['Id'] in ids:
            raise Pending('Email messaging key identifiers must be distinct')
        ids.add(row['Id']); secret_reference(row, 'Key', f'messaging.decrypt-{number}.key', 'key32', expected)
    message_bytes = KERNEL.uint(value['Limits'].get('MaxMessageSizeBytes'), 1_073_741_824)
    payload = KERNEL.uint(msg['MaxPayloadBytes'], 1_073_741_824)
    if message_bytes < 65536 or payload < (4*message_bytes+2)//3+1048576:
        raise Pending('Email messaging capacity cannot hold the declared message envelope')
    KERNEL.uint(msg['InlinePayloadThresholdBytes'], min(1048576, payload))
    for field, minimum, maximum in (('LeaseSeconds', 5, 3600), ('NotificationFallbackSeconds', 1, 300)):
        if KERNEL.uint(msg[field], maximum) < minimum: raise Pending('unsupported Email messaging interval')
    object_fields = {'Provider', 'ConnectionString', 'ConnectionStringFile', 'ContainerName', 'ObjectPrefix', 'CreateContainerIfMissing'}
    KERNEL.known(objects, object_fields, object_fields)
    if objects['Provider'] != 'azure-blob' or flag(objects, 'CreateContainerIfMissing'):
        raise Pending('Email transport profile requires preprovisioned azure-blob object storage')
    container = objects['ContainerName']
    if (type(container) is not str or re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', container) is None
        or '--' in container): raise Pending('unsupported Email object container name')
    prefix = objects['ObjectPrefix']
    if type(prefix) is not str or len(prefix) > 512 or prefix.startswith('/') or '//' in prefix or '\0' in prefix:
        raise Pending('unsupported Email object prefix')
    secret_reference(objects, 'ConnectionString', 'objects.connection', 'connection', expected)
    return expected


def configuration(value, peer):
    """Check selected Worker fields and every supported credential reference."""
    expected = transport_configuration(value, peer)
    oauth, mfa, dkim = (value[name] for name in ('OAuth', 'Mfa', 'Dkim'))
    enabled = flag(oauth, 'EnableOAuth'); oidc = flag(oauth, 'EnableOpenIdConnect')
    if oidc and not enabled: raise Pending('Email OpenID Connect requires OAuth')
    secret_reference(oauth, 'SigningKey', 'oauth-signing.pem', 'pem', expected, oidc)
    totp = flag(mfa, 'EnableTotp')
    if totp and not enabled: raise Pending('Email TOTP requires OAuth')
    secret_reference(mfa, 'EncryptionKey', 'mfa.key', 'key32', expected, totp)
    if flag(dkim, 'EnableSigning'):
        if dkim.get('PrivateKeyPath') != 'dkim.pem': raise Pending('Email DKIM requires its credential leaf')
        expected['dkim.pem'] = 'pem'
    elif dkim.get('PrivateKeyPath', '') not in ('', None):
        raise Pending('disabled DKIM still references a private key')
    return expected


def secret_bytes(raw, kind):
    """Syntax checks only; no entropy, Azure, ASN.1, RSA or native authentication."""
    try:
        text = raw.decode('ascii').rstrip('\r\n')
        if not text or text.casefold() == 'change_me': raise ValueError('missing material')
        if kind == 'key32':
            decoded = base64.b64decode(text, validate=True)
            if len(decoded) != 32 or not any(decoded) or base64.b64encode(decoded).decode('ascii') != text:
                raise ValueError('invalid 256-bit material')
        elif kind == 'pem':
            if not re.fullmatch(r'-----BEGIN ((?:RSA )?PRIVATE KEY)-----\n[A-Za-z0-9+/=\r\n]+\n-----END \1-----', text):
                raise ValueError('unsupported private PEM spelling')
        elif not 16 <= len(text) <= 8192 or any(not 33 <= ord(c) <= 126 for c in text):
            raise ValueError('unsupported secret spelling')
    except (ValueError, UnicodeError) as error:
        raise Pending('Email credential material does not meet its bounded syntax') from error


def prerequisite(end, context):
    BASE.fence(end)
    try: raw = JOIN.prepare(deadline=end)
    except JOIN.Pending as error: raise Pending('Email Application/PG prerequisite refused') from error
    if type(raw) is not bytes or not raw or len(raw) > JOIN.MAX_OUTPUT:
        raise Pending('unsupported complete Email Application/PG preparation')
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
        fields = {'schema', 'profile', 'state', 'namespace', 'identities', 'postgresql',
                  'role_bindings', 'identity_sha256', 'postgresql_sha256'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or
            value['profile'] != 'application-postgresql-peer-role-files-v1' or
            value['state'] != 'protected-application-postgresql-role-intention-only' or
            KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or raw != BASE.canonical(value) or
            BASE.canonical(value['role_bindings']) != BASE.canonical(JOIN.bindings(value['identities'], value['postgresql']))):
            raise Pending('Email Application/PG source correspondence differs')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete Email Application/PG preparation') from error
    BASE.fence(end)
    return raw, value


def observe(peer, end):
    descriptor_raw, value, descriptor_source = document(INPUT, MAX_INPUT, end)
    value = descriptor(value)
    settings_raw, settings, settings_source = document(Path(value['settings']), MAX_SETTINGS, end)
    expected = configuration(settings, peer)
    if set(value['credentials']) != set(expected): raise Pending('Email credential sources differ from the complete selected references')
    credentials = [{'id': 'environment.json', 'source': settings_source, 'bytes': len(settings_raw)}]
    private = [descriptor_raw, settings_raw]
    for name, kind in sorted(expected.items()):
        raw, source = BASE.read_protected(Path(value['credentials'][name]), MAX_SECRET, True, end)
        secret_bytes(raw, kind); private.append(raw)
        credentials.append({'id': name, 'source': source, 'bytes': len(raw)})
    if sum(row['bytes'] for row in credentials) > MAX_CREDENTIAL_BYTES:
        raise Pending('combined Email unit credentials exceed their bounded capacity')
    return {'descriptor_source': descriptor_source, 'credentials': credentials,
            'worker_id': settings['Messaging']['WorkerId'], 'container': settings['ObjectStorage']['ContainerName']}, tuple(private)


def render(joined, inputs):
    role = joined['role_bindings']['mk8.email']
    release = joined['identities']['releases']['applications']['mk8.email']
    binding = joined['identities']['execution_bindings']['mk8.email']['application']
    directory, entry = literal(release['directory']), literal(role['entry_point'])
    if not entry.startswith(directory+'/'): raise Pending('Email Worker entry is outside its admitted release')
    environment = ['PATH=/usr/bin:/usr/sbin', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8', 'HOME=/nonexistent',
                   'TMPDIR=/tmp', 'DOTNET_NOLOGO=1', 'DOTNET_ENVIRONMENT=Production',
                   'MK8EMAIL_CONFIG_FILE=${CREDENTIALS_DIRECTORY}/environment.json']
    commands = {mode: ['/usr/bin/env', '-i', *environment, entry, '--'+mode] for mode in ('serve', 'prepare', 'drain')}
    lines = ['[Unit]', 'Description=Protected Email Application Worker intention',
        'After=network-online.target debian13s4-postgresql-server.service', 'Wants=network-online.target',
        'RequiresMountsFor='+directory+' '+BASE.SOCKET_DIRECTORY, '[Service]', 'Type=exec',
        'User='+JOIN.IDENTITIES.name(role['user']), 'Group='+JOIN.IDENTITIES.name(binding['primary_group']),
        'WorkingDirectory=%d', 'UMask=0077', 'Restart=no', 'TimeoutStartSec=30s', 'TimeoutStopSec=120s',
        'KillMode=control-group', 'SendSIGKILL=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
        'AmbientCapabilities=', 'PrivateTmp=yes', 'PrivateDevices=yes', 'ProtectSystem=strict',
        'ProtectHome=yes', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectControlGroups=yes',
        'RestrictSUIDSGID=yes', 'LockPersonality=yes', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
        'StandardInput=null', 'StandardOutput=journal', 'StandardError=journal']
    lines += ['LoadCredential='+row['id']+':'+literal(row['source']['path']) for row in inputs['credentials']]
    lines += ['ExecStart='+' '.join(commands['serve'])]
    unit = '\n'.join(lines)+'\n'
    return {'unit_name': UNIT, 'unit': unit, 'unit_sha256': hashlib.sha256(unit.encode('ascii')).hexdigest(),
        'commands': commands, 'application_identity': binding, 'release_generation': release['generation'],
        'release_sha256': hashlib.sha256(BASE.canonical(joined['identities']['releases'])).hexdigest(),
        'identity_sha256': hashlib.sha256(BASE.canonical(joined['identities'])).hexdigest(),
        'database_intention': role['connection_intention'], 'inputs': inputs,
        'startup_database_mutations': True, 'full_native_configuration_validated': False}


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Email Worker window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing Email Worker namespace')
    child_raw, joined = prerequisite(end, context)
    inputs, private = observe(joined['role_bindings']['mk8.email'], end)
    plan = render(joined, inputs)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
                          'application_pg_sha256': hashlib.sha256(child_raw).hexdigest(), 'plan': plan})
    if len(raw) > MAX_OUTPUT: raise Pending('complete Email Worker intention exceeds its output bound')
    after, value = prerequisite(end, context)
    if after != child_raw: raise Pending('complete Email Application/PG preparation changed')
    after_inputs, after_private = observe(value['role_bindings']['mk8.email'], end)
    if BASE.canonical(inputs) != BASE.canonical(after_inputs) or private != after_private:
        raise Pending('Email settings or credential observations changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('Email Worker namespace changed')
    BASE.fence(end)
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', action='store_true', help='emit the Worker service intention text')
    args = parser.parse_args(argv)
    try:
        raw = prepare()
        if args.unit: raw = json.loads(raw)['plan']['unit'].encode('ascii')
        count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete Email Worker intention output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
