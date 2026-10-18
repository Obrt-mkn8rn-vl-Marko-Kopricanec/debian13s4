#!/usr/bin/python3
"""Prepare Sava service and credential-delivery intentions from protected files.

This command renders units; it never writes units, creates storage, delivers
credentials or starts an application. Native systemd/.NET interpretation,
publisher identity, effective credentials and readiness remain unverified.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_sava_service_ingress',
    Path(__file__).resolve().with_name('sava_ingress.py'))
INGRESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INGRESS)
SAVA = INGRESS.SAVA
BASE, KERNEL, Pending = SAVA.BASE, SAVA.KERNEL, SAVA.Pending
ATTEMPT_SECONDS = 1220
MAX_OUTPUT = 131072
# Deliberately below systemd 257's aggregate 1 MiB credential limit.
MAX_CREDENTIAL_BYTES = 1_000_000
UNITS = {role: 'debian13s4-sava-'+role+'.service' for role in ('application', 'gateway')}
PROFILE = 'sava-systemd-credential-service-intentions-v1'
STATE = 'protected-sava-service-intention-only'
CREDENTIAL_DIRECTORY = '${CREDENTIALS_DIRECTORY}'


def path(value):
    """A literal systemd operand, never a specifier or shell expression."""
    if (type(value) is not str or not 1 < len(value) <= 512 or
        re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value) is None or
        os.path.normpath(value) != value or any(p in ('.', '..') for p in value.split('/'))):
        raise Pending('unsupported literal Sava service path')
    return value


def configuration_keys(value):
    """Reject ambiguous .NET key paths without claiming full CLR validation."""
    stack = [value]
    while stack:
        row = stack.pop()
        if type(row) is dict:
            names = set()
            for key, child in row.items():
                folded = key.casefold()
                if ':' in key or folded in names:
                    raise Pending('ambiguous case-insensitive or flattened configuration key')
                names.add(folded)
                stack.append(child)
        elif type(row) is list:
            stack.extend(row)


def prerequisite(end, context):
    BASE.fence(end)
    try:
        raw = INGRESS.prepare(deadline=end)
    except INGRESS.Pending as error:
        raise Pending('Sava ingress preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > INGRESS.MAX_OUTPUT:
        raise Pending('unsupported complete Sava ingress receipt')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite ingress receipt')))
        fields = {'schema', 'profile', 'state', 'namespace', 'sava', 'sava_sha256',
                  'ingress', 'ingress_sha256', 'gateway'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or
            value['profile'] != 'sava-gateway-nginx-file-correspondence-v1' or
            value['state'] != 'protected-sava-gateway-ingress-source-only' or
            KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
            raw != BASE.canonical(value)):
            raise Pending('Sava ingress profile, namespace or canonical bytes differ')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete Sava ingress receipt') from error
    BASE.fence(end)
    return raw, value


def application_files(ingress, end):
    """Read the two real settings files; retain private bytes only locally."""
    settings = ingress['sava']['settings']
    private, values = [], {}
    for role in UNITS:
        source = settings[role+'_source']
        raw, value, actual = SAVA.document(Path(path(source['path'])), SAVA.MAX_SETTINGS, end)
        if BASE.canonical(actual) != BASE.canonical(source):
            raise Pending('Sava settings differ from the complete ingress observation')
        configuration_keys(value)
        if role == 'application':
            KERNEL.known(value, {'Sava', 'ApplicationTransport'}, {'Sava', 'ApplicationTransport'})
        SAVA.settings(value, settings['access_key_source']['path'])
        if (hashlib.sha256(BASE.canonical(value['Sava'])).hexdigest() != settings['policy_sha256'] or
            hashlib.sha256(BASE.canonical(value['ApplicationTransport'])).hexdigest() != settings['transport_sha256']):
            raise Pending('Sava policy or transport differs from its protected source')
        private.append(raw)
        values[role] = value
    return values, tuple(private)


def credential(name, source):
    filename = path(source['path'])
    size = KERNEL.uint(source['identity'][5], MAX_CREDENTIAL_BYTES)
    if size == 0:
        raise Pending('empty Sava service credential')
    return {'id': name, 'source': source, 'bytes': size,
            'load_directive': name+':'+filename}


def unit(role, binding, directory, data, credentials):
    account = SAVA.IDENTITIES.name(binding['name'])
    group = SAVA.IDENTITIES.name(binding['primary_group'])
    for field in ('uid', 'primary_gid'):
        if not 100 <= KERNEL.uint(binding[field], 999):
            raise Pending('Sava service requires a dedicated system identity')
    entry = path(binding['entry_point'])
    directory, data = path(directory), path(data)
    if not entry.startswith(directory+'/'):
        raise Pending('Sava service entry is outside its admitted release')
    # systemd expands only these fixed credential references. env -i removes
    # inherited configuration, profiler, loader and startup-hook variables.
    environment = ['PATH=/usr/bin:/usr/sbin', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8',
                   'HOME=/nonexistent', 'TMPDIR=/tmp', 'DOTNET_NOLOGO=1',
                   'DOTNET_ENVIRONMENT=Production', 'ASPNETCORE_ENVIRONMENT=Production']
    command = ['/usr/bin/env', '-i', *environment, entry,
               '--contentRoot', CREDENTIAL_DIRECTORY, '--environment', 'Production',
               '--ApplicationTransport:AccessKeyFile='+CREDENTIAL_DIRECTORY+'/rpc.key']
    if role == 'gateway':
        command += ['--Kestrel:Endpoints:Private:Certificate:Path='+CREDENTIAL_DIRECTORY+'/certificate.pem',
                    '--Kestrel:Endpoints:Private:Certificate:KeyPath='+CREDENTIAL_DIRECTORY+'/private-key.pem']
    lines = ['[Unit]', 'Description=Protected Sava '+role+' service intention',
             'After=network-online.target', 'Wants=network-online.target',
             'RequiresMountsFor='+directory+' '+data]
    if role == 'gateway':
        lines += ['Requires='+UNITS['application'], 'After='+UNITS['application']]
    lines += ['[Service]', 'Type=exec', 'User='+account, 'Group='+group,
              'WorkingDirectory='+directory, 'UMask=0077', 'Restart=no',
              'TimeoutStartSec=30s', 'TimeoutStopSec=120s', 'KillMode=control-group',
              'SendSIGKILL=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
              'AmbientCapabilities=', 'PrivateTmp=yes', 'PrivateDevices=yes',
              'ProtectSystem=strict', 'ProtectHome=yes', 'ProtectKernelTunables=yes',
              'ProtectKernelModules=yes', 'ProtectControlGroups=yes',
              'RestrictSUIDSGID=yes', 'LockPersonality=yes',
              'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
              ('ReadWritePaths=' if role == 'application' else 'InaccessiblePaths=')+data,
              'StandardInput=null', 'StandardOutput=journal', 'StandardError=journal']
    lines += ['LoadCredential='+row['load_directive'] for row in credentials]
    lines += ['ExecStart='+' '.join(command)]
    text = '\n'.join(lines)+'\n'
    return {'name': UNITS[role], 'identity': binding, 'argv': command,
            'credentials': credentials, 'unit': text,
            'unit_sha256': hashlib.sha256(text.encode('ascii')).hexdigest()}


def render(ingress):
    sava, gateway = ingress['sava'], ingress['gateway']
    settings = sava['settings']
    identity = sava['identities']
    bindings = identity['execution_bindings']['mk8.sava']
    if bindings['application']['uid'] == bindings['gateway']['uid']:
        raise Pending('Sava Application and Gateway identities must remain distinct')
    release = identity['releases']['applications']['mk8.sava']
    data = settings['storage_directory_intention']
    result = {}
    for role in UNITS:
        credentials = [credential('appsettings.json', settings[role+'_source']),
                       credential('rpc.key', settings['access_key_source'])]
        if role == 'gateway':
            credentials += [credential('certificate.pem', gateway['certificate_source']),
                            credential('private-key.pem', gateway['private_key_source'])]
        total = sum(row['bytes'] for row in credentials)
        if total > MAX_CREDENTIAL_BYTES:
            raise Pending('combined Sava unit credentials exceed their bounded capacity')
        result[role] = unit(role, bindings[role], release['directory'], data, credentials)
        result[role]['credential_bytes'] = total
    return {'units': result, 'release_generation': release['generation'],
            'required_storage': {'path': data, 'owner_uid': bindings['application']['uid'],
                'owner_gid': bindings['application']['primary_gid'], 'mode': '0700',
                'observed': False, 'created': False},
            'rpc_listener_intention': settings['rpc'],
            'gateway_listener_intention': gateway['listener']}


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited Sava service window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing Sava service namespace')
    raw, ingress = prerequisite(end, context)
    _, private = application_files(ingress, end)
    plan = render(ingress)
    payload = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE,
        'namespace': context, 'ingress_sha256': hashlib.sha256(raw).hexdigest(),
        'plan': plan})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete Sava service intention exceeds its output bound')
    after, after_value = prerequisite(end, context)
    if after != raw:
        raise Pending('complete Sava ingress, settings or identity preparation changed')
    _, after_private = application_files(after_value, end)
    if after_private != private:
        raise Pending('Sava settings bytes changed after service encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('Sava service namespace changed')
    BASE.fence(end)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', choices=tuple(UNITS), help='emit only the selected unit text')
    args = parser.parse_args(argv)
    try:
        raw = prepare()
        if args.unit:
            raw = json.loads(raw)['plan']['units'][args.unit]['unit'].encode('ascii')
        sink = sys.stdout.buffer
        count = sink.write(raw)
        if type(count) is not int or count != len(raw):
            raise Pending('incomplete Sava service intention output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
