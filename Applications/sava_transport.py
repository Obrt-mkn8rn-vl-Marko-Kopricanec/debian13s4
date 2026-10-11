#!/usr/bin/python3
"""Observe paired Sava transport/policy files and private key SOURCE material.

Only selected fields and whole-file correspondence are admitted. This does not
validate every CLR option, listener, credential delivery, storage, account power,
native RPC authentication or service launch. Secret values are never returned.
"""
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_sava_identities',
    Path(__file__).resolve().with_name('identities.py'))
IDENTITIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITIES)
BASE, KERNEL, Pending = IDENTITIES.BASE, IDENTITIES.KERNEL, IDENTITIES.Pending
INPUT = Path('/etc/debian13s4/sava-transport.json')
SETTINGS_ROOT = Path('/etc/debian13s4-sava')
MAX_INPUT = 8192
MAX_SETTINGS = 1048576
MAX_KEY_FILE = 4096
MAX_NODES = 16384
MAX_OUTPUT = 4194305
ATTEMPT_SECONDS = 280
FILES = ('application_settings', 'gateway_settings', 'access_key')
TRANSPORT_FIELDS = {'Endpoint', 'AccessKeyFile', 'MaximumControlFrameBytes', 'ConnectTimeout', 'RequestTimeout'}
POLICY_FIELDS = {'DataPath', 'DefaultAccount', 'Accounts', 'DataEncryptionKeys',
    'AccountCapabilities', 'ObjectReplicationPolicies', 'AllowAnonymousPublicAccess',
    'MaximumRequestBodyBytes', 'BearerAuthentication'}


def material(text):
    if type(text) is not str or not 44 <= len(text) <= 684:
        raise Pending('unsupported bounded base64 key spelling')
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, UnicodeError) as error:
        raise Pending('invalid canonical base64 key') from error
    if not 32 <= len(raw) <= 512 or not any(raw) or base64.b64encode(raw).decode('ascii') != text:
        raise Pending('key requires canonical nonzero 32..512 byte material')
    return raw


def duration(value, maximum):
    if type(value) is not str or re.fullmatch(r'[0-9]{2}:[0-5][0-9]:[0-5][0-9]', value) is None:
        raise Pending('explicit transport duration requires canonical HH:MM:SS')
    h, m, s = map(int, value.split(':')); seconds = h*3600+m*60+s
    if not 1 <= seconds <= maximum:
        raise Pending('transport duration exceeds its supported source bound')
    return seconds


def endpoint(value):
    match = re.fullmatch(r'http://(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})/internal/application', value) if type(value) is str else None
    if match is None or not 1024 <= int(match[2]) <= 65535 or int(match[2]) == 5432:
        raise Pending('this profile requires an explicit canonical loopback HTTP RPC endpoint')
    return {'address': '::1' if match[1] == '[::1]' else match[1], 'port': int(match[2]),
        'path': '/internal/application', 'scheme': 'http'}


def checked(value):
    KERNEL.known(value, {'schema', *FILES}, {'schema', *FILES})
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported Sava transport source schema')
    selected = set()
    for field in FILES:
        text = value[field]
        if type(text) is not str or not 1 <= len(text) <= 240 or os.path.normpath(text) != text:
            raise Pending('unsupported explicit protected Sava settings path')
        try:
            name = str(Path(text).relative_to(SETTINGS_ROOT))
        except ValueError as error:
            raise Pending('Sava inputs must be explicit descendants of the product settings directory') from error
        IDENTITIES.RELEASE.relative(name)
        if not name.endswith('.key' if field == 'access_key' else '.json') or text in selected:
            raise Pending('Sava settings/key paths require distinct named files')
        selected.add(text)
    return json.loads(BASE.canonical(value))


def structural(value):
    """Finite JSON structure only; not the complete CLR configuration validator."""
    stack = [(value, 0)]; count = 0
    while stack:
        item, depth = stack.pop(); count += 1
        if count > MAX_NODES or depth > 32:
            raise Pending('Sava settings exceed their structural bound')
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or not 1 <= len(key) <= 128 or any(not 32 <= ord(c) <= 126 for c in key):
                    raise Pending('unsupported settings property spelling')
                stack.append((child, depth+1))
        elif type(item) is list:
            stack.extend((child, depth+1) for child in item)
        elif type(item) is str:
            if len(item) > 65536 or any(not 32 <= ord(c) <= 126 for c in item):
                raise Pending('unsupported settings string')
        elif type(item) is int:
            if not -(2**63) <= item <= 2**63-1: raise Pending('settings integer exceeds signed64 source range')
        elif type(item) is float:
            if not math.isfinite(item): raise Pending('nonfinite Sava settings number')
        elif item is not None and type(item) is not bool:
            raise Pending('unsupported settings value')


def document(path, limit, end):
    raw, source = BASE.read_protected(path, limit, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite Sava JSON')))
        structural(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected Sava JSON') from error
    if type(value) is not dict or raw != BASE.canonical(value):
        raise Pending('Sava input requires canonical ASCII JSON object plus LF')
    return raw, value, source


def settings(value, key_path):
    if not {'Sava', 'ApplicationTransport'} <= set(value):
        raise Pending('both selected Sava sections must be explicit')
    transport, policy = value['ApplicationTransport'], value['Sava']
    KERNEL.known(transport, TRANSPORT_FIELDS, TRANSPORT_FIELDS)
    listener = endpoint(transport['Endpoint'])
    if transport['AccessKeyFile'] != key_path or type(transport['AccessKeyFile']) is not str:
        raise Pending('transport must reference the declared protected key file')
    if not 4096 <= KERNEL.uint(transport['MaximumControlFrameBytes'], 64*1024*1024) <= 64*1024*1024:
        raise Pending('unsupported explicit control frame capacity')
    duration(transport['ConnectTimeout'], 60); duration(transport['RequestTimeout'], 3600)
    if type(policy) is not dict or not POLICY_FIELDS <= set(policy):
        raise Pending('selected Sava policy fields must be explicit')
    data = policy['DataPath']
    if (type(data) is not str or not 6 <= len(data) <= 240 or
        re.fullmatch(r'/(srv|var/lib)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', data) is None or
        any(part in ('.', '..') for part in data.split('/')[1:])):
        raise Pending('storage requires an explicit canonical supported directory intention')
    accounts = policy['Accounts']
    if type(accounts) is not dict or not 1 <= len(accounts) <= 64:
        raise Pending('Sava policy requires explicit bounded account material')
    for account, key in accounts.items():
        if re.fullmatch(r'[a-z0-9]{3,24}', account) is None: raise Pending('unsupported storage account name')
        material(key)
    if type(policy['DefaultAccount']) is not str or policy['DefaultAccount'] not in accounts:
        raise Pending('default storage account must explicitly identify declared material')
    encryption = policy['DataEncryptionKeys']
    if type(encryption) is not dict or set(encryption) != set(accounts):
        raise Pending('each account requires explicit data encryption material, without fallback')
    for key in encryption.values(): material(key)
    capabilities = policy['AccountCapabilities']
    if type(capabilities) is not dict or set(capabilities) != set(accounts) or any(type(row) is not dict for row in capabilities.values()):
        raise Pending('each account requires an explicit capability object')
    if type(policy['ObjectReplicationPolicies']) is not list or len(policy['ObjectReplicationPolicies']) > 64:
        raise Pending('unsupported explicit replication policy list')
    if type(policy['AllowAnonymousPublicAccess']) is not bool or policy['AllowAnonymousPublicAccess']:
        raise Pending('this source profile refuses anonymous public access')
    if not 1 <= KERNEL.uint(policy['MaximumRequestBodyBytes'], 5_000*1024*1024):
        raise Pending('unsupported explicit request body capacity')
    bearer = policy['BearerAuthentication']
    if type(bearer) is not dict or type(bearer.get('Enabled')) is not bool:
        raise Pending('bearer enablement must be explicit; native option validation remains required')
    return listener


def observe(end):
    descriptor_raw, descriptor, descriptor_source = document(INPUT, MAX_INPUT, end)
    descriptor = checked(descriptor)
    app_raw, app, app_source = document(Path(descriptor['application_settings']), MAX_SETTINGS, end)
    gateway_raw, gateway, gateway_source = document(Path(descriptor['gateway_settings']), MAX_SETTINGS, end)
    listener = settings(app, descriptor['access_key']); settings(gateway, descriptor['access_key'])
    if (BASE.canonical(app['Sava']) != BASE.canonical(gateway['Sava']) or
        BASE.canonical(app['ApplicationTransport']) != BASE.canonical(gateway['ApplicationTransport'])):
        raise Pending('whole selected Sava policy or transport sections differ between hosts')
    key_raw, key_source = BASE.read_protected(Path(descriptor['access_key']), MAX_KEY_FILE, True, end)
    try:
        key = material(key_raw[:-1].decode('ascii'))
    except UnicodeError as error:
        raise Pending('invalid protected RPC key encoding') from error
    if key_raw != base64.b64encode(key)+b'\n':
        raise Pending('protected RPC key requires canonical base64 plus exact LF')
    record = {'configuration_source': descriptor_source, 'application_source': app_source,
        'gateway_source': gateway_source, 'access_key_source': key_source,
        'rpc': listener, 'control_frame_bytes': app['ApplicationTransport']['MaximumControlFrameBytes'],
        'connect_seconds': duration(app['ApplicationTransport']['ConnectTimeout'], 60),
        'request_seconds': duration(app['ApplicationTransport']['RequestTimeout'], 3600),
        'policy_sha256': hashlib.sha256(BASE.canonical(app['Sava'])).hexdigest(),
        'transport_sha256': hashlib.sha256(BASE.canonical(app['ApplicationTransport'])).hexdigest(),
        'key_bytes': len(key), 'key_material_sha256': hashlib.sha256(key).hexdigest(),
        'storage_directory_intention': app['Sava']['DataPath']}
    # Private comparison buffers stay in this preparation; never serialize them.
    return record, (descriptor_raw, app_raw, gateway_raw, key_raw)


def identity_bytes(end):
    BASE.fence(end)
    raw = IDENTITIES.prepare(deadline=end)
    if type(raw) is not bytes or len(raw) > IDENTITIES.MAX_OUTPUT:
        raise Pending('unsupported whole protected release/account receipt')
    BASE.fence(end)
    return raw


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Sava preparation window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing Sava caller namespace')
    identities = identity_bytes(end)
    identity = json.loads(identities, object_pairs_hook=KERNEL.unique_object)
    if KERNEL.uint(identity['namespace'], 0xffffffffffffffff) != context:
        raise Pending('Sava release/account namespace differs')
    observed, private = observe(end)
    payload = BASE.canonical({'schema': 1, 'profile': 'sava-paired-transport-policy-files-v1',
        'state': 'sava-split-transport-policy-source-only', 'namespace': context,
        'identities': identity, 'identity_sha256': hashlib.sha256(identities).hexdigest(),
        'settings': observed})
    if len(payload) > MAX_OUTPUT: raise Pending('Sava source receipt exceeds its complete output bound')
    after, after_private = observe(end)
    if after != observed or after_private != private: raise Pending('whole Sava settings/key file observations changed')
    if identity_bytes(end) != identities: raise Pending('complete release/account identities changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('Sava caller namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1: raise Pending('Sava source preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('Sava source preparation requires binary stdout')
        payload = prepare(); count = sink.write(payload)
        if type(count) is not int or count != len(payload): raise Pending('incomplete Sava receipt publication')
        sink.flush(); return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr); return 75


if __name__ == '__main__':
    sys.exit(main())
