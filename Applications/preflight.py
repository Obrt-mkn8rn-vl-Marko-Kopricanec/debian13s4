#!/usr/bin/python3
"""Read protected application inputs and report their source correspondence.

No service is installed or started. The report covers sequential file
observations, not executable validity, native credentials or application health.
Run with an isolated interpreter: python3 -I -B applications/preflight.py.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import time


CHECKS = {
    'releases': ('releases.py', 'four-app-complete-release-files-v1',
                 'protected-preinstalled-release-source-only'),
    'identities': ('identities.py', 'four-app-release-account-intention-v1',
                   'protected-application-execution-identity-source-only'),
    'dns': ('dns_service.py', 'protected-dns-release-service-intention-v1',
            'protected-dns-release-service-intention-only'),
    'postgresql': ('postgresql_identity.py', 'application-postgresql-peer-role-files-v1',
                   'protected-application-postgresql-role-intention-only'),
    'sava': ('sava_transport.py', 'sava-paired-transport-policy-files-v1',
             'sava-split-transport-policy-source-only'),
    'ingress': ('sava_ingress.py', 'sava-gateway-nginx-file-correspondence-v1',
                'protected-sava-gateway-ingress-source-only'),
    'prerequisites': ('prepare.py', 'application-file-prerequisites-v1',
                      'application-file-prerequisites-source-only'),
}
ATTEMPT_SECONDS = 2400
MAX_OUTPUT = 65536
LIMITATIONS = (
    'Application binaries, framework compatibility and native credentials are unverified.',
    'Runtime settings, service health and complete four-application integration remain unverified.',
    'Sequential file observations do not prove continuous identity or reserve network ports.',
)


class Pending(ValueError):
    """A requested input check or its cross-component correspondence refused."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')


def now():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def fence(end):
    if now() >= end:
        raise Pending('application preflight window expired')


def owned(check):
    spec = importlib.util.spec_from_file_location('debian13s4_preflight_'+check,
        Path(__file__).resolve().with_name(CHECKS[check][0]))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Pending('duplicate prerequisite property')
        value[key] = item
    return value


def finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise Pending('nonfinite prerequisite number')
    return value


def observe(check, module, end, namespace):
    fence(end)
    try:
        raw = module.prepare(deadline=end)
    except (module.Pending, OSError) as error:
        raise Pending(check+': protected inputs refused: '+str(error)) from error
    if type(raw) is not bytes or not raw or len(raw) > module.MAX_OUTPUT:
        raise Pending(check+': unsupported prerequisite bytes')
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_float=finite,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite prerequisite')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending(check+': invalid prerequisite JSON') from error
    if (type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1 or
        value.get('profile') != CHECKS[check][1] or value.get('state') != CHECKS[check][2] or
        type(value.get('namespace')) is not int or value['namespace'] != namespace or
        raw != canonical(value)):
        raise Pending(check+': prerequisite profile, context or canonical bytes differ')
    fence(end)
    return raw, value


def listener_plan(prerequisites, ingress):
    """Refuse collisions among the selected TCP listener intentions, not sockets."""
    if canonical(prerequisites['components']['sava']) != canonical(ingress['sava']):
        raise Pending('Sava release, account or settings observations differ between checks')
    claims = []
    web = ingress['ingress']['configuration']['value']['applications']
    for app, row in sorted(web.items()):
        claims.append({'owner': app+' HTTPS gateway', 'address': '127.0.0.1',
                       'port': row['upstream_port'], 'transport': 'tcp'})
    rpc = ingress['sava']['settings']['rpc']
    claims.append({'owner': 'mk8.sava Application RPC', 'address': rpc['address'],
                   'port': rpc['port'], 'transport': 'tcp'})
    dns = prerequisites['components']['dns']['dns_service']['plan']['listeners']
    for row in dns:
        claims.append({'owner': row['unit']+' health', 'address': row['health_address'],
                       'port': row['health_port'], 'transport': 'tcp'})
    occupied = {}
    for row in claims:
        if (row['address'] not in ('127.0.0.1', '::1') or
            type(row['port']) is not int or not 1024 <= row['port'] <= 65535 or row['port'] == 5432):
            raise Pending('unsupported loopback listener intention')
        key = row['address'], row['port'], row['transport']
        if key in occupied:
            raise Pending(f"listener conflict at {key[0]}:{key[1]}: {occupied[key]} and {row['owner']}")
        occupied[key] = row['owner']
    return claims


def prepare(check='all', deadline=None):
    if type(check) is not str or check not in (*CHECKS, 'all'):
        raise Pending('unknown application preflight check')
    start = now()
    if deadline is not None and (type(deadline) not in (int, float) or
                                not math.isfinite(deadline) or deadline <= start):
        raise Pending('invalid inherited preflight deadline')
    end = min(start+ATTEMPT_SECONDS, deadline) if deadline is not None else start+ATTEMPT_SECONDS
    selected = ('prerequisites', 'ingress') if check == 'all' else (check,)
    values, summaries, modules = {}, {}, []
    namespace = None
    for tag in selected:
        fence(end)
        module = owned(tag)
        context = module.KERNEL.uint(module.KERNEL.namespace(), 0xffffffffffffffff)
        if context == 0 or namespace is not None and context != namespace:
            raise Pending(tag+': namespace unavailable or changed')
        namespace = context
        raw, value = observe(tag, module, end, namespace)
        modules.append(module)
        values[tag] = value
        summaries[tag] = {'state': value['state'], 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()}
    listeners = listener_plan(values['prerequisites'], values['ingress']) if check == 'all' else []
    payload = canonical({'schema': 1, 'state': 'application-preflight-source-only',
        'requested': check, 'namespace': namespace, 'checks': summaries,
        'listener_intentions': listeners, 'limitations': list(LIMITATIONS)})
    if len(payload) > MAX_OUTPUT:
        raise Pending('preflight report exceeds its bound')
    for module in modules:
        if module.KERNEL.uint(module.KERNEL.namespace(), 0xffffffffffffffff) != namespace:
            raise Pending('preflight namespace changed')
    fence(end)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', choices=(*CHECKS, 'all'), default='all')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    args = parser.parse_args(argv)
    try:
        raw = prepare(args.check)
        if args.format == 'text':
            value = json.loads(raw)
            lines = ['Protected application file checks completed: '+', '.join(value['checks'])+'.',
                     'Scope: source inputs only; application readiness remains unverified.']
            lines.extend(f"{row['owner']}: {row['address']}:{row['port']} ({row['transport']} intention)"
                         for row in value['listener_intentions'])
            lines.extend(value['limitations'])
            raw = ('\n'.join(lines)+'\n').encode('ascii')
        sink = sys.stdout.buffer
        count = sink.write(raw)
        if type(count) is not int or count != len(raw):
            raise Pending('incomplete preflight output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
