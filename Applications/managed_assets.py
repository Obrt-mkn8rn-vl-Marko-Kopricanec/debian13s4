#!/usr/bin/python3
"""Bind already-selected .NET dependency assets to protected release files.

This is a closed app-directory file profile, not host probing, RID fallback,
framework resolution, native dependency resolution, signature or ABI validation.
No CLR, package, application, socket or process entry occurs here.
"""
import base64
import hashlib
import importlib.util
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_managed_assets_runtime',
    Path(__file__).resolve().with_name('managed_runtime.py'))
RUNTIME = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(RUNTIME)
RELEASE, BASE, KERNEL, Pending = RUNTIME.RELEASE, RUNTIME.BASE, RUNTIME.KERNEL, RUNTIME.Pending
PROFILE = 'four-app-selected-dependency-file-correspondence-v1'
STATE = 'protected-managed-dependency-files-source-only'
ATTEMPT_SECONDS = 2 * (RUNTIME.ATTEMPT_SECONDS + RELEASE.ATTEMPT_SECONDS) + 10
MAX_OUTPUT, MAX_ASSETS = 1048577, 256


def library_name(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value) is None:
        raise Pending('unsupported dependency library name')
    return value


def version(value):
    if type(value) is not str or re.fullmatch(r'[0-9][A-Za-z0-9_.+-]{0,95}', value) is None:
        raise Pending('dependency requires an explicit bounded version')
    return value


def library(value):
    if type(value) is not str or value.count('/') != 1:
        raise Pending('dependency library key requires name/version')
    name, release = value.split('/')
    return library_name(name), version(release)


def library_record(value):
    KERNEL.known(value, {'type', 'serviceable', 'sha512', 'path', 'hashPath'}, {'type', 'serviceable', 'sha512'})
    if value['type'] not in ('project', 'package', 'reference') or type(value['serviceable']) is not bool:
        raise Pending('unsupported selected dependency library record')
    digest = value['sha512']
    if type(digest) is not str or len(digest) > 88: raise Pending('unsupported dependency hash declaration')
    if digest:
        try: data = base64.b64decode(digest, validate=True)
        except ValueError as error: raise Pending('invalid dependency hash declaration') from error
        if len(data) != 64 or base64.b64encode(data).decode('ascii') != digest:
            raise Pending('dependency hash declaration is not canonical SHA512-sized data')
    for name in ('path', 'hashPath'):
        if name in value: RELEASE.relative(value[name])


def asset_path(kind, name, value):
    RELEASE.relative(name)
    fields = {'assemblyVersion', 'fileVersion'} | ({'locale'} if kind == 'resources' else set())
    KERNEL.known(value, fields, {'locale'} if kind == 'resources' else set())
    for key in ('assemblyVersion', 'fileVersion'):
        if key in value:
            text = value[key]
            if (type(text) is not str or re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}', text) is None or
                any(int(part) > 65535 for part in text.split('.'))):
                raise Pending('unsupported reported dependency asset version')
    pieces = name.split('/')
    if pieces[-1] == '_._': raise Pending('dependency placeholders are outside the selected file profile')
    if kind == 'resources':
        locale = value['locale']
        if (type(locale) is not str or re.fullmatch(r'[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,4}', locale) is None or
            len(pieces) < 2 or pieces[-2] != locale):
            raise Pending('resource path and explicit locale differ')
        return locale+'/'+pieces[-1]
    return pieces[-1]


def bind(value, architecture, entry, declared, observed):
    """Correspondence within the owned whole release; no external probing."""
    summary = RUNTIME.dependencies(value, architecture)
    target = summary['runtime_target']
    if set(value['targets']) != {target} or set(value['targets'][target]) != set(value['libraries']):
        raise Pending('dependency file requires one complete already-selected target')
    RELEASE.relative(entry)
    parent = Path(entry).parent
    assets, destinations, entry_count = [], set(), 0
    group = value['targets'][target]
    for key, row in sorted(group.items()):
        library(key); library_record(value['libraries'][key])
        KERNEL.known(row, {'dependencies', 'runtime', 'native', 'resources'}, set())
        dependencies = row.get('dependencies', {})
        if type(dependencies) is not dict or len(dependencies) > 4096:
            raise Pending('unsupported selected dependency references')
        for name, release in dependencies.items():
            reference = library_name(name)+'/'+version(release)
            if reference not in group: raise Pending('dependency reference is absent from the selected library table')
        for kind in ('runtime', 'native', 'resources'):
            table = row.get(kind, {})
            if type(table) is not dict or len(table) > MAX_ASSETS:
                raise Pending('dependency asset inventory exceeds its bound')
            for name, facts in sorted(table.items()):
                relative = str(parent/asset_path(kind, name, facts))
                RELEASE.relative(relative)
                if relative in destinations: raise Pending('dependency assets collide at one published file')
                destinations.add(relative)
                if relative not in declared['files'] or relative not in observed['files']:
                    raise Pending('selected dependency asset is absent from the whole release: '+relative)
                item, source = declared['files'][relative], observed['files'][relative]
                if (item['bytes'] == 0 or item['mode'] not in (('0644', '0755') if kind == 'native' else ('0644',)) or
                    source['sha256'] != item['sha256'] or source['identity'][5] != item['bytes'] or
                    source['path'] != str(Path(declared['directory'])/relative)):
                    raise Pending('dependency asset differs from its nonempty protected file declaration')
                assets.append({'library': key, 'kind': kind, 'declared_path': name,
                               'release_path': relative, 'source': source})
                if kind == 'runtime' and relative == entry+'.dll': entry_count += 1
                if len(assets) > MAX_ASSETS: raise Pending('selected dependency assets exceed their combined bound')
    if entry_count != 1:
        raise Pending('dependency target must include the declared entry assembly exactly once')
    return {'runtime_target': target, 'libraries': len(group), 'assets': assets,
            'framework_resolution_verified': False, 'loader_resolution_verified': False,
            'package_hashes_verified': False}


def prerequisites(end, context):
    BASE.fence(end)
    try: runtime_raw = RUNTIME.prepare(deadline=end)
    except RUNTIME.Pending as error: raise Pending('complete managed runtime preparation refused') from error
    if type(runtime_raw) is not bytes or not runtime_raw or len(runtime_raw) > RUNTIME.MAX_OUTPUT:
        raise Pending('unsupported managed runtime receipt')
    runtime = RUNTIME.decoded(runtime_raw)
    fields = {'schema', 'profile', 'state', 'namespace', 'image_configuration', 'release_sha256', 'applications'}
    KERNEL.known(runtime, fields, fields)
    if (type(runtime['schema']) is not int or runtime['schema'] != 1 or runtime['profile'] != RUNTIME.PROFILE or
        runtime['state'] != RUNTIME.STATE or KERNEL.uint(runtime['namespace'], 0xffffffffffffffff) != context or
        runtime_raw != BASE.canonical(runtime)):
        raise Pending('managed runtime profile, context or canonical receipt differs')
    release_raw, release = RUNTIME.IMAGE.prerequisite(end, context)
    if hashlib.sha256(release_raw).hexdigest() != runtime['release_sha256']:
        raise Pending('managed runtime and whole release observations differ')
    BASE.fence(end)
    return runtime_raw, runtime, release_raw, release


def observations(runtime, release, end):
    result = {}
    architecture = runtime['image_configuration']['value']['architecture']
    for app in RELEASE.APPLICATIONS:
        declared, observed = release['configuration']['value']['applications'][app], release['applications'][app]
        result[app] = {}
        for role in RELEASE.SERVICES:
            entry = declared['entry_points'][role]; expected = runtime['applications'][app][role]['sources']['dependencies']
            raw, source = BASE.read_protected(Path(declared['directory'])/(entry+'.deps.json'), RUNTIME.MAX_JSON, False, end)
            if BASE.canonical(source) != BASE.canonical(expected): raise Pending('selected dependency file observation changed')
            BASE.fence(end)
            value = bind(RUNTIME.decoded(raw), architecture, entry, declared, observed)
            result[app][role] = {'dependencies': source, **value}
            BASE.fence(end)
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited dependency file window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if not context: raise Pending('missing dependency file namespace')
    runtime_raw, runtime, release_raw, release = prerequisites(end, context)
    observed = observations(runtime, release, end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'runtime_sha256': hashlib.sha256(runtime_raw).hexdigest(), 'release_sha256': hashlib.sha256(release_raw).hexdigest(),
        'image_configuration': runtime['image_configuration'], 'applications': observed})
    if len(raw) > MAX_OUTPUT: raise Pending('dependency file report exceeds its bound')
    final_runtime_raw, final_runtime, final_release_raw, final_release = prerequisites(end, context)
    if (final_runtime_raw != runtime_raw or final_release_raw != release_raw or
        BASE.canonical(observations(final_runtime, final_release, end)) != BASE.canonical(observed)):
        raise Pending('managed runtime, release or dependency observations changed after encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('dependency file namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('dependency file inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete dependency file output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
