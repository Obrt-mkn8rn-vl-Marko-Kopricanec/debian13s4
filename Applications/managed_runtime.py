#!/usr/bin/python3
"""Check conventional framework-dependent .NET10 release metadata as files.

No dotnet, loader, package query, assembly or application is executed. Companion
names are this explicit profile's convention, not decoded apphost bindings.
"""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_managed_image_profile',
    Path(__file__).resolve().with_name('linux_images.py'))
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)
RELEASE, BASE, KERNEL, Pending = IMAGE.RELEASE, IMAGE.BASE, IMAGE.KERNEL, IMAGE.Pending
MAX_JSON, MAX_OUTPUT, ATTEMPT_SECONDS = 1048576, 262145, 150
PROFILE = 'four-app-dotnet10-framework-metadata-v1'
STATE = 'protected-managed-runtime-metadata-source-only'
FRAMEWORKS = {'Microsoft.NETCore.App', 'Microsoft.AspNetCore.App'}
BOOL_PROPERTIES = {'System.GC.Server', 'System.GC.Concurrent', 'System.Runtime.TieredCompilation',
    'System.Runtime.TieredPGO', 'System.Globalization.Invariant', 'System.Globalization.PredefinedCulturesOnly',
    'System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault', 'System.Diagnostics.Tracing.EventSource.IsSupported'}
FALSE_PROPERTIES = {'System.Reflection.Metadata.MetadataUpdater.IsSupported',
                    'System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization'}


def decoded(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON:
        raise Pending('managed metadata requires bounded immutable whole bytes')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite managed metadata')))
        stack = [(value, 0)]; nodes = 0
        while stack:
            item, depth = stack.pop(); nodes += 1
            if nodes > 65536 or depth > 24: raise Pending('managed metadata exceeds its structural bound')
            if type(item) is dict:
                for key, child in item.items():
                    if len(key) > 512 or any(ord(c) < 32 for c in key): raise Pending('invalid managed metadata key')
                    stack.append((child, depth+1))
            elif type(item) is list: stack.extend((child, depth+1) for child in item)
            elif type(item) is str:
                if len(item) > 8192 or any(ord(c) < 32 for c in item): raise Pending('invalid managed metadata string')
            elif type(item) is int:
                if not -(2**63) <= item < 2**63: raise Pending('managed metadata integer exceeds signed64')
            elif type(item) is float and not math.isfinite(item): raise Pending('nonfinite managed metadata')
        if type(value) is not dict: raise Pending('managed metadata requires a JSON object')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid strict managed metadata JSON') from error
    # SDK whitespace/order is retained verbatim in the protected source hash.
    return value


def runtime(value):
    KERNEL.known(value, {'runtimeOptions'}, {'runtimeOptions'})
    options = value['runtimeOptions']
    KERNEL.known(options, {'tfm', 'framework', 'frameworks', 'rollForward', 'applyPatches', 'configProperties'},
                         {'tfm', 'rollForward'})
    if (options['tfm'] != 'net10.0' or options['rollForward'] != 'LatestPatch' or
        'applyPatches' in options and options['applyPatches'] is not True):
        raise Pending('managed profile requires net10.0 with explicit LatestPatch and enabled patch selection')
    if ('framework' in options) == ('frameworks' in options):
        raise Pending('managed profile requires exactly one framework declaration form')
    rows = [options['framework']] if 'framework' in options else options['frameworks']
    if type(rows) is not list or not 1 <= len(rows) <= 2: raise Pending('unsupported framework count')
    result = {}
    for row in rows:
        KERNEL.known(row, {'name', 'version', 'rollForward', 'applyPatches'}, {'name', 'version'})
        name, version = row['name'], row['version']
        if (type(name) is not str or name not in FRAMEWORKS or name in result or type(version) is not str or
            re.fullmatch(r'10\.0\.(?:0|[1-9][0-9]{0,3})', version) is None or
            row.get('rollForward', 'LatestPatch') != 'LatestPatch' or
            'applyPatches' in row and row['applyPatches'] is not True):
            raise Pending('unsupported, repeated or conflicting managed framework reference')
        result[name] = version
    if 'Microsoft.NETCore.App' not in result: raise Pending('the core framework must be explicit')
    properties = options.get('configProperties', {})
    if type(properties) is not dict or set(properties)-BOOL_PROPERTIES-FALSE_PROPERTIES:
        raise Pending('unsupported runtime property; this profile has no probing/startup-hook overrides')
    for name, setting in properties.items():
        if type(setting) is not bool or name in FALSE_PROPERTIES and setting:
            raise Pending('runtime property has an unsupported value')
    return {'tfm': 'net10.0', 'roll_forward': 'LatestPatch', 'frameworks': result, 'properties': properties}


def dependencies(value, architecture):
    if type(architecture) is not str or architecture not in ('x86_64', 'aarch64'):
        raise Pending('dependency metadata requires an explicit supported architecture')
    KERNEL.known(value, {'runtimeTarget', 'compilationOptions', 'targets', 'libraries'},
                         {'runtimeTarget', 'targets', 'libraries'})
    target = value['runtimeTarget']
    KERNEL.known(target, {'name', 'signature'}, {'name'})
    rid = {'x86_64': 'linux-x64', 'aarch64': 'linux-arm64'}[architecture]
    portable = '.NETCoreApp,Version=v10.0'
    name = target['name']
    if type(name) is not str or name not in (portable, portable+'/'+rid):
        raise Pending('dependency target differs from net10.0 and the explicit Linux architecture')
    if 'signature' in target and type(target['signature']) is not str: raise Pending('invalid dependency signature spelling')
    targets, libraries = value['targets'], value['libraries']
    if (type(targets) is not dict or not 1 <= len(targets) <= 2 or name not in targets or
        set(targets)-{portable, portable+'/'+rid} or type(libraries) is not dict or not 1 <= len(libraries) <= 4096):
        raise Pending('unsupported bounded dependency target/library tables')
    for group in targets.values():
        if type(group) is not dict or not 1 <= len(group) <= 4096 or set(group)-set(libraries):
            raise Pending('dependency target entries require corresponding library records')
        if any(type(row) is not dict for row in group.values()): raise Pending('dependency target entries must be objects')
    if any(type(row) is not dict for row in libraries.values()): raise Pending('dependency library records must be objects')
    if 'compilationOptions' in value and type(value['compilationOptions']) is not dict:
        raise Pending('dependency compilation metadata must be an object')
    return {'runtime_target': name, 'libraries': len(libraries), 'selected_target_libraries': len(targets[name])}


def metadata(releases, architecture, end):
    result = {}
    for app in RELEASE.APPLICATIONS:
        declared = releases['configuration']['value']['applications'][app]
        observed = releases['applications'][app]
        result[app] = {}
        for role in RELEASE.SERVICES:
            entry = declared['entry_points'][role]
            if entry+'.runtimeconfig.dev.json' in declared['files']:
                raise Pending('development probing metadata is outside this runtime profile')
            sources, parsed = {}, {}
            for label, suffix in (('assembly', '.dll'), ('runtime', '.runtimeconfig.json'), ('dependencies', '.deps.json')):
                name = entry+suffix
                if (name not in declared['files'] or declared['files'][name]['mode'] != '0644' or
                    declared['files'][name]['bytes'] == 0):
                    raise Pending('managed entry requires explicit nonempty 0644 assembly/runtime/dependency companions')
                source = observed['files'][name]
                sources[label] = source
                if label == 'assembly': continue  # Whole release preparation already reads these opaque bytes.
                raw, actual = BASE.read_protected(Path(declared['directory'])/name, MAX_JSON, False, end)
                if BASE.canonical(actual) != BASE.canonical(source): raise Pending('managed metadata differs from the protected release')
                value = decoded(raw)
                parsed[label] = runtime(value) if label == 'runtime' else dependencies(value, architecture)
                BASE.fence(end)
            result[app][role] = {'sources': sources, **parsed}
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited managed metadata window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing managed metadata namespace')
    settings = IMAGE.configuration(end)
    child_raw, releases = IMAGE.prerequisite(end, context)
    values = metadata(releases, settings['value']['architecture'], end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'image_configuration': settings, 'release_sha256': hashlib.sha256(child_raw).hexdigest(), 'applications': values})
    if len(raw) > MAX_OUTPUT: raise Pending('managed metadata report exceeds its output bound')
    if IMAGE.configuration(end) != settings: raise Pending('explicit target architecture changed')
    after, observed = IMAGE.prerequisite(end, context)
    if after != child_raw or metadata(observed, settings['value']['architecture'], end) != values:
        raise Pending('complete releases or managed metadata changed after encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('managed metadata namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('managed metadata inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete managed metadata output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
