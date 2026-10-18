#!/usr/bin/python3
"""Observe protected PE/CLI entry structure alongside complete .NET metadata.

No CLR, apphost, assembly, native parser or application is executed. This is a
selected structural profile, not IL verification, dependency resolution,
publisher authentication, native compatibility or readiness.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def module(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(leaf))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


RUNTIME = module('debian13s4_managed_images_runtime', 'managed_runtime.py')
CLI = module('debian13s4_managed_images_cli', 'cli_image.py')
BASE, KERNEL, Pending = RUNTIME.BASE, RUNTIME.KERNEL, RUNTIME.Pending
PROFILE = 'four-app-pe-cli-entry-structure-v1'
STATE = 'protected-managed-entry-structure-source-only'
ATTEMPT_SECONDS, MAX_OUTPUT = 350, 262145


def prerequisite(end, context):
    BASE.fence(end)
    try: raw = RUNTIME.prepare(deadline=end)
    except RUNTIME.Pending as error: raise Pending('managed runtime preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > RUNTIME.MAX_OUTPUT:
        raise Pending('unsupported complete managed runtime receipt')
    value = RUNTIME.decoded(raw)
    fields = {'schema', 'profile', 'state', 'namespace', 'image_configuration', 'release_sha256', 'applications'}
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or value['profile'] != RUNTIME.PROFILE or
        value['state'] != RUNTIME.STATE or KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
        raw != BASE.canonical(value)):
        raise Pending('managed runtime receipt profile/context/canonical bytes differ')
    BASE.fence(end)
    return raw, value


def images(runtime, end):
    architecture = runtime['image_configuration']['value']['architecture']
    result = {}
    KERNEL.known(runtime['applications'], set(RUNTIME.RELEASE.APPLICATIONS), set(RUNTIME.RELEASE.APPLICATIONS))
    for app in RUNTIME.RELEASE.APPLICATIONS:
        roles = runtime['applications'][app]
        KERNEL.known(roles, set(RUNTIME.RELEASE.SERVICES), set(RUNTIME.RELEASE.SERVICES))
        result[app] = {}
        for role in RUNTIME.RELEASE.SERVICES:
            expected = roles[role]['sources']['assembly']
            raw, source = BASE.read_protected(Path(expected['path']), CLI.MAX_BYTES, False, end)
            if BASE.canonical(source) != BASE.canonical(expected):
                raise Pending('managed entry bytes differ from the complete release observation')
            BASE.fence(end)
            try: image = CLI.inspect(raw, architecture)
            except CLI.Pending as error: raise Pending('managed entry structure refused: '+app+' '+role) from error
            BASE.fence(end)
            result[app][role] = {'source': source, 'structure': image}
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited managed entry window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if not context: raise Pending('missing managed entry namespace')
    original, runtime = prerequisite(end, context)
    observed = images(runtime, end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'runtime_sha256': hashlib.sha256(original).hexdigest(), 'release_sha256': runtime['release_sha256'],
        'image_configuration': runtime['image_configuration'], 'applications': observed})
    if len(raw) > MAX_OUTPUT: raise Pending('managed entry report exceeds its output bound')
    after, value = prerequisite(end, context)
    if after != original or BASE.canonical(images(value, end)) != BASE.canonical(observed):
        raise Pending('complete managed runtime or entry observations changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('managed entry namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('managed entry inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete managed entry output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
