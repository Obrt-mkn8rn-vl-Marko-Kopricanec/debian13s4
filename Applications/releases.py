#!/usr/bin/python3
"""Observe complete protected, preinstalled four-app release file intentions.

No binary is executed, installed, adopted or authenticated. Matching public
hashes and repeated filesystem facts are SOURCE correspondence only, not a
signed publisher/release, loaded memory, ABI, service or readiness certificate.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_release_reader',
    Path(__file__).resolve().parents[1] / 'PostgreSQL/prepare.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
KERNEL, Pending = BASE.KERNEL, BASE.Pending
INPUT = Path('/etc/debian13s4/application-releases.json')
RELEASE_ROOT = Path('/opt/debian13s4-apps')
APPLICATIONS = ('mk8.sava', 'mk8.drava', 'mk8.dns', 'mk8.email')
SERVICES = ('application', 'gateway')
MAX_INPUT = 262145
MAX_OUTPUT = 1048577
MAX_FILES = 256
MAX_DIRECTORIES = 256
MAX_TREE_ITEMS = 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
ATTEMPT_SECONDS = 60


def relative(value):
    if (type(value) is not str or not 1 <= len(value) <= 160 or
        re.fullmatch(r'[A-Za-z0-9_.-]{1,64}(?:/[A-Za-z0-9_.-]{1,64}){0,7}', value) is None or
        any(part in ('.', '..') for part in value.split('/'))):
        raise Pending('unsupported canonical relative release path')
    return value


def sha(value):
    if (type(value) is not str or re.fullmatch(r'[0-9a-f]{64}', value) is None or
        value == '0' * 64):
        raise Pending('unsupported release SHA256 spelling')
    return value


def generation(entries, files):
    return hashlib.sha256(BASE.canonical({'entry_points': entries, 'files': files})).hexdigest()


def checked(value):
    KERNEL.known(value, {'schema', 'applications'}, {'schema', 'applications'})
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported application release schema')
    KERNEL.known(value['applications'], set(APPLICATIONS), set(APPLICATIONS))
    total = 0
    for app in APPLICATIONS:
        row = value['applications'][app]
        fields = {'generation', 'directory', 'entry_points', 'files'}
        KERNEL.known(row, fields, fields)
        marker = sha(row['generation'])
        if type(row['directory']) is not str or row['directory'] != str(RELEASE_ROOT / app / marker):
            raise Pending('release requires its explicit product/generation directory')
        KERNEL.known(row['entry_points'], set(SERVICES), set(SERVICES))
        entries = [relative(row['entry_points'][role]) for role in SERVICES]
        if entries[0] == entries[1]:
            raise Pending('application and gateway entry points must differ')
        files = row['files']
        if type(files) is not dict or not 2 <= len(files) <= MAX_FILES:
            raise Pending('release requires a complete bounded file inventory')
        for name, item in files.items():
            relative(name)
            KERNEL.known(item, {'bytes', 'mode', 'sha256'}, {'bytes', 'mode', 'sha256'})
            if type(item['mode']) is not str or item['mode'] not in ('0644', '0755'):
                raise Pending('unsupported release file mode')
            total += KERNEL.uint(item['bytes'], MAX_FILE_BYTES)
            sha(item['sha256'])
        if total > MAX_TOTAL_BYTES:
            raise Pending('whole release inventory byte capacity exceeded')
        for name in entries:
            if name not in files or files[name]['mode'] != '0755' or files[name]['bytes'] == 0:
                raise Pending('release entry requires a declared nonempty executable')
        if generation(row['entry_points'], files) != marker:
            raise Pending('release generation does not bind the complete declared inventory')
    return json.loads(BASE.canonical(value))


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite release JSON')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected application release input') from error
    if raw != BASE.canonical(value):
        raise Pending('release input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def protected_directory(path, end):
    BASE.fence(end)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending('noncanonical release directory')
    path.relative_to(BASE.TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != BASE.TRUSTED_UID or
            info.st_mode & 0o022):
            raise Pending('unprotected release directory or ancestry')
        if current == BASE.TRUST_ROOT:
            break
        current = current.parent
    return path.lstat()


def tree(directory, end):
    """Fresh bounded whole tree, retaining directory identities, never content cache."""
    stack = [(Path(directory), '')]
    directories, files, device, items = {}, set(), None, 0
    while stack:
        BASE.fence(end)
        path, name = stack.pop()
        before = protected_directory(path, end)
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != BASE.TRUSTED_UID or
            stat.S_IMODE(before.st_mode) != 0o755 or
            device is not None and before.st_dev != device):
            raise Pending('release tree requires protected same-device 0755 directories')
        device = before.st_dev
        directories[name or '.'] = list(KERNEL.signature(before))
        if len(directories) > MAX_DIRECTORIES:
            raise Pending('release directory count exceeds its bound')
        with os.scandir(path) as entries:
            for entry in entries:
                BASE.fence(end)
                items += 1
                if items > MAX_TREE_ITEMS:
                    raise Pending('release tree exceeds its entry bound')
                child = entry.name if not name else name + '/' + entry.name
                relative(child)
                fact = entry.stat(follow_symlinks=False)
                if fact.st_dev != device:
                    raise Pending('release tree crosses a device boundary')
                if stat.S_ISDIR(fact.st_mode):
                    stack.append((path / entry.name, child))
                elif stat.S_ISREG(fact.st_mode):
                    files.add(child)
                    if len(files) > MAX_FILES:
                        raise Pending('release tree exceeds its file count')
                else:
                    raise Pending('release tree contains a link or unsupported object')
        if KERNEL.signature(path.lstat()) != KERNEL.signature(before):
            raise Pending('release directory changed during enumeration')
    return {'directories': directories, 'files': sorted(files)}


def observe(row, end):
    directory = Path(row['directory'])
    before = tree(directory, end)
    expected_directories = {'.'}
    for name in row['files']:
        expected_directories.update(str(parent) for parent in Path(name).parents if str(parent) != '.')
    if set(before['files']) != set(row['files']) or set(before['directories']) != expected_directories:
        raise Pending('complete release tree differs from declared files or parents')
    sources = {}
    for name in sorted(row['files']):
        item = row['files'][name]
        raw, source = BASE.read_protected(directory / name, item['bytes'], False, end)
        identity = source['identity']
        if (len(raw) != item['bytes'] or source['sha256'] != item['sha256'] or
            stat.S_IMODE(identity[2]) != int(item['mode'], 8) or identity[0] != before['directories']['.'][0]):
            raise Pending('protected release file bytes, mode or device differs')
        sources[name] = source
    if tree(directory, end) != before:
        raise Pending('complete release tree changed during file reads')
    return {'generation': row['generation'], 'directory': str(directory),
        'entry_points': {role: str(directory / row['entry_points'][role]) for role in SERVICES},
        'directories': before['directories'], 'files': sources}


def prepare(deadline=None):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited release window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing release caller namespace')
    settings = configuration(end)
    observed = {app: observe(settings['value']['applications'][app], end) for app in APPLICATIONS}
    payload = BASE.canonical({'schema': 1, 'profile': 'four-app-complete-release-files-v1',
        'state': 'protected-preinstalled-release-source-only', 'namespace': context,
        'configuration': settings, 'applications': observed})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete release receipt exceeds its output bound')
    if configuration(end) != settings:
        raise Pending('protected release intentions changed')
    for app in APPLICATIONS:
        if observe(settings['value']['applications'][app], end) != observed[app]:
            raise Pending('protected release files or identities changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('release caller namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('release admission accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('release admission requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete release receipt publication')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
