#!/usr/bin/python3
"""Describe a protected release tree without copying, installing or executing it.

The resulting declaration proposes its generation directory. The operator must
publish the same bytes separately before releases.py can admit that directory.
Public hashes identify bytes; they do not authenticate a publisher or CLR/ABI.
"""
import argparse
import importlib.util
from pathlib import Path
import stat
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_manifest_releases',
    Path(__file__).resolve().with_name('releases.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
BASE, KERNEL, Pending = RELEASE.BASE, RELEASE.KERNEL, RELEASE.Pending
MAX_OUTPUT = RELEASE.MAX_OUTPUT


def prepare(application, directory, application_entry, gateway_entry, deadline=None):
    if type(application) is not str or application not in RELEASE.APPLICATIONS:
        raise Pending('select one supported application explicitly')
    if type(directory) is not type(BASE.TRUST_ROOT):
        raise Pending('release inventory requires an explicit absolute directory')
    entries = {'application': RELEASE.relative(application_entry), 'gateway': RELEASE.relative(gateway_entry)}
    if application_entry == gateway_entry:
        raise Pending('application and gateway entry points must differ')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid release inventory deadline')
    end = min(start+RELEASE.ATTEMPT_SECONDS, deadline) if deadline is not None else start+RELEASE.ATTEMPT_SECONDS
    BASE.fence(end)
    namespace = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if not namespace:
        raise Pending('missing release inventory namespace')
    before = RELEASE.tree(directory, end)
    if not 2 <= len(before['files']) <= RELEASE.MAX_FILES or not set(entries.values()) <= set(before['files']):
        raise Pending('both entry points must occur in the complete release inventory')
    expected_directories = {'.'}
    facts, total = {}, 0
    for name in before['files']:
        BASE.fence(end)
        expected_directories.update(str(p) for p in Path(name).parents if str(p) != '.')
        info = (directory/name).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != BASE.TRUSTED_UID or
            info.st_dev != before['directories']['.'][0] or stat.S_IMODE(info.st_mode) not in (0o644, 0o755) or
            not 0 <= info.st_size <= RELEASE.MAX_FILE_BYTES):
            raise Pending('unsupported release file owner, type, link, mode, device or size')
        total += info.st_size
        if total > RELEASE.MAX_TOTAL_BYTES:
            raise Pending('release inventory exceeds its total byte bound')
        facts[name] = info
    if set(before['directories']) != expected_directories:
        raise Pending('release tree contains undeclared empty directories')
    for entry in entries.values():
        if stat.S_IMODE(facts[entry].st_mode) != 0o755 or facts[entry].st_size == 0:
            raise Pending('release entry points require nonempty executable files')
    files, sources = {}, {}
    for name, info in facts.items():
        raw, source = BASE.read_protected(directory/name, info.st_size, False, end)
        if source['identity'] != list(KERNEL.signature(info)):
            raise Pending('release file changed after inventory')
        files[name] = {'bytes': len(raw), 'mode': format(stat.S_IMODE(info.st_mode), '04o'), 'sha256': source['sha256']}
        sources[name] = source
    if RELEASE.tree(directory, end) != before:
        raise Pending('release inventory changed during file reads')
    generation = RELEASE.generation(entries, files)
    declaration = {'generation': generation, 'directory': str(RELEASE.RELEASE_ROOT/application/generation),
                   'entry_points': entries, 'files': files}
    payload = BASE.canonical({'schema': 1, 'state': 'release-manifest-proposal-only',
        'application': application, 'namespace': namespace, 'source_directory': str(directory),
        'declaration': declaration, 'observed_sources': sources, 'observed_directories': before['directories']})
    if len(payload) > MAX_OUTPUT:
        raise Pending('release inventory proposal exceeds its output bound')
    # Reuse the complete production admission reader for the final observation.
    # Its directory is the actual staging tree, not the proposed destination.
    actual = dict(declaration, directory=str(directory))
    after = RELEASE.observe(actual, end)
    if after['files'] != sources or after['directories'] != before['directories']:
        raise Pending('release inventory changed after proposal encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != namespace:
        raise Pending('release inventory namespace changed')
    BASE.fence(end)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', choices=RELEASE.APPLICATIONS, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--application-entry', required=True)
    parser.add_argument('--gateway-entry', required=True)
    args = parser.parse_args(argv)
    try:
        raw = prepare(args.application, args.directory, args.application_entry, args.gateway_entry)
        sink = sys.stdout.buffer
        count = sink.write(raw)
        if type(count) is not int or count != len(raw):
            raise Pending('incomplete release proposal output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
