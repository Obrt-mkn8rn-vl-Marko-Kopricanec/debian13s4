#!/usr/bin/python3
"""Observe empty nftables space for the limited initial preparation profile.

Any existing object, including the reserved table, refuses. This does not inspect
legacy xtables, tc/eBPF or other namespaces, and is not installation authority.
"""

import importlib.util
import json
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import os

SPEC = importlib.util.spec_from_file_location('debian13s4_nft_kernel', Path(__file__).with_name('kernel.py'))
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending
BINARY = Path('/usr/sbin/nft')
COMMAND = ('--json', '--numeric', '--handle', 'list', 'ruleset')
MAX_BYTES = 262144
ATTEMPT_SECONDS = 10


def native_query(deadline):
    if not KERNEL.finite_deadline(deadline) or deadline <= KERNEL.now():
        raise Pending('invalid or expired nft read deadline')
    identity = KERNEL.trusted_binary(BINARY)
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    if KERNEL.now() >= end:
        raise Pending('nft read admission expired')
    process = subprocess.Popen([str(BINARY), *COMMAND], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = end - KERNEL.now()
                if remaining <= 0:
                    raise Pending('nft read timed out')
                for key, _ in selector.select(remaining):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending('nft read output limit exceeded')
                    buffer.extend(data)
            remaining = end - KERNEL.now()
            if remaining <= 0 or process.wait(timeout=remaining) != 0 or buffers['stderr']:
                raise Pending('nft read failed or warned')
        if KERNEL.trusted_binary(BINARY) != identity:
            raise Pending('nft binary changed during read')
        try:
            return json.loads(buffers['stdout'].decode('utf-8'), object_pairs_hook=KERNEL.unique_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Pending('invalid nft read JSON') from error
    except subprocess.TimeoutExpired as error:
        raise Pending('nft read timed out after pipe closure') from error
    finally:
        try:
            # Retain the leader PID until its owned group is terminated on a
            # capture error; trusted native tools must stay in this session.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            process.stdout.close()
            process.stderr.close()


def metadata(value):
    fields = {'version', 'release_name', 'json_schema_version'}
    KERNEL.known(value, fields, fields)
    if type(value['json_schema_version']) is not int or value['json_schema_version'] != 1:
        raise Pending('unsupported nft JSON schema')
    if type(value['version']) is not str or len(value['version']) > 32 or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value['version']) is None:
        raise Pending('invalid nft version metadata')
    release = value['release_name']
    if type(release) is not str or not release or len(release) > 128 or any(ord(char) < 32 or ord(char) > 126 for char in release):
        raise Pending('invalid nft release metadata')
    return dict(value)


def empty_ruleset(value):
    KERNEL.known(value, {'nftables'}, ('nftables',))
    rows = KERNEL.rows(value['nftables'])
    if not rows or set(rows[0]) != {'metainfo'}:
        raise Pending('missing native nft metainfo')
    info = metadata(rows[0]['metainfo'])
    if len(rows) != 1:
        # A name/comment/owner flag cannot establish that an existing table's
        # complete content belongs to this installer. Do not overwrite it.
        raise Pending('existing nft objects require separate ownership/coexistence verification')
    return info


def validate_receipt(value):
    fields = {'schema', 'namespace', 'empty', 'source'}
    KERNEL.known(value, fields, fields)
    if value['schema'] != 'debian13s4-nft-empty-1' or value['empty'] is not True or not KERNEL.uint(value['namespace'], (1 << 64) - 1):
        raise Pending('invalid empty nft receipt')
    source = value['source']
    fields = {'binary', 'version', 'release_name', 'json_schema_version'}
    KERNEL.known(source, fields, fields)
    if source['binary'] != str(BINARY):
        raise Pending('nft receipt source differs from the fixed tool')
    metadata({key: source[key] for key in fields - {'binary'}})
    return value


def observe(query=native_query, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid nft observation deadline')
    deadline = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = scope()
    if not KERNEL.uint(namespace, (1 << 64) - 1):
        raise Pending('invalid nft observer namespace')
    first = empty_ruleset(query(deadline))
    second = empty_ruleset(query(deadline))
    if first != second or scope() != namespace or KERNEL.now() >= deadline:
        raise Pending('nft observation changed or expired')
    return validate_receipt({'schema': 'debian13s4-nft-empty-1', 'namespace': namespace, 'empty': True,
                             'source': {'binary': str(BINARY), **second}})


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        payload = json.dumps(observe(), sort_keys=True, separators=(',', ':')) + '\n'
        sys.stdout.write(payload)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'debian13s4 nft preflight pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
