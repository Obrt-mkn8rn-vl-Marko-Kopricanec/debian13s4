#!/usr/bin/python3
"""Bind protected release files to explicit existing local account intentions.

These repeated file observations do not authenticate NSS/PAM, effective process
credentials, group privileges, IPC, publisher provenance or running services.
No accounts, directories, units or processes are created or changed.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_identity_releases',
    Path(__file__).resolve().with_name('releases.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
BASE, KERNEL, Pending = RELEASE.BASE, RELEASE.KERNEL, RELEASE.Pending
INPUT = Path('/etc/debian13s4/application-identities.json')
PASSWD, GROUP = Path('/etc/passwd'), Path('/etc/group')
MAX_INPUT = 8192
MAX_INVENTORY = 262144
MAX_ROWS = 4096
MAX_OUTPUT = 2097153
ATTEMPT_SECONDS = 130


def name(value):
    if (type(value) is not str or
        re.fullmatch(r'[a-z][a-z0-9_]{0,30}', value) is None or value == 'root'):
        raise Pending('unsupported explicit application account or group name')
    return value


def checked(value):
    KERNEL.known(value, {'schema', 'applications'}, {'schema', 'applications'})
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported application identity schema')
    KERNEL.known(value['applications'], set(RELEASE.APPLICATIONS), set(RELEASE.APPLICATIONS))
    names = set()
    for app in RELEASE.APPLICATIONS:
        row = value['applications'][app]
        fields = {'application_user', 'gateway_user', 'shared_groups'}
        KERNEL.known(row, fields, fields)
        shared = row['shared_groups']
        if type(shared) is not list or len(shared) > 8:
            raise Pending('explicit shared groups require a bounded list, possibly empty')
        for entry in [row['application_user'], row['gateway_user'], *shared]:
            entry = name(entry)
            if entry in names:
                raise Pending('application roles and shared groups must have distinct names')
            names.add(entry)
    return json.loads(BASE.canonical(value))


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite identity input')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected application identity input') from error
    if raw != BASE.canonical(value):
        raise Pending('identity input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def records(raw, columns):
    if (type(raw) is not bytes or not raw or len(raw) > MAX_INVENTORY or
        not raw.endswith(b'\n') or any(c != 10 and not 32 <= c <= 126 for c in raw)):
        raise Pending('account inventories require bounded printable ASCII LF records')
    lines = raw[:-1].decode('ascii').split('\n')
    if len(lines) > MAX_ROWS:
        raise Pending('account inventory exceeds its row bound')
    rows = {}
    for line in lines:
        fields = line.split(':')
        if (len(fields) != columns or
            re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', fields[0]) is None or
            fields[0] in rows):
            raise Pending('malformed or duplicate account inventory record')
        rows[fields[0]] = fields
    return rows


def numeric(text):
    if re.fullmatch(r'0|[1-9][0-9]{0,9}', text) is None:
        raise Pending('noncanonical account inventory number')
    return KERNEL.uint(int(text), 0x7fffffff)


def accounts(passwd, group, settings):
    settings = checked(settings)
    users, groups = records(passwd, 7), records(group, 4)
    primary, uids, gids, memberships = {}, set(), set(), {}
    for account, row in users.items():
        uid, gid = numeric(row[2]), numeric(row[3])
        if uid in uids:
            raise Pending('ambiguous application account UID')
        uids.add(uid); primary[account] = (uid, gid)
    for group_name, row in groups.items():
        gid = numeric(row[2]); members = row[3].split(',') if row[3] else []
        if (gid in gids or len(members) != len(set(members)) or
            any(member not in users for member in members)):
            raise Pending('ambiguous application group identity or membership')
        gids.add(gid); memberships[group_name] = (gid, set(members))
    result = {}
    for app in RELEASE.APPLICATIONS:
        intended = settings['applications'][app]
        pair = {intended['application_user'], intended['gateway_user']}
        roles, shared = {}, {}
        for role in RELEASE.SERVICES:
            account = intended[role+'_user']
            if account not in users or account not in memberships:
                raise Pending('application service account or named primary group is missing')
            row = users[account]; uid, gid = primary[account]
            if (not 100 <= uid <= 999 or not 100 <= gid <= 999 or
                row[1] not in ('x', '!', '*') or
                row[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false') or
                memberships[account][0] != gid or memberships[account][1] - {account} or
                any(other != account and other_gid == gid for other, (_, other_gid) in primary.items())):
                raise Pending('application requires a dedicated nonlogin system account and primary group')
            allowed = {account, *intended['shared_groups']}
            if any(account in members and group_name not in allowed
                   for group_name, (_, members) in memberships.items()):
                raise Pending('application account has undeclared supplementary membership')
            roles[role] = {'name': account, 'uid': uid, 'primary_group': account,
                'primary_gid': gid, 'shell': row[6]}
        for group_name in intended['shared_groups']:
            if group_name not in memberships:
                raise Pending('declared application shared group is missing')
            gid, members = memberships[group_name]
            if (not 100 <= gid <= 999 or members != pair or
                any(primary_gid == gid for _, primary_gid in primary.values())):
                raise Pending('shared group requires only the explicit supplementary role pair')
            shared[group_name] = gid
        result[app] = {'roles': roles, 'shared_groups': shared}
    return result


def release_bytes(end):
    BASE.fence(end)
    raw = RELEASE.prepare(deadline=end)
    if type(raw) is not bytes or len(raw) > RELEASE.MAX_OUTPUT:
        raise Pending('unsupported complete release receipt bytes')
    BASE.fence(end)
    return raw


def prepare(deadline=None):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited application identity window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing application identity namespace')
    settings = configuration(end)
    passwd, user_source = BASE.read_protected(PASSWD, MAX_INVENTORY, False, end)
    group, group_source = BASE.read_protected(GROUP, MAX_INVENTORY, False, end)
    selected = accounts(passwd, group, settings['value'])
    raw_release = release_bytes(end)
    release = json.loads(raw_release, object_pairs_hook=KERNEL.unique_object)
    if (KERNEL.uint(release['namespace'], 0xffffffffffffffff) != context or
        raw_release != BASE.canonical(release)):
        raise Pending('complete protected release namespace or canonical bytes differ')
    bindings = {}
    for app in RELEASE.APPLICATIONS:
        bindings[app] = {role: {**selected[app]['roles'][role],
            'shared_groups': selected[app]['shared_groups'],
            'entry_point': release['applications'][app]['entry_points'][role]}
            for role in RELEASE.SERVICES}
    payload = BASE.canonical({'schema': 1, 'profile': 'four-app-release-account-intention-v1',
        'state': 'protected-application-execution-identity-source-only', 'namespace': context,
        'configuration': settings, 'passwd_source': user_source, 'group_source': group_source,
        'releases': release, 'release_sha256': hashlib.sha256(raw_release).hexdigest(),
        'execution_bindings': bindings})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete execution identity receipt exceeds its output bound')
    if configuration(end) != settings:
        raise Pending('protected execution account intentions changed')
    for path, raw, source in ((PASSWD, passwd, user_source), (GROUP, group, group_source)):
        after, after_source = BASE.read_protected(path, MAX_INVENTORY, False, end)
        if after != raw or after_source != source:
            raise Pending('complete application account or group inventory changed')
    if release_bytes(end) != raw_release:
        raise Pending('complete protected application releases changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('application execution identity namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('application identities accept no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('application identities require binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete identity receipt publication')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
