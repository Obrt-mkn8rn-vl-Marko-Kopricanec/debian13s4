#!/usr/bin/python3
"""Check an explicitly enrolled, pre-provisioned local PostgreSQL 17 cluster.

No package, account, cluster, role, database or SQL mutation is performed here.
The installer startup join consumes existing private cluster enrollment.
Public system identifiers and honest native replies are not authentication,
ownership, complete catalog safety, application migration or runtime attestation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_postgresql_prepare', Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
ENROLLMENT = Path('/etc/debian13s4/postgresql-cluster.json')
DATA = Path(PREP.DATA_DIRECTORY)
CONFIG = Path(PREP.CONFIG_DIRECTORY)
RUNUSER = Path('/usr/sbin/runuser')
PSQL = Path('/usr/lib/postgresql/17/bin/psql')
CONTROL = Path('/usr/lib/postgresql/17/bin/pg_controldata')
SERVER = Path('/usr/lib/postgresql/17/bin/postgres')
ATTEMPT_SECONDS = 10
MAX_BYTES = 262144
SETTING_NAMES = ('data_directory', 'config_file', 'hba_file', 'ident_file', 'listen_addresses', 'port',
    'unix_socket_directories', 'unix_socket_permissions', 'ssl', 'fsync', 'full_page_writes',
    'synchronous_commit', 'password_encryption', 'max_connections', 'shared_buffers',
    'shared_preload_libraries', 'session_preload_libraries', 'local_preload_libraries', 'default_transaction_read_only')
# Fixed read-only query. No application identifier is interpolated into SQL.
SQL = """SELECT pg_catalog.json_build_object(
 'version',pg_catalog.current_setting('server_version_num')::integer,
 'identifier',(pg_catalog.pg_control_system()).system_identifier::text,
 'user',current_user,'database',pg_catalog.current_database(),
 'client',pg_catalog.inet_client_addr()::text,'authentication',system_user,
 'start',pg_catalog.pg_postmaster_start_time()::text,'recovery',pg_catalog.pg_is_in_recovery(),
 'settings',(SELECT pg_catalog.json_object_agg(name,pg_catalog.json_build_object(
   'value',setting,'unit',unit,'pending_restart',pending_restart)) FROM pg_catalog.pg_settings
   WHERE name IN ('data_directory','config_file','hba_file','ident_file','listen_addresses','port',
   'unix_socket_directories','unix_socket_permissions','ssl','fsync','full_page_writes',
   'synchronous_commit','password_encryption','max_connections','shared_buffers',
   'shared_preload_libraries','session_preload_libraries','local_preload_libraries','default_transaction_read_only')),
 'roles',(SELECT pg_catalog.json_agg(pg_catalog.json_build_object('name',rolname,'super',rolsuper,
   'inherit',rolinherit,'createdb',rolcreatedb,'createrole',rolcreaterole,'login',rolcanlogin,
   'replication',rolreplication,'bypass',rolbypassrls,'limit',rolconnlimit,'password',rolpassword,
   'valid_until',rolvaliduntil)) FROM pg_catalog.pg_authid WHERE pg_catalog.left(rolname,3)<>'pg_'),
 'overrides',(SELECT count(*) FROM pg_catalog.pg_db_role_setting),
 'memberships',(SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member IN
   (SELECT oid FROM pg_catalog.pg_authid WHERE pg_catalog.left(rolname,3)<>'pg_')),
 'databases',(SELECT pg_catalog.json_agg(pg_catalog.json_build_object('name',datname,
   'owner',pg_catalog.pg_get_userbyid(datdba),'encoding',pg_catalog.pg_encoding_to_char(encoding),
   'limit',datconnlimit,'allow',datallowconn,'template',datistemplate,
   'public_access',EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(datacl,
     pg_catalog.acldefault('d',datdba))) WHERE grantee=0))) FROM pg_catalog.pg_database));
"""


def end_window(deadline):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid PostgreSQL inherited window')
        end = min(end, deadline)
    PREP.fence(end)
    return end


def enrollment(end):
    raw, source = PREP.read_protected(ENROLLMENT, 4096, True, end)
    value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
        parse_constant=lambda value: (_ for _ in ()).throw(Pending('nonfinite enrollment')))
    KERNEL.known(value, {'schema', 'system_identifier'}, {'schema', 'system_identifier'})
    if type(value['schema']) is not int or value['schema'] != 1 or not KERNEL.uint(value['system_identifier'], 2**64-1):
        raise Pending('unsupported explicit PostgreSQL cluster enrollment')
    if raw != PREP.canonical(value): raise Pending('noncanonical PostgreSQL cluster enrollment')
    return {'value': value, 'source': source}


def postgres_account(end):
    raw, _ = PREP.read_protected(PREP.PASSWD, PREP.MAX_ACCOUNTS, False, end)
    # Admit the complete original grammar and selected application accounts too.
    settings = PREP.configuration(end); PREP.accounts(raw, settings['value'])
    rows = [line.split(':') for line in raw.decode('ascii')[:-1].split('\n')]
    selected = [row for row in rows if row[0] == 'postgres']
    if len(selected) != 1: raise Pending('missing dedicated PostgreSQL system account')
    row = selected[0]; uid, gid = int(row[2]), int(row[3])
    if not 100 <= uid <= 999 or gid == 0 or row[1] not in ('x', '!', '*'):
        raise Pending('unsupported PostgreSQL system account')
    app_uids = {int(item[2]) for item in rows if item[0] in
        {settings['value']['applications'][app]['role'] for app in PREP.APPLICATIONS}}
    if uid in app_uids: raise Pending('shared PostgreSQL server/application identity')
    return uid, gid


def data_read(path, end):
    """Allow the existing postgres-owned private leaf; never create/follow it."""
    uid, gid = postgres_account(end); PREP.fence(end)
    if not DATA.is_absolute() or os.path.normpath(str(DATA))!=str(DATA):
        raise Pending('noncanonical PostgreSQL data directory')
    DATA.relative_to(PREP.TRUST_ROOT)
    if path.parent != DATA: raise Pending('unapproved PostgreSQL data leaf')
    current = DATA.parent
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != PREP.TRUSTED_UID or info.st_mode & 0o022:
            raise Pending('unprotected PostgreSQL data ancestry')
        if current == PREP.TRUST_ROOT: break
        current = current.parent
    directory = DATA.lstat(); before = path.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid or directory.st_gid != gid or
        stat.S_IMODE(directory.st_mode) != 0o700 or not stat.S_ISREG(before.st_mode) or
        before.st_uid != uid or before.st_gid != gid or stat.S_IMODE(before.st_mode) != 0o600 or
        before.st_nlink != 1 or before.st_size > 4096):
        raise Pending('unsupported PostgreSQL data directory/leaf identity')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if KERNEL.signature(os.fstat(fd)) != KERNEL.signature(before): raise Pending('PostgreSQL data FD differs')
        raw = bytearray()
        while True:
            PREP.fence(end); part = os.read(fd, 4097-len(raw))
            if not part: break
            raw.extend(part)
            if len(raw)>4096: raise Pending('PostgreSQL data leaf exceeds bound')
        if (KERNEL.signature(os.fstat(fd)) != KERNEL.signature(before) or
            KERNEL.signature(path.lstat()) != KERNEL.signature(before) or len(raw)!=before.st_size or
            KERNEL.signature(DATA.lstat()) != KERNEL.signature(directory)):
            raise Pending('PostgreSQL data leaf/ancestry changed')
    finally: os.close(fd)
    PREP.fence(end)
    return bytes(raw), {'path': str(path), 'identity': list(KERNEL.signature(before)),
                        'sha256': hashlib.sha256(raw).hexdigest()}


def native(kind, end):
    if kind == 'control': binary, arguments = CONTROL, ('--pgdata', str(DATA))
    elif kind == 'catalog':
        binary = PSQL
        arguments = ('--no-psqlrc', '--no-password', '--host', PREP.SOCKET_DIRECTORY, '--port', '5432',
                     '--username', 'postgres', '--dbname', 'postgres', '--tuples-only', '--no-align',
                     '--set', 'ON_ERROR_STOP=1', '--command', SQL)
    else: raise Pending('unapproved PostgreSQL native read')
    PREP.fence(end); before = (KERNEL.trusted_binary(RUNUSER), KERNEL.trusted_binary(binary))
    until = min(end, KERNEL.now()+KERNEL.QUERY_SECONDS); PREP.fence(until)
    child = subprocess.Popen([str(RUNUSER), '-u', 'postgres', '--', str(binary), *arguments],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'}, close_fds=True, start_new_session=True)
    buffers = {'stdout':bytearray(), 'stderr':bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (('stdout',child.stdout),('stderr',child.stderr)):
                os.set_blocking(stream.fileno(),False); selector.register(stream,selectors.EVENT_READ,name)
            while selector.get_map():
                PREP.fence(until)
                remaining=until-KERNEL.now()
                if remaining<=0:raise Pending('PostgreSQL native read window expired')
                for key,_ in selector.select(remaining):
                    part=os.read(key.fileobj.fileno(),65536)
                    if not part: selector.unregister(key.fileobj); continue
                    buffer=buffers[key.data]
                    if len(buffer)+len(part)>MAX_BYTES: raise Pending('PostgreSQL native channel bound')
                    buffer.extend(part)
            PREP.fence(until); remaining=until-KERNEL.now()
            if remaining<=0:raise Pending('PostgreSQL native wait window expired')
            code=child.wait(timeout=remaining)
            if type(code) is not int or code!=0 or buffers['stderr']: raise Pending('PostgreSQL native read failed/warned')
        if (KERNEL.trusted_binary(RUNUSER),KERNEL.trusted_binary(binary))!=before:
            raise Pending('PostgreSQL native executable changed')
        PREP.fence(until); return bytes(buffers['stdout'])
    finally:
        try:
            if child.returncode is None:
                try: os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            try: child.stdout.close()
            finally: child.stderr.close()


def intention(end):
    # Real accepted preparation, not a caller-supplied manifest/healthy flag.
    record=json.loads(PREP.prepare(deadline=end))
    return record, enrollment(end)


def prestart(read=native, deadline=None):
    end=end_window(deadline); record, registered=intention(end)
    version,_=data_read(DATA/'PG_VERSION',end)
    if version!=b'17\n': raise Pending('unsupported pre-provisioned PostgreSQL major version')
    if (DATA/'postmaster.pid').exists() or (DATA/'postmaster.pid').is_symlink():
        raise Pending('PostgreSQL data has an existing or unverifiable postmaster')
    raw,_=data_read(DATA/'postgresql.auto.conf',end)
    if any(line.strip() and not line.startswith(b'#') for line in raw.split(b'\n')):
        raise Pending('PostgreSQL automatic startup overrides refuse')
    text=read('control',end).decode('ascii'); values={}
    for line in text.split('\n'):
        if not line: continue
        name, separator,value=line.partition(':')
        if not separator or name in values or any(ord(c)<32 or ord(c)>126 for c in line):
            raise Pending('unsupported pg_controldata representation')
        values[name]=value.strip()
    required={'Database system identifier','Database cluster state','Data page checksum version'}
    if not required<=values.keys() or values['Database cluster state']!='shut down' or values['Data page checksum version']!='1':
        raise Pending('PostgreSQL cluster is not cleanly stopped/checksummed')
    if values['Database system identifier']!=str(registered['value']['system_identifier']):
        raise Pending('PostgreSQL offline identifier differs from enrollment')
    if enrollment(end)!=registered or json.loads(PREP.prepare(deadline=end))!=record:
        raise Pending('PostgreSQL prestart inputs changed')
    PREP.fence(end); return record


def settings_expected(record):
    value=record['configuration']['value']
    return {'data_directory':str(DATA),'config_file':str(CONFIG/'postgresql.conf'),
        'hba_file':str(CONFIG/'pg_hba.conf'),'ident_file':str(CONFIG/'pg_ident.conf'),'listen_addresses':'',
        'port':'5432','unix_socket_directories':PREP.SOCKET_DIRECTORY,'unix_socket_permissions':'0777',
        'ssl':'off','fsync':'on','full_page_writes':'on','synchronous_commit':'on','password_encryption':'scram-sha-256',
        'max_connections':str(value['max_connections']),'shared_buffers':str(value['shared_buffers_mb']*128),
        'shared_preload_libraries':'','session_preload_libraries':'','local_preload_libraries':'','default_transaction_read_only':'off'}


def catalog(value, record, registered):
    fields={'version','identifier','user','database','client','authentication','start','recovery','settings','roles','memberships','overrides','databases'}
    KERNEL.known(value,fields,fields)
    if (type(value['version']) is not int or not 170000<=value['version']<180000 or
        type(value['identifier']) is not str or value['identifier']!=str(registered['value']['system_identifier']) or
        value['user']!='postgres' or value['database']!='postgres' or value['client'] is not None or
        value['authentication']!='peer:postgres' or value['recovery'] is not False or
        type(value['start']) is not str or not 1<=len(value['start'])<=64 or
        any(ord(c)<32 or ord(c)>126 for c in value['start']) or type(value['memberships']) is not int or value['memberships']!=0 or
        type(value['overrides']) is not int or value['overrides']!=0):
        raise Pending('unsupported PostgreSQL server/session identity')
    expected=settings_expected(record); KERNEL.known(value['settings'],set(expected),set(expected))
    for name,wanted in expected.items():
        row=value['settings'][name]; KERNEL.known(row,{'value','unit','pending_restart'},{'value','unit','pending_restart'})
        if row['value']!=wanted or row['pending_restart'] is not False or row['unit']!=('8kB' if name=='shared_buffers' else None):
            raise Pending('PostgreSQL loaded setting differs or awaits restart')
    roles=KERNEL.rows(value['roles'],3); by_name={}
    applications=record['configuration']['value']['applications']
    expected_roles={item['role']:item['connection_limit'] for item in applications.values()}
    for row in roles:
        fields={'name','super','inherit','createdb','createrole','login','replication','bypass','limit','password','valid_until'}
        KERNEL.known(row,fields,fields); name=row['name']
        if type(name) is not str or name in by_name or name not in {'postgres',*expected_roles}:
            raise Pending('foreign or duplicate PostgreSQL login role')
        privileged=name=='postgres'
        for key in ('super','inherit','createdb','createrole','replication','bypass'):
            if row[key] is not privileged: raise Pending('unexpected PostgreSQL role privilege')
        if row['login'] is not True or type(row['limit']) is not int or row['limit']!=(-1 if privileged else expected_roles[name]) or row['password'] is not None or row['valid_until'] is not None:
            raise Pending('unexpected PostgreSQL role authentication/limit')
        by_name[name]=row
    if set(by_name)!={'postgres',*expected_roles}: raise Pending('missing PostgreSQL application role')
    databases=KERNEL.rows(value['databases'],5); seen=set()
    owned={item['database']:item for item in applications.values()}
    for row in databases:
        fields={'name','owner','encoding','limit','allow','template','public_access'};KERNEL.known(row,fields,fields)
        name=row['name']
        if type(name) is not str or name in seen or name not in {'postgres','template0','template1',*owned}:
            raise Pending('foreign/duplicate PostgreSQL database')
        if name in owned:
            item=owned[name]
            if (row['owner']!=item['role'] or row['encoding']!='UTF8' or type(row['limit']) is not int or
                row['limit']!=item['connection_limit'] or row['allow'] is not True or row['template'] is not False or row['public_access'] is not False):
                raise Pending('PostgreSQL application database differs')
        elif (row['owner']!='postgres' or row['encoding']!='UTF8' or type(row['limit']) is not int or row['limit']!=-1 or
              row['allow'] is not (name!='template0') or row['template'] is not (name!='postgres') or type(row['public_access']) is not bool):
            raise Pending('unsupported PostgreSQL template/admin database')
        seen.add(name)
    if seen!={'postgres','template0','template1',*owned}: raise Pending('missing PostgreSQL database')
    return json.loads(PREP.canonical(value))


def check(read=native, deadline=None):
    end=end_window(deadline); record,registered=intention(end)
    version,_=data_read(DATA/'PG_VERSION',end)
    if version!=b'17\n': raise Pending('unsupported PostgreSQL data version')
    expected_files=record['plan']['files']; sources={}
    for name,text in expected_files.items():
        raw,source=PREP.read_protected(CONFIG/name,4096,False,end)
        if raw!=text.encode('ascii'): raise Pending('PostgreSQL published config differs')
        sources[name]=source
    auto,_=data_read(DATA/'postgresql.auto.conf',end)
    if any(line.strip() and not line.startswith(b'#') for line in auto.split(b'\n')): raise Pending('PostgreSQL automatic overrides refuse')
    first=catalog(json.loads(read('catalog',end).decode('utf-8'),object_pairs_hook=KERNEL.unique_object),record,registered)
    second=catalog(json.loads(read('catalog',end).decode('utf-8'),object_pairs_hook=KERNEL.unique_object),record,registered)
    if first!=second: raise Pending('PostgreSQL complete selected catalog drift')
    payload=PREP.canonical({'schema':1,'state':'enrolled-local-postgresql-source-only','namespace':record['namespace'],
        'enrollment':registered,'accounts':record['accounts'],'catalog':second})
    if len(payload)>PREP.MAX_OUTPUT: raise Pending('PostgreSQL receipt bound exceeded')
    if enrollment(end)!=registered: raise Pending('PostgreSQL enrollment changed')
    final=json.loads(PREP.prepare(deadline=end))
    if final!=record: raise Pending('PostgreSQL preparation inputs changed')
    for name,source in sources.items():
        raw,after=PREP.read_protected(CONFIG/name,4096,False,end)
        if source!=after or raw!=expected_files[name].encode('ascii'): raise Pending('PostgreSQL config changed')
    after,_=data_read(DATA/'postgresql.auto.conf',end)
    if auto!=after: raise Pending('PostgreSQL startup overrides changed')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=record['namespace']:
        raise Pending('PostgreSQL final context changed')
    PREP.fence(end); return payload


def startup(deadline=None):
    end=end_window(deadline);record,registered=intention(end);files={}
    for name,text in record['plan']['files'].items():
        raw,source=PREP.read_protected(CONFIG/name,4096,False,end)
        if raw!=text.encode('ascii'):raise Pending('PostgreSQL startup config differs')
        files[name]=source
    version,version_source=data_read(DATA/'PG_VERSION',end)
    auto,auto_source=data_read(DATA/'postgresql.auto.conf',end)
    if version!=b'17\n' or any(line.strip() and not line.startswith(b'#') for line in auto.split(b'\n')):
        raise Pending('unsupported PostgreSQL startup data')
    executables={}
    for path in (RUNUSER,PSQL,CONTROL,SERVER):
        signature=KERNEL.trusted_binary(path)
        _,source=PREP.read_protected(path,67108864,False,end)
        if list(signature)!=source['identity']:raise Pending('PostgreSQL executable changed')
        executables[str(path)]=source
    payload=PREP.canonical({'configuration':record['configuration'],'accounts':record['accounts'],
        'account_source':record['account_source'],
        'namespace':record['namespace'],'enrollment':registered,'files':files,'version':version_source,
        'automatic_configuration':auto_source,'executables':executables})
    if len(payload)>16384:raise Pending('PostgreSQL startup identity exceeds bound')
    if json.loads(PREP.prepare(deadline=end))!=record or enrollment(end)!=registered:
        raise Pending('PostgreSQL startup inputs changed')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=record['namespace']:
        raise Pending('PostgreSQL final startup context changed')
    PREP.fence(end);return payload


def main():
    try:
        args=sys.argv[1:]
        sink=sys.stdout.buffer
        if not callable(getattr(sink,'write',None)) or not callable(getattr(sink,'flush',None)):
            raise Pending('binary output required')
        if args==['--check']: payload=check()
        elif args==['--prestart']: prestart(); return 0
        elif args==['--identity']: payload=startup()
        elif len(args)==2 and args[0]=='--file' and args[1] in ('postgresql.conf','pg_hba.conf','pg_ident.conf'):
            end=end_window(None);record,_=intention(end);payload=record['plan']['files'][args[1]].encode('ascii');PREP.fence(end)
        else: raise Pending('unsupported PostgreSQL startup action')
        count=sink.write(payload)
        if type(count) is not int or count!=len(payload): raise Pending('short PostgreSQL output')
        sink.flush();return 0
    except (Pending,OSError,ValueError,TypeError,AttributeError,UnicodeError,RecursionError,subprocess.TimeoutExpired) as error:
        print('Pending: '+str(error),file=sys.stderr);return 75


if __name__=='__main__':sys.exit(main())
