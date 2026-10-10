"""Private native, manager, UID and package deliveries; no host PostgreSQL."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import tempfile
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


def ownership_context(data):
    original_lstat=Path.lstat;original_fstat=os.fstat
    def substitute(info,path):
        if path==data or data in path.parents:
            values={name:getattr(info,name) for name in ('st_mode','st_ino','st_dev','st_nlink','st_uid','st_gid',
                'st_size','st_atime','st_mtime','st_ctime','st_atime_ns','st_mtime_ns','st_ctime_ns')}
            values['st_uid']=220;values['st_gid']=220;return SimpleNamespace(**values)
        return info
    def lstat(path,*args,**kw):return substitute(original_lstat(path,*args,**kw),path)
    def fstat(fd):
        path=Path(os.readlink('/proc/self/fd/'+str(fd)))
        return substitute(original_fstat(fd),path)
    stack=ExitStack();stack.enter_context(patch.object(Path,'lstat',lstat));stack.enter_context(patch.object(os,'fstat',fstat))
    return stack


def configure(m,root):
    m.PREP.TRUST_ROOT=root;m.PREP.TRUSTED_UID=os.getuid()
    m.PREP.INPUT=root/'etc/postgresql.json';m.PREP.PASSWD=root/'etc/passwd'
    m.DATA=root/'data';m.CONFIG=root/'config';m.ENROLLMENT=root/'etc/postgresql-cluster.json'
    m.PREP.DATA_DIRECTORY=str(m.DATA);m.PREP.CONFIG_DIRECTORY=str(m.CONFIG);m.PREP.SOCKET_DIRECTORY=str(root/'socket')
    m.RUNUSER=root/'native/runuser';m.PSQL=root/'native/psql';m.CONTROL=root/'native/pg_controldata';m.SERVER=root/'native/postgres'
    m.KERNEL.TRUST_ROOT=root;m.KERNEL.TRUSTED_UID=os.getuid();m.KERNEL.namespace=lambda:4711
    m.PREP.prepare.__defaults__=(None,m.KERNEL.namespace)


class PrivatePG:
    def __init__(self):
        if os.getuid()==0:raise RuntimeError('Run PostgreSQL private fixtures as ordinary UID')
        self.directory=tempfile.TemporaryDirectory(dir='/dev/shm');self.root=Path(self.directory.name);self.root.chmod(0o700)
        try:
            for name in ('etc','data','config','socket','native','state','systemd','library','library/postgresql','library/maintenance','library/firewall','library/tasks','library/tasks/prerequisites'):
                (self.root/name).mkdir(mode=0o700)
            spec=importlib.util.spec_from_file_location('private_pg_live',ROOT/'PostgreSQL/live.py')
            self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m);configure(self.m,self.root)
            self.value={'schema':1,'max_connections':40,'shared_buffers_mb':128,'applications':{
                'mk8.dns':{'role':'dns_demo','database':'dns_store','connection_limit':12},
                'mk8.email':{'role':'mail_demo','database':'mail_store','connection_limit':16}}}
            self.write(self.m.PREP.INPUT,self.m.PREP.canonical(self.value))
            self.write(self.m.PREP.PASSWD,b'root:x:0:0:root:/root:/bin/bash\n'
                b'postgres:x:220:220:PostgreSQL:/nonexistent:/bin/bash\n'
                b'dns_demo:x:210:210:DNS:/nonexistent:/usr/sbin/nologin\n'
                b'mail_demo:x:211:211:Mail:/nonexistent:/usr/sbin/nologin\n',0o644)
            self.enrolled={'schema':1,'system_identifier':7341234567890123456}
            self.write(self.m.ENROLLMENT,self.m.PREP.canonical(self.enrolled))
            self.write(self.m.DATA/'PG_VERSION',b'17\n');self.write(self.m.DATA/'postgresql.auto.conf',b'# private empty auto configuration\n')
            self.record=json.loads(self.m.PREP.prepare());self.publish()
            self.reply=self.catalog()
            self.control=b'Database system identifier: 7341234567890123456\nDatabase cluster state: shut down\nData page checksum version: 1\n'
            self.ledger=self.root/'native.jsonl';self.database=self.root/'manager.json'
            self.write(self.database,json.dumps({'active':{},'enabled':{},'faults':{},'starts':0,'pid':42342}).encode())
            self.write(self.root/'control.txt',self.control);self.write(self.root/'catalog.json',json.dumps(self.reply).encode())
            for path in (self.m.PSQL,self.m.CONTROL,self.m.SERVER):self.write(path,b'#!/bin/sh\nexit 0\n',0o700)
            self.write(self.m.RUNUSER,('#!/usr/bin/python3\n'+NATIVE.replace('ROOT_REPR',repr(str(self.root)))).encode(),0o700)
            for name in ('prepare.py','live.py','common.sh','repair.sh','debian13s4-postgresql-server.service','debian13s4-postgresql.service','debian13s4-postgresql.timer'):
                self.write(self.root/'library/postgresql'/name,(ROOT/'PostgreSQL'/name).read_bytes(),0o700 if name=='repair.sh' else 0o600)
            self.write(self.root/'library/maintenance/common.sh',(ROOT/'Maintenance/common.sh').read_bytes())
            self.write(self.root/'library/firewall/kernel.py',(ROOT/'Firewall/kernel.py').read_bytes())
            self.write(self.root/'library/tasks/prerequisites/common.sh',(ROOT/'Tasks/prerequisites/common.sh').read_bytes())
            wrapper='''import importlib.util,sys\nfrom pathlib import Path\n'''
            wrapper+=f'root=Path({str(self.root)!r})\nspec=importlib.util.spec_from_file_location("pg_live",root/"library/postgresql/live.py")\nm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n'
            wrapper+=f'spec=importlib.util.spec_from_file_location("fixture_delivery",{str(Path(__file__).resolve())!r})\nf=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)\nf.configure(m,root)\n'
            wrapper+='with f.ownership_context(root/"data"):\n sys.exit(m.main())\n'
            self.write(self.root/'policy.py',wrapper.encode());self.write(self.root/'manager.py',MODEL.encode())
        except BaseException:
            self.directory.cleanup();raise

    def close(self):self.directory.cleanup()
    @staticmethod
    def write(path,raw,mode=0o600):path.write_bytes(raw);path.chmod(mode)
    def context(self):return ownership_context(self.m.DATA)
    def publish(self):
        plan=self.m.PREP.render(self.value)
        for name,text in plan['files'].items():self.write(self.m.CONFIG/name,text.encode('ascii'),0o644)
    def catalog(self):
        settings={name:{'value':value,'unit':'8kB' if name=='shared_buffers' else None,'pending_restart':False}
                  for name,value in self.m.settings_expected(self.record).items()}
        roles=[]
        for name,limit in [('postgres',-1),('dns_demo',12),('mail_demo',16)]:
            admin=name=='postgres';roles.append({'name':name,'super':admin,'inherit':admin,'createdb':admin,
                'createrole':admin,'login':True,'replication':admin,'bypass':admin,'limit':limit,'password':None,'valid_until':None})
        databases=[]
        for name in ('postgres','template0','template1'):
            databases.append({'name':name,'owner':'postgres','encoding':'UTF8','limit':-1,'allow':name!='template0',
                              'template':name!='postgres','public_access':True})
        for app in self.value['applications'].values():databases.append({'name':app['database'],'owner':app['role'],
            'encoding':'UTF8','limit':app['connection_limit'],'allow':True,'template':False,'public_access':False})
        return {'version':170006,'identifier':str(self.enrolled['system_identifier']),'user':'postgres','database':'postgres',
                'client':None,'authentication':'peer:postgres','start':'2026-10-10 10:00:00+00','recovery':False,
                'settings':settings,'roles':roles,'memberships':0,'overrides':0,'databases':databases}
    def read(self,kind,end):return self.control if kind=='control' else json.dumps(self.reply).encode()
    def faults(self,**values):
        state=json.loads(self.database.read_bytes());state['faults'].update(values);self.write(self.database,json.dumps(state).encode())
    def shell(self,command):
        q=shlex.quote
        text=(ROOT/'PostgreSQL/common.sh').read_text().replace('. /usr/local/lib/debian13s4/maintenance/common.sh','# maintenance already sourced')
        return f'''set -Eeuo pipefail
umask 077
source {q(str(ROOT/'Maintenance/common.sh'))}
source /dev/stdin <<'PG_COMMON'
{text}
PG_COMMON
S4M_STATE={q(str(self.root/'state'))}
S4M_SYSTEMD={q(str(self.root/'systemd'))}
S4M_LIBRARY={q(str(self.root/'library/maintenance'))}
S4G_LIBRARY={q(str(self.root/'library/postgresql'))}
S4G_CONFIG={q(str(self.m.CONFIG))}
S4G_INPUT={q(str(self.m.PREP.INPUT))}
S4G_ENROLLMENT={q(str(self.m.ENROLLMENT))}
s4m_trusted() {{
 local path=$1 owner mode
 [[ $path == {q(str(self.root))} || $path == {q(str(self.root))}/* ]] || return 1
 while :; do
  [[ -e $path && ! -L $path ]] || return 1
  read -r owner mode < <(/usr/bin/stat --format='%u %a' -- "$path") || return 1
  [[ $owner == "$EUID" ]] && (( (8#$mode & 8#022) == 0 )) || return 1
  [[ $path == {q(str(self.root))} ]] && return 0
  path=${{path%/*}}
 done
}}
s4m_control() {{
 local command=$1;shift
 case $command in
  dpkg-query) /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} package "$@" ;;
  dpkg) /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} audit "$@" ;;
  *) return 1 ;;
 esac
}}
s4m_systemctl() {{ /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} systemctl "$@"; }}
s4g_action() {{ [[ $1 == start || $1 == stop ]] && s4m_systemctl "$1" "$S4G_SERVER"; }}
s4m_sync() {{ /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} sync "$@"; }}
s4g_policy() {{ /usr/bin/python3 -B {q(str(self.root/'policy.py'))} "$@"; }}
s4m_load_packages() {{
 source {q(str(ROOT/'Tasks/prerequisites/common.sh'))}
 s4p_query() {{ /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} package "$@"; }}
 s4p_dpkg() {{ /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} audit "$@"; }}
}}
{command}
'''


NATIVE=r'''
import json,os,pathlib,sys,time
root=pathlib.Path(ROOT_REPR);args=sys.argv[1:];state=json.loads((root/'manager.json').read_bytes());faults=state['faults']
assert args[:3]==['-u','postgres','--'],args
binary=pathlib.Path(args[3]);kind='control' if binary.name=='pg_controldata' else 'catalog'
with (root/'native.jsonl').open('a') as out:out.write(json.dumps({'kind':kind,'argv':sys.argv,'environment':dict(os.environ),'pid':os.getpid(),'sid':os.getsid(0)})+'\n')
if faults.get('sleep'):time.sleep(10)
if faults.get('native_warning'):sys.stderr.write('warning\n')
if faults.get('native_exit'):raise SystemExit(2)
if faults.get('native_large'):
 sys.stdout.buffer.write(b'x'*262145);raise SystemExit(0)
if kind=='control':
 assert args[4:]==['--pgdata',str(root/'data')],args
 assert not (root/'data/postmaster.pid').exists()
 sys.stdout.buffer.write((root/'control.txt').read_bytes())
else:
 assert args[4:18]==['--no-psqlrc','--no-password','--host',str(root/'socket'),'--port','5432','--username','postgres','--dbname','postgres','--tuples-only','--no-align','--set','ON_ERROR_STOP=1'],args
 assert args[18]=='--command' and len(args)==20 and 'SELECT pg_catalog.json_build_object' in args[19],args
 reply=json.loads((root/'catalog.json').read_bytes())
 if faults.get('wrong_catalog'):reply['roles'][1]['super']=True
 if faults.get('loaded_snapshot') and 'loaded_config' in state:
  loaded=bytes.fromhex(state['loaded_config']).decode()
  import re
  reply['settings']['max_connections']['value']=re.search(r'^max_connections = (\d+)$',loaded,re.M)[1]
 sys.stdout.write(json.dumps(reply)+'\n')
'''


MODEL=r'''
import json,pathlib,sys
root,action,*args=sys.argv[1:];root=pathlib.Path(root);path=root/'manager.json';state=json.loads(path.read_bytes());faults=state['faults'];systemd=root/'systemd';code=0;output=''
if action=='package':
 assert len(args)==4 and args[:3]==['--show','--showformat=${Status}\\n','--'] and args[3] in ('postgresql-17','postgresql-client-17'),args
 output='install ok installed' if not faults.get('packages') else 'not installed'
elif action=='audit':
 assert args==['--audit'];output='unconfigured' if faults.get('audit') else ''
elif action=='sync':
 assert args and all(pathlib.Path(x).exists() for x in args)
 if faults.get('sync') or faults.get('sync_loaded') and any('postgresql.loaded' in x for x in args):code=1
elif action=='systemctl':
 operation,unit=args[0],args[-1]
 if faults.get(operation) or faults.get(operation+'_'+unit):code=1
 elif operation=='show':
  active=state['active'].get(unit,False)
  if args[:-1]==['show','--property=ActiveState','--property=MainPID','--property=InvocationID']:
   output='MainPID='+str(state['pid'] if active else 0)+'\nActiveState='+('active' if active else 'inactive')+'\nInvocationID='+(format(state['starts'],'032x') if active else '')
   if faults.get('generation'):output=faults['generation']
  else:
   assert len(args)==4 and args[2]=='--value',args
   prop=args[1].split('=',1)[1];target=systemd/unit
   if prop=='LoadState':output='loaded' if target.is_file() else 'not-found'
   elif prop=='ActiveState':output='active' if active else 'inactive'
   elif prop=='MainPID':output=str(state['pid'] if active else 0)
   elif prop=='FragmentPath':output=str(target)
   elif prop=='DropInPaths':output='foreign.conf' if faults.get('dropin') else ''
   else:raise AssertionError(prop)
 elif operation=='stop':
  if not faults.get('stop_incomplete'):
   state['active'][unit]=False
   if unit=='debian13s4-postgresql-server.service':(root/'data/postmaster.pid').unlink(missing_ok=True)
 elif operation=='start':
  if not faults.get('start_incomplete') and not state['active'].get(unit):
   state['active'][unit]=True
   if unit=='debian13s4-postgresql-server.service':
    state['starts']+=1;state['loaded_config']=(root/'config/postgresql.conf').read_bytes().hex()
    (root/'data/postmaster.pid').write_text(str(state['pid'])+'\n')
 elif operation=='daemon-reload':pass
 elif operation=='enable':
  folder=systemd/('timers.target.wants' if unit.endswith('.timer') else 'multi-user.target.wants');folder.mkdir(mode=0o700,exist_ok=True)
  link=folder/unit
  if not link.is_symlink():link.symlink_to(systemd/unit)
  state['enabled'][unit]=True
 elif operation=='is-enabled':output='enabled' if state['enabled'].get(unit) else 'disabled';code=0 if state['enabled'].get(unit) else 1
 else:raise AssertionError(args)
else:raise AssertionError(action)
path.write_text(json.dumps(state))
with (root/'events.jsonl').open('a') as out:out.write(json.dumps({'action':action,'args':args,'code':code})+'\n')
if output:print(output)
raise SystemExit(code)
'''
