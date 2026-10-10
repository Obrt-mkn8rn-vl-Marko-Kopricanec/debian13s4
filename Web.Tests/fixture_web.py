"""Persistent private TLS/native/manager deliveries, no host nginx or crypto.

Native public-key/verify replies are MODELS (not an independent crypto oracle).
Start snapshots keep disk bytes separate from acknowledged daemon inputs.
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import time
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def configure(m,root):
    m.PREP.BASE.TRUST_ROOT=root;m.PREP.BASE.TRUSTED_UID=os.getuid();m.PREP.INPUT=root/'etc/web.json'
    m.CONFIG=root/'config/nginx.conf';m.PASSWD=root/'etc/passwd';m.GROUP=root/'etc/group';m.CA=root/'etc/ca.pem'
    m.NGINX=root/'native/nginx';m.OPENSSL=root/'native/openssl';m.SS=root/'native/ss'
    m.KERNEL.TRUST_ROOT=root;m.KERNEL.TRUSTED_UID=os.getuid();m.KERNEL.namespace=lambda:4711
    m.PREP.prepare.__defaults__=(None,m.KERNEL.namespace)
    def process(pid):
        state=json.loads((root/'manager.json').read_bytes())
        return {'uid':0 if pid==state['pid'] else 33,'gid':0 if pid==state['pid'] else 33,'ppid':1 if pid==state['pid'] else state['pid'],'start':500+state['starts']}
    m.check.__defaults__=(m.native,None,None,process)


class PrivateWeb:
    def __init__(self):
        if os.getuid()==0:raise RuntimeError('Use ordinary UID private web fixtures')
        self.private=tempfile.TemporaryDirectory(dir='/dev/shm');self.root=Path(self.private.name);self.root.chmod(0o700)
        try:
            for name in ('etc','config','native','state','systemd','library','library/web','library/postgresql','library/firewall','library/maintenance','library/tasks','library/tasks/prerequisites'):
                (self.root/name).mkdir(mode=0o700)
            spec=importlib.util.spec_from_file_location('private_web_live',ROOT/'Web/live.py')
            self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
            self.database=self.root/'manager.json';self.write(self.database,json.dumps({'active':{},'enabled':{},'starts':0,'pid':42342,'faults':{}}).encode())
            configure(self.m,self.root)
            self.value={'schema':1,'applications':{}}
            for i,app in enumerate(self.m.PREP.APPLICATIONS):
                item={'hostname':f'web{i}.example.invalid','certificate':str(self.root/'etc'/f'chain{i}.pem'),
                    'private_key':str(self.root/'etc'/f'key{i}.pem'),'upstream_port':9100+i,
                    'upstream_name':f'gateway{i}.example.invalid','upstream_ca':str(self.root/'etc'/f'ca{i}.pem'),
                    'body_bytes':1048576,'idle_seconds':60}
                self.value['applications'][app]=item
                for field in ('certificate','upstream_ca','private_key'):
                    self.write(Path(item[field]),self.pem(field=='private_key'),0o600 if field=='private_key' else 0o644)
            self.write(self.m.PREP.INPUT,self.m.PREP.BASE.canonical(self.value))
            self.write(self.m.PASSWD,b'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:Web:/var/www:/usr/sbin/nologin\n',0o644)
            self.write(self.m.GROUP,b'root:x:0:\nwww-data:x:33:\n',0o644)
            self.write(self.m.CA,self.pem(),0o644)
            self.write(self.m.CONFIG,self.m.PREP.render(self.value).encode(),0o644)
            for path in (self.m.NGINX,self.m.OPENSSL,self.m.SS):
                self.write(path,('#!/usr/bin/python3\n'+NATIVE.replace('ROOT_REPR',repr(str(self.root)))).encode(),0o700)
            for name in ('prepare.py','live.py','common.sh','repair.sh','debian13s4-web-server.service','debian13s4-web.service','debian13s4-web.timer'):
                self.write(self.root/'library/web'/name,(ROOT/'Web'/name).read_bytes(),0o700 if name=='repair.sh' else 0o600)
            for source,target in (('PostgreSQL/prepare.py','library/postgresql/prepare.py'),('Firewall/kernel.py','library/firewall/kernel.py'),
                                  ('Maintenance/common.sh','library/maintenance/common.sh'),('Tasks/prerequisites/common.sh','library/tasks/prerequisites/common.sh')):
                self.write(self.root/target,(ROOT/source).read_bytes())
            wrapper=f'''import importlib.util,sys
from pathlib import Path
root=Path({str(self.root)!r})
spec=importlib.util.spec_from_file_location('web_policy',root/'library/web/live.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec=importlib.util.spec_from_file_location('fixture_delivery',{str(Path(__file__).resolve())!r})
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);f.configure(m,root)
sys.exit(m.main())
'''
            self.write(self.root/'policy.py',wrapper.encode());self.write(self.root/'manager.py',MODEL.encode())
        except BaseException:self.private.cleanup();raise

    @staticmethod
    def write(path,raw,mode=0o600):path.write_bytes(raw);path.chmod(mode)
    @staticmethod
    def pem(private=False,body=b'private-model-not-crypto'):
        import base64
        label=b'PRIVATE KEY' if private else b'CERTIFICATE'
        encoded=base64.b64encode(body)
        return b'-----BEGIN '+label+b'-----\n'+encoded+b'\n-----END '+label+b'-----\n'
    def private_processes(self):
        names={str(self.root/name).encode() for name in ('policy.py','manager.py','native/nginx','native/openssl','native/ss')}
        result=[]
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal():continue
            try:
                if path.stat().st_uid!=os.getuid():continue
                argv=[value for value in (path/'cmdline').read_bytes().split(b'\0') if value]
                if not any(value in names for value in argv):continue
                fields=(path/'stat').read_bytes().rsplit(b') ',1)[1].split()
                if fields[0] not in (b'Z',b'X',b'x'):
                    result.append((int(path.name),int(fields[19]),argv))
            except (FileNotFoundError,ProcessLookupError,PermissionError):pass
        return result

    def cleanup_private_processes(self):
        # ONLY exact scripts below this acquired private0700 directory, under
        # the honest same-UID/argv assumption; not arbitrary escaped reaping.
        end=time.monotonic()+5
        while True:
            pending=self.private_processes()
            if not pending:return
            for pid,start,argv in pending:
                try:
                    path=Path('/proc')/str(pid)
                    fields=(path/'stat').read_bytes().rsplit(b') ',1)[1].split()
                    current=[value for value in (path/'cmdline').read_bytes().split(b'\0') if value]
                    if int(fields[19])==start and current==argv:os.kill(pid,signal.SIGKILL)
                except (FileNotFoundError,ProcessLookupError,PermissionError):pass
            if time.monotonic()>=end:raise RuntimeError('private web scripts did not terminate')
            time.sleep(.01)

    def controller(self,command,timeout=120):
        spec=importlib.util.spec_from_file_location('web_owned_session',ROOT/'Bootstrap.Tests/fixture_process.py')
        owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
        argv=['/bin/bash','-p','-c',self.shell(command)]
        child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            out,err=child.communicate(timeout=timeout)
            return subprocess.CompletedProcess(argv,child.returncode,out,err)
        finally:
            try:
                owned.terminate_session(child)
                self.cleanup_private_processes()
            finally:
                child.wait(timeout=5)
                try:child.stdout.close()
                finally:child.stderr.close()

    def close(self):
        self.cleanup_private_processes()
        self.private.cleanup()
    def settings(self):self.write(self.m.PREP.INPUT,self.m.PREP.BASE.canonical(self.value))
    def faults(self,**values):
        state=json.loads(self.database.read_bytes());state['faults'].update(values);self.write(self.database,json.dumps(state).encode())
    def shell(self,command):
        q=shlex.quote
        common=(ROOT/'Web/common.sh').read_text().replace('. /usr/local/lib/debian13s4/maintenance/common.sh','# already sourced')
        return f'''set -Eeuo pipefail
umask 077
source {q(str(ROOT/'Maintenance/common.sh'))}
source /dev/stdin <<'WEB_COMMON'
{common}
WEB_COMMON
S4M_STATE={q(str(self.root/'state'))}
S4M_SYSTEMD={q(str(self.root/'systemd'))}
S4M_LIBRARY={q(str(self.root/'library/maintenance'))}
S4W_LIBRARY={q(str(self.root/'library/web'))}
S4W_CONFIG={q(str(self.m.CONFIG.parent))}
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
s4m_systemctl() {{ /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} systemctl "$@"; }}
s4w_action() {{ [[ $1 == start || $1 == stop ]] && s4m_systemctl "$1" "$S4W_SERVER"; }}
s4w_policy() {{ /usr/bin/python3 -B {q(str(self.root/'policy.py'))} "$@"; }}
s4m_sync() {{ /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} sync "$@"; }}
s4m_control() {{ local action=$1;shift; case $action in
 dpkg-query) /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} package "$@" ;;
 dpkg) /usr/bin/python3 -B {q(str(self.root/'manager.py'))} {q(str(self.root))} audit "$@" ;;
 *) return 1 ;; esac; }}
s4m_load_packages() {{ source {q(str(ROOT/'Tasks/prerequisites/common.sh'))}; }}
{command}
'''


NATIVE=r'''
import base64,json,os,pathlib,sys,time
root=pathlib.Path(ROOT_REPR);state=json.loads((root/'manager.json').read_bytes());faults=state['faults'];args=sys.argv[1:];binary=pathlib.Path(sys.argv[0]).name
with (root/'native.jsonl').open('a') as out:out.write(json.dumps({'binary':binary,'argv':sys.argv,'environment':dict(os.environ),'pid':os.getpid(),'sid':os.getsid(0)})+'\n')
if faults.get('sleep'):time.sleep(10)
if faults.get('warning'):sys.stderr.write('warning\n')
if faults.get('exit'):raise SystemExit(2)
if faults.get('large'):sys.stdout.buffer.write(b'x'*262145);raise SystemExit(0)
if binary=='openssl':
 if args[0]=='x509':
  assert args[1]=='-in' and args[-2:]==['-pubkey','-noout'] and len(args)==5,args
 elif args[0]=='pkey':
  assert args[1]=='-in' and args[-2:]==['-passin','pass:'],args
  if '-check' in args:
   assert args==['pkey','-in',args[2],'-check','-noout','-passin','pass:'],args
   sys.stdout.write('Key is valid\n' if not faults.get('invalid_key') else 'Key is invalid\n');raise SystemExit(0)
  assert args==['pkey','-in',args[2],'-pubout','-passin','pass:'],args
 elif args[0]=='verify':
  assert args[1:6]==['-x509_strict','-auth_level','2','-purpose','sslserver'],args
  assert args[6]=='-verify_hostname' and args[8]=='-attime' and args[9].isdigit(),args
  assert args[10:15]==['-CAfile',str(root/'etc/ca.pem'),'-no-CApath','-no-CAstore','-untrusted'],args
  assert len(args)==17 and args[15]==args[16],args
  if faults.get('verify'):raise SystemExit(1)
  sys.stdout.write(args[-1]+': OK\n');raise SystemExit(0)
 else:raise AssertionError(args)
 body=base64.b64encode(b'public-key-MODEL' if not (faults.get('key_mismatch') and args[0]=='pkey') else b'changed-MODEL')
 sys.stdout.buffer.write(b'-----BEGIN PUBLIC KEY-----\n'+body+b'\n-----END PUBLIC KEY-----\n')
elif binary=='nginx':
 assert args==['-t','-q','-c',str(root/'config/nginx.conf'),'-p',str(root/'config')+'/'],args
 if faults.get('syntax'):raise SystemExit(1)
elif binary=='ss':
 assert args==['-H','-n','-l','-t','-p','sport = :80 or sport = :443'],args
 if not state['active'].get('debian13s4-web-server.service'):raise SystemExit(0)
 pid=state['pid'] if not faults.get('foreign_socket') else state['pid']+1
 for address in ('0.0.0.0:80','[::]:80','0.0.0.0:443','[::]:443'):
  sys.stdout.write('LISTEN 0 511 '+address+' *:* users:(("nginx",pid='+str(pid)+',fd=6),("nginx",pid=42343,fd=6))\n')
else:raise AssertionError(binary)
'''


MODEL=r'''
import json,pathlib,sys
root,action,*args=sys.argv[1:];root=pathlib.Path(root);path=root/'manager.json';state=json.loads(path.read_bytes());faults=state['faults'];systemd=root/'systemd';code=0;output=''
if action=='package':
 assert len(args)==4 and args[:3]==['--show','--showformat=${Status}\\n','--'] and args[3] in ('nginx','nginx-common','openssl','ca-certificates'),args
 output='install ok installed' if not faults.get('packages') else 'not installed'
elif action=='audit':assert args==['--audit'];output='unconfigured' if faults.get('audit') else ''
elif action=='sync':
 assert args and all(pathlib.Path(x).exists() for x in args)
 if faults.get('sync') or faults.get('sync_loaded') and any('web.loaded' in x for x in args):code=1
elif action=='systemctl':
 operation,unit=args[0],args[-1]
 if faults.get(operation) or faults.get(operation+'_'+unit):code=1
 elif operation=='show':
  active=state['active'].get(unit,False) or unit=='nginx.service' and faults.get('vendor_active',False)
  if args[:-1]==['show','--property=ActiveState','--property=MainPID','--property=InvocationID']:
   output='MainPID='+str(state['pid'] if active else 0)+'\nActiveState='+('active' if active else 'inactive')+'\nInvocationID='+(format(state['starts'],'032x') if active else '')
   if faults.get('generation'):output=faults['generation']
  else:
   assert len(args)==4 and args[2]=='--value',args
   prop=args[1].split('=',1)[1];target=systemd/unit
   if prop=='LoadState':output=faults.get('vendor_load','loaded') if unit=='nginx.service' else ('loaded' if target.is_file() else 'not-found')
   elif prop=='ActiveState':output='active' if active else 'inactive'
   elif prop=='MainPID':output=str(state['pid'] if active else 0)
   elif prop=='FragmentPath':output=str(target)
   elif prop=='DropInPaths':output='foreign.conf' if faults.get('dropin') else ''
   else:raise AssertionError(prop)
 elif operation=='stop':
  assert unit!='nginx.service','vendor must NEVER be stopped/adopted'
  if not faults.get('stop_incomplete'):state['active'][unit]=False
 elif operation=='start':
  if not faults.get('start_incomplete') and not state['active'].get(unit):
   state['active'][unit]=True
   if unit=='debian13s4-web-server.service':
    state['starts']+=1;state['loaded_config']=(root/'config/nginx.conf').read_bytes().hex()
    settings=json.loads((root/'etc/web.json').read_bytes())
    state['loaded_keys']={name:pathlib.Path(item['private_key']).read_bytes().hex() for name,item in settings['applications'].items()}
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
