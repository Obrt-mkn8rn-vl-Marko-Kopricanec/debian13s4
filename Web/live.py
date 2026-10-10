#!/usr/bin/python3
"""Bound existing TLS inputs, fixed native checks and reported nginx listeners.

Calling default checks reads native host state and nginx -t may open/create
referenced runtime files. Controller start/publication is MUTATING. Neither is
operationally authorized by source review or by the private fixture evidence.
Honest native replies/manager reports are not loaded-memory or client proof.
"""
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location('debian13s4_web_prepare', Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
CONFIG = Path('/etc/debian13s4-web/nginx.conf')
NGINX = Path('/usr/sbin/nginx')
OPENSSL = Path('/usr/bin/openssl')
SS = Path('/usr/bin/ss')
PASSWD = Path('/etc/passwd')
GROUP = Path('/etc/group')
CA = Path('/etc/ssl/certs/ca-certificates.crt')
PROC = Path('/proc')
MAX_BYTES = 262144
ATTEMPT_SECONDS = 60


def window(deadline, seconds=ATTEMPT_SECONDS):
    end = KERNEL.now() + seconds
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited web window')
        end = min(end, deadline)
    PREP.BASE.fence(end); return end


def worker(raw):
    try: text=raw.decode('ascii')
    except UnicodeError as error: raise Pending('unsupported web account encoding') from error
    if not text.endswith('\n') or any(c!='\n' and not 32<=ord(c)<=126 for c in text):
        raise Pending('unsupported web account inventory')
    rows=text[:-1].split('\n'); seen=set();uids=set();selected=None
    if len(rows)>4096:raise Pending('web account row bound')
    for line in rows:
        row=line.split(':')
        if len(row)!=7 or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',row[0]) is None or row[0] in seen:
            raise Pending('malformed web account')
        if any(re.fullmatch(r'0|[1-9][0-9]{0,9}',row[i]) is None for i in (2,3)):
            raise Pending('malformed web account identity')
        uid,gid=(KERNEL.uint(int(row[i]),0x7fffffff) for i in (2,3))
        if uid in uids:raise Pending('shared web account UID')
        seen.add(row[0]);uids.add(uid)
        if row[0]=='www-data':
            if (not 1<=uid<=999 or gid==0 or row[1] not in ('x','!','*') or
                row[6] not in ('/usr/sbin/nologin','/sbin/nologin','/bin/false')):
                raise Pending('unsupported existing nginx worker account')
            selected={'uid':uid,'gid':gid,'name':'www-data'}
    if selected is None:raise Pending('missing existing nginx worker account')
    return selected


def groups(raw,account):
    text=raw.decode('ascii')
    if not text.endswith('\n') or any(c!='\n' and not 32<=ord(c)<=126 for c in text):
        raise Pending('unsupported web group inventory')
    rows=text[:-1].split('\n');names=set();gids=set();selected=False
    if len(rows)>4096:raise Pending('web group row bound')
    for line in rows:
        row=line.split(':')
        if (len(row)!=4 or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',row[0]) is None or
            row[0] in names or re.fullmatch(r'0|[1-9][0-9]{0,9}',row[2]) is None):
            raise Pending('malformed web group')
        gid=KERNEL.uint(int(row[2]),0x7fffffff)
        if gid in gids:raise Pending('ambiguous web group GID')
        names.add(row[0]);gids.add(gid)
        members=row[3].split(',') if row[3] else []
        if len(set(members))!=len(members) or any(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',member) is None for member in members):
            raise Pending('malformed web group membership')
        if row[0]=='www-data':
            if gid!=account['gid'] or any(member!='www-data' for member in members):
                raise Pending('shared or changed nginx worker group')
            selected=True
        elif 'www-data' in members:raise Pending('supplementary nginx worker group refuses')
    if not selected:raise Pending('missing dedicated nginx worker group')


def inputs(end):
    record=json.loads(PREP.prepare(deadline=end))
    raw,source=PREP.BASE.read_protected(PASSWD,262144,False,end)
    account=worker(raw)
    group,group_source=PREP.BASE.read_protected(GROUP,262144,False,end);groups(group,account)
    ca,ca_source=PREP.BASE.read_protected(CA,524288,False,end)
    if not ca:raise Pending('empty fixed system CA bundle')
    config,config_source=PREP.BASE.read_protected(CONFIG,PREP.MAX_OUTPUT,False,end)
    if config!=record['nginx'].encode('ascii'):raise Pending('installed nginx configuration differs')
    binaries={}
    for path in (NGINX,OPENSSL,SS):
        before=KERNEL.trusted_binary(path)
        _,fact=PREP.BASE.read_protected(path,16777216,False,end)
        if KERNEL.trusted_binary(path)!=before:raise Pending('web native executable changed')
        binaries[str(path)]={'signature':list(before),'source':fact}
    return {'intention':record,'account':account,'account_source':source,'group_source':group_source,'ca_source':ca_source,
            'config_source':config_source,'binaries':binaries}


def arguments(kind,item=None,epoch=None):
    if kind=='nginx':return NGINX,('-t','-q','-c',str(CONFIG),'-p',str(CONFIG.parent)+'/')
    if kind=='sockets':return SS,('-H','-n','-l','-t','-p','sport = :80 or sport = :443')
    if kind not in ('certificate-key','private-key','key-check','verify'):raise Pending('unapproved web native check')
    if type(item) is not dict:raise Pending('missing checked TLS item')
    for field in ('certificate','private_key','upstream_ca'):PREP.material_path(item[field])
    PREP.hostname(item['hostname'])
    if kind=='certificate-key':args=('x509','-in',item['certificate'],'-pubkey','-noout')
    elif kind=='private-key':args=('pkey','-in',item['private_key'],'-pubout','-passin','pass:')
    elif kind=='key-check':args=('pkey','-in',item['private_key'],'-check','-noout','-passin','pass:')
    else:
        if type(epoch) is not int or not 1<=epoch<=0x7fffffff:raise Pending('invalid explicit TLS verification time')
        args=('verify','-x509_strict','-auth_level','2','-purpose','sslserver','-verify_hostname',item['hostname'],
            '-attime',str(epoch),'-CAfile',str(CA),'-no-CApath','-no-CAstore',
            '-untrusted',item['certificate'],item['certificate'])
    return OPENSSL,args


def native(kind,item,end,epoch=None):
    PREP.BASE.fence(end);binary,args=arguments(kind,item,epoch)
    before=KERNEL.trusted_binary(binary)
    until=min(end,KERNEL.now()+KERNEL.QUERY_SECONDS);PREP.BASE.fence(until)
    child=subprocess.Popen([str(binary),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,bufsize=0,env={'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'},
        close_fds=True,start_new_session=True)
    buffers={'stdout':bytearray(),'stderr':bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for name,stream in (('stdout',child.stdout),('stderr',child.stderr)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
            while selector.get_map():
                PREP.BASE.fence(until);remaining=until-KERNEL.now()
                if remaining<=0:raise Pending('web native capture window expired')
                for key,_ in selector.select(remaining):
                    part=os.read(key.fileobj.fileno(),65536)
                    if not part:selector.unregister(key.fileobj);continue
                    buffer=buffers[key.data]
                    if len(buffer)+len(part)>MAX_BYTES:raise Pending('web native channel bound')
                    buffer.extend(part)
            PREP.BASE.fence(until);remaining=until-KERNEL.now()
            if remaining<=0:raise Pending('web native root wait window expired')
            code=child.wait(timeout=remaining)
            if type(code) is not int or code!=0 or buffers['stderr']:raise Pending('web native check failed/warned')
        if KERNEL.trusted_binary(binary)!=before:raise Pending('web native executable drift')
        PREP.BASE.fence(until);return bytes(buffers['stdout'])
    finally:
        try:
            if child.returncode is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            try:child.stdout.close()
            finally:child.stderr.close()


def public_key(raw):
    if type(raw) is not bytes or len(raw)>16384:raise Pending('invalid native public key bytes')
    prefix=b'-----BEGIN PUBLIC KEY-----\n';suffix=b'-----END PUBLIC KEY-----\n'
    if not raw.startswith(prefix) or not raw.endswith(suffix):raise Pending('invalid native public key framing')
    body=raw[len(prefix):-len(suffix)]
    if not body.endswith(b'\n'):raise Pending('invalid native public key newline')
    lines=body[:-1].split(b'\n')
    if not lines or any(len(line)!=64 for line in lines[:-1]) or not 1<=len(lines[-1])<=64:
        raise Pending('invalid native public key line grammar')
    encoded=b''.join(lines)
    try:decoded=base64.b64decode(encoded,validate=True)
    except ValueError as error:raise Pending('invalid native public key base64') from error
    if not decoded or base64.b64encode(decoded)!=encoded:raise Pending('noncanonical native public key')
    return raw


def process_stat(raw,pid):
    if type(raw) is not bytes or len(raw)>4096:raise Pending('web process stat bound')
    prefix=str(pid).encode()+b' (';end=raw.rfind(b')')
    if not raw.startswith(prefix) or end<0:raise Pending('unsupported web process stat identity')
    fields=raw[end+2:].split()
    if len(fields)<20 or any(re.fullmatch(rb'[0-9]+',fields[i]) is None for i in (1,19)):
        raise Pending('unsupported web process parent/start fields')
    return KERNEL.uint(int(fields[1]),0x7fffffff),KERNEL.uint(int(fields[19]),2**64-1)


def process_credentials(raw):
    if type(raw) is not bytes or len(raw)>65536:raise Pending('web process status bound')
    rows=raw.decode('ascii').split('\n');result={}
    for name in ('Uid','Gid'):
        selected=[row for row in rows if row.startswith(name+':')]
        if len(selected)!=1 or re.fullmatch(name+r':\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+',selected[0]) is None:
            raise Pending('unsupported web process credentials')
        values=[KERNEL.uint(int(value),0x7fffffff) for value in selected[0].split()[1:]]
        if len(set(values))!=1:raise Pending('mixed web process credentials')
        result[name.lower()]=values[0]
    return result


def process(pid):
    # Honest procfs SOURCE identity; mutable CPU/fault/state counters are not
    # loaded-generation identity and may change during normal serving traffic.
    if not KERNEL.uint(pid,0x7fffffff):raise Pending('invalid web listener PID')
    root=PROC/str(pid)
    ppid,start=process_stat((root/'stat').read_bytes(),pid)
    credentials=process_credentials((root/'status').read_bytes())
    loaded=(root/'exe').stat();current=NGINX.stat()
    if Path(os.readlink(root/'exe'))!=NGINX or (loaded.st_dev,loaded.st_ino)!=(current.st_dev,current.st_ino):
        raise Pending('web process executable differs')
    if (process_stat((root/'stat').read_bytes(),pid)!=(ppid,start) or
        process_credentials((root/'status').read_bytes())!=credentials):
        raise Pending('web process credentials/parent/start changed')
    final=(root/'exe').stat();current_after=NGINX.stat()
    if (Path(os.readlink(root/'exe'))!=NGINX or
        (final.st_dev,final.st_ino)!=(loaded.st_dev,loaded.st_ino) or
        (current_after.st_dev,current_after.st_ino)!=(current.st_dev,current.st_ino)):
        raise Pending('web process executable changed')
    return {**credentials,'ppid':ppid,'start':start}


def sockets(raw,pid,account,proc=process):
    if not KERNEL.uint(pid,0x7fffffff):raise Pending('invalid nginx master PID')
    if type(raw) is not bytes or len(raw)>MAX_BYTES:raise Pending('invalid nginx listener bytes')
    text=raw.decode('ascii')
    if not text.endswith('\n') or any(c!='\n' and not 32<=ord(c)<=126 for c in text):raise Pending('unsupported nginx listener encoding')
    expected={'0.0.0.0:80','[::]:80','0.0.0.0:443','[::]:443'};found=set();owners={}
    for line in text[:-1].split('\n'):
        parts=line.split()
        if (len(parts)!=6 or parts[0]!='LISTEN' or parts[3] not in expected or parts[3] in found or
            parts[4] not in ('0.0.0.0:*','[::]:*','*:*') or
            any(re.fullmatch(r'[0-9]+',value) is None for value in parts[1:3])):
            raise Pending('unsupported/foreign nginx listener row')
        for value in parts[1:3]:KERNEL.uint(int(value))
        if not parts[5].startswith('users:(') or not parts[5].endswith(')'):raise Pending('missing nginx owner data')
        body=parts[5][7:-1];matches=re.findall(r'\("nginx",pid=([1-9][0-9]*),fd=([0-9]+)\)',body)
        if not matches or ','.join(f'("nginx",pid={p},fd={fd})' for p,fd in matches)!=body:
            raise Pending('foreign or malformed nginx socket owners')
        ids=[]
        for p,fd in matches:
            number=KERNEL.uint(int(p),0x7fffffff);KERNEL.uint(int(fd));ids.append(number)
            if number not in owners:owners[number]=proc(number)
            info=owners[number]
            KERNEL.known(info,{'uid','gid','ppid','start'},{'uid','gid','ppid','start'})
            for field in ('uid','gid','ppid'):KERNEL.uint(info[field],0x7fffffff)
            if not KERNEL.uint(info['start'],2**64-1):raise Pending('missing process start identity')
            if number==pid:
                if info['uid']!=0 or info['gid']!=0:raise Pending('nonroot reported nginx master')
            elif info['uid']!=account['uid'] or info['gid']!=account['gid'] or info['ppid']!=pid:raise Pending('foreign nginx worker')
        if pid not in ids or len(set(ids))!=len(ids):raise Pending('missing/duplicate nginx master owner')
        found.add(parts[3])
    if found!=expected:raise Pending('incomplete public nginx listener inventory')
    for number,before in owners.items():
        if proc(number)!=before:raise Pending('nginx process owner changed')


def file_payload(deadline=None):
    end=window(deadline,10)
    first=PREP.prepare(deadline=end);record=json.loads(first)
    payload=record['nginx'].encode('ascii')
    # Projection/encoding precedes a SECOND complete accepted preparation and
    # the final outer scope/time fence; only these exact cached bytes return.
    if PREP.prepare(deadline=end)!=first:raise Pending('web configuration projection changed')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=record['namespace']:raise Pending('web projection context changed')
    PREP.BASE.fence(end);return payload


def identity(deadline=None):
    end=window(deadline,10);first=inputs(end)
    payload=PREP.BASE.canonical({'schema':1,'namespace':first['intention']['namespace'],
        'startup_sha256':hashlib.sha256(PREP.BASE.canonical(first)).hexdigest()})
    if inputs(end)!=first:raise Pending('web startup inputs changed')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=first['intention']['namespace']:raise Pending('web identity context changed')
    PREP.BASE.fence(end);return payload


def check(read=native,deadline=None,pid=None,proc=process):
    end=window(deadline)
    if pid is not None and not KERNEL.uint(pid,0x7fffffff):raise Pending('invalid nginx master PID')
    first=inputs(end)
    timestamp=time.time()
    if type(timestamp) not in (int,float) or not math.isfinite(timestamp) or not 1<=timestamp<=0x7fffffff-3600:
        raise Pending('invalid web wallclock sample')
    epoch=int(timestamp)
    for app in PREP.APPLICATIONS:
        item=first['intention']['configuration']['value']['applications'][app]
        certificate=public_key(read('certificate-key',item,end))
        if public_key(read('private-key',item,end))!=certificate:raise Pending('TLS certificate/private key differ')
        if read('key-check',item,end)!=b'Key is valid\n':raise Pending('native private key validation differs')
        for at in (epoch,epoch+3600):
            if read('verify',item,end,at)!=(item['certificate']+': OK\n').encode('ascii'):
                raise Pending('native TLS purpose/name/chain/current-or-hour check failed')
    if read('nginx',None,end):raise Pending('nginx quiet syntax check produced output')
    if pid is not None:sockets(read('sockets',None,end),pid,first['account'],proc)
    if inputs(end)!=first:raise Pending('web startup inputs drifted during native checks')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=first['intention']['namespace']:raise Pending('web native context changed')
    final=time.time()
    if type(final) not in (int,float) or not math.isfinite(final) or not timestamp<=final<timestamp+ATTEMPT_SECONDS:
        raise Pending('web wallclock changed or native admission expired')
    PREP.BASE.fence(end)


def main():
    try:
        args=sys.argv[1:]
        if args not in (['--file'],['--identity'],['--check']) and not (
            len(args)==2 and args[0]=='--live' and re.fullmatch(r'[1-9][0-9]{0,9}',args[1])):
            return 64
        sink=sys.stdout.buffer
        if not callable(getattr(sink,'write',None)) or not callable(getattr(sink,'flush',None)):raise Pending('web policy requires binary stdout')
        if args==['--file']:payload=file_payload()
        elif args==['--identity']:payload=identity()
        else:
            check(pid=int(args[1]) if args[0]=='--live' else None);return 0
        count=sink.write(payload)
        if type(count) is not int or count!=len(payload):raise Pending('web policy incomplete byte publication')
        sink.flush();return 0
    except (Pending,OSError,ValueError,TypeError,AttributeError,UnicodeError,RecursionError,subprocess.TimeoutExpired) as error:
        print('debian13s4 web pending: '+str(error),file=sys.stderr);return 75


if __name__=='__main__':sys.exit(main())
