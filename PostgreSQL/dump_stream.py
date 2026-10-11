#!/usr/bin/python3
"""One lazy fixed dump-child stream; no real-host calling authority or publication.

Caller role/database inputs are validated syntax, NOT protected enrollment/NSS
or peer authentication. A future orchestrator must bind fresh backup intentions.
Constructing this stream does not start a child; an exclusive stage writer can
acquire its target before the first read. Failures poison the stream, never reset
it. EOF is returned only after both channels close, root zero/no warning and
checked completion. This is not archive validity, restore, durability or ownership.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import selectors
import signal
import subprocess

SPEC = importlib.util.spec_from_file_location('debian13s4_dump_inputs', Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
RUNUSER = Path('/usr/sbin/runuser')
DUMP = Path('/usr/lib/postgresql/17/bin/pg_dump')
MAX_BYTES = 1 << 40
MAX_STDERR = 1048576
CHUNK = 65536
MAX_RECEIPT = 16384


class Uncertain(RuntimeError):
    """Preserve the original cause and separate cleanup failures; no second child."""
    def __init__(self, cause, evidence, cleanup):
        super().__init__('dump child may have entered; no automatic retry')
        self.cause, self.evidence, self.cleanup = cause, evidence, cleanup


class DumpStream:
    def __init__(self, role, database, limit, stderr_limit, seconds, lock_wait_ms, deadline=None):
        role, database = PREP.identifier(role), PREP.identifier(database)
        for value, low, high in ((limit,1024,MAX_BYTES),(stderr_limit,1,MAX_STDERR),
                                 (seconds,1,3600),(lock_wait_ms,1,60000)):
            if type(value) is not int or not low <= value <= high:
                raise Pending('unsupported explicit dump stream bound')
        start = KERNEL.now()
        if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
            raise Pending('invalid inherited dump stream deadline')
        self.end = min(start+seconds,deadline) if deadline is not None else start+seconds
        self.argv = (str(RUNUSER),'-u',role,'--',str(DUMP),'--format=custom','--no-password',
            '--host',PREP.SOCKET_DIRECTORY,'--port','5432','--username',role,'--dbname',database,
            '--lock-wait-timeout='+str(lock_wait_ms))
        self.limit, self.stderr_limit = limit, stderr_limit
        self.child, self.selector, self.context, self.executables = None, None, None, None
        self.streams = {}; self.received = 0; self.hashed = hashlib.sha256(); self.stderr = bytearray()
        self.started, self.closed, self.done = False, False, False
        self.receipt, self.poison = None, None

    def fence(self):
        if KERNEL.now() >= self.end:
            raise Pending('dump stream admission window expired')
        if self.context is not None:
            current = KERNEL.namespace()
            if type(current) is not int or current != self.context:
                raise Pending('dump stream namespace changed')

    def start(self):
        if self.started or self.closed:
            raise Pending('dump stream cannot enter twice')
        self.fence()
        context = KERNEL.uint(KERNEL.namespace(),2**64-1)
        if not context: raise Pending('missing dump stream namespace')
        self.context = context
        self.executables = (KERNEL.trusted_binary(RUNUSER),KERNEL.trusted_binary(DUMP))
        self.fence()
        self.started = True # A Popen error may follow an attempted child entry.
        self.child = subprocess.Popen(self.argv,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'},close_fds=True,start_new_session=True)
        self.streams = {'stdout':self.child.stdout,'stderr':self.child.stderr}
        self.selector = selectors.DefaultSelector()
        for name, stream in self.streams.items():
            os.set_blocking(stream.fileno(),False)
            self.selector.register(stream,selectors.EVENT_READ,name)

    def evidence(self):
        return (self.argv,self.context,self.executables,self.received,self.hashed.hexdigest(),
                bytes(self.stderr),None if self.child is None else self.child.returncode,
                self.started,self.closed)

    def close(self):
        if self.closed: return ()
        self.closed = True # Retirement precedes every cleanup attempt.
        errors = []
        if self.child is not None and self.child.returncode is None:
            try:
                try: os.killpg(self.child.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                self.child.wait(timeout=KERNEL.CLEANUP_SECONDS)
            except BaseException as error: errors.append(error)
        selector,self.selector = self.selector,None
        if selector is not None:
            try: selector.close()
            except BaseException as error: errors.append(error)
        for name in ('stdout','stderr'):
            stream = self.streams.pop(name,None)
            if self.child is not None:
                if stream is None: stream = getattr(self.child,name,None)
                setattr(self.child,name,None) # Retire the Popen reference before close.
            if stream is not None:
                try: stream.close()
                except BaseException as error: errors.append(error)
        return tuple(errors)

    def fail(self, cause):
        cleanup = self.close()
        if self.started:
            self.poison = Uncertain(cause,self.evidence(),cleanup)
            raise self.poison from cause
        if cleanup:
            raise Uncertain(cause,self.evidence(),cleanup) from cause
        raise cause

    def finish(self):
        self.fence()
        remaining = self.end-KERNEL.now()
        if remaining <= 0: raise Pending('dump completion window expired')
        code = self.child.wait(timeout=remaining)
        self.fence()
        if type(code) is not int or code != 0 or self.stderr or not self.received:
            raise Pending('dump child failed, warned or produced no archive bytes')
        receipt = PREP.canonical({'schema':1,'state':'dump-stream-receipt-only',
            'argv':list(self.argv),'namespace':self.context,
            'executables':[list(row) for row in self.executables],
            'received_bytes':self.received,'received_sha256':self.hashed.hexdigest(),
            'limit_bytes':self.limit,'stderr_limit_bytes':self.stderr_limit,
            'root_exit':code,'stderr_hex':bytes(self.stderr).hex()})
        if len(receipt)>MAX_RECEIPT: raise Pending('dump stream receipt exceeds bound')
        if (KERNEL.trusted_binary(RUNUSER),KERNEL.trusted_binary(DUMP))!=self.executables:
            raise Pending('dump stream executable changed')
        self.fence()
        cleanup = self.close()
        if cleanup: raise Uncertain(cleanup[0],self.evidence(),cleanup[1:]) from cleanup[0]
        self.receipt, self.done = receipt, True

    def read(self, requested):
        if self.poison is not None: raise self.poison
        if type(requested) is not int or not 1 <= requested <= CHUNK:
            self.fail(Pending('unsupported dump stream read size'))
        if self.done: return b''
        if self.closed: raise Pending('dump stream is retired')
        try:
            if not self.started: self.start()
            self.fence()
            while self.selector.get_map():
                self.fence(); remaining = self.end-KERNEL.now()
                if remaining<=0: raise Pending('dump capture window expired')
                chunk = None
                for key,_ in self.selector.select(remaining):
                    size = min(requested,self.limit-self.received+1) if key.data=='stdout' else min(CHUNK,self.stderr_limit-len(self.stderr)+1)
                    part = os.read(key.fileobj.fileno(),size)
                    self.fence()
                    if not part:
                        self.selector.unregister(key.fileobj);continue
                    if key.data=='stdout':
                        self.received += len(part);self.hashed.update(part)
                        if self.received>self.limit: raise Pending('dump stdout exceeds byte bound')
                        chunk = part
                    else:
                        self.stderr.extend(part)
                        if len(self.stderr)>self.stderr_limit: raise Pending('dump stderr exceeds byte bound')
                if chunk is not None: return chunk
            self.finish(); return b''
        except BaseException as error:
            if isinstance(error,Uncertain) and self.closed:
                self.poison=error;raise
            self.fail(error)
