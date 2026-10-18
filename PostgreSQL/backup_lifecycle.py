#!/usr/bin/python3
"""One reserved selected-stage/listing/history SOURCE attempt; no host authority.

Default calls WOULD protected-read/connect PG/run dump/createpartial/list/store;
real-host calling remains unauthorized. No archive validity/completeness, final
backup, publication, restore, native recovery, reset or retry is supplied. Slots
are per-directory/cooperating history, not authenticated/global deduplication.
Sequential locks/reads/public hashes/markers are non-atomic/ABA/future; finite IO,
scheduling, honest modules/native delivery/private ancestry are assumed.
"""
import fcntl
import importlib.util
import os
from pathlib import Path


def module(name,leaf):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(leaf))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


MANIFEST=module('debian13s4_backup_lifecycle_manifest','stage_manifest.py')
ATTEMPT=module('debian13s4_backup_lifecycle_attempt','backup_attempt.py')
FAILURE=module('debian13s4_backup_lifecycle_failure','attempt_failure.py')
LISTING=MANIFEST.LISTING
UNCERTAINTY=LISTING.HISTORY
SELECTED=UNCERTAINTY.SELECTED # EXACT class consumed by historical uncertainty capture.
BACKUP,PREP,KERNEL,Pending=LISTING.BACKUP,LISTING.PREP,LISTING.KERNEL,LISTING.Pending
STAGE=SELECTED.STAGE
ATTEMPT_SECONDS=SELECTED.ATTEMPT_SECONDS+LISTING.ATTEMPT_SECONDS+BACKUP.ATTEMPT_SECONDS+30
MAX_OUTPUT=SELECTED.MAX_OUTPUT+LISTING.MAX_OUTPUT+MANIFEST.MAX_RECORD+ATTEMPT.MAX_BYTES+8192


class Blocked(RuntimeError):
    """Keep original cause, known source outcomes and separate history/cleanup."""
    def __init__(self,cause,reservation,selection,listing,manifest,history_error,cleanup):
        super().__init__('backup SOURCE attempt incomplete; reserved slot forbids automatic retry')
        self.cause,self.reservation,self.selection=cause,reservation,selection
        self.listing,self.manifest,self.history_error,self.cleanup=listing,manifest,history_error,cleanup
        self.failure_record,self.failure_record_error=None,None


def admission(end,context):LISTING.fence(end,context)


def outcomes_absent(path,end):
    backend=ATTEMPT._STORAGE;until=backend.window(end);directory,before=backend.locked(path,until)
    try:
        for leaf in (MANIFEST.LEAF,UNCERTAINTY.LEAF,FAILURE.LEAF):
            backend.admission(until)
            try:os.stat(leaf,dir_fd=directory,follow_symlinks=False)
            except FileNotFoundError:continue
            if leaf==FAILURE.LEAF:
                raise ATTEMPT.Blocked('backup failure history closes this attempt; no automatic retry')
            raise Pending('existing backup outcome history forbids another attempt')
        backend.directory_matches(path,directory,before);backend.admission(until)
    finally:os.close(directory)


def run_once(path,application,stderr_limit,read=None,listing=None,deadline=None):
    if type(application) is not str or application not in PREP.APPLICATIONS or type(stderr_limit) is not int or not 1<=stderr_limit<=SELECTED.DUMP.MAX_STDERR or read is not None and not callable(read) or listing is not None and not callable(listing):
        raise Pending('unsupported explicit backup lifecycle selector/bounds/deliveries')
    start=KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline<=start):raise Pending('invalid backup lifecycle inherited deadline')
    end=min(start+ATTEMPT_SECONDS,deadline) if deadline is not None else start+ATTEMPT_SECONDS
    context=KERNEL.uint(KERNEL.namespace(),2**64-1)
    if not context:raise Pending('missing backup lifecycle context')
    query=BACKUP.ACCESS.LIVE.native if read is None else read
    inspect=LISTING.INSPECT.native if listing is None else listing
    def delivered(operation,*args):
        window=args[-1]
        if not KERNEL.finite_deadline(window) or window>end:raise Pending('backup delivery exceeds inherited window')
        admission(end,context);PREP.fence(window)
        raw=operation(*args)
        PREP.fence(window);admission(end,context)
        return raw
    def capture(kind,window):return delivered(query,kind,window)
    def list_stage(archive,maximum,window):return delivered(inspect,archive,maximum,window)
    admission(end,context);outcomes_absent(path,end)
    reservation=ATTEMPT.reserve(path,application,context,deadline=end)
    selected,listed,manifest,directory=None,None,None,None
    phase='pre-stage'
    try:
        outcomes_absent(path,end)
        if ATTEMPT.load(path,deadline=end)!=reservation:raise Pending('backup attempt changed before fresh stage')
        admission(end,context)
        phase='stage'
        selected=SELECTED.stage_selected(application,stderr_limit,read=capture,deadline=end)
        phase='pre-listing'
        outcomes_absent(path,end)
        if ATTEMPT.load(path,deadline=end)!=reservation:raise Pending('backup attempt changed before listing')
        admission(end,context)
        phase='listing'
        listed=LISTING.inspect_selected(selected,read=capture,listing=list_stage,deadline=end)
        phase='manifest'
        outcomes_absent(path,end)
        manifest=MANIFEST.record(path,listed,deadline=end)
        phase='final-validation'
        stage=LISTING.checked(selected)['stage'];result=MANIFEST.listing_checked(listed)
        original=PREP.canonical(result['selection']['backup_intention'])
        archive=Path(stage['directory']);before=tuple(stage['directory_identity'])
        directory=os.open(archive,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        STAGE.directory_matches(archive,directory,before);fcntl.flock(directory,fcntl.LOCK_SH|fcntl.LOCK_NB)
        payload=PREP.canonical({'schema':1,'state':'single-attempt-selected-backup-source-only','namespace':context,
            'application':application,'reservation':BACKUP.ACCESS.decoded(reservation,ATTEMPT.MAX_BYTES),
            'selection':result['selection'],'listing':result,'manifest':MANIFEST.checked(manifest)})
        if len(payload)>MAX_OUTPUT:raise Pending('backup lifecycle SOURCE result exceeds bound')
        final,_=SELECTED.intention(capture,end)
        if final!=original:raise Pending('complete protected backup intention changed after history')
        STAGE.readback(directory,stage['leaf'],tuple(stage['identity']),stage['bytes'],stage['sha256'],end)
        STAGE.directory_matches(archive,directory,before)
        if list(LISTING.INSPECT.KERNEL.trusted_binary(LISTING.INSPECT.RESTORE))!=result['inspection']['executable'] or [list(SELECTED.DUMP.KERNEL.trusted_binary(p)) for p in (SELECTED.DUMP.RUNUSER,SELECTED.DUMP.DUMP)]!=result['selection']['stream']['executables']:
            raise Pending('backup executable identities changed after history')
        if ATTEMPT.load(path,deadline=end)!=reservation or MANIFEST.load(path,deadline=end)!=manifest:raise Pending('checked backup attempt/outcome history changed')
        admission(end,context)
        closing,directory=directory,None;os.close(closing)
        return payload
    except BaseException as cause:
        cleanup=[]
        if directory is not None:
            closing,directory=directory,None
            try:os.close(closing)
            except BaseException as error:cleanup.append(error)
        history_error=None
        if type(cause) is SELECTED.Incomplete:
            try:UNCERTAINTY.record(path,cause,deadline=end)
            except BaseException as failure:history_error=failure
        blocked=Blocked(cause,reservation,selected,listed,manifest,history_error,tuple(cleanup))
        try:
            blocked.failure_record=FAILURE.record(path,reservation,phase,cause,
                {'selection':selected,'listing':listed,'manifest':manifest},history_error,tuple(cleanup),deadline=end)
        except BaseException as failure:
            blocked.failure_record_error=failure
        raise blocked from cause
