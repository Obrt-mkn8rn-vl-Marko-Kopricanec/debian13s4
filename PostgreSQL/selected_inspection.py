#!/usr/bin/python3
"""Fresh protected selection -> whole private staged-byte listing SOURCE only.

Default calls WOULD protected-read/connect PG/run pg_restore --list on the host;
none is authorized here. Reported historical dump success/public receipts are
forgeable, not origin, ownership, archive validity/completeness or backup proof.
This entry never creates/dumps/promotes/restores/deletes/retries a stage. Separate
locks/equal reads are non-atomic/ABA/future; honest modules/native delivery/private
ancestry/finite IO and caller custody of failures remain required.
"""
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('debian13s4_selected_listing_history',Path(__file__).with_name('selected_uncertainty.py'))
HISTORY = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(HISTORY)
SELECTED, BACKUP, PREP, KERNEL, Pending = HISTORY.SELECTED, HISTORY.BACKUP, HISTORY.PREP, HISTORY.KERNEL, HISTORY.Pending
INSPECT, STAGE = SELECTED.INSPECT, SELECTED.STAGE
ATTEMPT_SECONDS = 2 * BACKUP.ATTEMPT_SECONDS + INSPECT.ATTEMPT_SECONDS
MAX_OUTPUT = SELECTED.MAX_OUTPUT + INSPECT.MAX_OUTPUT + 8192


class Incomplete(RuntimeError):
    """Original selection and known listing remain distinct; no retry permission."""
    def __init__(self, cause, selection, listing, cleanup):
        super().__init__('selected stage listing incomplete; stage retained, no promotion or automatic retry')
        self.cause, self.selection, self.listing, self.cleanup = cause, selection, listing, cleanup


def checked(raw):
    """Historical rendering/type correspondence ONLY, no fresh observer or clock."""
    value = BACKUP.ACCESS.decoded(raw,SELECTED.MAX_OUTPUT)
    HISTORY.fields(value,'schema state application namespace backup_intention stream stage')
    app = value['application']
    if type(value['schema']) is not int or value['schema'] != 1 or value['state'] != 'protected-selected-dump-stage-source-only' or type(app) is not str or app not in PREP.APPLICATIONS or type(value['namespace']) is not int or not 0 < value['namespace'] < 2**64:
        raise Pending('unsupported historical selected-stage receipt')
    plan = HISTORY.intention(PREP.canonical(value['backup_intention']))
    settings = BACKUP.checked(plan['configuration']['value']);job = plan['jobs'][app]
    stage = INSPECT.checked(PREP.canonical(value['stage']))
    path = STAGE.TRUST_ROOT/Path(settings['directory']).relative_to('/')
    if stage['directory'] != str(path) or stage['leaf'] != settings['generation']+'-'+app+'.dump.partial' or stage['limit_bytes'] != settings['archive_limit_bytes'] or plan['namespace'] != value['namespace']:
        raise Pending('historical selected stage differs from protected job intention')
    stream = value['stream']
    HISTORY.fields(stream,'schema state argv namespace executables received_bytes received_sha256 limit_bytes stderr_limit_bytes root_exit stderr_hex')
    if type(stream['schema']) is not int or stream['schema'] != 1 or stream['state'] != 'dump-stream-receipt-only' or stream['argv'] != job['dump_argv'] or type(stream['namespace']) is not int or stream['namespace'] != value['namespace'] or type(stream['root_exit']) is not int or stream['root_exit'] != 0 or stream['stderr_hex'] != '' or type(stream['stderr_limit_bytes']) is not int or not 1 <= stream['stderr_limit_bytes'] <= SELECTED.DUMP.MAX_STDERR:
        raise Pending('historical selected dump receipt types or job differ')
    if type(stream['received_bytes']) is not int or stream['received_bytes'] != stage['bytes'] or stream['received_sha256'] != stage['sha256'] or type(stream['limit_bytes']) is not int or stream['limit_bytes'] != stage['limit_bytes']:
        raise Pending('historical dump capture and stage bytes differ')
    rows = stream['executables']
    if type(rows) is not list or len(rows) != 2 or any(type(row) is not list or len(row) != 8 or any(type(n) is not int for n in row) for row in rows):
        raise Pending('untyped historical dump executable signatures')
    if raw != PREP.canonical(value):raise Pending('selected-stage receipt is not canonical')
    return value


def fence(end, context):
    PREP.fence(end)
    for kernel in (KERNEL,INSPECT.KERNEL):
        current = kernel.namespace()
        if type(current) is not int or current != context:raise Pending('selected inspection namespace changed')


def inspect_selected(raw, read=None, listing=None, deadline=None):
    if read is not None and not callable(read) or listing is not None and not callable(listing):
        raise Pending('unsupported selected inspection deliveries')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):raise Pending('invalid selected inspection inherited deadline')
    end = min(start+ATTEMPT_SECONDS,deadline) if deadline is not None else start+ATTEMPT_SECONDS
    context = KERNEL.uint(KERNEL.namespace(),2**64-1)
    if not context:raise Pending('missing selected inspection context')
    fence(end,context);value = checked(raw)
    if value['namespace'] != context:raise Pending('historical selected-stage context differs')
    original = PREP.canonical(value['backup_intention']);settings = BACKUP.checked(value['backup_intention']['configuration']['value'])
    job = value['backup_intention']['jobs'][value['application']];stage = value['stage']
    path = Path(stage['directory']);target = path/stage['leaf']
    if job['inspection_argv'][0] != str(INSPECT.RESTORE) or job['inspection_environment'] != {'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'}:
        raise Pending('selected inspection binary or environment differs from protected intention')
    listing_receipt, directory = None, None
    try:
        fresh,_ = SELECTED.intention(read,end)
        if fresh != original:raise Pending('complete fresh backup intention differs before listing')
        fence(end,context)
        listing_receipt = INSPECT.inspect_stage(PREP.canonical(stage),settings['inventory_limit_bytes'],read=listing,deadline=end)
        observed = BACKUP.ACCESS.decoded(listing_receipt,INSPECT.MAX_OUTPUT)
        # The owned library supplies this receipt. Complete typed byte equality
        # prevents Boolean/int aliasing or a substituted partial receipt.
        expected = {'schema':1,'state':'private-archive-listing-source-only','stage':stage,
            'stage_sha256':hashlib.sha256(PREP.canonical(stage)).hexdigest(),'namespace':context,
            'argv':[str(INSPECT.RESTORE),'--list',str(target)],'executable':observed['executable'],
            'listing_limit_bytes':settings['inventory_limit_bytes'],'listing_bytes':observed['listing_bytes'],
            'listing_sha256':observed['listing_sha256'],'listing_hex':observed['listing_hex']}
        data = HISTORY.hex_bytes(observed['listing_hex'],settings['inventory_limit_bytes'])
        if not data or type(observed['listing_bytes']) is not int or observed['listing_bytes'] != len(data) or observed['listing_sha256'] != hashlib.sha256(data).hexdigest() or listing_receipt != PREP.canonical(expected):
            raise Pending('complete selected listing receipt differs')
        executable = observed['executable']
        if type(executable) is not list or len(executable) != 8 or any(type(n) is not int for n in executable):raise Pending('untyped selected listing executable')
        before = tuple(stage['directory_identity'])
        directory = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        STAGE.directory_matches(path,directory,before);fcntl.flock(directory,fcntl.LOCK_SH|fcntl.LOCK_NB)
        payload = PREP.canonical({'schema':1,'state':'protected-selected-stage-listing-source-only',
            'namespace':context,'selection':value,'selection_sha256':hashlib.sha256(raw).hexdigest(),
            'inspection':observed,'inspection_sha256':hashlib.sha256(listing_receipt).hexdigest()})
        if len(payload)>MAX_OUTPUT:raise Pending('selected listing outer receipt exceeds bound')
        final,_ = SELECTED.intention(read,end)
        if final != original:raise Pending('complete fresh backup intention changed after listing')
        STAGE.readback(directory,stage['leaf'],tuple(stage['identity']),stage['bytes'],stage['sha256'],end)
        STAGE.directory_matches(path,directory,before)
        if list(INSPECT.KERNEL.trusted_binary(INSPECT.RESTORE)) != executable:raise Pending('selected inspection executable changed')
        fence(end,context)
        closing,directory = directory,None;os.close(closing)
        return payload
    except BaseException as cause:
        cleanup = list(STAGE.cleanup_errors(cause,
            (PREP.CleanupFailure, BACKUP.ACCESS.LIVE.CleanupFailure)))
        if directory is not None:
            closing,directory = directory,None
            try:os.close(closing)
            except BaseException as error:cleanup.append(error)
        raise Incomplete(cause,raw,listing_receipt,tuple(cleanup)) from cause
