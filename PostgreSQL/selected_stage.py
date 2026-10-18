#!/usr/bin/python3
"""Fresh protected selected backup intention -> one create-only partial stage.

Default calls WOULD connect to PG and run a dump; real-host calling is unauthorized.
No directory provisioning, native archive inspection, final backup publication,
restore, durable uncertainty, retry or controller/installer join is supplied.
All receipts are SOURCE only; private ancestry/modules/native delivery are trusted,
read/lock equality is sequential/non-atomic/ABA/future, not ownership authentication.
"""
import importlib.util
import json
import os
from pathlib import Path
import fcntl


def module(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


BACKUP = module('debian13s4_selected_backup', 'backup.py')
DUMP = module('debian13s4_selected_dump', 'dump_stream.py')
INSPECT = module('debian13s4_selected_inspection', 'archive_inspection.py')
STAGE = INSPECT.STAGE
PREP, KERNEL, Pending = BACKUP.PREP, BACKUP.KERNEL, BACKUP.Pending
# Contains two independent60s preparations and at most3600s dump admission;
# no accepted primitive window is widened, and these are not hard IO budgets.
ATTEMPT_SECONDS = 2 * BACKUP.ATTEMPT_SECONDS + 3600
MAX_OUTPUT = BACKUP.MAX_OUTPUT + DUMP.MAX_RECEIPT + STAGE.MAX_RECEIPT + 8192


class Incomplete(RuntimeError):
    """Preserve original failure/uncertainty, known receipts and separate cleanup."""
    def __init__(self, cause, uncertainty, stream_receipt, stage_receipt, cleanup, provenance):
        super().__init__('selected backup stage may exist; no automatic retry or publication')
        self.cause, self.uncertainty = cause, uncertainty
        self.stream_receipt, self.stage_receipt, self.cleanup = stream_receipt, stage_receipt, cleanup
        self.provenance = provenance # Original immutable intention and AFTER-cleanup capture.


def fence(end, context):
    PREP.fence(end)
    for kernel in (KERNEL, DUMP.KERNEL, STAGE.KERNEL):
        current = kernel.namespace()
        if type(current) is not int or current != context:
            raise Pending('selected backup stage namespace changed')


def intention(read, end):
    raw = BACKUP.prepare(read=read, deadline=end)
    value = BACKUP.ACCESS.decoded(raw, BACKUP.MAX_OUTPUT)
    if (type(value.get('schema')) is not int or value['schema'] != 1 or
        value.get('profile') != 'postgresql17-selected-logical-backup-intention-v1' or
        value.get('state') != 'postgresql-logical-backup-intention-only' or
        value['jobs'] != BACKUP.render(value['configuration']['value'], value['source_intention']) or
        raw != PREP.canonical(value)):
        raise Pending('selected stage requires the complete real canonical backup intention')
    return raw, value


def stage_selected(application, stderr_limit, read=None, deadline=None):
    if type(application) is not str or application not in PREP.APPLICATIONS:
        raise Pending('unsupported selected PostgreSQL backup application')
    if type(stderr_limit) is not int or not 1 <= stderr_limit <= DUMP.MAX_STDERR or read is not None and not callable(read):
        raise Pending('unsupported explicit selected dump delivery or stderr bound')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid selected backup inherited deadline')
    end = min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS
    context = KERNEL.uint(KERNEL.namespace(), 2**64-1)
    if not context: raise Pending('missing selected backup context')
    fence(end, context)
    original, value = intention(read, end)
    if type(value['namespace']) is not int or value['namespace'] != context:
        raise Pending('selected backup intention context differs')
    settings = BACKUP.checked(value['configuration']['value']); job = value['jobs'][application]
    path = STAGE.TRUST_ROOT / Path(settings['directory']).relative_to('/')
    leaf = settings['generation'] + '-' + application + '.dump.partial'
    stream = DUMP.DumpStream(job['role'],job['database'],settings['archive_limit_bytes'],stderr_limit,
        settings['dump_timeout_seconds'],settings['lock_wait_ms'],deadline=end)
    staged = None; directory = None
    try:
        if tuple(job['dump_argv']) != stream.argv or job['dump_environment'] != {'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'}:
            raise Pending('selected dump argv or environment differs from protected intention')
        fence(end, context)
        staged = STAGE.stage(path,leaf,stream,settings['archive_limit_bytes'],deadline=end)
        if stream.done is not True or stream.closed is not True or type(stream.receipt) is not bytes:
            raise Pending('selected stage lacks checked dump completion')
        stage_value = INSPECT.checked(staged)
        stream_value = BACKUP.ACCESS.decoded(stream.receipt,DUMP.MAX_RECEIPT)
        expected = {'schema':1,'state':'dump-stream-receipt-only','argv':list(stream.argv),
            'namespace':stream.context,'executables':[list(row) for row in stream.executables],
            'received_bytes':stream.received,'received_sha256':stream.hashed.hexdigest(),
            'limit_bytes':stream.limit,'stderr_limit_bytes':stream.stderr_limit,
            'root_exit':stream.child.returncode,'stderr_hex':bytes(stream.stderr).hex()}
        if type(stream.child.returncode) is not int or stream.child.returncode != 0 or stream.stderr or stream.receipt != PREP.canonical(expected):
            raise Pending('complete dump receipt differs from actual captured completion')
        if (stream_value['namespace'] != context or stream_value['argv'] != job['dump_argv'] or
            stream_value['root_exit'] != 0 or stream_value['stderr_hex'] != '' or
            stream_value['received_bytes'] != stage_value['bytes'] or
            stream_value['received_sha256'] != stage_value['sha256']):
            raise Pending('selected protected stage and received dump bytes differ')
        before = tuple(stage_value['directory_identity'])
        directory = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        STAGE.directory_matches(path,directory,before)
        fcntl.flock(directory,fcntl.LOCK_SH|fcntl.LOCK_NB)
        payload = PREP.canonical({'schema':1,'state':'protected-selected-dump-stage-source-only',
            'application':application,'namespace':context,'backup_intention':value,
            'stream':stream_value,'stage':stage_value})
        if len(payload)>MAX_OUTPUT: raise Pending('selected backup stage receipt exceeds bound')
        final, _ = intention(read,end)
        if final != original: raise Pending('complete protected backup intention changed after staging')
        STAGE.readback(directory,leaf,tuple(stage_value['identity']),stage_value['bytes'],stage_value['sha256'],end)
        STAGE.directory_matches(path,directory,before)
        if [list(DUMP.KERNEL.trusted_binary(p)) for p in (DUMP.RUNUSER,DUMP.DUMP)] != stream_value['executables']:
            raise Pending('selected dump executable changed after staging')
        fence(end,context)
        closing, directory = directory, None
        os.close(closing)
        cleanup = stream.close()
        if cleanup: raise DUMP.Uncertain(cleanup[0],stream.evidence(),cleanup[1:]) from cleanup[0]
        return payload
    except BaseException as cause:
        cleanup = list(STAGE.cleanup_errors(cause,
            (PREP.CleanupFailure, BACKUP.ACCESS.LIVE.CleanupFailure)))
        if directory is not None:
            closing, directory = directory, None
            try: os.close(closing)
            except BaseException as error: cleanup.append(error)
        try: cleanup.extend(stream.close())
        except BaseException as error: cleanup.append(error)
        uncertainty = stream.poison
        if isinstance(cause,DUMP.Uncertain): uncertainty = cause
        if uncertainty is None and stream.started and not stream.done:
            uncertainty = DUMP.Uncertain(cause,stream.evidence(),tuple(cleanup))
        raise Incomplete(cause,uncertainty,stream.receipt,staged,tuple(cleanup),
            (original,application,stderr_limit,stream.evidence())) from cause
