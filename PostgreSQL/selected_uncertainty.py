#!/usr/bin/python3
"""Private historical selected-stage failure custody; NEVER a retry decision.

No stage/dump/source observation is called here. Original intentions, captures,
exceptions and public hashes are reported/forgeable historical DATA. Known
receipts are retained as OPAQUE bytes, including rejected receipt spellings;
none is promoted to archive validity, completion, ownership or publication.
Separate history failure MUST leave the original Incomplete/Uncertain intact.
Trusted modules/private ancestry/cooperating locks/finite IO are required;
equal samples and sync are not atomicity, non-ABA or power-loss guarantees.
"""
import hashlib
import importlib.util
from pathlib import Path
import re


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


SELECTED = module('debian13s4_selected_history_source', Path(__file__).with_name('selected_stage.py'))
_STORAGE = module('debian13s4_selected_history_storage', Path(__file__).with_name('private_storage.py'))
BACKUP, DUMP, PREP, KERNEL, Pending = SELECTED.BACKUP, SELECTED.DUMP, SELECTED.PREP, SELECTED.KERNEL, SELECTED.Pending
LEAF = 'selected-stage-incomplete.json'
STATE = 'historical-selected-stage-incomplete-no-retry'
MAX_RECORD = 6 * BACKUP.MAX_OUTPUT + 4 * DUMP.MAX_STDERR + 2 * DUMP.MAX_RECEIPT + 2 * SELECTED.STAGE.MAX_RECEIPT + 65536
MAX_BYTES = 2 * MAX_RECORD + 4096


def encoded(value):
    return PREP.canonical(value)


def fields(value, names):
    KERNEL.known(value, set(names.split()), set(names.split()))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_bytes(value, limit):
    if type(value) is not str or len(value) > 2 * limit or len(value) % 2 or re.fullmatch('[0-9a-f]*', value) is None:
        raise Pending('unsupported historical binary prefix')
    return bytes.fromhex(value)


def diagnostic(value):
    if type(value) is not list or len(value) != 2 or type(value[0]) is not str or re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',value[0]) is None or type(value[1]) is not str or len(value[1]) > 1024:
        raise Pending('unsupported historical failure diagnostic')
    value[1].encode('utf-8')


def diagnostics(values):
    if type(values) is not list or len(values) > 16:raise Pending('historical diagnostic inventory exceeds bound')
    for value in values:diagnostic(value)


def describe(error):
    if not isinstance(error,BaseException):raise Pending('historical failure is not an exception')
    row = [type(error).__name__,str(error)[:1024]];diagnostic(row);return row


def chain(error):
    rows, seen = [], set()
    while error is not None:
        if id(error) in seen or len(rows) == 16:raise Pending('cyclic or excessive historical cause chain')
        seen.add(id(error));rows.append(describe(error))
        error = error.__cause__ if error.__cause__ is not None else (None if error.__suppress_context__ else error.__context__)
    return rows


def intention(raw):
    """Re-render historical jobs/PG plan; preserve access/account facts as DATA."""
    value = BACKUP.ACCESS.decoded(raw,BACKUP.MAX_OUTPUT)
    fields(value,'schema profile state namespace configuration source_intention enrollment access jobs')
    if type(value['schema']) is not int or value['schema'] != 1 or value['profile'] != 'postgresql17-selected-logical-backup-intention-v1' or value['state'] != 'postgresql-logical-backup-intention-only' or type(value['namespace']) is not int or not 0 < value['namespace'] < 2**64:
        raise Pending('unsupported historical selected backup intention')
    fields(value['configuration'],'value source');settings = BACKUP.checked(value['configuration']['value'])
    source = value['source_intention']
    fields(source,'schema profile state namespace configuration account_source accounts plan')
    fields(source['configuration'],'value source')
    deployment = PREP.checked(source['configuration']['value'])
    if type(source['schema']) is not int or source['schema'] != 1 or source['namespace'] != value['namespace'] or type(source['namespace']) is not int or source['profile'] != 'postgresql17-local-peer-new-cluster-intention-v1' or source['state'] != 'local-peer-provisioning-intention-only' or encoded(source['plan']) != encoded(PREP.render(deployment)) or encoded(value['jobs']) != encoded(BACKUP.render(settings,source)) or raw != encoded(value):
        raise Pending('historical protected intention rendering or encoding differs')
    return value


def evidence(value, plan, application, stderr_limit):
    if type(value) is not list or len(value) != 9:raise Pending('unsupported historical dump capture')
    argv, context, executables, count, sha, stderr, code, started, closed = value
    job = plan['jobs'][application];settings = plan['configuration']['value']
    if type(argv) is not list or argv != job['dump_argv'] or type(count) is not int or not 0 <= count <= settings['archive_limit_bytes'] + 1 or type(sha) is not str or re.fullmatch('[0-9a-f]{64}',sha) is None or type(started) is not bool or closed is not True or (code is not None and (type(code) is not int or not -(1<<31) <= code < (1<<31))):
        raise Pending('historical dump capture types or job differ')
    hex_bytes(stderr,stderr_limit+1)
    if context is not None and (type(context) is not int or context != plan['namespace']):raise Pending('historical dump context differs')
    if executables is not None:
        if type(executables) is not list or len(executables) != 2:raise Pending('unsupported historical executable inventory')
        for row in executables:
            if type(row) is not list or len(row) != 8 or any(type(n) is not int for n in row):raise Pending('untyped historical executable signature')
    if started and (context is None or executables is None):raise Pending('entered dump lacks reported source identity')
    if not started and (count or stderr or code is not None):raise Pending('pre-entry capture reports produced bytes or exit')
    if count == 0 and sha != digest(b''):raise Pending('empty received prefix hash differs')


def checked(raw):
    value = BACKUP.ACCESS.decoded(raw,MAX_RECORD)
    fields(value,'schema state intention intention_sha256 application stderr_limit_bytes cause cleanup capture uncertainty stream_receipt_hex stage_receipt_hex')
    if value['schema'] != 'debian13s4-selected-stage-incomplete-1' or value['state'] != STATE or type(value['intention']) is not str or type(value['application']) is not str or value['application'] not in PREP.APPLICATIONS or type(value['stderr_limit_bytes']) is not int or not 1 <= value['stderr_limit_bytes'] <= DUMP.MAX_STDERR:
        raise Pending('unsupported selected-stage history schema or bounds')
    original = value['intention'].encode('utf-8');plan = intention(original)
    if value['intention_sha256'] != digest(original):raise Pending('historical intention hash differs')
    diagnostics(value['cause']);diagnostics(value['cleanup'])
    if not value['cause']:raise Pending('missing historical original failure')
    evidence(value['capture'],plan,value['application'],value['stderr_limit_bytes'])
    uncertain = value['uncertainty']
    if uncertain is not None:
        fields(uncertain,'cause cleanup capture');diagnostics(uncertain['cause']);diagnostics(uncertain['cleanup'])
        if not uncertain['cause']:raise Pending('missing uncertainty cause')
        evidence(uncertain['capture'],plan,value['application'],value['stderr_limit_bytes'])
    for field,maximum in (('stream_receipt_hex',DUMP.MAX_RECEIPT),('stage_receipt_hex',SELECTED.STAGE.MAX_RECEIPT)):
        if value[field] is not None:hex_bytes(value[field],maximum)
    if raw != encoded(value):raise Pending('historical selected-stage bytes are not canonical')
    return value


def copy_capture(row):
    if type(row) is not tuple or len(row) != 9 or type(row[0]) is not tuple or type(row[5]) is not bytes or (row[2] is not None and (type(row[2]) is not tuple or any(type(item) is not tuple for item in row[2]))):
        raise Pending('unsupported immutable selected dump evidence')
    if len(row[0]) != 16 or any(type(item) is not str or len(item) > 512 for item in row[0]) or (row[2] is not None and (len(row[2]) != 2 or any(len(item) != 8 for item in row[2]))):
        raise Pending('historical capture inventory exceeds bound')
    if len(row[5]) > DUMP.MAX_STDERR+1:raise Pending('historical warning prefix exceeds bound')
    return [list(row[0]),row[1],None if row[2] is None else [list(item) for item in row[2]],row[3],row[4],row[5].hex(),row[6],row[7],row[8]]


def capture(error):
    if type(error) is not SELECTED.Incomplete or type(error.provenance) is not tuple or len(error.provenance) != 4 or type(error.cleanup) is not tuple or len(error.cleanup) > 16:
        raise Pending('exact selected-stage incomplete delivery is required')
    original, app, stderr_limit, row = error.provenance
    intention(original)
    receipts = []
    for raw, maximum in ((error.stream_receipt,DUMP.MAX_RECEIPT),(error.stage_receipt,SELECTED.STAGE.MAX_RECEIPT)):
        if raw is not None and (type(raw) is not bytes or len(raw) > maximum):raise Pending('known opaque receipt exceeds bound')
        receipts.append(None if raw is None else raw.hex())
    uncertain = error.uncertainty
    if uncertain is not None:
        if type(uncertain) is not DUMP.Uncertain or type(uncertain.cleanup) is not tuple or len(uncertain.cleanup) > 16:raise Pending('unsupported original selected dump uncertainty')
        uncertain = {'cause':chain(uncertain.cause),'cleanup':[describe(e) for e in uncertain.cleanup],'capture':copy_capture(uncertain.evidence)}
    raw = encoded({'schema':'debian13s4-selected-stage-incomplete-1','state':STATE,
        'intention':original.decode('utf-8'),'intention_sha256':digest(original),'application':app,'stderr_limit_bytes':stderr_limit,
        'cause':chain(error.cause),'cleanup':[describe(e) for e in error.cleanup],'capture':copy_capture(row),
        'uncertainty':uncertain,'stream_receipt_hex':receipts[0],'stage_receipt_hex':receipts[1]})
    checked(raw);return raw


def envelope(payload):
    checked(payload)
    raw = encoded({'schema':'debian13s4-selected-stage-incomplete-history-1','state':STATE,
        'payload':payload.decode('utf-8'),'payload_sha256':digest(payload)})
    if len(raw)>MAX_BYTES:raise Pending('selected-stage history envelope exceeds bound')
    return raw


def stored(raw):
    value = BACKUP.ACCESS.decoded(raw,MAX_BYTES);fields(value,'schema state payload payload_sha256')
    if value['schema'] != 'debian13s4-selected-stage-incomplete-history-1' or value['state'] != STATE or type(value['payload']) is not str:raise Pending('unsupported selected-stage history envelope')
    payload = value['payload'].encode('utf-8');checked(payload)
    if value['payload_sha256'] != digest(payload) or raw != encoded(value):raise Pending('selected-stage history envelope differs')
    return payload


_STORAGE.LEAF, _STORAGE.MAX_BYTES, _STORAGE.envelope, _STORAGE.checked = LEAF, MAX_BYTES, envelope, stored


def record(path, error, deadline=None):
    """Storage errors propagate separately; they NEVER discharge original failure."""
    end = _STORAGE.window(deadline);raw = capture(error);_STORAGE.admission(end)
    return _STORAGE.create(path,raw,deadline=end)


def load(path, deadline=None):
    return _STORAGE.load(path,deadline=deadline)
