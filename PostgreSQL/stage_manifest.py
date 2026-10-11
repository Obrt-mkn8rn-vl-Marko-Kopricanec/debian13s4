#!/usr/bin/python3
"""Retain whole selected-stage/listing SOURCE correspondence in private history.

This is a historical source manifest, NEVER completed/valid backup metadata or
promotion, restore, retry, ownership, native-origin or readiness authority.
No native/source observer/default directory/CLI/controller is called. Whole
reported receipts and public hashes/generation may be forged. Existing private
storage requires honest ancestry/modules/cooperating locks/finite IO; sync and
sequential equal samples are not atomicity/non-ABA/physical persistence proof.
"""
import hashlib
import importlib.util
from pathlib import Path
import stat


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


LISTING=module('debian13s4_stage_manifest_listing',Path(__file__).with_name('selected_inspection.py'))
_STORAGE=module('debian13s4_stage_manifest_storage',Path(__file__).parent.parent/'Firewall/proposal_store.py')
HISTORY, PREP, KERNEL, Pending=LISTING.HISTORY,LISTING.PREP,LISTING.KERNEL,LISTING.Pending
LEAF='selected-stage-manifest.json'
STATE='historical-selected-listing-manifest-only'
MAX_RECORD=2*LISTING.MAX_OUTPUT+4096
MAX_BYTES=2*MAX_RECORD+4096


def encoded(value):return PREP.canonical(value)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def listing_checked(raw):
    """Recompute typed correspondence; never observe current state or re-list."""
    value=LISTING.BACKUP.ACCESS.decoded(raw,LISTING.MAX_OUTPUT)
    HISTORY.fields(value,'schema state namespace selection selection_sha256 inspection inspection_sha256')
    if type(value['schema']) is not int or value['schema']!=1 or value['state']!='protected-selected-stage-listing-source-only' or type(value['namespace']) is not int or not 0<value['namespace']<2**64:
        raise Pending('unsupported historical selected listing profile')
    selection=encoded(value['selection']);selected=LISTING.checked(selection)
    plan=selected['backup_intention'];app=selected['application'];settings=LISTING.BACKUP.checked(plan['configuration']['value'])
    observed=value['inspection']
    HISTORY.fields(observed,'schema state stage stage_sha256 namespace argv executable listing_limit_bytes listing_bytes listing_sha256 listing_hex')
    stage=selected['stage'];stage_raw=encoded(stage)
    data=HISTORY.hex_bytes(observed['listing_hex'],settings['inventory_limit_bytes'])
    expected={'schema':1,'state':'private-archive-listing-source-only','stage':stage,'stage_sha256':digest(stage_raw),
        'namespace':selected['namespace'],'argv':[str(LISTING.INSPECT.RESTORE),'--list',str(Path(stage['directory'])/stage['leaf'])],
        'executable':observed['executable'],'listing_limit_bytes':settings['inventory_limit_bytes'],
        'listing_bytes':len(data),'listing_sha256':digest(data),'listing_hex':data.hex()}
    row=observed['executable']
    if type(row) is not list or len(row)!=8 or any(type(item) is not int for item in row):raise Pending('untyped historical listing executable')
    if any(item<0 for item in row[:6]) or not row[1] or not stat.S_ISREG(row[2]) or not row[2]&0o100 or row[2]&0o022 or row[3]!=LISTING.INSPECT.KERNEL.TRUSTED_UID:
        raise Pending('unsupported reported listing executable kind/owner/mode')
    if not data or value['namespace']!=selected['namespace'] or encoded(observed)!=encoded(expected) or value['selection_sha256']!=digest(selection) or value['inspection_sha256']!=digest(encoded(observed)) or raw!=encoded(value):
        raise Pending('whole historical selected listing correspondence differs')
    return value


def capture(raw):
    value=listing_checked(raw);selected=value['selection'];settings=selected['backup_intention']['configuration']['value']
    payload=encoded({'schema':'debian13s4-selected-stage-source-manifest-1','state':STATE,
        'application':selected['application'],'generation':settings['generation'],
        'selected_listing':raw.decode('utf-8'),'selected_listing_sha256':digest(raw)})
    checked(payload);return payload


def checked(raw):
    value=LISTING.BACKUP.ACCESS.decoded(raw,MAX_RECORD)
    HISTORY.fields(value,'schema state application generation selected_listing selected_listing_sha256')
    if value['schema']!='debian13s4-selected-stage-source-manifest-1' or value['state']!=STATE or type(value['selected_listing']) is not str:
        raise Pending('unsupported selected-stage source manifest')
    payload=value['selected_listing'].encode('utf-8');source=listing_checked(payload);selected=source['selection']
    if type(value['application']) is not str or value['application']!=selected['application'] or value['generation']!=selected['backup_intention']['configuration']['value']['generation'] or value['selected_listing_sha256']!=digest(payload) or raw!=encoded(value):
        raise Pending('historical source manifest label/integrity differs')
    return value


def envelope(payload):
    checked(payload)
    raw=encoded({'schema':'debian13s4-selected-stage-source-manifest-history-1','state':STATE,
        'payload':payload.decode('utf-8'),'payload_sha256':digest(payload)})
    if len(raw)>MAX_BYTES:raise Pending('historical source manifest envelope exceeds bound')
    return raw


def stored(raw):
    value=LISTING.BACKUP.ACCESS.decoded(raw,MAX_BYTES);HISTORY.fields(value,'schema state payload payload_sha256')
    if value['schema']!='debian13s4-selected-stage-source-manifest-history-1' or value['state']!=STATE or type(value['payload']) is not str:raise Pending('unsupported source manifest history envelope')
    payload=value['payload'].encode('utf-8');checked(payload)
    if value['payload_sha256']!=digest(payload) or raw!=encoded(value):raise Pending('source manifest envelope differs')
    return payload


_STORAGE.LEAF,_STORAGE.MAX_BYTES,_STORAGE.envelope,_STORAGE.checked=LEAF,MAX_BYTES,envelope,stored


def record(path,listing,deadline=None):
    """No-replace historical storage; failure may leave bytes, never retry authority."""
    end=_STORAGE.window(deadline);payload=capture(listing);_STORAGE.admission(end)
    return _STORAGE.create(path,payload,deadline=end)


def load(path,deadline=None):return _STORAGE.load(path,deadline=deadline)
