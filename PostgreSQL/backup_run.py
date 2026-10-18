#!/usr/bin/python3
"""Explicit command interface for one reserved backup SOURCE attempt.

status reads existing history only. run-once launches the configured native
PostgreSQL queries, dump and listing and writes private stage/history files;
it requires separate operational authorization. No automatic scheduler, retry,
reset, promotion, completed-backup certification or restore is provided.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

APPLICATIONS = ('mk8.dns', 'mk8.email')
MAX_STDERR = 1048576
MAX_DIAGNOSTIC = 1048576


class Pending(ValueError):
    pass


def owned():
    # Argument errors and --help must not load the preparation/native graph.
    spec = importlib.util.spec_from_file_location('debian13s4_backup_command_status',
        Path(__file__).resolve().with_name('backup_status.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stderr_bound(value):
    if re.fullmatch('[1-9][0-9]{0,6}', value) is None or int(value) > MAX_STDERR:
        raise argparse.ArgumentTypeError('stderr bytes must be an integer from 1 through 1048576')
    return int(value)


def write(stream, raw, maximum):
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise Pending('unsupported bounded backup command output')
    count = stream.write(raw)
    if type(count) is not int or count != len(raw):
        raise Pending('incomplete backup command output')
    stream.flush()


def commitment(raw):
    if raw is None:
        return {'returned': False}
    if type(raw) is not bytes:
        return {'returned': True, 'supported_bytes': False}
    return {'returned': True, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def describe(error):
    # Diagnostic formatting must not replace an existing lifecycle failure.
    name = type(error).__name__[:128]
    try:
        message = str(error)[:1024]
    except BaseException as formatting_error:
        message = '<message unavailable: '+type(formatting_error).__name__[:128]+'>'
    return {'type': name, 'message_prefix': message}


def chain(error):
    rows, seen = [], set()
    while error is not None and id(error) not in seen and len(rows) < 16:
        seen.add(id(error)); rows.append(describe(error))
        error = error.__cause__ if error.__cause__ is not None else (
            None if error.__suppress_context__ else error.__context__)
    return {'entries': rows, 'truncated_or_cyclic': error is not None}


def failure(error, status, operation, phase, directory, result):
    value = {'schema': 1, 'state': 'backup-command-failed-no-retry',
        'operation': operation, 'phase': phase, 'directory': str(directory),
        'backup_complete': False, 'retry_authorized': False, 'diagnostics_only': True,
        'cause': chain(error), 'known_result': commitment(result)}
    if status is not None and isinstance(error, status.LIFECYCLE.Blocked):
        value['state'] = 'reserved-backup-attempt-incomplete-no-retry'
        value['lifecycle'] = {'phase': error.phase, 'reservation': commitment(error.reservation),
            'known': {name: commitment(getattr(error, name)) for name in ('selection', 'listing', 'manifest')},
            'history_error': None if error.history_error is None else chain(error.history_error),
            'failure_record': commitment(error.failure_record),
            'failure_record_error': None if error.failure_record_error is None else chain(error.failure_record_error),
            'cleanup': [describe(item) for item in error.cleanup[:16]],
            'cleanup_truncated': len(error.cleanup) > 16}
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False)+'\n').encode('ascii')
    if len(raw) > MAX_DIAGNOSTIC:
        raise Pending('backup command diagnostics exceed their output bound')
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    history = actions.add_parser('status', help='read existing history without a native operation')
    history.add_argument('--directory', type=Path, required=True)
    run = actions.add_parser('run-once', help='perform one explicit reserved native dump/listing attempt')
    run.add_argument('--directory', type=Path, required=True, help='existing private history directory')
    run.add_argument('--application', choices=APPLICATIONS, required=True)
    run.add_argument('--stderr-bytes', type=stderr_bound, required=True,
                     help='explicit bounded raw dump-warning capacity')
    args = parser.parse_args(argv)
    status, result, phase = None, None, 'admission'
    try:
        status = owned()
        if args.action == 'status':
            phase = 'history-read'
            result = status.inspect(args.directory)
            maximum = status.MAX_OUTPUT
        else:
            lifecycle = status.LIFECYCLE
            if tuple(lifecycle.PREP.APPLICATIONS) != APPLICATIONS or lifecycle.SELECTED.DUMP.MAX_STDERR != MAX_STDERR:
                raise Pending('backup command and owned lifecycle bounds differ')
            phase = 'lifecycle'
            result = lifecycle.run_once(args.directory, args.application, args.stderr_bytes)
            maximum = lifecycle.MAX_OUTPUT
        phase = 'output'
        write(sys.stdout.buffer, result, maximum)
        return 0
    except (OSError, ValueError, RuntimeError, TypeError, AttributeError, UnicodeError, RecursionError, KeyboardInterrupt) as error:
        try:
            diagnostic = failure(error, status, args.action, phase, args.directory, result)
            write(sys.stderr.buffer, diagnostic, MAX_DIAGNOSTIC)
        except (OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
            # An unavailable diagnostic sink still cannot turn failure into success.
            pass
        return 130 if isinstance(error, KeyboardInterrupt) else 75


if __name__ == '__main__':
    sys.exit(main())
