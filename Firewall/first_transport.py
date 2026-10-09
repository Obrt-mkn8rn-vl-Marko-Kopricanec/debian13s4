#!/usr/bin/python3
"""Fixed native batch transport for a checked historical first-create plan.

Library only; no CLI, default workflow, registration, fresh-source observation,
ownership or installer integration. Calling transmit is a MUTATING native entry:
future callers still need independent current admission/authority/lifecycle gates.
Tests use private executables only. Zero exit is not effective-state verification;
every failure after the spawn attempt is uncertain and MUST NOT trigger a retry.
"""

import hashlib
import importlib.util
import os
from pathlib import Path
import selectors
import signal
import subprocess

SPEC = importlib.util.spec_from_file_location('debian13s4_first_transport_match', Path(__file__).with_name('first_match.py'))
MATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATCH)
KERNEL, STATE, Pending = MATCH.KERNEL, MATCH.STATE, MATCH.Pending
BINARY = Path('/usr/sbin/nft')
COMMAND = ('--file', '-')
ATTEMPT_SECONDS = 10
MAX_BYTES = 262144
MAX_RECEIPT = 4096


class Uncertain(RuntimeError):
    """An attempted child may have changed state; retain bounded raw evidence."""

    def __init__(self, reason, evidence):
        super().__init__(reason)
        self.evidence = evidence


def _deliver(data, plan_identity, namespace, end):
    binary, command = BINARY, (str(BINARY), *COMMAND)
    identity = KERNEL.trusted_binary(binary)
    # Prepare the immutable completion record before entering the child. Return
    # it only after complete input/EOF/capture/root/trust/context/time admission.
    receipt = STATE.encoded({'schema': 'debian13s4-first-create-native-transport-1',
        'state': 'native-zero-exit-empty-capture', 'profile': 'checked-historical-first-create-batch-1',
        'namespace': namespace, **plan_identity, 'input_bytes': len(data),
        'source': {'binary': command[0], 'argv': list(command[1:]), 'identity': list(identity)}}) + b'\n'
    limit = min(end, KERNEL.now() + KERNEL.QUERY_SECONDS)
    current = KERNEL.namespace()
    if len(receipt) > MAX_RECEIPT or type(current) is not int or current != namespace or KERNEL.now() >= limit:
        raise Pending('native first-create pre-entry identity or window refused')
    process, failure = None, None
    streams, buffers, received = {}, {'stdout': bytearray(), 'stderr': bytearray()}, {'stdout': 0, 'stderr': 0}
    written, cleanup = 0, []
    try:
        # Once this call is attempted, even an exec/spawn/IO/close error is NOT
        # evidence of unchanged native state. Never issue a second transaction.
        process = subprocess.Popen(list(command), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
        streams = {'stdin': process.stdin, 'stdout': process.stdout, 'stderr': process.stderr}
        with selectors.DefaultSelector() as selector:
            for label, stream in streams.items():
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_WRITE if label == 'stdin' else selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = limit - KERNEL.now()
                if remaining <= 0:raise Pending('native first-create IO timed out')
                for key, _ in selector.select(remaining):
                    if key.data == 'stdin':
                        chunk = data[written:written + 65536]
                        count = os.write(key.fileobj.fileno(), chunk)
                        if type(count) is not int or not 0 < count <= len(chunk):
                            raise Pending('native first-create input count is unverifiable')
                        written += count
                        if written == len(data):
                            selector.unregister(key.fileobj)
                            stream = streams.pop('stdin')
                            stream.close()  # retire ownership BEFORE its one checked close
                    else:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            stream = streams.pop(key.data)
                            stream.close()
                        else:
                            label = key.data;received[label] += len(chunk)
                            buffer = buffers[label]
                            room = MAX_BYTES - len(buffer)
                            buffer.extend(chunk[:room])
                            if len(chunk) > room:raise Pending('native first-create capture limit exceeded')
            remaining = limit - KERNEL.now()
            if remaining <= 0:raise Pending('native first-create completion expired after EOF')
            result = process.wait(timeout=remaining)
            if written != len(data) or type(result) is not int or result != 0 or any(buffers.values()):
                raise Pending('native first-create input, exit or capture refused')
        if KERNEL.trusted_binary(binary) != identity:
            raise Pending('native first-create executable changed')
        current = KERNEL.namespace()
        if type(current) is not int or current != namespace or KERNEL.now() >= limit:
            raise Pending('native first-create final context or window changed')
    except BaseException as error:
        failure = error
    finally:
        if process is not None and process.returncode is None:
            try:
                # Do not poll/reap before killing on capture failure: the owned
                # unreaped leader still prevents PID/group-number reuse.
                try:os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=KERNEL.CLEANUP_SECONDS)
            except BaseException as error:cleanup.append(error)
        for label in tuple(streams):
            stream = streams.pop(label)
            try:stream.close()
            except BaseException as error:cleanup.append(error)
    if failure is not None or cleanup:
        evidence = {'command': command, 'namespace': namespace, 'deadline': limit, **plan_identity,
            'input': data, 'input_written': written,
            'stdout': bytes(buffers['stdout']), 'stderr': bytes(buffers['stderr']), 'received': dict(received),
            'returncode': None if process is None else process.returncode,
            'cleanup_errors': tuple((type(error).__name__, str(error)[:1024]) for error in cleanup)}
        cause = failure if failure is not None else cleanup[0]
        raise Uncertain('native first-create outcome uncertain; no automatic retry', evidence) from cause
    return receipt


def transmit(payload, deadline=None):
    """Explicit mutating transport, NOT fresh admission or application authority."""
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid first-create transport deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(KERNEL.namespace(), (1 << 64) - 1)
    if not namespace or KERNEL.now() >= end:raise Pending('invalid first-create transport context')
    plan = MATCH.checked(payload)
    if plan['namespace'] != namespace or KERNEL.now() >= end:
        raise Pending('historical first-create transport context differs or expired')
    identity = {'proposal_sha256': hashlib.sha256(payload).hexdigest(),
        'correlation_id': plan['correlation_id'], 'transaction_sha256': plan['transaction_sha256']}
    return _deliver(plan['transaction'].encode('utf-8'), identity, namespace, end)
