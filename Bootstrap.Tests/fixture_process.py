"""Bound and terminate only a disposable Bash fixture's own Linux session."""

import os
from pathlib import Path
import signal
import subprocess
import time


def session_processes(session):
    result = []
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            # Read no command-line arguments or unrelated process content.
            if path.stat().st_uid != os.geteuid():
                continue
            fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
            if int(fields[3]) == session and fields[0] not in ('Z', 'X', 'x'):
                result.append((int(path.name), int(fields[19])))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def terminate_session(process):
    session = process.pid
    if session <= 1 or session == os.getsid(0):
        raise ValueError('refusing nonfixture session')
    # GNU timeout creates another process group. The owned session identifies
    # those descendants too; stopping just the initial Bash group is insufficient.
    process.kill()
    deadline = time.monotonic() + 5
    while True:
        members = session_processes(session)
        if not members:
            return
        for pid, identity in members:
            try:
                fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
                if int(fields[3]) == session and int(fields[19]) == identity:
                    os.kill(pid, signal.SIGKILL)
            except (FileNotFoundError, ProcessLookupError):
                continue
        if time.monotonic() >= deadline:
            raise RuntimeError('fixture session did not terminate')
        time.sleep(0.01)


def run_bash(script, timeout):
    command = ['/bin/bash', '--noprofile', '--norc', '-c', script]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        # Preserve the native timeout exception and its raw bytes through cleanup.
        stdout, stderr = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    finally:
        try:
            terminate_session(process)
        finally:
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
