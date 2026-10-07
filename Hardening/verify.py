"""Observe required host controls and plan only their drifting sysctl keys."""

import os
from pathlib import Path
import re
import stat
import sys


PROC = Path("/proc/sys")
TRUSTED_UID = 0
POLICY = {
    "kernel/randomize_va_space": 2,
    "kernel/kptr_restrict": 2,
    "kernel/dmesg_restrict": 1,
    "kernel/perf_event_paranoid": 3,
    "kernel/yama/ptrace_scope": 2,
    "kernel/unprivileged_bpf_disabled": 1,
    "kernel/sysrq": 0,
    "fs/suid_dumpable": 0,
    "fs/protected_symlinks": 1,
    "fs/protected_hardlinks": 1,
    "fs/protected_fifos": 2,
    "fs/protected_regular": 2,
    "vm/unprivileged_userfaultfd": 0,
}


def trusted(path, kind):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise ValueError("noncanonical host-control path")
    current = path
    while True:
        info = current.lstat()
        expected = kind if current == path else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError("untrusted host-control path: " + str(current))
        if current == current.parent:
            return path.lstat()
        current = current.parent


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def value(path):
    before = trusted(path, stat.S_ISREG)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if signature(os.fstat(descriptor)) != signature(before):
            raise ValueError("host-control descriptor changed")
        data = os.read(descriptor, 65)
        if len(data) > 64 or os.read(descriptor, 1) or not re.fullmatch(rb"-?[0-9]+\n?", data):
            raise ValueError("invalid host-control scalar")
        number = int(data)
        if not -2147483648 <= number <= 2147483647:
            raise ValueError("host-control scalar outside native integer range")
        if signature(os.fstat(descriptor)) != signature(before) or signature(path.lstat()) != signature(before):
            raise ValueError("host-control scalar changed")
        return number
    finally:
        os.close(descriptor)


def complies(key, number):
    if key == "kernel/perf_event_paranoid":
        return number >= POLICY[key]
    if key == "kernel/yama/ptrace_scope":
        return number in (2, 3)
    return number == POLICY[key]


def plan():
    # Every control is required. Missing/partial/unverifiable namespaces fail
    # before emitting a write plan, including kernels lacking the needed LSM.
    before = {key: value(PROC / key) for key in POLICY}
    after = {key: value(PROC / key) for key in POLICY}
    if before != after:
        raise ValueError("host controls changed during observation; retry required")
    return [key for key, number in before.items() if not complies(key, number)]


def main():
    if sys.argv[1:] not in ([], ["--plan"]):
        return 64
    try:
        pending = plan()
        if sys.argv[1:]:
            if pending:
                print("\n".join(pending))
        elif pending:
            raise ValueError("host policy differs: " + ", ".join(pending))
        return 0
    except (OSError, ValueError) as error:
        print("debian13s4 host verification: " + str(error), file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
