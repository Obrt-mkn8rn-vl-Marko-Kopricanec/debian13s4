"""Check the default journal's effective policy and archived-file retention."""

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


TRUSTED_UID = 0
PREFIXES = tuple(Path(p) for p in ("/etc/systemd", "/run/systemd", "/usr/local/lib/systemd", "/usr/lib/systemd"))
MACHINE = Path("/etc/machine-id")
JOURNALS = ((Path("/var/log/journal"), 128 * 1024**2, 32),
            (Path("/run/log/journal"), 32 * 1024**2, 8))
POLICY = {
    "Storage": "persistent", "Compress": "yes",
    "SystemMaxUse": "128M", "RuntimeMaxUse": "32M",
    "SystemKeepFree": "512M", "RuntimeKeepFree": "64M",
    "SystemMaxFileSize": "8M", "RuntimeMaxFileSize": "4M",
    "SystemMaxFiles": "32", "RuntimeMaxFiles": "8",
    "MaxFileSec": "1day", "MaxRetentionSec": "14day",
}
MAX_INPUT = 1024**2
MAX_FILES = 100000
AGE = 14 * 86400
ARCHIVE = re.compile(r".+@[0-9a-fA-F]{32}-[0-9a-fA-F]{16}-([0-9a-fA-F]{16})\.journal\Z")
UNCLEAN = re.compile(r".+@([0-9a-fA-F]{16})-[0-9a-fA-F]{16}\.journal~\Z")


def trusted(path, kind=stat.S_ISREG):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError("noncanonical journal path")
    leaf = path
    while True:
        info = path.lstat()
        if not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError("untrusted journal path: " + str(path))
        if path == path.parent:
            return leaf.lstat()
        path = path.parent


def signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path):
    before = trusted(path)
    if before.st_size > MAX_INPUT:
        raise ValueError("oversized journal input")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if signature(before) != signature(os.fstat(descriptor)):
            raise ValueError("journal input descriptor changed")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, MAX_INPUT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_INPUT:
                raise ValueError("oversized journal input")
        if signature(before) != signature(os.fstat(descriptor)) or signature(before) != signature(trusted(path)):
            raise ValueError("journal input changed")
        return bytes(data)
    finally:
        os.close(descriptor)


def sources():
    result = {}
    total = 0
    def add(path):
        nonlocal total
        if len(result) >= 1024:
            raise ValueError("excessive journal configuration")
        data = read(path)
        total += len(data)
        if total > MAX_INPUT:
            raise ValueError("excessive journal configuration")
        result[str(path)] = data
    for prefix in PREFIXES:
        for path in (prefix / "journald.conf", prefix / "journald.conf.d"):
            if not path.exists() and not path.is_symlink():
                continue
            if path.name == "journald.conf":
                add(path)
            else:
                trusted(path, stat.S_ISDIR)
                for leaf in path.iterdir():
                    if leaf.name.endswith(".conf"):
                        add(leaf)
    return result


def policy(text):
    values, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        # Refuse syntax whose continuation/quoting could make this observer
        # disagree with the native parser, rather than guessing its meaning.
        if line.endswith("\\"):
            raise ValueError("continued journal configuration is unverifiable")
        if line.startswith("["):
            if not re.fullmatch(r"\[[A-Za-z0-9]+\]", line):
                raise ValueError("invalid journal section")
            section = line[1:-1]
        elif section == "Journal":
            key, separator, value = line.partition("=")
            if not separator:
                raise ValueError("invalid journal assignment")
            if key.strip() in POLICY:
                values[key.strip()] = value.strip()
    if values != POLICY:
        raise ValueError("effective journal policy differs")


def configuration():
    before = sources()
    result = subprocess.run(["/usr/bin/systemd-analyze", "--no-pager", "cat-config", "systemd/journald.conf"],
                            capture_output=True, check=True, timeout=5)
    if result.stderr or len(result.stdout) > MAX_INPUT + 262144:
        raise ValueError("unverifiable native journal configuration")
    text = result.stdout.decode("utf-8", errors="strict")
    emitted = re.findall(r"^# (/[^\n]+)$", text, re.M)
    if not emitted or len(emitted) != len(set(emitted)) or any(path not in before for path in emitted):
        raise ValueError("untrusted native journal configuration source")
    policy(text)
    if sources() != before:
        raise ValueError("journal configuration changed")
    return hashlib.sha256(result.stdout).hexdigest()


def directories(require_persistent=False):
    data = read(MACHINE)
    if not re.fullmatch(rb"[0-9a-f]{32}\n?", data):
        raise ValueError("unverifiable journal machine identity")
    machine = data.decode("ascii", errors="strict").rstrip("\n")
    if not re.fullmatch(r"[0-9a-f]{32}", machine) or machine == "0" * 32:
        raise ValueError("unverifiable journal machine identity")
    result = []
    for base, size, count in JOURNALS:
        if base.exists() or base.is_symlink():
            trusted(base, stat.S_ISDIR)
            path = base / machine
            if path.exists() or path.is_symlink():
                trusted(path, stat.S_ISDIR)
                inventory(path)
                result.append((path, size, count))
                continue
        else:
            trusted(base.parent, stat.S_ISDIR)
        if require_persistent and base == JOURNALS[0][0]:
            raise ValueError("persistent default journal is absent")
    return result


def inventory(path):
    result = []
    for leaf in path.iterdir():
        info = trusted(leaf)
        match = ARCHIVE.fullmatch(leaf.name) or UNCLEAN.fullmatch(leaf.name)
        if match:
            stamp = min(int(match[1], 16), info.st_mtime_ns // 1000,
                        info.st_ctime_ns // 1000, info.st_atime_ns // 1000)
            result.append((leaf.name, info.st_blocks * 512, stamp))
        if len(result) > MAX_FILES:
            raise ValueError("excessive journal inventory")
    return result


def observe():
    now = int(time.time() * 1000000)
    for path, size, count in directories(require_persistent=True):
        rows = inventory(path)
        if (len(rows) > count or sum(row[1] for row in rows) > size or
                any(row[2] < max(0, now - AGE * 1000000) for row in rows)):
            raise ValueError("archived default journals still exceed retention")


def vacuum():
    directories()
    subprocess.run(["/usr/bin/journalctl", "--flush"], check=True, timeout=40)
    subprocess.run(["/usr/bin/journalctl", "--rotate"], check=True, timeout=40)
    for path, size, count in directories(require_persistent=True):
        subprocess.run(["/usr/bin/journalctl", "--directory=" + str(path),
                        "--vacuum-size=" + str(size), "--vacuum-time=14days", "--vacuum-files=" + str(count)],
                       check=True, timeout=40)
    # Native vacuum logs unlink failures but may still exit zero. Actual
    # archived-file observations are required; active files are not a quota.
    observe()


def main():
    if sys.argv[1:] == ["--config"]:
        directories()
        print(configuration())
    elif sys.argv[1:] == ["--observe"]:
        observe()
    elif sys.argv[1:] == ["--vacuum"] and os.geteuid() == TRUSTED_UID:
        vacuum()
    else:
        raise ValueError("expected --config, --observe or trusted --vacuum")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print("debian13s4 journal retention: " + str(error), file=sys.stderr)
        sys.exit(1)
