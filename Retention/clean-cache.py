"""Clean only APT download archives after a checked, locked package audit."""

import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys


POLICY = Path("/usr/local/lib/debian13s4/retention/apt.conf")
CACHE = Path("/var/cache/apt/archives")
LISTS = Path("/var/lib/debian13s4/retention-empty-lists")
STATUS = Path("/var/lib/dpkg/status")
TRUSTED_UID = 0
MAX_FILES = 100000
RESERVED = {"lock", "partial", "auxfiles", "lost+found"}


def trusted(path, kind=stat.S_ISREG, owners=None):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError("noncanonical archive path")
    leaf = path
    while True:
        info = path.lstat()
        allowed = (owners or {TRUSTED_UID}) if path == leaf else {TRUSTED_UID}
        if path != leaf and path in {CACHE / "partial", LISTS / "partial"}:
            allowed = {TRUSTED_UID, pwd.getpwnam("_apt").pw_uid}
        if (not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_mode & 0o022 or
                info.st_uid not in allowed):
            raise ValueError("untrusted archive path: " + str(path))
        if path == path.parent:
            return leaf.lstat()
        path = path.parent


def inventory(directory, partial=False):
    owners = {TRUSTED_UID, pwd.getpwnam("_apt").pw_uid}
    trusted(directory, stat.S_ISDIR, owners if partial else None)
    result = []
    for leaf in directory.iterdir():
        if not partial and leaf.name in {"partial", "auxfiles", "lost+found"}:
            trusted(leaf, stat.S_ISDIR, owners if leaf.name in {"partial", "auxfiles"} else None)
            if leaf.name == "partial":
                result.extend(inventory(leaf, partial=True))
        else:
            # Validate lock leaves too: native GetLock uses O_RDWR and must not
            # receive a FIFO/device even though it already refuses symlinks.
            trusted(leaf, owners=None if leaf.name == "lock" else owners)
            if partial or leaf.name not in RESERVED:
                result.append(leaf)
        if len(result) > MAX_FILES:
            raise ValueError("excessive archive inventory")
    return result


def prepare():
    trusted(CACHE.parent, stat.S_ISDIR)
    if not CACHE.exists() and not CACHE.is_symlink():
        CACHE.mkdir(mode=0o755)
    inventory(CACHE)
    trusted(LISTS.parent, stat.S_ISDIR)
    if not LISTS.exists() and not LISTS.is_symlink():
        LISTS.mkdir(mode=0o700)
    inventory(LISTS)


def audit():
    result = subprocess.run(["/usr/bin/dpkg", "--audit"], capture_output=True, check=True, timeout=10)
    if result.stdout or result.stderr:
        raise ValueError("archive cleanup requires an empty dpkg audit")


def configuration():
    trusted(POLICY)
    trusted(STATUS)
    if os.environ.get("APT_CONFIG") != str(POLICY):
        raise ValueError("unexpected archive APT profile")
    import apt_pkg
    apt_pkg.init()
    config = apt_pkg.config
    if (config.find("Dir::Etc::parts") or config.find("Dir::Etc::main") or
            config.find("Dir::Etc::sourcelist") != "-" or config.find("Dir::Etc::sourceparts") != "-" or
            config.find_dir("Dir::Cache::archives").rstrip("/") != str(CACHE) or
            config.find_dir("Dir::State::lists").rstrip("/") != str(LISTS) or
            config.find_file("Dir::Cache::pkgcache") or config.find_file("Dir::Cache::srcpkgcache") or
            config.find_file("Dir::State::status") != str(STATUS) or
            config.find_b("Debug::NoLocking", True) or config.find("APT::Sandbox::User") != "_apt"):
        raise ValueError("unverified archive cleanup configuration")
    return apt_pkg


def clean():
    apt_pkg = configuration()
    # Retain repair downloads while dpkg is incomplete. The native package
    # lock covers the audit, archive delivery and postconditions; apt-get clean
    # also owns the native archive lock, without disabling either lock.
    with apt_pkg.SystemLock():
        audit()
        prepare()
        subprocess.run(["/usr/bin/apt-get", "clean"], check=True, timeout=120)
        if inventory(CACHE) or inventory(LISTS):
            raise ValueError("native archive cleanup left downloaded files")
        audit()


def main():
    if sys.argv[1:] != ["--apply"] or os.geteuid() != TRUSTED_UID:
        raise ValueError("archive cleanup requires trusted --apply")
    clean()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print("debian13s4 archive retention: " + str(error), file=sys.stderr)
        sys.exit(1)
