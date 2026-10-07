"""Observe the host network policy; this helper never writes kernel settings."""

import os
from pathlib import Path
import re
import stat
import sys


PROC = Path("/proc/sys")
TRUSTED_UID = 0
MAX_INTERFACES = 1024
GLOBALS = {"ip_forward": 0, "tcp_syncookies": 1,
           "icmp_echo_ignore_broadcasts": 1, "icmp_ignore_bogus_error_responses": 1}
IPV4 = {"forwarding": 0, "accept_redirects": 0, "send_redirects": 0,
        "accept_source_route": 0, "rp_filter": 2, "route_localnet": 0, "proxy_arp": 0}
IPV6 = {"forwarding": 0, "accept_redirects": 0, "accept_source_route": -1, "proxy_ndp": 0}


def trusted(path, kind):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise ValueError(f"noncanonical path: {path}")
    current = path
    while True:
        info = current.lstat()
        expected = kind if current == path else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError(f"untrusted path: {current}")
        if current == Path("/"):
            return path.lstat()
        current = current.parent


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def value(path):
    before = trusted(path, stat.S_ISREG)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if signature(os.fstat(fd)) != signature(before):
            raise ValueError(f"changed descriptor: {path}")
        data = os.read(fd, 65)
        if len(data) > 64 or os.read(fd, 1) or not re.fullmatch(rb"-?[0-9]+\n?", data):
            raise ValueError(f"invalid scalar: {path}")
        if signature(os.fstat(fd)) != signature(before) or signature(path.lstat()) != signature(before):
            raise ValueError(f"changed scalar: {path}")
        return int(data)
    finally:
        os.close(fd)


def interfaces(family):
    base = PROC / "net" / family
    # A compiled-out or unloaded IPv6 stack has no namespace. Partial, symbolic
    # or unreadable namespaces cannot be confused with that optional absence.
    if family == "ipv6" and not os.path.lexists(base):
        trusted(base.parent, stat.S_ISDIR)
        return None
    directory = base / "conf"
    trusted(directory, stat.S_ISDIR)
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if len(names) >= MAX_INTERFACES + 2:
                raise ValueError("too many interfaces for bounded verification")
            if not entry.name or len(os.fsencode(entry.name)) > 15 or entry.name in (".", ".."):
                raise ValueError("invalid interface name")
            trusted(directory / entry.name, stat.S_ISDIR)
            names.append(entry.name)
    if not {"all", "default", "lo"}.issubset(names):
        raise ValueError(f"incomplete {family} interface inventory")
    return sorted(names)


def verify():
    inventories = {family: interfaces(family) for family in ("ipv4", "ipv6")}
    for name, expected in GLOBALS.items():
        path = PROC / "net/ipv4" / name
        if value(path) != expected:
            raise ValueError(f"policy differs: {path}")
    for family, policy in (("ipv4", IPV4), ("ipv6", IPV6)):
        for interface in inventories[family] or ():
            for name, expected in policy.items():
                path = PROC / "net" / family / "conf" / interface / name
                if value(path) != expected:
                    raise ValueError(f"policy differs: {path}")
    if any(interfaces(family) != names for family, names in inventories.items()):
        raise ValueError("interface inventory changed; retry required")


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        verify()
        return 0
    except (OSError, ValueError) as error:
        print(f"debian13s4 network verification: {error}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
