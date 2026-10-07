#!/usr/bin/python3
"""Observe classic resolver configuration and supported kernel egress bindings.

This partial record is not a firewall policy input or an installed controller.
Local stub upstreams and encrypted/manager-specific DNS require later adapters.
"""

import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

SPEC = importlib.util.spec_from_file_location("debian13s4_kernel", Path(__file__).with_name("kernel.py"))
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending

TRUST_ROOT = Path("/")
TRUSTED_UID = 0
RESOLV_CONF = Path("/etc/resolv.conf")
TARGETS = {Path("/run/NetworkManager/resolv.conf"), Path("/run/resolvconf/resolv.conf")}
MAX_FILE = 65536
MAX_LINES = 1024
MAX_LINE = 1024
MAX_SERVERS = 3
ATTEMPT_SECONDS = 60
OPTIONS = {"debug", "rotate", "no-aaaa", "edns0", "single-request", "single-request-reopen",
           "use-vc", "trust-ad", "no-check-names", "no-tld-query"}
NUMERIC_OPTIONS = {"ndots": (0, 15), "timeout": (1, 30), "attempts": (1, 5)}
ROUTE_KEYS = {"dst", "dev", "gateway", "prefsrc", "src", "from", "table", "type", "uid",
              "flags", "cache", "metric", "protocol", "scope", "pref", "mtu", "advmss"}


def trusted(path, symbolic=False):
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending("noncanonical resolver path")
    path.relative_to(TRUST_ROOT)
    current = path
    leaf = None
    while True:
        info = current.lstat()
        kind = stat.S_ISDIR if current != path else stat.S_ISLNK if symbolic else stat.S_ISREG
        if not kind(info.st_mode) or info.st_uid != TRUSTED_UID or (not symbolic or current != path) and info.st_mode & 0o022:
            raise Pending("untrusted resolver leaf or ancestry")
        if current == path:
            leaf = info
        if current == TRUST_ROOT:
            return KERNEL.signature(leaf)
        current = current.parent


def read_configuration():
    link = None
    path = RESOLV_CONF
    if stat.S_ISLNK(path.lstat().st_mode):
        link = trusted(path, symbolic=True)
        # Admit exact native spellings only. Lexically collapsing arbitrary
        # '..' components can disagree with kernel symlink traversal.
        spellings = {str(target): target for target in TARGETS}
        spellings.update({os.path.relpath(target, RESOLV_CONF.parent): target for target in TARGETS})
        path = spellings.get(os.readlink(path))
        if path is None:
            raise Pending("unsupported resolver link target")
    before = trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if KERNEL.signature(os.fstat(fd)) != before:
            raise Pending("resolver descriptor changed")
        chunks = bytearray()
        while True:
            data = os.read(fd, min(65536, MAX_FILE + 1 - len(chunks)))
            if not data:
                break
            chunks.extend(data)
            if len(chunks) > MAX_FILE:
                raise Pending("resolver configuration too large")
        if KERNEL.signature(os.fstat(fd)) != before or trusted(path) != before:
            raise Pending("resolver changed during read")
    finally:
        os.close(fd)
    if link is not None and trusted(RESOLV_CONF, symbolic=True) != link:
        raise Pending("resolver link changed during read")
    return {"path": str(path), "signature": before, "link": link,
            "sha256": hashlib.sha256(chunks).hexdigest()}, bytes(chunks)


def parse_configuration(raw):
    if type(raw) is not bytes or len(raw) > MAX_FILE:
        raise Pending("invalid resolver configuration bytes")
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise Pending("invalid resolver configuration encoding") from error
    if any(ord(char) < 32 and char not in "\n\t" or ord(char) == 127 for char in text):
        raise Pending("control byte in resolver configuration")
    lines = text.splitlines()
    if len(lines) > MAX_LINES or any(len(line.encode()) > MAX_LINE for line in lines):
        raise Pending("resolver line limit exceeded")
    servers = []
    for line in lines:
        if not line or line[0] in "#;" or not line.strip():
            continue
        # glibc MATCH is anchored at column zero, rather than stripping an
        # indented nameserver and accidentally admitting an ignored endpoint.
        if line[0].isspace():
            raise Pending("indented resolver directive")
        words = line.split()
        directive = words[0]
        if directive == "nameserver":
            if len(words) < 2 or len(servers) >= MAX_SERVERS:
                raise Pending("missing or excessive resolver servers")
            token = words[1]
            if len(words) > 2 and not words[2].startswith(("#", ";")):
                raise Pending("unsupported resolver server suffix")
            parts = token.split("%")
            if len(parts) > 2:
                raise Pending("invalid resolver scope")
            try:
                ip = ipaddress.ip_address(parts[0])
            except ValueError as error:
                raise Pending("invalid resolver address") from error
            if ip.is_loopback or ip.is_unspecified:
                raise Pending("local resolver stub requires an upstream adapter")
            KERNEL.address(parts[0], ip.version)
            scope = parts[1] if len(parts) == 2 else None
            if scope is not None and (ip.version != 6 or not ip.is_link_local or
                                      not scope or len(scope) > 15 or
                                      not (scope.isascii() and scope.isdecimal() or KERNEL.NAME.fullmatch(scope))):
                raise Pending("unsupported resolver scope")
            if ip.version == 6 and ip.is_link_local and scope is None:
                raise Pending("link-local DNS lacks explicit scope")
            servers.append((str(ip), scope))
        elif directive == "options":
            for token in words[1:]:
                if token.startswith(("#", ";")):
                    break
                if token in OPTIONS:
                    continue
                parts = token.split(":")
                if len(parts) != 2 or parts[0] not in NUMERIC_OPTIONS or not re.fullmatch(r"0|[1-9][0-9]{0,2}", parts[1]):
                    raise Pending("unsupported resolver option")
                lower, upper = NUMERIC_OPTIONS[parts[0]]
                if not lower <= int(parts[1]) <= upper:
                    raise Pending("resolver option outside supported bounds")
        elif directive in ("search", "domain", "sortlist"):
            if len(words) < 2:
                raise Pending("empty resolver directive")
            # These do not choose DNS server/port/interface. Their complete
            # bytes are still bounded and participate in source stability.
        else:
            raise Pending("unsupported resolver directive")
    if not servers:
        raise Pending("no explicit external resolver servers")
    return servers


def scoped_interface(scope, interfaces):
    if scope is None:
        return None
    if scope.isascii() and scope.isdecimal():
        if str(int(scope)) != scope or int(scope) == 0:
            raise Pending("noncanonical resolver scope index")
        matches = [entry["name"] for entry in interfaces if entry["index"] == int(scope)]
    else:
        matches = [entry["name"] for entry in interfaces if entry["name"] == scope]
    if len(matches) != 1:
        raise Pending("resolver scope lacks observed interface")
    return matches[0]


def bind_route(destination, scope, routes, interfaces):
    if len(KERNEL.rows(routes, 1)) != 1:
        raise Pending("missing or ambiguous DNS route")
    row = routes[0]
    KERNEL.known(row, ROUTE_KEYS, ("dst", "dev"))
    if row["dst"] != destination or KERNEL.route_type(row.get("type", "unicast")) != "unicast":
        raise Pending("DNS route is local, negative or changed destination")
    if KERNEL.table(row.get("table", 254)) not in (253, 254):
        raise Pending("DNS route uses unsupported table")
    if KERNEL.flags(row.get("flags", [])) or row.get("cache", []) != []:
        raise Pending("DNS route has unsupported cache or flags")
    if "uid" in row and KERNEL.uint(row["uid"]) != os.geteuid():
        raise Pending("route lookup UID changed")
    ip = ipaddress.ip_address(destination)
    if "from" in row and row["from"] != ("0.0.0.0" if ip.version == 4 else "::"):
        raise Pending("source-specific DNS route")
    for field in ("src", "prefsrc"):
        if field in row:
            KERNEL.address(row[field], ip.version)
    if "src" in row and "prefsrc" in row and row["src"] != row["prefsrc"]:
        raise Pending("inconsistent DNS source address")
    matches = [entry for entry in interfaces if entry["name"] == row["dev"]]
    if len(matches) != 1 or not matches[0]["up"] or scope is not None and row["dev"] != scope:
        raise Pending("DNS route lacks an active observed interface")
    entry = matches[0]
    if "gateway" in row:
        KERNEL.address(row["gateway"], ip.version)
        if row["gateway"] not in {item["address"] for item in entry["gateways"]}:
            raise Pending("DNS route gateway was not observed")
    elif not any(ip.version == net.version and ip in net for net in map(ipaddress.ip_network, entry["prefixes"])):
        raise Pending("direct DNS route outside observed link")
    return {"interface": entry["name"], "address": destination}


def observe(read=read_configuration, topology=KERNEL.observe, route=KERNEL.native_route):
    deadline = KERNEL.now() + ATTEMPT_SECONDS
    first_source, first_bytes = read()
    servers = parse_configuration(first_bytes)
    first_kernel = topology(deadline=deadline)
    endpoints = []
    bindings = []
    for destination, scope in servers:
        interface = scoped_interface(scope, first_kernel["interfaces"])
        first_route = route(destination, interface, deadline)
        endpoints.append(bind_route(destination, interface, first_route, first_kernel["interfaces"]))
        bindings.append((destination, interface, first_route))
    second_source, second_bytes = read()
    if first_source != second_source or first_bytes != second_bytes:
        raise Pending("resolver source changed during observation")
    second_kernel = topology(deadline=deadline)
    if first_kernel != second_kernel:
        raise Pending("kernel topology changed during DNS observation")
    for destination, interface, first_route in bindings:
        second_route = route(destination, interface, deadline)
        first_bound = bind_route(destination, interface, first_route, first_kernel["interfaces"])
        if bind_route(destination, interface, second_route, second_kernel["interfaces"]) != first_bound or first_route != second_route:
            raise Pending("DNS route changed during observation")
    last_source, last_bytes = read()
    if last_source != first_source or last_bytes != first_bytes or KERNEL.namespace() != first_kernel["namespace"] or KERNEL.now() >= deadline:
        raise Pending("DNS observation changed or expired before publication")
    return {"schema": "debian13s4-resolver-1", "kernel": second_kernel,
            "source": {"path": first_source["path"], "sha256": first_source["sha256"]},
            "dns": [{"interface": name, "address": address}
                    for name, address in sorted({(entry["interface"], entry["address"]) for entry in endpoints})]}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        result = observe()
        payload = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        if len(payload.encode()) > KERNEL.MAX_BYTES:
            raise Pending("DNS observation too large")
        sys.stdout.write(payload)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, KERNEL.subprocess.TimeoutExpired) as error:
        print(f"debian13s4 resolver observation pending: {error}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
