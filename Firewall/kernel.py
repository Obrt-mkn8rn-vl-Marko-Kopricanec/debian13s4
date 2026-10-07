#!/usr/bin/python3
"""Observe a supported kernel topology without applying network changes.

The kernel-v1 record deliberately lacks DNS, NTP and DHCP-manager admission. It
cannot be passed straight to the firewall compiler or certify firewall readiness.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

IP_BINARY = Path("/usr/bin/ip")
TRUST_ROOT = Path("/")
TRUSTED_UID = 0
QUERY_SECONDS = 3.0
ATTEMPT_SECONDS = 60.0
CLEANUP_SECONDS = 1.0
MAX_BYTES = 1048576
MAX_ITEMS = 4096
MAX_LINKS = 33
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
STATES = {"INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT", "NONE"}
RESOLVED = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
LINK_FLAGS = set("UP BROADCAST DEBUG LOOPBACK POINTOPOINT NOTRAILERS NOARP PROMISC ALLMULTI MASTER SLAVE MULTICAST PORTSEL AUTOMEDIA DYNAMIC LOWER_UP DORMANT ECHO NO-CARRIER".split())
COMMANDS = {
    "links": ("-details", "link", "show"),
    "addresses": ("address", "show"),
    "routes4": ("-4", "route", "show", "table", "all"),
    "routes6": ("-6", "route", "show", "table", "all"),
    "rules4": ("-4", "rule", "show"),
    "rules6": ("-6", "rule", "show"),
    "neighbors4": ("-4", "neigh", "show", "nud", "all"),
    "neighbors6": ("-6", "neigh", "show", "nud", "all"),
    "proxy4": ("-4", "neigh", "show", "proxy"),
    "proxy6": ("-6", "neigh", "show", "proxy"),
}
LINK_KEYS = set("ifindex ifname flags mtu qdisc operstate group txqlen link_type address broadcast altnames linkmode inet6_addr_gen_mode promiscuity allmulti min_mtu max_mtu num_tx_queues num_rx_queues gso_max_size gso_max_segs tso_max_size tso_max_segs gro_max_size gso_ipv4_max_size gro_ipv4_max_size parentbus parentdev link_index linkinfo".split())
ADDRESS_KEYS = LINK_KEYS | {"addr_info"}
IP_KEYS = set("family local prefixlen broadcast scope label valid_life_time preferred_life_time dynamic mngtmpaddr noprefixroute tentative dadfailed deprecated temporary secondary optimistic permanent".split())
ROUTE_KEYS = set("dst dev gateway table type protocol scope metric prefsrc flags pref expires mtu advmss hoplimit features initcwnd initrwnd quickack congctl rtt rttvar rto_min window cwnd ssthresh reordering fastopen_no_cookie".split())
NEIGHBOR_KEYS = {"dst", "dev", "lladdr", "state", "router", "protocol"}


class Pending(ValueError):
    """A complete supported observation could not be established; retry later."""


def now():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def trusted_binary(path):
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending("noncanonical native path")
    path.relative_to(TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        kind = stat.S_ISREG if current == path else stat.S_ISDIR
        if not kind(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending("untrusted native binary or ancestry")
        if current == TRUST_ROOT:
            break
        current = current.parent
    before = path.lstat()
    if not before.st_mode & 0o100:
        raise Pending("native binary is not executable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if signature(os.fstat(fd)) != signature(before) or signature(path.lstat()) != signature(before):
            raise Pending("native descriptor changed")
    finally:
        os.close(fd)
    return signature(before)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Pending("duplicate native JSON field")
        result[key] = value
    return result


def rows(value, limit=MAX_ITEMS):
    if type(value) is not list or len(value) > limit or any(type(item) is not dict for item in value):
        raise Pending("invalid native inventory")
    return value


def known(item, allowed, required=()):
    if type(item) is not dict or not set(required).issubset(item) or not set(item).issubset(allowed):
        raise Pending("missing or unsupported native fields")


def uint(value, maximum=0xffffffff):
    if type(value) is not int or not 0 <= value <= maximum:
        raise Pending("invalid native integer")
    return value


def address(value, version, unicast=True):
    if type(value) is not str or len(value) > 45 or "%" in value:
        raise Pending("invalid native address")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as error:
        raise Pending("invalid native address") from error
    if ip.version != version or str(ip) != value or (version == 6 and ip.ipv4_mapped is not None):
        raise Pending("noncanonical or wrong-family address")
    if unicast and (ip.is_unspecified or ip.is_multicast or ip.is_loopback or (version == 4 and int(ip) == 0xffffffff)):
        raise Pending("non-unicast external address")
    return ip


def ethernet(value):
    if type(value) is not str or MAC.fullmatch(value) is None or value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        raise Pending("invalid native Ethernet identity")
    return value


def link_type(value):
    # ip -N bypasses ll_type_n2a names and prints bracketed ARPHRD values.
    if type(value) is not str or value not in ("ether", "[1]", "loopback", "[772]"):
        raise Pending("unsupported native link type")
    return "ether" if value in ("ether", "[1]") else "loopback"


def vlan_protocol(value):
    names = {"802.1Q": "802.1Q", "802.1q": "802.1Q", "[33024]": "802.1Q",
             "802.1ad": "802.1ad", "[34984]": "802.1ad"}
    if type(value) is not str or value not in names:
        raise Pending("unsupported VLAN protocol")
    return names[value]


def prefix(value, version):
    if value == "default":
        return ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")
    if type(value) is not str or len(value) > 49:
        raise Pending("invalid native prefix")
    try:
        result = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise Pending("invalid native prefix") from error
    canonical = str(result) if "/" in value else str(result.network_address)
    if result.version != version or canonical != value:
        raise Pending("noncanonical native prefix")
    return result


def table(value):
    aliases = {"local": 255, "main": 254, "default": 253, "255": 255, "254": 254, "253": 253}
    if type(value) is str:
        value = aliases.get(value)
    if type(value) is not int or value not in (253, 254, 255):
        raise Pending("unsupported routing table")
    return value


def route_type(value):
    types = {"1": "unicast", "2": "local", "3": "broadcast", "5": "multicast",
             "6": "blackhole", "7": "unreachable", "8": "prohibit"}
    if type(value) is not str:
        raise Pending("invalid native route type")
    result = types.get(value, value)
    if result not in types.values():
        raise Pending("unsupported native route type")
    return result


def flags(value):
    if type(value) is not list or any(type(flag) is not str for flag in value) or len(value) != len(set(value)):
        raise Pending("invalid native flags")
    return set(value)


def native_query(name, deadline):
    if type(name) is not str or name not in COMMANDS:
        raise Pending("native command is not an admitted read-only query")
    identity = trusted_binary(IP_BINARY)
    end = min(deadline, now() + QUERY_SECONDS)
    if now() >= end:
        raise Pending("observation deadline expired")
    process = subprocess.Popen([str(IP_BINARY), "-j", "-N", *COMMANDS[name]],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
                               close_fds=True, start_new_session=True)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = end - now()
                if remaining <= 0:
                    raise Pending("native query timed out")
                for key, _ in selector.select(remaining):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending("native output limit exceeded")
                    buffer.extend(data)
            remaining = end - now()
            if remaining <= 0 or process.wait(timeout=remaining) != 0 or buffers["stderr"]:
                raise Pending("native query failed or warned")
        if trusted_binary(IP_BINARY) != identity:
            raise Pending("native binary changed during observation")
        try:
            value = json.loads(buffers["stdout"].decode("utf-8"), object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Pending("invalid native JSON") from error
        return rows(value, MAX_LINKS if name in ("links", "addresses") else MAX_ITEMS)
    except subprocess.TimeoutExpired as error:
        raise Pending("native query timed out after pipe closure") from error
    finally:
        try:
            # Keep the direct PID unreaped until group termination on a capture
            # error. A leader that exited while a child holds a pipe still owns
            # its PID, so this cannot target a newly reused process group.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=CLEANUP_SECONDS)
        finally:
            process.stdout.close()
            process.stderr.close()


def normalize(snapshot):
    if type(snapshot) is not dict or set(snapshot) != set(COMMANDS):
        raise Pending("incomplete kernel snapshot")
    count = sum(len(rows(value, MAX_LINKS if name in ("links", "addresses") else MAX_ITEMS)) for name, value in snapshot.items())
    if count > MAX_ITEMS or snapshot["proxy4"] or snapshot["proxy6"]:
        raise Pending("oversized or proxy topology")
    links, indexes, parents = {}, {}, {}
    for item in snapshot["links"]:
        known(item, LINK_KEYS, ("ifindex", "ifname", "flags", "link_type", "address"))
        index, name = uint(item["ifindex"]), item["ifname"]
        if index == 0 or index in indexes or type(name) is not str or NAME.fullmatch(name) is None or name in links:
            raise Pending("invalid or duplicate link identity")
        link_flags = flags(item["flags"])
        if not link_flags.issubset(LINK_FLAGS):
            raise Pending("unsupported link flags")
        if name == "lo":
            if link_type(item["link_type"]) != "loopback" or "LOOPBACK" not in link_flags:
                raise Pending("invalid loopback identity")
            mac = None
        else:
            if link_type(item["link_type"]) != "ether" or link_flags & {"LOOPBACK", "POINTOPOINT", "NOARP", "MASTER", "SLAVE"}:
                raise Pending("unsupported link arrangement")
            mac = ethernet(item["address"])
        info = item.get("linkinfo", {})
        known(info, {"info_kind", "info_data"})
        kind = info.get("info_kind")
        if kind not in (None, "vlan") or ("info_data" in info and kind != "vlan"):
            raise Pending("unsupported virtual link")
        vlan_identity = None
        if kind == "vlan":
            if name == "lo" or "link_index" not in item:
                raise Pending("missing VLAN parent")
            vlan = info.get("info_data")
            known(vlan, {"protocol", "id", "flags"}, ("id", "protocol"))
            vlan_flags = flags(vlan.get("flags", []))
            if not 1 <= uint(vlan["id"], 4094) or not vlan_flags.issubset({"REORDER_HDR"}):
                raise Pending("unsupported VLAN identity")
            vlan_identity = {"id": vlan["id"], "protocol": vlan_protocol(vlan["protocol"]),
                             "flags": sorted(vlan_flags)}
            parents[name] = uint(item["link_index"])
        elif "link_index" in item:
            raise Pending("unidentified parent link")
        links[name] = {"name": name, "index": index, "mac": mac,
                       "up": {"UP", "LOWER_UP"}.issubset(link_flags), "kind": "ether",
                       "flags": sorted(link_flags), "parent": parents.get(name), "vlan": vlan_identity,
                       "prefixes": set(), "gateways": {}, "neighbors": {}}
        indexes[index] = name
    if "lo" not in links:
        raise Pending("missing loopback inventory")
    for name in parents:
        visited = {name}
        current = name
        while current in parents:
            current = indexes.get(parents[current])
            if current is None or current == "lo" or current in visited or len(visited) > 4:
                raise Pending("unresolved or cyclic VLAN parent")
            visited.add(current)
    seen = set()
    ipv6_present = False
    for item in snapshot["addresses"]:
        known(item, ADDRESS_KEYS, ("ifindex", "ifname", "addr_info", "address", "link_type", "flags"))
        name = item["ifname"]
        if type(name) is not str or name not in links or name in seen or uint(item["ifindex"]) != links[name]["index"]:
            raise Pending("address/link inventory disagreement")
        if item["address"] != ("00:00:00:00:00:00" if name == "lo" else links[name]["mac"]):
            raise Pending("address/link MAC disagreement")
        if link_type(item["link_type"]) != ("loopback" if name == "lo" else "ether"):
            raise Pending("address/link kind disagreement")
        if sorted(flags(item["flags"])) != links[name]["flags"]:
            raise Pending("address/link flags disagreement")
        seen.add(name)
        for entry in rows(item["addr_info"]):
            count += 1
            known(entry, IP_KEYS, ("family", "local", "prefixlen"))
            family = entry["family"]
            if family not in ("inet", "inet6"):
                raise Pending("unsupported address family")
            version = 4 if family == "inet" else 6
            ip = address(entry["local"], version, name != "lo")
            if name == "lo" and not ip.is_loopback:
                raise Pending("external address on loopback")
            length = uint(entry["prefixlen"], ip.max_prefixlen)
            if length == 0:
                raise Pending("default assigned prefix")
            ipv6_present |= version == 6
            # An assigned mask (especially noprefixroute) is not proof of a
            # connected FIB route. Keep only this host identity here; direct
            # native routes below supply admitted on-link networks.
            links[name]["prefixes"].add(ipaddress.ip_network(str(ip)))
    if seen != set(links):
        raise Pending("partial address inventory")
    for version in (4, 6):
        rule_set = set()
        for item in snapshot[f"rules{version}"]:
            known(item, {"priority", "src", "dst", "table"}, ("priority", "src", "table"))
            priority, table_id = uint(item["priority"]), table(item["table"])
            expected = {0: 255, 32766: 254, 32767: 253}
            if item["src"] != "all" or item.get("dst", "all") != "all" or expected.get(priority) != table_id or priority in rule_set:
                raise Pending("unsupported routing policy")
            rule_set.add(priority)
        absent6 = version == 6 and not ipv6_present and not any(snapshot[name] for name in ("routes6", "rules6", "neighbors6"))
        if not absent6 and not {0, 32766}.issubset(rule_set):
            raise Pending("incomplete routing policy")
        for item in snapshot[f"routes{version}"]:
            known(item, ROUTE_KEYS, ("dst",))
            destination = prefix(item["dst"], version)
            table_id = table(item.get("table", 254))
            route_flags = flags(item.get("flags", []))
            if not route_flags.issubset({"onlink", "linkdown"}):
                raise Pending("unsupported route flags")
            kind = route_type(item.get("type", "unicast"))
            if kind in ("unreachable", "blackhole", "prohibit"):
                if "gateway" in item:
                    raise Pending("gateway on negative route")
                continue
            name = item.get("dev")
            if type(name) is not str or name not in links:
                raise Pending("route without observed link")
            if kind in ("local", "broadcast", "multicast"):
                if table_id != 255 or "gateway" in item:
                    raise Pending("unexpected local route")
                continue
            if kind != "unicast" or table_id == 255 or name == "lo":
                raise Pending("unsupported route type")
            if "gateway" in item:
                gateway = address(item["gateway"], version)
                links[name]["gateways"][gateway] = None
                if "onlink" in route_flags:
                    links[name]["prefixes"].add(ipaddress.ip_network(str(gateway)))
            else:
                if destination.prefixlen == 0:
                    raise Pending("ambiguous direct default route")
                links[name]["prefixes"].add(destination)
        for item in snapshot[f"neighbors{version}"]:
            known(item, NEIGHBOR_KEYS, ("dst", "dev"))
            name = item["dev"]
            if type(name) is not str or name not in links:
                raise Pending("neighbor without observed Ethernet link")
            states = item.get("state", ["NONE"])
            if type(states) is not list or len(states) != 1 or type(states[0]) is not str or states[0] not in STATES:
                raise Pending("unsupported neighbor state")
            state = states[0]
            router = "router" in item
            if router and item["router"] is not None and item["router"] is not True:
                raise Pending("invalid native router flag")
            if state == "NOARP" and not router:
                # Synthetic NOARP cache entries (also present on loopback)
                # cannot admit SSH or resolve a gateway.
                address(item["dst"], version, False)
                continue
            if name == "lo":
                raise Pending("unexpected resolved or router neighbor on loopback")
            ip = address(item["dst"], version)
            if state in RESOLVED and "lladdr" not in item:
                raise Pending("resolved neighbor lacks Ethernet identity")
            mac = ethernet(item["lladdr"]) if state in RESOLVED else None
            if ip in links[name]["neighbors"] and links[name]["neighbors"][ip] != (mac, state):
                raise Pending("conflicting neighbor identity")
            links[name]["neighbors"][ip] = (mac, state)
            if router:
                links[name]["gateways"].setdefault(ip, None)
    if count > MAX_ITEMS:
        raise Pending("aggregate kernel inventory too large")
    result = []
    for name, item in sorted(links.items()):
        if name == "lo":
            continue
        for ip in set(item["gateways"]) | set(item["neighbors"]):
            if not any(ip.version == net.version and ip in net for net in item["prefixes"]):
                raise Pending("off-link gateway or neighbor; no inferred prefix")
        for ip in item["gateways"]:
            item["gateways"][ip] = item["neighbors"].get(ip, (None, "NONE"))[0]
        item["prefixes"] = sorted(map(str, item["prefixes"]))
        item["gateways"] = [{"address": str(ip), "mac": mac} for ip, mac in sorted(item["gateways"].items(), key=lambda pair: str(pair[0]))]
        item["neighbors"] = [{"address": str(ip), "mac": mac, "state": state} for ip, (mac, state) in sorted(item["neighbors"].items(), key=lambda pair: str(pair[0]))]
        result.append(item)
    return result


def namespace():
    value = os.readlink("/proc/self/ns/net")
    match = re.fullmatch(r"net:\[([0-9]+)\]", value)
    if match is None:
        raise Pending("unverifiable process network namespace")
    return int(match[1])


def observe(query=native_query, scope=namespace):
    deadline = now() + ATTEMPT_SECONDS
    identity = scope()
    first = normalize({name: query(name, deadline) for name in COMMANDS})
    second = normalize({name: query(name, deadline) for name in COMMANDS})
    if first != second or scope() != identity or now() >= deadline:
        raise Pending("kernel topology changed or observation expired")
    return {"schema": "debian13s4-kernel-1", "namespace": identity, "interfaces": second}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        result = json.dumps(observe(), sort_keys=True, separators=(",", ":")) + "\n"
        if len(result.encode()) > MAX_BYTES:
            raise Pending("normalized observation too large")
        sys.stdout.write(result)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"debian13s4 kernel observation pending: {error}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
