#!/usr/bin/python3
"""Compile a bounded, internally observed topology into one nft transaction.

This module only emits text. Kernel discovery, installation, boot ownership and
live reconciliation are separate responsibilities; callers must supply a complete
trusted observation, not owner configuration or a guess at the local network.
"""

import ipaddress
import json
import re
import sys

MAX_INPUT = 262144
MAX_OUTPUT = 1048576
MAX_INTERFACES = 32
MAX_ITEMS = 4096
INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
PRIVATE4 = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
PRIVATE6 = tuple(map(ipaddress.ip_network, ("fc00::/7", "fe80::/10")))
BLOCKED4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
)
BLOCKED6 = (
    "::/3", "4000::/2", "8000::/1", "2001::/32", "2001:2::/48",
    "2001:10::/28", "2001:20::/28", "2001:db8::/32", "2002::/16",
)
STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP", "INCOMPLETE", "FAILED", "NONE"}
ADMITTED_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}


class InvalidTopology(ValueError):
    """The observation cannot safely determine a policy."""


def fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise InvalidTopology("unexpected or missing record fields")


def sequence(value, limit=MAX_ITEMS):
    if type(value) is not list or len(value) > limit:
        raise InvalidTopology("invalid or oversized inventory")
    return value


def address(value):
    if type(value) is not str or len(value) > 45 or "%" in value:
        raise InvalidTopology("invalid address")
    try:
        result = ipaddress.ip_address(value)
    except ValueError as error:
        raise InvalidTopology("invalid address") from error
    if str(result) != value or result.is_unspecified or result.is_multicast or result.is_loopback:
        raise InvalidTopology("noncanonical or non-unicast external address")
    if result.version == 4 and int(result) == 0xffffffff:
        raise InvalidTopology("broadcast address")
    if result.version == 6 and result.ipv4_mapped is not None:
        raise InvalidTopology("mapped IPv4 address")
    return result


def mac(value):
    if type(value) is not str or MAC.fullmatch(value) is None:
        raise InvalidTopology("invalid Ethernet address")
    if value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        raise InvalidTopology("non-unicast Ethernet address")
    return value


def network(value):
    if type(value) is not str or len(value) > 49:
        raise InvalidTopology("invalid on-link prefix")
    try:
        result = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise InvalidTopology("invalid on-link prefix") from error
    if str(result) != value or result.prefixlen == 0:
        raise InvalidTopology("noncanonical or default on-link prefix")
    return result


def onlink(ip, prefixes):
    return any(ip.version == prefix.version and ip in prefix for prefix in prefixes)


def private(ip):
    return onlink(ip, PRIVATE4 if ip.version == 4 else PRIVATE6)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidTopology("duplicate JSON field")
        result[key] = value
    return result


def decode(raw):
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise InvalidTopology("invalid or oversized input")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidTopology("invalid topology JSON") from error
    fields(value, ("schema", "interfaces", "dns", "ntp", "dhcp4", "dhcp6"))
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise InvalidTopology("unsupported topology schema")
    interfaces = {}
    count = 0
    for item in sequence(value["interfaces"], MAX_INTERFACES):
        fields(item, ("name", "kind", "prefixes", "gateways", "neighbors", "dhcp4", "dhcp6"))
        name = item["name"]
        if type(name) is not str or INTERFACE.fullmatch(name) is None or name == "lo" or name in interfaces:
            raise InvalidTopology("invalid or duplicate interface")
        if item["kind"] != "ether" or type(item["dhcp4"]) is not bool or type(item["dhcp6"]) is not bool:
            raise InvalidTopology("unsupported link or DHCP observation")
        prefixes = tuple(network(prefix) for prefix in sequence(item["prefixes"]))
        count += len(prefixes)
        gateways, neighbors = {}, {}
        for entry in sequence(item["gateways"]):
            fields(entry, ("address", "mac"))
            ip = address(entry["address"])
            if not onlink(ip, prefixes):
                raise InvalidTopology("gateway outside observed link")
            link_address = None if entry["mac"] is None else mac(entry["mac"])
            if ip in gateways and gateways[ip] != link_address:
                raise InvalidTopology("conflicting gateway observation")
            gateways[ip] = link_address
            count += 1
        for entry in sequence(item["neighbors"]):
            fields(entry, ("address", "mac", "state"))
            ip = address(entry["address"])
            state = entry["state"]
            if type(state) is not str or state not in STATES or not onlink(ip, prefixes):
                raise InvalidTopology("invalid neighbor observation")
            link_address = None if entry["mac"] is None else mac(entry["mac"])
            if state in ADMITTED_STATES and link_address is None:
                raise InvalidTopology("missing resolved neighbor address")
            observed = (link_address, state)
            if ip in neighbors and neighbors[ip] != observed:
                raise InvalidTopology("conflicting neighbor observation")
            if ip in gateways and gateways[ip] is not None and gateways[ip] != link_address:
                raise InvalidTopology("gateway/neighbor identity disagreement")
            neighbors[ip] = observed
            count += 1
        interfaces[name] = (prefixes, gateways, neighbors, item["dhcp4"], item["dhcp6"])
    endpoints = {}
    for service in ("dns", "ntp", "dhcp4", "dhcp6"):
        endpoints[service] = set()
        for entry in sequence(value[service], 256):
            fields(entry, ("interface", "address"))
            name = entry["interface"]
            if type(name) is not str or name not in interfaces:
                raise InvalidTopology("endpoint without observed interface")
            ip = address(entry["address"])
            if service.startswith("dhcp"):
                version = int(service[-1])
                enabled = interfaces[name][3 if version == 4 else 4]
                if ip.version != version or not enabled:
                    raise InvalidTopology("DHCP endpoint without admitted client")
                if version == 6 and (not ip.is_link_local or not onlink(ip, interfaces[name][0])):
                    raise InvalidTopology("DHCPv6 endpoint outside local link")
            endpoints[service].add((name, ip))
            count += 1
    if count > MAX_ITEMS:
        raise InvalidTopology("aggregate inventory too large")
    return interfaces, endpoints


def atoms(entries):
    return ", ".join(sorted(set(entries)))


def tuple_text(*parts):
    return " . ".join(parts)


def quote(name):
    # Only validated interface names enter this serializer.
    return '"' + name + '"'


def compile_policy(raw):
    interfaces, endpoints = decode(raw)
    sets = []

    def add_set(name, datatype, entries, interval=False):
        flags = "constant, interval" if interval else "constant"
        elements = f" elements = {{ {atoms(entries)} }};" if entries else ""
        sets.append(f"    set {name} {{ type {datatype}; flags {flags};{elements} }}")

    peers = {4: set(), 6: set()}
    for name, (prefixes, gateways, neighbors, _, _) in interfaces.items():
        # An unresolved router cannot be distinguished from a private peer.
        if any(link_address is None for link_address in gateways.values()):
            continue
        router_macs = set(gateways.values())
        for ip, (link_address, state) in neighbors.items():
            if state in ADMITTED_STATES and private(ip) and ip not in gateways and link_address not in router_macs:
                if ip.version == 4 and any(prefix.prefixlen < 31 and ip in (prefix.network_address, prefix.broadcast_address)
                                           for prefix in prefixes if prefix.version == 4 and ip in prefix):
                    continue
                peers[ip.version].add((name, ip, link_address))
    for version, reserved in ((4, BLOCKED4), (6, BLOCKED6)):
        datatype = "ipv4_addr" if version == 4 else "ipv6_addr"
        local = [prefix for prefixes, *_ in interfaces.values() for prefix in prefixes if prefix.version == version]
        blocked = ipaddress.collapse_addresses([*map(ipaddress.ip_network, reserved), *local])
        add_set(f"blocked{version}", datatype, list(map(str, blocked)), True)
        add_set(f"ssh{version}", f"ifname . {datatype} . ether_addr",
                [tuple_text(quote(name), str(ip), link_address) for name, ip, link_address in peers[version]])
        add_set(f"ssh_reply{version}", f"ifname . {datatype}",
                [tuple_text(quote(name), str(ip)) for name, ip, _ in peers[version]])
        for service in ("dns", "ntp", "dhcp4", "dhcp6"):
            add_set(f"{service}_{version}", f"ifname . {datatype}",
                    [tuple_text(quote(name), str(ip)) for name, ip in endpoints[service] if ip.version == version])
        if version == 6:
            add_set("onlink6", datatype, list(map(str, ipaddress.collapse_addresses(local))), True)
    for version in (4, 6):
        add_set(f"dhcp{version}_links", "ifname", [quote(name) for name, item in interfaces.items() if item[3 if version == 4 else 4]])

    chains = {"input": [], "forward": [], "output": []}

    def rule(chain, expression, verdict="accept"):
        chains[chain].append(f"        {expression} counter {verdict}")

    for chain, direction in (("input", "iifname"), ("output", "oifname")):
        rule(chain, "ct state invalid", "drop")
        rule(chain, f'{direction} "lo"')
    rule("input", "ip saddr 127.0.0.0/8", "drop")
    rule("input", "ip6 saddr ::1", "drop")
    # Only related errors, not arbitrary helper-created related connections.
    for chain in ("input", "output"):
        rule(chain, "ct state related icmp type { destination-unreachable, time-exceeded, parameter-problem }")
        rule(chain, "ct state related icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem }")
    rule("input", "ip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 code 0 icmpv6 type nd-router-advert")
    for source in ("::", "fe80::/10", "@onlink6"):
        rule("input", f"ip6 saddr {source} ip6 hoplimit 255 icmpv6 code 0 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }}")
    rule("output", "ip6 daddr ff02::2 ip6 hoplimit 255 icmpv6 code 0 icmpv6 type nd-router-solicit")
    for destination in ("fe80::/10", "ff02::/16", "@onlink6"):
        rule("output", f"ip6 daddr {destination} ip6 hoplimit 255 icmpv6 code 0 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }}")
    rule("input", "ip6 saddr fe80::/10 ip6 hoplimit 1 icmpv6 code 0 icmpv6 type mld-listener-query")
    rule("output", "ip6 daddr ff02::/16 ip6 hoplimit 1 icmpv6 code 0 icmpv6 type { mld-listener-report, mld-listener-done, mld2-listener-report }")
    rule("input", "meta nfproto ipv4 iifname @dhcp4_links udp sport 67 udp dport 68")
    rule("output", "oifname @dhcp4_links ip daddr 255.255.255.255 udp sport 68 udp dport 67")
    rule("input", "iifname @dhcp6_links ip6 saddr fe80::/10 udp sport 547 udp dport 546")
    rule("output", "oifname @dhcp6_links ip6 daddr ff02::1:2 udp sport 546 udp dport 547")
    for version in (4, 6):
        protocol = "ip" if version == 4 else "ip6"
        for service, port, transports in (("dns", 53, ("udp", "tcp")), ("ntp", 123, ("udp",))):
            for transport in transports:
                rule("output", f"oifname . {protocol} daddr @{service}_{version} ct direction original ct state {{ new, established }} {transport} dport {port}")
                rule("input", f"iifname . {protocol} saddr @{service}_{version} ct direction reply ct state established {transport} sport {port} ct original proto-dst {port}")
        client, server = (68, 67) if version == 4 else (546, 547)
        rule("output", f"oifname . {protocol} daddr @dhcp{version}_{version} udp sport {client} udp dport {server}")
        # Server replies go before LAN isolation; original outbound connections do not.
        rule("output", f"oifname . {protocol} daddr @ssh_reply{version} ct direction reply ct state established tcp sport 22 ct original proto-dst 22")
    rule("output", "ct direction reply ct state established tcp sport { 80, 443 } ct original proto-dst { 80, 443 }")
    for version in (4, 6):
        protocol = "ip" if version == 4 else "ip6"
        rule("output", f"{protocol} daddr @blocked{version}", "drop")
        rule("input", f"ct direction reply {protocol} saddr @blocked{version}", "drop")
    # Scope every original SSH packet, including existing connections. Never add a
    # blanket established accept ahead of this identity check or the LAN drops.
    for state in ("new", "established"):
        syn = " tcp flags & (fin | syn | rst | ack) == syn" if state == "new" else ""
        rule("input", f"ct direction original ct state {state} tcp dport {{ 80, 443 }}{syn}")
        for version in (4, 6):
            protocol = "ip" if version == 4 else "ip6"
            rule("input", f"iifname . {protocol} saddr . ether saddr @ssh{version} ct direction original ct state {state} tcp dport 22{syn}")
        rule("output", f"ct direction original ct state {state} tcp dport {{ 80, 443 }}{syn}")
    rule("input", "ct direction reply ct state established tcp sport { 80, 443 } ct original proto-dst { 80, 443 }")
    result = ["destroy table inet debian13s4", "table inet debian13s4 {", *sets]
    for chain, rules in chains.items():
        result += [f"    chain {chain} {{", f"        type filter hook {chain} priority 0; policy drop;", *rules, "    }"]
    result += ["}", ""]
    text = "\n".join(result)
    if len(text.encode("utf-8")) > MAX_OUTPUT:
        raise InvalidTopology("compiled policy too large")
    return text


def main():
    try:
        text = compile_policy(sys.stdin.buffer.read(MAX_INPUT + 1))
    except InvalidTopology as error:
        print(f"debian13s4 firewall: {error}", file=sys.stderr)
        return 65
    except OSError:
        return 74
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except OSError:
        return 74
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
