import copy
import importlib.util
import ipaddress
import json
import pathlib
import re
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("firewall_policy", ROOT / "Firewall/policy.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def topology():
    return {
        "schema": 1,
        "interfaces": [{
            "name": "enp1s0", "kind": "ether", "dhcp4": True, "dhcp6": True,
            "prefixes": ["192.168.50.0/24", "44.0.0.0/24", "fd50::/64", "fe80::/64", "2606:4700:10::/64"],
            "gateways": [
                {"address": "192.168.50.1", "mac": "02:00:00:00:00:01"},
                {"address": "fe80::1", "mac": "02:00:00:00:00:01"},
            ],
            "neighbors": [
                {"address": "192.168.50.20", "mac": "02:00:00:00:00:20", "state": "REACHABLE"},
                {"address": "fd50::20", "mac": "02:00:00:00:00:20", "state": "STALE"},
                {"address": "fe80::20", "mac": "02:00:00:00:00:20", "state": "PERMANENT"},
                {"address": "192.168.50.1", "mac": "02:00:00:00:00:01", "state": "REACHABLE"},
                {"address": "192.168.50.2", "mac": "02:00:00:00:00:01", "state": "REACHABLE"},
                {"address": "44.0.0.20", "mac": "02:00:00:00:00:44", "state": "REACHABLE"},
            ],
        }],
        "dns": [{"interface": "enp1s0", "address": "192.168.50.1"}, {"interface": "enp1s0", "address": "2606:4700:4700::1111"}],
        "ntp": [{"interface": "enp1s0", "address": "192.168.50.3"}],
        "dhcp4": [{"interface": "enp1s0", "address": "192.168.50.1"}],
        "dhcp6": [{"interface": "enp1s0", "address": "fe80::1"}],
    }


def encode(value):
    return json.dumps(value).encode("utf-8")


def atom(value):
    if value.startswith('"'):
        return value[1:-1]
    if value.isdecimal():
        return int(value)
    try:
        return ipaddress.ip_network(value) if "/" in value else ipaddress.ip_address(value)
    except ValueError:
        return value


def contains(expected, actual):
    if isinstance(expected, tuple):
        return isinstance(actual, tuple) and len(expected) == len(actual) and all(contains(a, b) for a, b in zip(expected, actual))
    if isinstance(expected, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return isinstance(actual, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and actual.version == expected.version and actual in expected
    return expected == actual


class PacketModel:
    """Independent interpreter for this emitted subset, not a kernel emulator.

    Tests evaluate serialized nft text, not production planner/helper decisions.
    Conntrack fields are supplied scenarios; they are not inferred from packets.
    """

    def __init__(self, text):
        self.sets = {}
        self.chains = {}
        current = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("set "):
                name = line.split()[1]
                match = re.search(r"elements = \{ (.+) \};", line)
                values = [] if match is None else match[1].split(", ")
                self.sets[name] = [tuple(atom(part) for part in value.split(" . ")) if " . " in value else atom(value) for value in values]
            elif line.startswith("chain "):
                current = line.split()[1]
                self.chains[current] = []
            elif line == "}":
                current = None
            elif current and line.startswith("type filter"):
                assert f"hook {current} priority 0; policy drop;" in line
            elif current:
                expression, verdict = line.rsplit(" counter ", 1)
                assert verdict in ("accept", "drop")
                self.chains[current].append((expression, verdict))

    def value(self, text):
        match = re.match(r'(@[a-z0-9_]+|\{[^}]+\}|"[^"]+"|[^ ]+)(?: |$)', text)
        assert match, text
        token = match[1]
        if token.startswith("@"):
            values = self.sets[token[1:]]
        elif token.startswith("{"):
            values = [atom(value.strip()) for value in token[1:-1].split(",")]
        else:
            values = [atom(token)]
        return values, text[match.end():]

    def matches(self, text, packet):
        while text:
            if text.startswith("tcp flags & (fin | syn | rst | ack) == syn"):
                if packet["protocol"] != "tcp" or packet["flags"] & 0x17 != 0x02:
                    return False
                text = text[len("tcp flags & (fin | syn | rst | ack) == syn"):].lstrip()
                continue
            tuple_match = re.match(r"(iifname|oifname) \. (ip6|ip) (saddr|daddr)( \. ether saddr)? ", text)
            if tuple_match:
                interface, family, field, ethernet = tuple_match.groups()
                if packet["version"] != (4 if family == "ip" else 6):
                    return False
                actual = (packet[interface], packet[field])
                if ethernet:
                    actual += (packet["mac"],)
                text = text[tuple_match.end():]
            else:
                selector = re.match(r"(ct original proto-dst|ct direction|ct state|meta nfproto|iifname|oifname|ip6 (?:saddr|daddr|hoplimit)|ip (?:saddr|daddr)|tcp (?:sport|dport)|udp (?:sport|dport)|icmpv6 (?:type|code)|icmp type) ", text)
                assert selector, text
                key = selector[1]
                text = text[selector.end():]
                if key == "meta nfproto":
                    actual = "ipv4" if packet["version"] == 4 else "ipv6"
                elif key.startswith(("tcp ", "udp ", "icmp ", "icmpv6 ")):
                    protocol, field = key.split()
                    if packet["protocol"] != protocol:
                        return False
                    actual = packet[field]
                elif key.startswith(("ip ", "ip6 ")):
                    family, field = key.split()
                    if packet["version"] != (4 if family == "ip" else 6):
                        return False
                    actual = packet[field]
                else:
                    actual = packet[{"ct state": "state", "ct direction": "direction", "ct original proto-dst": "original_port"}.get(key, key)]
            values, text = self.value(text)
            if not any(contains(value, actual) for value in values):
                return False
        return True

    def verdict(self, chain, **overrides):
        values = {
            "saddr": "15.16.17.18", "daddr": "93.184.216.34", "mac": "02:00:00:00:00:20",
            "iifname": "enp1s0", "oifname": "enp1s0", "protocol": "tcp", "dport": 443,
            "sport": 40000, "original_port": 443, "direction": "original", "state": "new",
            "flags": 0x02, "type": "echo-request", "code": 0, "hoplimit": 64,
        }
        values.update(overrides)
        values["saddr"] = ipaddress.ip_address(values["saddr"])
        values["daddr"] = ipaddress.ip_address(values["daddr"])
        values["version"] = values["saddr"].version
        assert values["version"] == values["daddr"].version
        for expression, verdict in self.chains[chain]:
            if self.matches(expression, values):
                return verdict
        return "drop"


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.observation = topology()
        self.model = PacketModel(POLICY.compile_policy(encode(self.observation)))

    def reject(self, observation):
        with self.assertRaises(POLICY.InvalidTopology):
            POLICY.compile_policy(encode(observation))

    def test_public_web_connections_and_replies(self):
        for port in (80, 443):
            for state in ("new", "established"):
                self.assertEqual(self.model.verdict("input", dport=port, state=state), "accept")
                self.assertEqual(self.model.verdict("output", dport=port, state=state), "accept")
            self.assertEqual(self.model.verdict("output", direction="reply", state="established", sport=port, original_port=port), "accept")
            self.assertEqual(self.model.verdict("input", direction="reply", state="established", sport=port, original_port=port), "accept")

    def test_new_web_packets_require_initial_syn(self):
        for flags in (0, 0x10, 0x12, 0x03, 0x06):
            for chain in ("input", "output"):
                self.assertEqual(self.model.verdict(chain, flags=flags), "drop")

    def test_ipv6_web_and_public_maintenance(self):
        common = {"saddr": "2606:4700:20::1", "daddr": "2606:4700:4700::1001"}
        self.assertEqual(self.model.verdict("input", **common), "accept")
        self.assertEqual(self.model.verdict("output", **common), "accept")
        self.assertEqual(self.model.verdict("output", **common, direction="reply", state="established", sport=443), "accept")

    def test_nonessential_protocols_and_ports_drop(self):
        for port in (21, 22, 25, 53, 445, 3389, 8080, 8443):
            for chain in ("input", "output"):
                self.assertEqual(self.model.verdict(chain, dport=port), "drop")
                self.assertEqual(self.model.verdict(chain, dport=port, state="established"), "drop")
        for chain in ("input", "output"):
            self.assertEqual(self.model.verdict(chain, protocol="udp"), "drop")
            self.assertEqual(self.model.verdict(chain, protocol="gre"), "drop")

    def test_forwarding_never_gets_an_accept(self):
        for direction in ("original", "reply"):
            for state in ("new", "established", "related"):
                self.assertEqual(self.model.verdict("forward", direction=direction, state=state), "drop")

    def test_local_ssh_identity_scopes_new_and_existing_packets(self):
        for state in ("new", "established"):
            self.assertEqual(self.model.verdict("input", saddr="192.168.50.20", dport=22, original_port=22, state=state), "accept")
            for changed in ({"saddr": "192.168.50.21"}, {"mac": "02:00:00:00:00:21"}, {"iifname": "enp2s0"}):
                packet = {"saddr": "192.168.50.20", "dport": 22, "original_port": 22, "state": state}
                packet.update(changed)
                self.assertEqual(self.model.verdict("input", **packet), "drop")

    def test_ipv6_ula_and_linklocal_ssh(self):
        for source in ("fd50::20", "fe80::20"):
            self.assertEqual(self.model.verdict("input", saddr=source, daddr="fd50::100", dport=22, original_port=22), "accept")

    def test_public_cgnat_and_global_onlink_addresses_do_not_admit_ssh(self):
        for source in ("15.16.17.18", "100.64.0.20", "44.0.0.20"):
            self.assertEqual(self.model.verdict("input", saddr=source, dport=22, original_port=22, mac="02:00:00:00:00:44"), "drop")
        self.assertEqual(self.model.verdict("input", saddr="2606:4700:10::20", daddr="fd50::100", dport=22, original_port=22), "drop")

    def test_gateway_identity_alias_and_translated_ssh_drop(self):
        for source in ("192.168.50.1", "192.168.50.2", "192.168.50.20"):
            for state in ("new", "established"):
                self.assertEqual(self.model.verdict("input", saddr=source, mac="02:00:00:00:00:01", dport=22, original_port=22, state=state), "drop")

    def test_unresolved_gateway_closes_ssh_but_keeps_web_and_dns(self):
        self.observation["interfaces"][0]["gateways"][0]["mac"] = None
        model = PacketModel(POLICY.compile_policy(encode(self.observation)))
        self.assertEqual(model.verdict("input", saddr="192.168.50.20", dport=22), "drop")
        self.assertEqual(model.verdict("input"), "accept")
        self.assertEqual(model.verdict("output", daddr="192.168.50.1", protocol="udp", dport=53), "accept")

    def test_unresolved_and_noarp_neighbors_do_not_admit_ssh(self):
        for state in ("INCOMPLETE", "FAILED", "NONE", "NOARP"):
            self.observation["interfaces"][0]["neighbors"][0].update(state=state, mac=None)
            model = PacketModel(POLICY.compile_policy(encode(self.observation)))
            self.assertEqual(model.verdict("input", saddr="192.168.50.20", dport=22), "drop")

    def test_lan_and_connected_public_egress_drops_existing_connections(self):
        for destination in ("10.20.30.40", "172.16.4.20", "192.168.50.20", "169.254.10.20", "100.64.0.20", "44.0.0.20"):
            for state in ("new", "established"):
                for port in (80, 443, 22, 445):
                    self.assertEqual(self.model.verdict("output", daddr=destination, state=state, dport=port), "drop")
            self.assertEqual(self.model.verdict("input", saddr=destination, state="established", direction="reply", sport=443), "drop")

    def test_ipv6_lan_mapped_tunnel_and_nonpublic_egress_drop(self):
        for destination in ("fd50::20", "fe80::20", "2606:4700:10::20", "2002:c0a8:3214::1", "2001::20", "64:ff9b::c0a8:3214", "::ffff:c0a8:3214", "ff02::1"):
            for state in ("new", "established"):
                self.assertEqual(self.model.verdict("output", saddr="2606:4700:20::1", daddr=destination, state=state), "drop")

    def test_server_replies_to_lan_require_reply_direction_and_service(self):
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.20", sport=443, direction="reply", state="established"), "accept")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.20", sport=22, original_port=22, direction="reply", state="established"), "accept")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.21", sport=22, original_port=22, direction="reply", state="established"), "drop")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.20", sport=443, direction="original", state="established"), "drop")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.20", sport=8080, original_port=8080, direction="reply", state="established"), "drop")

    def test_dns_tcp_udp_and_ntp_are_endpoint_and_interface_scoped(self):
        for protocol in ("tcp", "udp"):
            self.assertEqual(self.model.verdict("output", daddr="192.168.50.1", protocol=protocol, dport=53), "accept")
            self.assertEqual(self.model.verdict("input", saddr="192.168.50.1", protocol=protocol, sport=53, original_port=53, direction="reply", state="established"), "accept")
            self.assertEqual(self.model.verdict("output", daddr="192.168.50.20", protocol=protocol, dport=53), "drop")
            self.assertEqual(self.model.verdict("output", daddr="192.168.50.1", oifname="enp2s0", protocol=protocol, dport=53), "drop")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.3", protocol="udp", dport=123), "accept")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.20", protocol="udp", dport=123), "drop")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.3", protocol="tcp", dport=123), "drop")

    def test_dns_input_requires_an_actual_tracked_reply(self):
        for direction, state in (("original", "new"), ("reply", "new"), ("reply", "untracked")):
            self.assertEqual(self.model.verdict("input", saddr="192.168.50.1", protocol="udp", sport=53, original_port=53, direction=direction, state=state), "drop")
        self.assertEqual(self.model.verdict("input", saddr="192.168.50.1", protocol="udp", sport=53, original_port=123, direction="reply", state="established"), "drop")

    def test_dhcp_client_protocols_and_disabled_interfaces(self):
        self.assertEqual(self.model.verdict("output", daddr="255.255.255.255", protocol="udp", sport=68, dport=67), "accept")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.1", protocol="udp", sport=68, dport=67), "accept")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.20", protocol="udp", sport=68, dport=67), "drop")
        self.assertEqual(self.model.verdict("input", saddr="192.168.50.1", protocol="udp", sport=67, dport=68), "accept")
        self.assertEqual(self.model.verdict("output", saddr="fe80::100", daddr="ff02::1:2", protocol="udp", sport=546, dport=547), "accept")
        self.assertEqual(self.model.verdict("input", saddr="fe80::1", daddr="fe80::100", protocol="udp", sport=547, dport=546), "accept")
        self.observation["interfaces"][0].update(dhcp4=False, dhcp6=False)
        self.observation.update(dhcp4=[], dhcp6=[])
        model = PacketModel(POLICY.compile_policy(encode(self.observation)))
        self.assertEqual(model.verdict("output", daddr="255.255.255.255", protocol="udp", sport=68, dport=67), "drop")

    def test_dhcp4_ports_do_not_open_ipv6_and_reversed_ports_drop(self):
        self.assertEqual(self.model.verdict("input", saddr="fd50::20", daddr="fd50::100", protocol="udp", sport=67, dport=68), "drop")
        self.assertEqual(self.model.verdict("input", saddr="192.168.50.1", protocol="udp", sport=68, dport=67), "drop")
        self.assertEqual(self.model.verdict("output", daddr="192.168.50.1", protocol="udp", sport=67, dport=68), "drop")

    def test_network_and_broadcast_neighbors_do_not_admit_ssh(self):
        for ip in ("192.168.50.0", "192.168.50.255"):
            value = copy.deepcopy(self.observation)
            value["interfaces"][0]["neighbors"][0]["address"] = ip
            model = PacketModel(POLICY.compile_policy(encode(value)))
            self.assertEqual(model.verdict("input", saddr=ip, dport=22), "drop")

    def test_ipv6_dns_and_dhcp_replies_remain_endpoint_scoped(self):
        self.assertEqual(self.model.verdict("output", saddr="fd50::100", daddr="2606:4700:4700::1111", protocol="udp", dport=53), "accept")
        self.assertEqual(self.model.verdict("input", saddr="2606:4700:4700::1111", daddr="fd50::100", protocol="udp", sport=53, original_port=53, direction="reply", state="established"), "accept")
        self.assertEqual(self.model.verdict("output", saddr="fe80::100", daddr="fe80::1", protocol="udp", sport=546, dport=547), "accept")
        self.assertEqual(self.model.verdict("output", saddr="fe80::100", daddr="fe80::20", protocol="udp", sport=546, dport=547), "drop")

    def test_ipv6_packet_too_big_can_arrive_from_local_router(self):
        common = {"saddr": "fe80::1", "daddr": "fd50::100", "protocol": "icmpv6", "type": "packet-too-big"}
        self.assertEqual(self.model.verdict("input", **common, state="related"), "accept")
        self.assertEqual(self.model.verdict("input", **common, state="new"), "drop")

    def test_interface_renaming_and_peer_removal_close_existing_ssh(self):
        self.observation["interfaces"][0]["neighbors"].clear()
        model = PacketModel(POLICY.compile_policy(encode(self.observation)))
        self.assertEqual(model.verdict("input", saddr="192.168.50.20", dport=22, state="established"), "drop")
        self.observation = topology()
        self.observation["interfaces"][0]["name"] = "lan.1"
        for service in ("dns", "ntp", "dhcp4", "dhcp6"):
            for endpoint in self.observation[service]:
                endpoint["interface"] = "lan.1"
        model = PacketModel(POLICY.compile_policy(encode(self.observation)))
        self.assertEqual(model.verdict("input", saddr="192.168.50.20", dport=22, iifname="enp1s0", state="established"), "drop")
        self.assertEqual(model.verdict("input", saddr="192.168.50.20", dport=22, iifname="lan.1", state="established"), "accept")

    def test_neighbor_discovery_router_advertisements_and_mld_bounds(self):
        common = {"saddr": "fe80::1", "daddr": "fe80::100", "protocol": "icmpv6", "hoplimit": 255}
        for kind in ("nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert"):
            self.assertEqual(self.model.verdict("input", **common, type=kind), "accept")
            self.assertEqual(self.model.verdict("input", **(common | {"hoplimit": 254}), type=kind), "drop")
            self.assertEqual(self.model.verdict("input", **common, type=kind, code=1), "drop")
        self.assertEqual(self.model.verdict("input", **common, type="nd-redirect"), "drop")
        self.assertEqual(self.model.verdict("input", **(common | {"saddr": "2606:4700:20::1"}), type="nd-router-advert"), "drop")
        self.assertEqual(self.model.verdict("output", **(common | {"daddr": "ff02::2"}), type="nd-router-solicit"), "accept")
        self.assertEqual(self.model.verdict("output", **(common | {"daddr": "2606:4700:20::1"}), type="nd-neighbor-solicit"), "drop")
        self.assertEqual(self.model.verdict("input", **(common | {"hoplimit": 1}), type="mld-listener-query"), "accept")
        self.assertEqual(self.model.verdict("output", **(common | {"hoplimit": 1, "daddr": "ff02::16"}), type="mld2-listener-report"), "accept")

    def test_related_errors_do_not_admit_unrelated_icmp_or_helpers(self):
        for chain in ("input", "output"):
            self.assertEqual(self.model.verdict(chain, protocol="icmp", type="destination-unreachable", state="related"), "accept")
            self.assertEqual(self.model.verdict(chain, protocol="icmp", type="destination-unreachable"), "drop")
            self.assertEqual(self.model.verdict(chain, state="related", dport=21), "drop")
            self.assertEqual(self.model.verdict(chain, protocol="icmp", type="echo-request"), "drop")

    def test_invalid_packets_and_external_loopback_spoof_drop(self):
        for chain in ("input", "output"):
            self.assertEqual(self.model.verdict(chain, state="invalid"), "drop")
            self.assertEqual(self.model.verdict(chain, iifname="lo", oifname="lo", dport=23456), "accept")
        self.assertEqual(self.model.verdict("input", saddr="127.0.0.1"), "drop")
        self.assertEqual(self.model.verdict("input", saddr="::1", daddr="fd50::100"), "drop")

    def test_unplugged_empty_observation_keeps_ssh_closed(self):
        model = PacketModel(POLICY.compile_policy(encode({"schema": 1, "interfaces": [], "dns": [], "ntp": [], "dhcp4": [], "dhcp6": []})))
        self.assertEqual(model.verdict("input", saddr="192.168.50.20", dport=22), "drop")
        self.assertEqual(model.verdict("output", daddr="192.168.50.20"), "drop")

    def test_interface_and_mac_injection_and_wrong_kinds_are_rejected(self):
        for name in ('eth0"; flush ruleset', "eth0\n", "*", "lo", "a" * 16, [], None):
            value = copy.deepcopy(self.observation)
            value["interfaces"][0]["name"] = name
            self.reject(value)
        for link_address in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:00:00:00:01", "02:00:00:00:00:FF", "02:00:00:00:00:20; accept", [], None):
            value = copy.deepcopy(self.observation)
            value["interfaces"][0]["neighbors"][0]["mac"] = link_address
            self.reject(value)

    def test_tunnels_bridges_duplicates_and_bad_types_are_rejected(self):
        for kind in ("bridge", "tun", "wireguard", "loopback", None):
            value = copy.deepcopy(self.observation)
            value["interfaces"][0]["kind"] = kind
            self.reject(value)
        for key, content in (("schema", True), ("schema", 2), ("interfaces", {}), ("dns", None)):
            self.reject(self.observation | {key: content})
        self.reject(self.observation | {"extra": 1})
        value = copy.deepcopy(self.observation)
        value["interfaces"].append(copy.deepcopy(value["interfaces"][0]))
        self.reject(value)

    def test_default_noncanonical_and_hostbit_prefixes_are_rejected(self):
        for prefix in ("0.0.0.0/0", "::/0", "192.168.50.1/24", "fd50:0:0:0::/64", "fd50::/64; accept", 1):
            value = copy.deepcopy(self.observation)
            value["interfaces"][0]["prefixes"].append(prefix)
            self.reject(value)

    def test_address_and_neighbor_state_refusals(self):
        for ip in ("0.0.0.0", "::", "127.0.0.1", "::1", "224.0.0.1", "ff02::1", "255.255.255.255", "::ffff:192.168.50.20", "fe80::20%enp1s0", "192.168.050.20", "192.168.51.20", None):
            value = copy.deepcopy(self.observation)
            value["interfaces"][0]["neighbors"][0]["address"] = ip
            self.reject(value)
        value = copy.deepcopy(self.observation)
        value["interfaces"][0]["neighbors"][0]["state"] = "UNKNOWN"
        self.reject(value)

    def test_conflicting_neighbor_and_gateway_observations_are_rejected(self):
        for collection in ("neighbors", "gateways"):
            value = copy.deepcopy(self.observation)
            entry = copy.deepcopy(value["interfaces"][0][collection][0])
            entry["mac"] = "02:00:00:00:00:99"
            value["interfaces"][0][collection].append(entry)
            self.reject(value)
        value = copy.deepcopy(self.observation)
        value["interfaces"][0]["neighbors"][3]["mac"] = "02:00:00:00:00:99"
        self.reject(value)

    def test_endpoint_scope_and_dhcp_observation_refusals(self):
        for service in ("dns", "ntp", "dhcp4", "dhcp6"):
            value = copy.deepcopy(self.observation)
            value[service][0]["interface"] = "unobserved"
            self.reject(value)
        for service, ip in (("dhcp4", "fe80::1"), ("dhcp6", "192.168.50.1"), ("dhcp6", "fd50::1")):
            value = copy.deepcopy(self.observation)
            value[service][0]["address"] = ip
            self.reject(value)
        value = copy.deepcopy(self.observation)
        value["interfaces"][0]["dhcp4"] = False
        self.reject(value)

    def test_observation_order_and_identical_duplicates_are_deterministic(self):
        original = POLICY.compile_policy(encode(self.observation))
        value = copy.deepcopy(self.observation)
        for name in ("prefixes", "neighbors", "gateways"):
            value["interfaces"][0][name].reverse()
            value["interfaces"][0][name].append(copy.deepcopy(value["interfaces"][0][name][0]))
        value["dns"].reverse()
        value["dns"].append(copy.deepcopy(value["dns"][0]))
        self.assertEqual(POLICY.compile_policy(encode(value)), original)

    def test_prefix_collapsing_covers_overlaps_without_changing_admission(self):
        self.observation["interfaces"][0]["prefixes"].extend(["192.168.50.0/25", "44.0.0.128/25"])
        model = PacketModel(POLICY.compile_policy(encode(self.observation)))
        blocked = model.sets["blocked4"]
        self.assertEqual(len(blocked), len(self.model.sets["blocked4"]))
        for ip in ("192.168.50.20", "44.0.0.200"):
            self.assertEqual(model.verdict("output", daddr=ip), "drop")

    def test_multi_interface_identity_and_unresolved_router_are_independent(self):
        extra = copy.deepcopy(self.observation["interfaces"][0])
        extra["name"] = "enp2s0"
        extra["gateways"][0]["mac"] = None
        self.observation["interfaces"].append(extra)
        model = PacketModel(POLICY.compile_policy(encode(self.observation)))
        self.assertEqual(model.verdict("input", saddr="192.168.50.20", dport=22), "accept")
        self.assertEqual(model.verdict("input", saddr="192.168.50.20", dport=22, iifname="enp2s0"), "drop")

    def test_inventory_and_aggregate_limits_are_enforced(self):
        value = copy.deepcopy(self.observation)
        value["dns"] *= 257
        self.reject(value)
        value = copy.deepcopy(self.observation)
        value["interfaces"][0]["prefixes"] = ["192.168.50.0/24"] * (POLICY.MAX_ITEMS + 1)
        self.reject(value)
        value = copy.deepcopy(self.observation)
        value["interfaces"][0]["prefixes"] *= 810
        value["interfaces"][0]["neighbors"] = value["interfaces"][0]["neighbors"] * 20
        self.reject(value)
        value = copy.deepcopy(self.observation)
        value["interfaces"] = [value["interfaces"][0]] * 33
        self.reject(value)

    def test_raw_encoding_duplicate_fields_and_size_fail_closed(self):
        for raw in (b"\xff", b"{", b"{}", b"[]", b'{"schema":1,"schema":1}', b"[" * 2000 + b"]" * 2000, b" " * (POLICY.MAX_INPUT + 1)):
            with self.assertRaises(POLICY.InvalidTopology):
                POLICY.compile_policy(raw)

    def test_transaction_has_only_its_owned_table_and_three_drop_policies(self):
        text = POLICY.compile_policy(encode(self.observation))
        self.assertTrue(text.startswith("destroy table inet debian13s4\ntable inet debian13s4 {\n"))
        self.assertNotIn("flush ruleset", text)
        self.assertNotIn("include", text)
        self.assertEqual(text.count("policy drop;"), 3)
        self.assertEqual(set(self.model.chains), {"input", "forward", "output"})
        self.assertEqual(self.model.chains["forward"], [])

    def test_compiler_cli_emits_exact_policy_and_rejects_without_partial_output(self):
        for raw, expected in ((encode(self.observation), 0), (b"\xff", 65), (b" " * (POLICY.MAX_INPUT + 1), 65)):
            result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "Firewall/policy.py")], input=raw, capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, expected)
            if expected == 0:
                self.assertEqual(result.stdout, POLICY.compile_policy(raw).encode("utf-8"))
                self.assertEqual(result.stderr, b"")
            else:
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"debian13s4 firewall:", result.stderr)


if __name__ == "__main__":
    unittest.main()
