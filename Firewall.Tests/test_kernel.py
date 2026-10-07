import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

from test_policy import PacketModel, POLICY

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("firewall_kernel", ROOT / "Firewall/kernel.py")
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)


def snapshot():
    loop = {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "link_type": "loopback", "address": "00:00:00:00:00:00"}
    ethernet = {"ifindex": 2, "ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "link_type": "ether", "address": "02:00:00:00:00:10"}
    return {
        "links": [loop, ethernet],
        "addresses": [
            copy.deepcopy(loop) | {"addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                                 {"family": "inet6", "local": "::1", "prefixlen": 128}]},
            copy.deepcopy(ethernet) | {"addr_info": [{"family": "inet", "local": "192.168.50.100", "prefixlen": 24},
                                     {"family": "inet6", "local": "fe80::100", "prefixlen": 64},
                                     {"family": "inet6", "local": "fd50::100", "prefixlen": 64}]},
        ],
        "routes4": [
            {"dst": "192.168.50.0/24", "dev": "eth0", "scope": "253", "table": "254", "flags": []},
            {"dst": "default", "dev": "eth0", "gateway": "192.168.50.1", "table": "254", "flags": []},
            {"type": "local", "dst": "192.168.50.100", "dev": "eth0", "scope": "254", "table": "255", "flags": []},
        ],
        "routes6": [
            {"dst": "fe80::/64", "dev": "eth0", "table": "254", "flags": []},
            {"dst": "fd50::/64", "dev": "eth0", "table": "254", "flags": []},
            {"dst": "default", "dev": "eth0", "gateway": "fe80::1", "table": "254", "flags": []},
            {"type": "multicast", "dst": "ff00::/8", "dev": "eth0", "table": "255", "flags": []},
        ],
        "rules4": [{"priority": 0, "src": "all", "table": "255"},
                   {"priority": 32766, "src": "all", "table": "254"},
                   {"priority": 32767, "src": "all", "table": "253"}],
        "rules6": [{"priority": 0, "src": "all", "table": "255"},
                   {"priority": 32766, "src": "all", "table": "254"}],
        "neighbors4": [
            {"dst": "192.168.50.1", "dev": "eth0", "lladdr": "02:00:00:00:00:01", "state": ["REACHABLE"]},
            {"dst": "192.168.50.20", "dev": "eth0", "lladdr": "02:00:00:00:00:20", "state": ["STALE"]},
            {"dst": "224.0.0.1", "dev": "eth0", "lladdr": "01:00:5e:00:00:01", "state": ["NOARP"]},
        ],
        "neighbors6": [
            {"dst": "fe80::1", "dev": "eth0", "lladdr": "02:00:00:00:00:01", "state": ["STALE"], "router": None},
            {"dst": "fd50::20", "dev": "eth0", "lladdr": "02:00:00:00:00:20", "state": ["REACHABLE"]},
        ],
        "proxy4": [], "proxy6": [],
    }


def policy_input(interfaces):
    # ONLY a test adapter: actual DNS/NTP/DHCP-manager observation is unfinished.
    records = [{name: entry[name] for name in ("name", "kind", "prefixes", "gateways", "neighbors")} | {"dhcp4": False, "dhcp6": False} for entry in interfaces]
    return json.dumps({"schema": 1, "interfaces": records, "dns": [], "ntp": [], "dhcp4": [], "dhcp6": []}).encode()


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.data = snapshot()

    def reject(self, value):
        with self.assertRaises(KERNEL.Pending):
            KERNEL.normalize(value)

    def test_native_identity_routes_neighbors_and_router_marker(self):
        result = KERNEL.normalize(self.data)
        self.assertEqual(len(result), 1)
        interface = result[0]
        self.assertEqual((interface["name"], interface["index"], interface["mac"], interface["up"]), ("eth0", 2, "02:00:00:00:00:10", True))
        self.assertIn("192.168.50.0/24", interface["prefixes"])
        self.assertIn("192.168.50.100/32", interface["prefixes"])
        self.assertEqual(interface["gateways"], [{"address": "192.168.50.1", "mac": "02:00:00:00:00:01"}, {"address": "fe80::1", "mac": "02:00:00:00:00:01"}])
        self.assertNotIn("224.0.0.1", [entry["address"] for entry in interface["neighbors"]])

    def test_native_numeric_link_types_and_no_carrier_preserve_inventory(self):
        expected = KERNEL.normalize(self.data)
        for collection in ("links", "addresses"):
            self.data[collection][0]["link_type"] = "[772]"
            self.data[collection][1]["link_type"] = "[1]"
        self.assertEqual(KERNEL.normalize(self.data), expected)
        for collection in ("links", "addresses"):
            self.data[collection][1]["flags"].remove("LOWER_UP")
            self.data[collection][1]["flags"].append("NO-CARRIER")
        interface = KERNEL.normalize(self.data)[0]
        self.assertFalse(interface["up"])
        self.assertIn("NO-CARRIER", interface["flags"])
        self.assertEqual(interface["neighbors"], expected[0]["neighbors"])
        self.data["links"][1]["link_type"] = "[65535]"
        self.reject(self.data)

    def test_numeric_native_route_types_match_names_and_unknown_types_refuse(self):
        self.data["routes4"].extend([
            {"dst": "192.168.50.255", "type": "broadcast", "dev": "eth0", "table": 255},
            {"dst": "10.0.0.0/8", "type": "blackhole", "table": 254},
            {"dst": "172.16.0.0/12", "type": "unreachable", "table": 254},
            {"dst": "44.0.0.0/24", "type": "prohibit", "table": 254},
        ])
        expected = KERNEL.normalize(self.data)
        numeric = {"unicast": "1", "local": "2", "broadcast": "3", "multicast": "5", "blackhole": "6", "unreachable": "7", "prohibit": "8"}
        for collection in ("routes4", "routes6"):
            for row in self.data[collection]:
                row["type"] = numeric[row.get("type", "unicast")]
        self.assertEqual(KERNEL.normalize(self.data), expected)
        for route_type in ("0", "4", "9", "10", "11", "nat", "throw", 1, True, None, []):
            value = copy.deepcopy(self.data)
            value["routes4"][0]["type"] = route_type
            with self.subTest(route_type=route_type):
                self.reject(value)

    def test_unselected_native_router_and_aliases_cannot_admit_ssh(self):
        self.data["neighbors6"].append({"dst": "fe80::2", "dev": "eth0", "lladdr": "02:00:00:00:00:02", "state": ["REACHABLE"], "router": None})
        self.data["neighbors4"].append({"dst": "192.168.50.2", "dev": "eth0", "lladdr": "02:00:00:00:00:02", "state": ["STALE"]})
        interfaces = KERNEL.normalize(self.data)
        self.assertIn({"address": "fe80::2", "mac": "02:00:00:00:00:02"}, interfaces[0]["gateways"])
        model = PacketModel(POLICY.compile_policy(policy_input(interfaces)))
        self.assertEqual(model.verdict("input", iifname="eth0", saddr="192.168.50.20", dport=22), "accept")
        self.assertEqual(model.verdict("input", iifname="eth0", saddr="192.168.50.2", mac="02:00:00:00:00:02", dport=22), "drop")

    def test_unresolved_gateway_retains_input_for_closed_ssh(self):
        self.data["neighbors4"][0] = {"dst": "192.168.50.1", "dev": "eth0", "state": ["INCOMPLETE"]}
        interfaces = KERNEL.normalize(self.data)
        self.assertIn({"address": "192.168.50.1", "mac": None}, interfaces[0]["gateways"])
        model = PacketModel(POLICY.compile_policy(policy_input(interfaces)))
        self.assertEqual(model.verdict("input", iifname="eth0", saddr="192.168.50.20", dport=22), "drop")
        self.assertEqual(model.verdict("input", iifname="eth0"), "accept")

    def test_native_none_failed_and_noarp_states_do_not_grant_peer(self):
        for state in (None, "FAILED", "NOARP"):
            value = copy.deepcopy(self.data)
            entry = value["neighbors4"][1]
            if state is None:
                entry.pop("state")
            else:
                entry["state"] = [state]
            interfaces = KERNEL.normalize(value)
            model = PacketModel(POLICY.compile_policy(policy_input(interfaces)))
            self.assertEqual(model.verdict("input", iifname="eth0", saddr="192.168.50.20", dport=22), "drop")

    def test_native_loopback_noarp_entries_do_not_hide_other_neighbors(self):
        expected = KERNEL.normalize(self.data)
        self.data["neighbors4"].append({"dst": "0.0.0.0", "dev": "lo", "lladdr": "00:00:00:00:00:00", "state": ["NOARP"]})
        self.data["neighbors6"].append({"dst": "ff02::1", "dev": "lo", "lladdr": "00:00:00:00:00:00", "state": ["NOARP"]})
        self.assertEqual(KERNEL.normalize(self.data), expected)
        for change in ({"dev": "hidden"}, {"router": None}, {"state": ["REACHABLE"]}):
            value = copy.deepcopy(self.data)
            value["neighbors6"][-1].update(change)
            self.reject(value)

    def test_assignment_mask_does_not_invent_onlink_prefix(self):
        self.data["routes4"] = []
        self.data["neighbors4"] = []
        self.data["addresses"][1]["addr_info"][0]["noprefixroute"] = True
        interfaces = KERNEL.normalize(self.data)
        self.assertIn("192.168.50.100/32", interfaces[0]["prefixes"])
        self.assertNotIn("192.168.50.0/24", interfaces[0]["prefixes"])

    def test_onlink_gateway_flag_adds_only_its_host_identity(self):
        self.data["routes4"][1].update(gateway="10.0.0.1", flags=["onlink"])
        self.data["neighbors4"][0]["dst"] = "10.0.0.1"
        interfaces = KERNEL.normalize(self.data)
        self.assertIn("10.0.0.1/32", interfaces[0]["prefixes"])
        self.assertNotIn("10.0.0.0/8", interfaces[0]["prefixes"])

    def test_offlink_gateway_and_neighbors_refuse_inference(self):
        for collection, field in (("routes4", "gateway"), ("neighbors4", "dst")):
            value = copy.deepcopy(self.data)
            value[collection][1 if collection == "routes4" else 0][field] = "10.0.0.1"
            self.reject(value)

    def test_no_proxy_dump_or_hidden_proxy_field_can_be_omitted(self):
        for family in (4, 6):
            value = copy.deepcopy(self.data)
            value[f"proxy{family}"] = [{"dst": "192.168.50.50", "dev": "eth0", "proxy": None}]
            self.reject(value)
        self.data["neighbors4"][0]["proxy"] = None
        self.reject(self.data)

    def test_policy_routing_missing_rules_and_altered_precedence_refuse(self):
        for change in ({"fwmark": "0x1"}, {"src": "192.168.50.0/24"}, {"table": 100}, {"priority": 100}, {"dst": "10.0.0.0/8"}, {"priority": True}):
            value = copy.deepcopy(self.data)
            value["rules4"][1].update(change)
            self.reject(value)
        self.data["rules4"].pop(0)
        self.reject(self.data)

    def test_multipath_nexthop_encapsulation_and_crossfamily_via_refuse(self):
        for field, content in (("nexthops", []), ("nhid", 12), ("encap", {}), ("via", {"family": "inet6", "addr": "fe80::1"}), ("tos", "0x04")):
            value = copy.deepcopy(self.data)
            value["routes4"][1][field] = content
            self.reject(value)
        for flags in (["cache"], ["dead"], ["pervasive"], "onlink"):
            value = copy.deepcopy(self.data)
            value["routes4"][1]["flags"] = flags
            self.reject(value)

    def test_direct_default_and_unknown_local_route_types_refuse(self):
        self.data["routes4"][1].pop("gateway")
        self.reject(self.data)
        for route_type in ("nat", "throw", "anycast", "mystery"):
            value = snapshot()
            value["routes4"][0]["type"] = route_type
            self.reject(value)

    def test_local_negative_and_multicast_routes_do_not_grant_prefixes(self):
        self.data["routes4"].append({"dst": "10.0.0.0/8", "type": "blackhole", "table": 254})
        interfaces = KERNEL.normalize(self.data)
        self.assertNotIn("10.0.0.0/8", interfaces[0]["prefixes"])
        self.assertNotIn("ff00::/8", interfaces[0]["prefixes"])
        self.data["routes4"][-1]["gateway"] = "192.168.50.1"
        self.reject(self.data)

    def test_link_address_and_inventory_identity_disagreements_refuse(self):
        for field, value in (("ifindex", 3), ("ifname", "eth1"), ("address", "02:00:00:00:00:99"), ("link_type", "tun"), ("flags", ["UP"])):
            data = copy.deepcopy(self.data)
            data["addresses"][1][field] = value
            self.reject(data)
        self.data["addresses"].pop()
        self.reject(self.data)

    def test_unknown_or_tunneled_links_and_masters_refuse(self):
        for kind in ("bridge", "bond", "vrf", "veth", "tun", "wireguard", "vxlan", "dummy"):
            value = copy.deepcopy(self.data)
            value["links"][1]["linkinfo"] = {"info_kind": kind}
            self.reject(value)
        for field, content in (("master", "br0"), ("link_netnsid", 0), ("link_index", 1), ("unknown_future_route_attribute", True), ("flags", ["MYSTERY"])):
            value = copy.deepcopy(self.data)
            value["links"][1][field] = content
            self.reject(value)

    def test_invalid_link_names_modes_and_duplicate_indices_refuse(self):
        for name in ("eth0; flush ruleset", "eth0\n", "a" * 16, [], None):
            value = copy.deepcopy(self.data)
            value["links"][1]["ifname"] = name
            self.reject(value)
        for flags in (["UP", "NOARP"], ["UP", "POINTOPOINT"], ["UP", "UP"]):
            value = copy.deepcopy(self.data)
            value["links"][1]["flags"] = flags
            self.reject(value)
        self.data["links"][1]["ifindex"] = 1
        self.reject(self.data)

    def test_vlan_parent_chain_is_observed_and_cycles_refuse(self):
        vlan = copy.deepcopy(self.data["links"][1])
        vlan.update(ifname="lan.7", ifindex=3, link_index=2, linkinfo={"info_kind": "vlan", "info_data": {"id": 7, "protocol": "802.1Q"}})
        self.data["links"].append(vlan)
        self.data["addresses"].append({name: value for name, value in vlan.items() if name not in ("link_index", "linkinfo")} | {"addr_info": []})
        result = KERNEL.normalize(self.data)
        self.assertEqual([entry["name"] for entry in result], ["eth0", "lan.7"])
        self.assertEqual(result[-1]["parent"], 2)
        self.assertEqual(result[-1]["vlan"], {"id": 7, "protocol": "802.1Q", "flags": []})
        self.data["links"][-1]["link_index"] = 3
        self.reject(self.data)

    def test_native_vlan_protocol_forms_and_unrecognized_options(self):
        for protocol, expected in (("802.1q", "802.1Q"), ("[33024]", "802.1Q"), ("[34984]", "802.1ad"), ("802.1ad", "802.1ad")):
            value = snapshot()
            value["links"][1].update(link_index=3, linkinfo={"info_kind": "vlan", "info_data": {"id": 7, "protocol": protocol, "flags": ["REORDER_HDR"]}})
            parent = copy.deepcopy(snapshot()["links"][1])
            parent.update(ifindex=3, ifname="eth1")
            value["links"].append(parent)
            value["addresses"].append(copy.deepcopy(parent) | {"addr_info": []})
            with self.subTest(protocol=protocol):
                self.assertEqual(KERNEL.normalize(value)[0]["vlan"]["protocol"], expected)
                for change in ({"protocol": "[65535]"}, {"protocol": []}, {"id": True}, {"flags": ["GVRP"]}, {"flags": ["LOOSE_BINDING"]}, {"ingress_qos": []}):
                    altered = copy.deepcopy(value)
                    altered["links"][1]["linkinfo"]["info_data"].update(change)
                    self.reject(altered)

    def test_empty_optional_ipv6_and_loopback_only_observations(self):
        self.data["addresses"][0]["addr_info"] = self.data["addresses"][0]["addr_info"][:1]
        self.data["addresses"][1]["addr_info"] = self.data["addresses"][1]["addr_info"][:1]
        for name in ("routes6", "rules6", "neighbors6", "proxy6"):
            self.data[name] = []
        self.assertEqual(len(KERNEL.normalize(self.data)), 1)
        self.data["links"] = self.data["links"][:1]
        self.data["addresses"] = self.data["addresses"][:1]
        for name in ("routes4", "neighbors4"):
            self.data[name] = []
        self.assertEqual(KERNEL.normalize(self.data), [])

    def test_partial_optional_ipv6_is_not_treated_as_absence(self):
        self.data["rules6"] = []
        self.reject(self.data)

    def test_neighbor_family_states_missing_mac_and_conflicts_refuse(self):
        for change in ({"dst": "fe80::1"}, {"dst": "192.168.050.1"}, {"lladdr": "ff:ff:ff:ff:ff:ff"}, {"state": ["UNKNOWN"]}, {"state": ["STALE", "REACHABLE"]}, {"state": "STALE"}):
            value = copy.deepcopy(self.data)
            value["neighbors4"][0].update(change)
            self.reject(value)
        value = copy.deepcopy(self.data)
        value["neighbors4"][0].pop("lladdr")
        self.reject(value)
        value = copy.deepcopy(self.data)
        value["neighbors4"].append(value["neighbors4"][0] | {"lladdr": "02:00:00:00:00:99"})
        self.reject(value)
        self.data["neighbors6"][0]["router"] = "false"
        self.reject(self.data)

    def test_complete_counted_inventory_and_unknown_field_refusal(self):
        value = copy.deepcopy(self.data)
        value.pop("proxy6")
        self.reject(value)
        value = copy.deepcopy(self.data)
        value["neighbors4"] *= KERNEL.MAX_ITEMS
        self.reject(value)
        value = copy.deepcopy(self.data)
        value["addresses"][1]["addr_info"] *= KERNEL.MAX_ITEMS
        self.reject(value)
        value = copy.deepcopy(self.data)
        value["links"] *= 34
        self.reject(value)
        value = copy.deepcopy(self.data)
        value["routes4"][0]["new_routing_selector"] = 1
        self.reject(value)

    def test_ordering_and_nonsecurity_lifetime_counters_do_not_change_facts(self):
        expected = KERNEL.normalize(self.data)
        for value in self.data.values():
            value.reverse()
        for item in self.data["addresses"]:
            for address in item["addr_info"]:
                address.update(valid_life_time=100, preferred_life_time=80)
        self.assertEqual(KERNEL.normalize(self.data), expected)


class ObservationTests(unittest.TestCase):
    def test_two_complete_readonly_rounds_and_scope(self):
        data, calls = snapshot(), []
        def query(name, deadline):
            calls.append((name, deadline))
            return copy.deepcopy(data[name])
        result = KERNEL.observe(query=query, scope=lambda: 77)
        self.assertEqual(result["schema"], "debian13s4-kernel-1")
        self.assertEqual(result["namespace"], 77)
        self.assertEqual([name for name, _ in calls], list(KERNEL.COMMANDS) * 2)
        self.assertEqual(len({deadline for _, deadline in calls}), 1)
        with self.assertRaises(POLICY.InvalidTopology):
            POLICY.compile_policy(json.dumps(result).encode())

    def test_changed_route_prefix_gateway_peer_and_flags_require_retry(self):
        for collection, modify in (("routes4", lambda rows: rows.append({"dst": "44.0.0.0/24", "dev": "eth0"})),
                                   ("neighbors4", lambda rows: rows[1].update(lladdr="02:00:00:00:00:99")),
                                   ("links", lambda rows: rows[1]["flags"].append("PROMISC"))):
            first, second = snapshot(), snapshot()
            modify(second[collection])
            if collection == "links":
                second["addresses"][1]["flags"].append("PROMISC")
            calls = 0
            def query(name, deadline):
                nonlocal calls
                source = first if calls < len(KERNEL.COMMANDS) else second
                calls += 1
                return copy.deepcopy(source[name])
            with self.subTest(collection=collection), self.assertRaises(KERNEL.Pending):
                KERNEL.observe(query=query, scope=lambda: 77)

    def test_changed_vlan_parent_or_tag_requires_retry(self):
        first = snapshot()
        parent = copy.deepcopy(first["links"][1])
        parent.update(ifindex=3, ifname="eth1")
        first["links"].append(parent)
        first["addresses"].append(copy.deepcopy(parent) | {"addr_info": []})
        first["links"][1].update(link_index=3, linkinfo={"info_kind": "vlan", "info_data": {"id": 7, "protocol": "802.1Q"}})
        for change in ("tag", "parent"):
            second = copy.deepcopy(first)
            if change == "tag":
                second["links"][1]["linkinfo"]["info_data"]["id"] = 8
            else:
                # Both parents are observed Ethernet devices; no cycle/error
                # can stand in for the intended two-round stability check.
                third = copy.deepcopy(parent)
                third.update(ifindex=4, ifname="eth2")
                first_with_parent = copy.deepcopy(first)
                first_with_parent["links"].append(third)
                first_with_parent["addresses"].append(copy.deepcopy(third) | {"addr_info": []})
                second = copy.deepcopy(first_with_parent)
                second["links"][1]["link_index"] = 4
            initial = first if change == "tag" else first_with_parent
            self.assertNotEqual(KERNEL.normalize(initial), KERNEL.normalize(second))
            calls = 0
            def query(name, deadline):
                nonlocal calls
                source = initial if calls < len(KERNEL.COMMANDS) else second
                calls += 1
                return copy.deepcopy(source[name])
            with self.subTest(change=change), self.assertRaises(KERNEL.Pending):
                KERNEL.observe(query=query, scope=lambda: 77)

    def test_namespace_change_and_shared_deadline_expiry_require_retry(self):
        data = snapshot()
        scopes = iter((77, 78))
        with self.assertRaises(KERNEL.Pending):
            KERNEL.observe(query=lambda name, deadline: copy.deepcopy(data[name]), scope=lambda: next(scopes))
        with patch.object(KERNEL, "now", side_effect=[10, 100]), patch.object(KERNEL, "ATTEMPT_SECONDS", 60):
            with self.assertRaises(KERNEL.Pending):
                KERNEL.observe(query=lambda name, deadline: copy.deepcopy(data[name]), scope=lambda: 77)

    def test_query_failure_does_not_publish_partial_observation(self):
        def failed(name, deadline):
            if name == "routes6":
                raise KERNEL.Pending("real delivery error")
            return copy.deepcopy(snapshot()[name])
        with self.assertRaises(KERNEL.Pending):
            KERNEL.observe(query=failed, scope=lambda: 77)

    def test_fixed_queries_have_all_tables_all_neighbor_states_and_proxy_turns(self):
        for family in (4, 6):
            self.assertEqual(KERNEL.COMMANDS[f"routes{family}"][-2:], ("table", "all"))
            self.assertEqual(KERNEL.COMMANDS[f"neighbors{family}"][-2:], ("nud", "all"))
            self.assertEqual(KERNEL.COMMANDS[f"proxy{family}"][-1], "proxy")
        self.assertTrue(all("show" in command for command in KERNEL.COMMANDS.values()))
        self.assertFalse(any(token in ("set", "add", "delete", "del", "flush", "netns") for command in KERNEL.COMMANDS.values() for token in command))


class NativeQueryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="debian13s4-kernel-", dir="/dev/shm")
        self.root = Path(self.directory.name)
        self.binary = self.root / "ip"
        self.patches = [patch.object(KERNEL, "IP_BINARY", self.binary), patch.object(KERNEL, "TRUST_ROOT", self.root), patch.object(KERNEL, "TRUSTED_UID", os.geteuid())]
        for setting in self.patches:
            setting.start()

    def tearDown(self):
        for setting in reversed(self.patches):
            setting.stop()
        self.directory.cleanup()

    def script(self, body):
        self.binary.write_text("#!/usr/bin/python3\n" + body + "\n")
        self.binary.chmod(0o700)

    def query(self):
        return KERNEL.native_query("links", KERNEL.now() + 5)

    def test_real_private_executable_capture_arguments_cleared_environment_and_fds(self):
        marker = self.root / "observed.json"
        sentinel = self.root / "parent-only"
        sentinel.write_bytes(b"parent descriptor")
        fd = os.open(sentinel, os.O_RDONLY)
        os.set_inheritable(fd, True)
        try:
            self.script(f"import json,os,sys\ntry:\n inherited=os.readlink('/proc/self/fd/{fd}')\nexcept FileNotFoundError:\n inherited=None\nwith open({str(marker)!r},'w') as stream: json.dump({{'argv':sys.argv[1:],'env':dict(os.environ),'sid':os.getsid(0),'pid':os.getpid(),'inherited':inherited}},stream)\nprint('[]')")
            with patch.dict(os.environ, {"DEBIAN13S4_UNTRUSTED_PARENT": "must not enter child"}):
                self.assertEqual(self.query(), [])
        finally:
            os.close(fd)
        result = json.loads(marker.read_text())
        self.assertEqual(result["argv"], ["-j", "-N", "-details", "link", "show"])
        self.assertNotIn("DEBIAN13S4_UNTRUSTED_PARENT", result["env"])
        self.assertEqual(result["env"]["LC_ALL"], "C")
        self.assertEqual(result["sid"], result["pid"])
        self.assertNotEqual(result["inherited"], str(sentinel))

    def test_native_nonzero_warning_and_invalid_json_are_pending(self):
        for body in ("import sys\nprint('[]')\nsys.exit(2)", "import sys\nprint('[]')\nprint('Dump was interrupted',file=sys.stderr)", "print('{')", "print('{}')", "import os\nos.write(1,b'\\xff')", "print('[{\"ifindex\":1,\"ifindex\":2}]')"):
            with self.subTest(body=body):
                self.script(body)
                with self.assertRaises(KERNEL.Pending):
                    self.query()

    def test_both_output_channels_have_real_finite_limits(self):
        for fd in (1, 2):
            self.script(f"import os\nos.write({fd},b'x'*8192)")
            with patch.object(KERNEL, "MAX_BYTES", 4096), self.assertRaises(KERNEL.Pending):
                self.query()

    def test_oversized_json_inventory_is_pending(self):
        self.script("import json\nprint(json.dumps([{}]*34))")
        with self.assertRaises(KERNEL.Pending):
            self.query()

    def test_checked_timeout_after_pipe_closure(self):
        self.script("import os,time\nos.close(1)\nos.close(2)\ntime.sleep(10)")
        started = time.monotonic()
        with patch.object(KERNEL, "QUERY_SECONDS", 1), self.assertRaises(KERNEL.Pending):
            self.query()
        self.assertLess(time.monotonic() - started, 4)

    def test_exited_leader_with_owned_pipe_child_is_killed_and_capture_is_pending(self):
        marker = self.root / "child.json"
        self.script(f"import json,os,time\npid=os.fork()\nif pid:\n os._exit(0)\nwith open('/proc/self/stat') as stream: start=stream.read().rsplit(') ',1)[1].split()[19]\nwith open({str(marker)!r},'w') as stream: json.dump({{'pid':os.getpid(),'sid':os.getsid(0),'pgid':os.getpgrp(),'start':start}},stream)\nwhile True:\n time.sleep(0.05)")
        with patch.object(KERNEL, "QUERY_SECONDS", 1), self.assertRaises(KERNEL.Pending):
            self.query()
        child = json.loads(marker.read_text())
        self.assertEqual(child["sid"], child["pgid"])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                fields = Path(f'/proc/{child["pid"]}/stat').read_text().rsplit(") ", 1)[1].split()
            except FileNotFoundError:
                break
            if fields[19] != child["start"] or fields[0] == "Z":
                break
            time.sleep(0.02)
        else:
            os.kill(child["pid"], signal.SIGKILL)
            self.fail("owned descendant remained live")

    def test_unknown_native_command_and_expired_deadline_never_execute(self):
        marker = self.root / "executed"
        self.script(f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\nprint('[]')")
        with self.assertRaises(KERNEL.Pending):
            KERNEL.native_query("link set eth0 down", KERNEL.now() + 5)
        with self.assertRaises(KERNEL.Pending):
            KERNEL.native_query("links", KERNEL.now() - 1)
        self.assertFalse(marker.exists())

    def test_symlink_fifo_directory_and_unsafe_leaf_or_ancestry_are_refused(self):
        victim = self.root / "victim"
        victim.write_bytes(b"untouched")
        victim_stat = victim.stat()
        self.binary.symlink_to(victim)
        with self.assertRaises(KERNEL.Pending):
            self.query()
        self.assertEqual(victim.read_bytes(), b"untouched")
        self.assertEqual(victim.stat().st_ino, victim_stat.st_ino)
        self.binary.unlink()
        os.mkfifo(self.binary)
        started = time.monotonic()
        with self.assertRaises(KERNEL.Pending):
            self.query()
        self.assertLess(time.monotonic() - started, 1)
        self.binary.unlink()
        self.binary.mkdir()
        with self.assertRaises(KERNEL.Pending):
            self.query()
        self.binary.rmdir()
        self.script("print('[]')")
        self.binary.chmod(0o722)
        with self.assertRaises(KERNEL.Pending):
            self.query()
        self.binary.chmod(0o700)
        self.root.chmod(0o722)
        try:
            with self.assertRaises(KERNEL.Pending):
                self.query()
        finally:
            self.root.chmod(0o700)

    def test_wrong_owner_and_nonexecutable_leaf_are_refused(self):
        self.script("print('[]')")
        with patch.object(KERNEL, "TRUSTED_UID", os.geteuid() + 1), self.assertRaises(KERNEL.Pending):
            self.query()
        self.binary.chmod(0o600)
        with self.assertRaises(KERNEL.Pending):
            self.query()

    def test_descriptor_or_native_file_change_is_not_certified(self):
        self.script("print('[]')")
        real_signature = KERNEL.signature
        calls = 0
        def changed(info):
            nonlocal calls
            calls += 1
            result = real_signature(info)
            return result if calls == 1 else result[:-1] + (result[-1] + 1,)
        with patch.object(KERNEL, "signature", side_effect=changed), self.assertRaises(KERNEL.Pending):
            self.query()


if __name__ == "__main__":
    unittest.main()
