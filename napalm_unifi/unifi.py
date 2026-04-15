"""
Napalm driver for Unifi.

Read https://napalm.readthedocs.io for more information.
"""

from abc import ABC
from collections import defaultdict
import json
import logging
import os
import re
from os import path
from typing import Any, Dict, List, Union

from napalm.base import NetworkDriver, models
from napalm.base.netmiko_helpers import netmiko_args
from netmiko.utilities import get_structured_data_textfsm

import ntc_templates
from textfsm import clitable

template_dir = path.abspath(path.join(path.dirname(__file__), "utils", "textfsm_templates"))
local_cli_table = clitable.CliTable("index", template_dir)

template_dir = path.join(path.dirname(ntc_templates.__file__), "templates")
ntc_cli_table = clitable.CliTable("index", template_dir)

log = logging.getLogger(__name__)

# UniFi devices inject background log messages into SSH sessions.
# These match the syslog-style prefix format e.g. "[warn ]", "[err  ]", "[info ]"
_UNIFI_LOG_LINE = re.compile(r"^\[(?:warn |err  |info |crit )\]")


def map_textfsm_template(command: str, platform="ubiquiti_unifi"):
    for table in [local_cli_table, ntc_cli_table]:
        row_idx = table.index.GetRowMatch({
            "Platform": platform,
            "Command": command,
        })
        if row_idx:
            return path.join(table.template_dir, table.index.index[row_idx]['Template'])
    return None


def correct_lldp_interface_names(old_prefix: str, new_prefix: str, neighbors: Dict[str, List]):
    for interface in list(neighbors.keys()):
        if interface.startswith(old_prefix):
            neighbors[f"{new_prefix}{interface.removeprefix(old_prefix).strip()}"] = neighbors.pop(interface)
    return neighbors


def parse_mca_dump(raw: str) -> dict:
    """Extract and parse JSON from mca-dump output, stripping any leading prompt/echo or log noise."""
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError(f"mca-dump returned no parseable JSON content: {raw!r}")
    return json.loads(raw[start:end])


def strip_unifi_log_lines(output: str) -> str:
    """Remove background syslog lines that UniFi injects into SSH sessions."""
    lines = [line for line in output.splitlines() if not _UNIFI_LOG_LINE.match(line)]
    return "\n".join(lines)


class UnifiBaseDriver(NetworkDriver, ABC):
    """Napalm driver for Unifi."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {
                "allow_agent": False,
                "allowed_types": ["password"],
            }
        self.netmiko_optional_args = netmiko_args(optional_args)
        self._config: dict = {
            "candidate": None,
            "running": None,
            "startup": None,
        }
        self._mca: dict = None
        self.cli_table = clitable.CliTable()

    def open(self):
        """Implement the NAPALM method open (mandatory)"""
        self.device = self._netmiko_open(
            device_type="linux",
            netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Implement the NAPALM method close (mandatory)"""
        self._mca = None
        self._netmiko_close()

    def _push_lldp_cables_to_diode(self):
        """Ingest LLDP-discovered cable entities into NetBox via the Diode SDK."""
        target = os.environ.get("DIODE_TARGET", "")
        if not target:
            log.debug("DIODE_TARGET not set; skipping LLDP cable push for %s", self.hostname)
            return

        try:
            from netboxlabs.diode.sdk import DiodeClient
            from netboxlabs.diode.sdk.ingester import Cable, CableTermination, Entity, Interface
        except ImportError:
            log.warning("netboxlabs-diode-sdk not installed; skipping LLDP cable push")
            return

        try:
            neighbors = self.get_lldp_neighbors_detail()
        except Exception as exc:
            log.warning("Failed to get LLDP neighbors for %s: %s", self.hostname, exc)
            return

        if not neighbors:
            return

        local_hostname = self._get_mca().get("hostname", self.hostname)
        entities = []
        for local_port, neighbor_list in neighbors.items():
            for neighbor in neighbor_list:
                remote_hostname = neighbor.get("remote_system_name", "")
                # Prefer the human-readable port description over the raw port ID
                remote_port = neighbor.get("remote_port_description") or neighbor.get("remote_port", "")
                if not remote_hostname or not remote_port:
                    continue
                cable = Cable(status="connected")
                term_a = CableTermination(
                    cable=cable,
                    cable_end="A",
                    termination_interface=Interface(device=local_hostname, name=local_port),
                )
                term_b = CableTermination(
                    cable=cable,
                    cable_end="B",
                    termination_interface=Interface(device=remote_hostname, name=remote_port),
                )
                entities.extend([
                    Entity(cable=cable),
                    Entity(cable_termination=term_a),
                    Entity(cable_termination=term_b),
                ])

        if not entities:
            return

        with DiodeClient(target=target, app_name="napalm-unifi", app_version="0.4.0") as client:
            response = client.ingest(entities=entities)
            if response.errors:
                log.warning("Diode LLDP cable ingest errors for %s: %s", self.hostname, response.errors)
            else:
                log.info("Pushed %d cable entities to Diode for %s", len(entities), self.hostname)

    def _get_mca(self) -> dict:
        """Return mca-dump as a dict, cached for the duration of the session."""
        if self._mca is None:
            raw = self._netmiko_device.send_command("mca-dump", read_timeout=60)
            self._mca = parse_mca_dump(raw)
        return self._mca

    def _get_config(self, retrieve: str = "all", full: bool = False, sanitized: bool = False, use_previous: bool = False) -> models.ConfigDict:
        if use_previous:
            if retrieve == "all" and self._config["candidate"] and self._config["running"] and self._config["startup"]:
                return self._config
            elif self._config[retrieve]:
                return self._config

        if retrieve == "all" or retrieve == "running":
            self._config["running"] = self._read_file("/tmp/running.cfg")

        if retrieve == "all" or retrieve == "startup":
            self._config["startup"] = self._read_file("/tmp/system.cfg")

        return self._config

    def get_config(self, retrieve: str = "all", full: bool = False, sanitized: bool = False) -> models.ConfigDict:
        return self._get_config(retrieve, full, sanitized)

    def get_facts(self) -> models.FactsDict:
        mca = self._get_mca()

        return {
            "fqdn": "",
            "hostname": mca["hostname"],
            "interface_list": list(self.get_interfaces().keys()),
            "model": mca["model"],
            "model_display": mca["model_display"],
            "os_version": mca["version"],
            "uptime": mca["uptime"],
            "serial_number": mca["serial"],
            "vendor": "Ubiquiti Inc.",
        }

    def _read_file(self, file_path):
        return self.send_command(f"cat {file_path}")

    def send_command(self, command: str):
        """Send a command, stripping UniFi log noise before any TextFSM parsing."""
        textfsm_template = map_textfsm_template(command, platform="ubiquiti_unifi")

        # Always fetch raw output first so we can clean it before TextFSM sees it
        raw = self._netmiko_device.send_command(
            command,
            use_textfsm=False,
            read_timeout=60,
        )
        clean = strip_unifi_log_lines(raw)

        if textfsm_template is not None:
            return get_structured_data_textfsm(clean, template=textfsm_template)
        return clean

    def is_physical_interface(self, interface_name) -> bool:
        output = self.send_command(f"readlink -f /sys/class/net/{interface_name}")
        return not output.startswith("/sys/devices/virtual")

    def get_interface_ipv4(self, interface_name):
        interface = self.get_interfaces_ip()[interface_name]
        ip, data = next(iter(interface["ipv4"].items()))
        return (interface_name, f"{ip}/{data['prefix_length']}")

    def get_primary_ipv4(self):
        return self.get_interface_ipv4("eth0")

    def get_interfaces_ip(self) -> Dict[str, models.InterfacesIPDict]:
        interfaces: Dict[str, models.InterfacesIPDict] = {}
        output = self.send_command("ip address show")
        for record in output:
            interface_name = record["interface"]
            interfaces.setdefault(interface_name, {
                "ipv4": {},
                "ipv6": {}
            })
            for i, ip_address in enumerate(record["ip_addresses"]):
                interfaces[interface_name]["ipv4"][ip_address] = {
                    "prefix_length": int(record["ip_masks"][i])
                }
            for i, ip_address in enumerate(record["ipv6_addresses"]):
                interfaces[interface_name]["ipv6"][ip_address] = {
                    "prefix_length": int(record["ipv6_masks"][i])
                }
        return interfaces

    def get_interfaces(self) -> Dict[str, models.InterfaceDict]:
        interfaces: Dict[str, models.InterfaceDict] = {}
        output = self.send_command("ip link show")
        for record in output:
            interface_name = record["interface"]
            if "@" in interface_name:
                interface_name = interface_name[:interface_name.find("@")]
            flags = set(record["flags"].split(","))
            interfaces[interface_name] = {
                "alias": record["alias"],
                "description": interface_name,
                "is_enabled": "UP" in flags,
                "is_up": "UP" in flags,
                "last_flapped": float(-1),
                "mac_address": record["mac_address"],
                "mtu": int(record["mtu"]),          # TextFSM returns strings; cast to int
                "speed": float(-1),
                "type": "virtual" if self.is_physical_interface(interface_name) else record["type"],
            }
            if interfaces[interface_name]["type"] != "virtual":
                try:
                    device_path = f"/sys/class/net/{interface_name}"
                    interfaces[interface_name]["speed"] = float(self._read_file(f"{device_path}/speed"))
                except ValueError:
                    pass  # Ignore bad speed parsing
        return interfaces


    def get_environment(self) -> models.EnvironmentDict:
        mca = self._get_mca()
        env: models.EnvironmentDict = {
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {},
        }
        if mca.get("has_temperature"):
            overheating = mca.get("overheating", False)
            env["temperature"]["system"] = {
                "temperature": float(mca.get("general_temperature", 0)),
                "is_alert": overheating,
                "is_critical": overheating,
            }
        if mca.get("has_fan"):
            env["fans"]["fan0"] = {"status": True}
        return env


class UnifiConfigMixin:
    def get_config_section(self, prefix: str, trim=False, group=True) -> list[str]:
        if group:
            section = {}
        else:
            section = []
        config = self._get_config("running", use_previous=True)["running"]
        if not isinstance(config, str):
            return section
        for line in config.splitlines():
            if line.startswith(prefix):
                if trim:
                    line = line.removeprefix(prefix)
                if line.startswith("."):
                    line = line.removeprefix(".")
                if group:
                    keys, value = line.split("=", 1)  # maxsplit=1 guards against values containing "="
                    keys = keys.split(".")
                    node = section
                    for key in keys[0:-1]:
                        node.setdefault(key, {})
                        node = node[key]
                    node[keys[-1]] = value
                else:
                    section.append(line)
        return section

    def get_config_value(self, key: str) -> str:
        config = self._get_config("running", use_previous=True)["running"]
        if not isinstance(config, str):
            raise KeyError(key)
        for line in config.splitlines():
            if line.strip().startswith("#"):
                continue
            if "=" not in line:
                continue  # Guard against malformed lines
            line_key, value = line.split("=", 1)  # maxsplit=1 guards against values containing "="
            if line_key == key:
                return value
        raise KeyError(key)


class LLDPCliMixin:
    def get_lldp_neighbors_detail(self, interface: str = "") -> Dict[str, List[models.LLDPNeighborDetailDict]]:
        output = self.lldp_show_neighbors()
        neighbors: Dict[str, List[models.LLDPNeighborDetailDict]] = defaultdict(list)

        for details in output["lldp"][0]["interface"]:
            neighbors[details["name"]].append({
                "parent_interface": "",
                "remote_chassis_id": details["chassis"][0]["id"][0]["value"],
                "remote_port": details["port"][0]["id"][0]["value"],
                "remote_port_description": details["port"][0]["descr"][0]["value"],
                "remote_system_capab": [cap["type"] for cap in details["chassis"][0]["capability"]],
                "remote_system_description": details["chassis"][0]["descr"][0]["value"],
                "remote_system_enable_capab": [cap["type"] for cap in details["chassis"][0]["capability"] if cap["enabled"]],
                "remote_system_name": details["chassis"][0]["name"][0]["value"],
            })
        if interface == "":
            return neighbors
        return {interface: neighbors.get(interface, None)}

    def get_lldp_neighbors(self) -> Dict[str, List[models.LLDPNeighborDict]]:
        neighbors: Dict[str, List[models.LLDPNeighborDict]] = defaultdict(list)
        for local_port, neighbors_detail in self.get_lldp_neighbors_detail().items():
            for neighbor in neighbors_detail:
                neighbors[local_port].append(
                    {
                        "hostname": neighbor["remote_system_name"],
                        "port": neighbor["remote_port"],
                    },
                )
        return neighbors


class NoEnableMixin:
    def open(self):
        super().open()
        self._netmiko_device.check_enable_mode = self.check_enable_mode

    def check_enable_mode(self, *args, **kwargs):
        return False


class UnifiSwitchBase(NoEnableMixin, UnifiConfigMixin, UnifiBaseDriver):

    def cli(self, commands: List[str], use_texfsm=False) -> Dict[str, Union[str, Dict[str, Any]]]:
        self._netmiko_device.send_command("cli", expect_string=r"[^\#\>]+\s*[\#\>]")
        self._netmiko_device.send_command("enable", expect_string=r"[\$\#\>]\s*$")
        self._netmiko_device.send_command("terminal length 0", expect_string=r"[\$\#\>]\s*$")
        output = {}
        for command in commands:
            textfsm_template = None
            if use_texfsm:
                textfsm_template = map_textfsm_template(command)
            output[command] = self._netmiko_device.send_command(
                command,
                use_textfsm=(textfsm_template is not None),
                textfsm_template=textfsm_template,
                expect_string=r"[\$\#\>]",
            )
        self._netmiko_device.send_command("exit", expect_string=r"[^\#\>]+\s*[\#\>]")
        self._netmiko_device.send_command("exit", expect_string=r"[^\#\>]+\s*[\#\>]")
        return output

    def _get_lldp_neighbors_detail(self, interface) -> Dict:
        raise NotImplementedError("_get_lldp_neighbors_detail may be implemented by sub-classes")

    def get_lldp_neighbors_detail(self, interface: str = "") -> Dict[str, List[models.LLDPNeighborDetailDict]]:
        neighbors: Dict[str, List[models.LLDPNeighborDetailDict]] = defaultdict(list)
        interfaces = []
        if interface == "":
            interfaces = self.get_lldp_neighbors().keys()
        else:
            interfaces = [interface]
        for interface in interfaces:
            output = self._get_lldp_neighbors_detail(interface)
            for neighbor in output:
                neighbors[interface].append({
                    "parent_interface": "",
                    "remote_chassis_id": neighbor["neighbor_chassis_id"],
                    "remote_port": neighbor["neighbor_portid"],
                    "remote_port_description": neighbor["port_descr"],
                    "remote_system_capab": neighbor.get("system_capabilities_supported", []),
                    "remote_system_description": neighbor["system_descr"],
                    "remote_system_enable_capab": neighbor["system_capabilities_enabled"],
                    "remote_system_name": neighbor["neighbor_sysname"],
                })
        return neighbors

    def _get_lldp_neighbors(self) -> Dict:
        raise NotImplementedError("_get_lldp_neighbors may be implemented by sub-classes")

    def get_lldp_neighbors(self) -> Dict[str, List[models.LLDPNeighborDict]]:
        neighbors: Dict[str, List[models.LLDPNeighborDict]] = defaultdict(list)
        output = self._get_lldp_neighbors()
        for neighbor in output:
            interface_name = neighbor["local_port"]
            neighbors[interface_name].append(
                {
                    "hostname": neighbor["system_name"],
                    "port": neighbor["remote_port"],
                },
            )
        return neighbors

    def get_ports(self) -> Dict[str, models.InterfaceDict]:
        ports: Dict[str, models.InterfaceDict] = {}
        mtu = 1500
        mca = self._get_mca()

        try:
            if self.get_config_value("switch.jumboframes") == "enabled":
                mtu = int(self.get_config_value("switch.mtu"))
        except KeyError:
            pass  # Jumbo frames not configured, stick with 1500

        for port, details in self.get_config_section("switch.port", group=True, trim=True).items():
            try:
                status = mca["port_table"][int(port) - 1]
            except (IndexError, KeyError):
                continue  # port_table shorter than config, skip gracefully
            enabled = details.get("status") != "disabled"
            port = f"Port {port}"
            ports[port] = {
                "description": details.get("name", ""),
                "is_enabled": enabled,
                "is_up": status["up"],
                "last_flapped": float(-1),
                "mac_address": None,
                "mtu": int(mtu),
                "speed": float(status.get("speed", -1)),
                "type": "ether",
                "alias": "",
            }
        return ports

    def get_interfaces(self) -> Dict[str, models.InterfaceDict]:
        interfaces = super().get_interfaces()
        interfaces.update(self.get_ports())
        return interfaces

    def get_vlans(self) -> Dict[str, models.VlanDict]:
        vlans: Dict[str, models.VlanDict] = {}

        # Build VLAN name map from switch.vlan.{id}.name config entries
        vlan_config = self.get_config_section("switch.vlan", group=True, trim=True)
        for vlan_id, vlan_data in vlan_config.items():
            name = (vlan_data.get("name", "") if isinstance(vlan_data, dict) else "") or f"VLAN{vlan_id}"
            vlans[vlan_id] = {"name": name, "interfaces": []}

        # Supplement with VLANs observed in mca-dump port_table mac entries (catches
        # VLANs that are active but have no switch.vlan.* config entry)
        mca = self._get_mca()
        for port in mca.get("port_table", []):
            port_idx = port.get("port_idx")
            port_name = f"Port {port_idx}" if port_idx is not None else None
            for mac_entry in port.get("mac_table", []):
                vlan_id = str(mac_entry.get("vlan", ""))
                if not vlan_id:
                    continue
                if vlan_id not in vlans:
                    vlans[vlan_id] = {"name": f"VLAN{vlan_id}", "interfaces": []}
                if port_name and port_name not in vlans[vlan_id]["interfaces"]:
                    vlans[vlan_id]["interfaces"].append(port_name)

        # Add port VLAN membership from switch.port.{id}.vlan.{vlan_id}=tagged/untagged
        port_config = self.get_config_section("switch.port", group=True, trim=True)
        for port_id, port_data in port_config.items():
            if not isinstance(port_data, dict):
                continue
            port_name = f"Port {port_id}"
            vlan_memberships = port_data.get("vlan", {})
            if not isinstance(vlan_memberships, dict):
                continue
            for vlan_id in vlan_memberships:
                if vlan_id in vlans and port_name not in vlans[vlan_id]["interfaces"]:
                    vlans[vlan_id]["interfaces"].append(port_name)

        return vlans

    def get_arp_table(self, vrf: str = "") -> List[models.ARPTableDict]:
        arp_table: List[models.ARPTableDict] = []
        for port in self._get_mca().get("port_table", []):
            port_idx = port.get("port_idx")
            port_name = f"Port {port_idx}" if port_idx is not None else ""
            for entry in port.get("mac_table", []):
                ip = entry.get("ip", "")
                if not ip:
                    continue
                arp_table.append({
                    "interface": port_name,
                    "mac": entry.get("mac", ""),
                    "ip": ip,
                    "age": float(entry.get("age", 0)),
                })
        return arp_table

    def get_mac_address_table(self) -> List[models.MACAddrTable]:
        mac_table: List[models.MACAddrTable] = []
        for port in self._get_mca().get("port_table", []):
            port_idx = port.get("port_idx")
            port_name = f"Port {port_idx}" if port_idx is not None else ""
            for entry in port.get("mac_table", []):
                mac_table.append({
                    "mac": entry.get("mac", ""),
                    "interface": port_name,
                    "vlan": entry.get("vlan", 0),
                    "static": entry.get("static", False),
                    "active": True,
                    "moves": 0,
                    "last_move": 0.0,
                })
        return mac_table

    def get_interfaces_counters(self) -> Dict[str, models.InterfaceCounterDict]:
        counters: Dict[str, models.InterfaceCounterDict] = {}
        for port in self._get_mca().get("port_table", []):
            port_idx = port.get("port_idx")
            if port_idx is None:
                continue
            rx_packets = port.get("rx_packets", 0)
            tx_packets = port.get("tx_packets", 0)
            rx_broadcast = port.get("rx_broadcast", 0)
            tx_broadcast = port.get("tx_broadcast", 0)
            rx_multicast = port.get("rx_multicast", 0)
            tx_multicast = port.get("tx_multicast", 0)
            counters[f"Port {port_idx}"] = {
                "tx_errors": port.get("tx_errors", 0),
                "rx_errors": port.get("rx_errors", 0),
                "tx_discards": port.get("tx_dropped", 0),
                "rx_discards": port.get("rx_dropped", 0),
                "tx_octets": port.get("tx_bytes", 0),
                "rx_octets": port.get("rx_bytes", 0),
                "tx_unicast_packets": max(0, tx_packets - tx_broadcast - tx_multicast),
                "rx_unicast_packets": max(0, rx_packets - rx_broadcast - rx_multicast),
                "tx_multicast_packets": tx_multicast,
                "rx_multicast_packets": rx_multicast,
                "tx_broadcast_packets": tx_broadcast,
                "rx_broadcast_packets": rx_broadcast,
            }
        return counters

    def close(self):
        """Push LLDP cable data to Diode, then close the SSH session."""
        try:
            self._push_lldp_cables_to_diode()
        except Exception as exc:
            log.warning("Failed to push LLDP cables to Diode for %s: %s", self.hostname, exc)
        super().close()
