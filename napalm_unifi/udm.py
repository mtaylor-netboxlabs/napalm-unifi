"""NAPALM driver for UniFi Dream Machine (UDM / UDM-Pro / UDM-SE)."""

import json
import re
from collections import defaultdict
from typing import Dict, List

from napalm.base import models

from .unifi import (
    UnifiBaseDriver as _Base,
    LLDPCliMixin,
    NoEnableMixin,
    UnifiConfigMixin,
    parse_mca_dump,
)

# VLAN bridge interfaces created by UniFi OS: br0 (management/VLAN 1),
# br<id> (e.g. br10, br99) for each additional VLAN.
_BR_VLAN_RE = re.compile(r"^\d+:\s+br(\d+)[@:]")


class UnifiDreamMachineDriver(NoEnableMixin, UnifiConfigMixin, LLDPCliMixin, _Base):
    """
    NAPALM driver for UniFi Dream Machine family (UDM, UDM-Pro, UDM-SE).

    UniFi OS exposes a plain bash shell over SSH (no VyOS/EdgeOS CLI).
    VLANs are represented as Linux bridge interfaces (br0, br10, …).
    mca-dump provides device facts, environment data, and port/MAC tables.
    """

    def get_primary_ipv4(self):
        return self.get_interface_ipv4("br0")

    def lldp_show_neighbors(self):
        return json.loads(self.send_command("lldpcli -f json0 show neighbors details"))

    # ------------------------------------------------------------------
    # VLANs
    # ------------------------------------------------------------------

    def get_vlans(self) -> Dict[str, dict]:
        vlans: Dict[str, dict] = {}

        # Try running-config VLAN names (same format as switches when present)
        vlan_config = self.get_config_section("switch.vlan", group=True, trim=True)
        for vlan_id, vlan_data in vlan_config.items():
            name = (vlan_data.get("name", "") if isinstance(vlan_data, dict) else "") or f"VLAN{vlan_id}"
            vlans[vlan_id] = {"name": name, "interfaces": []}

        # Discover VLANs from bridge interfaces (br0 = VLAN 1, br10 = VLAN 10 …)
        for line in self.send_command("ip link show type bridge").splitlines():
            m = _BR_VLAN_RE.match(line)
            if not m:
                continue
            vlan_id = m.group(1)
            iface = line.split(":")[1].strip().split("@")[0]
            if vlan_id not in vlans:
                vlans[vlan_id] = {"name": f"VLAN{vlan_id}", "interfaces": []}
            if iface not in vlans[vlan_id]["interfaces"]:
                vlans[vlan_id]["interfaces"].append(iface)

        # Also harvest from mca-dump port_table mac entries
        for port in self._get_mca().get("port_table", []):
            port_idx = port.get("port_idx")
            port_name = f"Port {port_idx}" if port_idx is not None else None
            for entry in port.get("mac_table", []):
                vlan_id = str(entry.get("vlan", ""))
                if not vlan_id:
                    continue
                if vlan_id not in vlans:
                    vlans[vlan_id] = {"name": f"VLAN{vlan_id}", "interfaces": []}
                if port_name and port_name not in vlans[vlan_id]["interfaces"]:
                    vlans[vlan_id]["interfaces"].append(port_name)

        return vlans

    # ------------------------------------------------------------------
    # ARP / MAC tables  (UDM-Pro has port_table in mca-dump like switches)
    # ------------------------------------------------------------------

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
