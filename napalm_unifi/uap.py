import json
from typing import Dict

from .unifi import UnifiBaseDriver as _Base, LLDPCliMixin, NoEnableMixin, UnifiConfigMixin


class UnifiAccessPointDriver(NoEnableMixin, LLDPCliMixin, UnifiConfigMixin, _Base):
    def get_primary_ipv4(self):
        return self.get_interface_ipv4("br0")

    def lldp_show_neighbors(self):
        return json.loads(self.send_command("lldpcli -f json0 show neighbors details"))

    def get_vlans(self) -> Dict[str, dict]:
        vlans: Dict[str, dict] = {}
        for vap in self._get_mca().get("vap_table", []):
            vlan_id = str(vap.get("vlan", 1))
            radio = vap.get("radio", "")
            if vlan_id not in vlans:
                vlans[vlan_id] = {"name": f"VLAN{vlan_id}", "interfaces": []}
            if radio and radio not in vlans[vlan_id]["interfaces"]:
                vlans[vlan_id]["interfaces"].append(radio)
        return vlans
