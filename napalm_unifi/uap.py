import json
import logging
import os
from typing import Dict

from .unifi import UnifiBaseDriver as _Base, LLDPCliMixin, NoEnableMixin, UnifiConfigMixin

log = logging.getLogger(__name__)

# Maps UniFi vap_table "security" values to NetBox WirelessLAN auth_type enum.
# NetBox accepts: "open", "wep", "wpa-personal", "wpa-enterprise"
_SECURITY_TO_AUTH_TYPE = {
    "open":      "open",
    "wep":       "wep",
    "wpa":       "wpa-personal",
    "wpa2":      "wpa-personal",
    "wpa3":      "wpa-personal",
    "wpa2/wpa3": "wpa-personal",
    "wpa/wpa2":  "wpa-personal",
    "wpae":      "wpa-enterprise",
    "wpa2e":     "wpa-enterprise",
    "wpa3e":     "wpa-enterprise",
}

# Maps UniFi encryption field to NetBox auth_cipher enum.
# NetBox accepts: "aes", "tkip", "auto"
_ENCRYPTION_TO_CIPHER = {
    "ccmp":    "aes",
    "aes":     "aes",
    "tkip":    "tkip",
    "tkip+ccmp": "auto",
    "auto":    "auto",
}


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

    def get_wireless_lans(self) -> Dict[str, dict]:
        """
        Return wireless LAN information keyed by SSID.

        Multiple vap_table entries may share the same SSID (one per radio band);
        this method deduplicates them and merges the radio list.

        Return format (maps directly to NetBox WirelessLAN via Diode):
        {
            "<ssid>": {
                "ssid":        str,
                "auth_type":   str,   # "open"|"wep"|"wpa-personal"|"wpa-enterprise"
                "auth_cipher": str,   # "aes"|"tkip"|"auto"|None
                "vlan":        int,   # 0 means untagged/native
                "status":      str,   # "active" or "disabled"
                "radios":      list,  # radio names carrying this SSID (informational)
                "bssids":      list,  # per-radio BSSIDs (informational)
            }
        }
        """
        wlans: Dict[str, dict] = {}
        for vap in self._get_mca().get("vap_table", []):
            ssid = vap.get("essid", "")
            if not ssid:
                continue

            security = vap.get("security", "open").lower()
            encryption = vap.get("encryption", "").lower()
            auth_type = _SECURITY_TO_AUTH_TYPE.get(security, "open")
            auth_cipher = _ENCRYPTION_TO_CIPHER.get(encryption) if encryption else None
            # Default WPA2/WPA3 cipher to AES when not explicitly set
            if auth_type in ("wpa-personal", "wpa-enterprise") and auth_cipher is None:
                auth_cipher = "aes"

            enabled = vap.get("enabled", True) and vap.get("up", True)
            vlan_id = vap.get("vlan", 0)
            radio = vap.get("radio", "")
            bssid = vap.get("bssid", "")

            if ssid not in wlans:
                wlans[ssid] = {
                    "ssid":        ssid,
                    "auth_type":   auth_type,
                    "auth_cipher": auth_cipher,
                    "vlan":        vlan_id,
                    "status":      "active" if enabled else "disabled",
                    "radios":      [],
                    "bssids":      [],
                }
            if radio and radio not in wlans[ssid]["radios"]:
                wlans[ssid]["radios"].append(radio)
            if bssid and bssid not in wlans[ssid]["bssids"]:
                wlans[ssid]["bssids"].append(bssid)

        return wlans

    def close(self):
        """Push wireless LAN and LLDP cable data to Diode, then close the SSH session."""
        try:
            self._push_wireless_lans_to_diode()
        except Exception as exc:
            log.warning("Failed to push wireless LANs to Diode for %s: %s", self.hostname, exc)
        try:
            self._push_lldp_cables_to_diode()
        except Exception as exc:
            log.warning("Failed to push LLDP cables to Diode for %s: %s", self.hostname, exc)
        super().close()

    def _push_wireless_lans_to_diode(self):
        """
        Ingest wireless LAN entities directly into NetBox via the Diode SDK.

        Reads connection details from environment variables so no extra
        configuration is needed beyond what device_discovery already sets:

            DIODE_TARGET          e.g. grpcs://fvye8799.cloud.netboxapp.com/diode
            DIODE_CLIENT_ID       e.g. ingest-digest-e672c183db3f5ea7
            DIODE_CLIENT_SECRET   e.g. JV2omwduoxLx1EQGsKSyNYdkyjXfmt0nZ4OBAlEDenY=
        """
        target = os.environ.get("DIODE_TARGET", "")
        if not target:
            log.debug("DIODE_TARGET not set; skipping wireless LAN push for %s", self.hostname)
            return

        try:
            from netboxlabs.diode.sdk import DiodeClient
            from netboxlabs.diode.sdk.ingester import Entity, WirelessLAN, VLAN as DiodeVLAN
        except ImportError:
            log.warning("netboxlabs-diode-sdk not installed; skipping wireless LAN push")
            return

        wlans = self.get_wireless_lans()
        if not wlans:
            return

        entities = []
        for wlan in wlans.values():
            kwargs = {
                "ssid": wlan["ssid"],
                "status": wlan["status"],
                "auth_type": wlan["auth_type"],
            }
            if wlan.get("auth_cipher"):
                kwargs["auth_cipher"] = wlan["auth_cipher"]
            if wlan.get("vlan"):
                kwargs["vlan"] = DiodeVLAN(vid=wlan["vlan"])
            entities.append(Entity(wireless_lan=WirelessLAN(**kwargs)))

        with DiodeClient(target=target, app_name="napalm-unifi", app_version="0.4.0") as client:
            response = client.ingest(entities=entities)
            if response.errors:
                log.warning(
                    "Diode wireless LAN ingest errors for %s: %s",
                    self.hostname,
                    response.errors,
                )
