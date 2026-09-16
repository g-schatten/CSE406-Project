"""RSN AKM analyzer: is a captured network offline-crackable?"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..parse import akm_map

# RSN AKM suite type bytes (OUI 00-0F-AC)
AKM_PSK = {0x02, 0x06}      # PSK / PSK-SHA256
AKM_SAE = {0x08, 0x09}      # SAE / FT-SAE


@dataclass
class AkmVerdict:
    bssid: str
    akms: List[int]
    verdict: str   # WARN-PSK / WARN-TRANSITION / OK-SAE / UNKNOWN
    message: str


def analyze(pcap_path: str) -> List[AkmVerdict]:
    out: List[AkmVerdict] = []
    for bssid, akms in akm_map(pcap_path).items():
        s = set(akms)
        has_psk = bool(s & AKM_PSK)
        has_sae = bool(s & AKM_SAE)
        if has_psk and has_sae:
            v, m = "WARN-TRANSITION", "WPA3 transition mode: WPA2-PSK fallback is still crackable offline"
        elif has_psk:
            v, m = "WARN-PSK", "WPA2-PSK: offline dictionary / PMKID attack possible"
        elif has_sae:
            v, m = "OK-SAE", "WPA3-SAE only: no offline PMK/PMKID target"
        else:
            v, m = "UNKNOWN", "no recognized AKM suite"
        out.append(AkmVerdict(bssid.hex(":"), sorted(s), v, m))
    return out
