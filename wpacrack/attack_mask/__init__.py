"""Attack 3 — mask / limited brute force.

Same verifiers as Attack 1/2, but candidates come from a hashcat-style mask
(e.g. ?d?d?d?d?d?d) instead of a wordlist, with a wall-clock time-box. Prefers
the MIC verifier; falls back to PMKID when no handshake pair is present.
"""

from __future__ import annotations

from typing import Optional

from ..candidates import iter_mask, mask_keyspace
from ..parse import parse_capture
from ..result import Verdict, NA
from ..select import select_record
from .. import attack_mic, attack_pmkid

ATTACK = "MASK"


def run(pcap_path: str, mask: str, ssid: Optional[str] = None,
        bssid: Optional[str] = None, timebox: Optional[float] = None) -> Verdict:
    records = parse_capture(pcap_path)
    if not records:
        return Verdict(ATTACK, NA, detail="no EAPOL frames in capture")

    rec = select_record(records, "mic", bssid)
    use_pmkid = rec is None or not rec.has_mic_pair()
    if use_pmkid:
        rec = select_record(records, "pmkid", bssid)
    if rec is None:
        return Verdict(ATTACK, NA, detail="no usable handshake or PMKID")

    detail = f"mask={mask}, keyspace={mask_keyspace(mask):,}"
    candidates = iter_mask(mask, timebox=timebox)
    if use_pmkid:
        v = attack_pmkid.run_on_record(rec, candidates, ssid)
    else:
        v = attack_mic.run_on_record(rec, candidates, ssid)
    v.attack = ATTACK
    v.detail = (v.detail + "; " if v.detail else "") + detail
    return v
