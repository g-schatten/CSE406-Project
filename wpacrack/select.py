"""Shared record selection used by the attack drivers."""

from __future__ import annotations

from typing import Dict, Optional

from .parse import HandshakeRecord


def select_record(
    records: Dict[bytes, HandshakeRecord],
    need: str,
    bssid: Optional[str] = None,
) -> Optional[HandshakeRecord]:
    """Pick a record. `need` is 'mic' or 'pmkid'. `bssid` filters by AP MAC hex."""
    def matches_bssid(rec: HandshakeRecord) -> bool:
        if bssid is None:
            return True
        want = bssid.lower().replace(":", "")
        return rec.bssid.hex() == want

    for rec in records.values():
        if not matches_bssid(rec):
            continue
        if need == "mic" and rec.has_mic_pair():
            return rec
        if need == "pmkid" and rec.has_pmkid():
            return rec
    # fall back to any bssid-matching record so callers can report N/A meaningfully
    for rec in records.values():
        if matches_bssid(rec):
            return rec
    return None
