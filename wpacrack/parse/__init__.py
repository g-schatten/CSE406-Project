"""802.11 + EAPOL parsing into a HandshakeRecord.

Handles radiotap/prism/none radio headers, QoS vs non-QoS data frames, EAPOL-Key
field extraction, beacon/probe SSID harvesting, and RSN IE AKM inspection.

All multi-byte EAPOL fields are big-endian; MAC addresses and nonces are raw
bytes; radiotap it_len is always little-endian.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..pcap import read_packets

EAPOL_ETHERTYPE = 0x888E

# Key Information bit masks
KI_INSTALL = 0x0040
KI_ACK = 0x0080
KI_MIC = 0x0100
KI_SECURE = 0x0200

RSN_AKM_OUI = b"\x00\x0f\xac"


@dataclass
class EapolMessage:
    msg_num: int              # 1..4 (0 = unknown)
    key_info: int
    aa: bytes                 # AP MAC
    spa: bytes                # station MAC
    nonce: bytes             # ANonce (M1/M3) or SNonce (M2)
    mic: bytes
    eapol_frame: bytes        # truncated to declared length, MIC intact
    pmkid: Optional[bytes]
    kdv: int


@dataclass
class HandshakeRecord:
    bssid: bytes
    ssid: Optional[str] = None
    aa: Optional[bytes] = None
    spa: Optional[bytes] = None
    anonce: Optional[bytes] = None
    snonce: Optional[bytes] = None
    mic_msg: Optional[EapolMessage] = None   # the message whose MIC we verify (M2 preferred)
    pmkid: Optional[bytes] = None
    pmkid_aa: Optional[bytes] = None
    pmkid_spa: Optional[bytes] = None
    messages: List[EapolMessage] = field(default_factory=list)

    def has_mic_pair(self) -> bool:
        return (
            self.aa is not None
            and self.spa is not None
            and self.anonce is not None
            and self.snonce is not None
            and self.mic_msg is not None
        )

    def has_pmkid(self) -> bool:
        return self.pmkid is not None and self.pmkid_aa is not None and self.pmkid_spa is not None


def _strip_radio(linktype: int, data: bytes) -> Optional[bytes]:
    """Return the 802.11 MAC frame with any radio header removed."""
    if linktype == 105:  # IEEE 802.11, no radio header
        return data
    if linktype == 127:  # radiotap
        if len(data) < 4:
            return None
        it_len = struct.unpack("<H", data[2:4])[0]  # always little-endian
        return data[it_len:]
    if linktype == 119:  # Prism AVS/monitor: msgcode(4) msglen(4) ...
        if len(data) < 8:
            return None
        msglen = struct.unpack("<I", data[4:8])[0]
        if msglen == 0 or msglen > len(data):
            msglen = 144  # common fixed prism header size fallback
        return data[msglen:]
    return None


def _mac(b: bytes) -> bytes:
    return bytes(b)


def _parse_dot11(frame: bytes):
    """Return (type, subtype, tods, fromds, addr1, addr2, addr3, body_offset) or None."""
    if len(frame) < 24:
        return None
    fc = frame[0]
    flags = frame[1]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    tods = flags & 0x01
    fromds = (flags & 0x02) >> 1
    addr1 = frame[4:10]
    addr2 = frame[10:16]
    addr3 = frame[16:22]
    offset = 24
    if tods and fromds:  # 4-address WDS frame
        offset += 6
    if ftype == 2 and (subtype & 0x08):  # QoS data: 2-byte QoS Control field
        offset += 2
    return ftype, subtype, tods, fromds, addr1, addr2, addr3, offset


def _ap_sta(tods: int, fromds: int, addr1: bytes, addr2: bytes, addr3: bytes):
    """Return (ap_mac, sta_mac) using the DS bits."""
    if fromds and not tods:      # AP -> STA
        return addr2, addr1
    if tods and not fromds:      # STA -> AP
        return addr1, addr2
    # IBSS / WDS: best-effort, addr3 is BSSID
    return addr3, addr2


def _classify_message(key_info: int, has_nonce_nonzero: bool) -> int:
    ack = bool(key_info & KI_ACK)
    mic = bool(key_info & KI_MIC)
    install = bool(key_info & KI_INSTALL)
    secure = bool(key_info & KI_SECURE)
    if ack and not mic and not install and not secure:
        return 1
    if not ack and mic and not install and not secure:
        return 2
    if ack and mic and install and secure:
        return 3
    if not ack and mic and not install and secure:
        return 4
    return 0


def _extract_pmkid(key_data: bytes) -> Optional[bytes]:
    """Find an RSN PMKID KDE: 0xDD <len> 00-0F-AC 04 <16-byte PMKID>."""
    i = 0
    n = len(key_data)
    while i + 2 <= n:
        tag = key_data[i]
        length = key_data[i + 1]
        val = key_data[i + 2 : i + 2 + length]
        if tag == 0xDD and len(val) >= 20 and val[0:3] == RSN_AKM_OUI and val[3] == 0x04:
            return val[4:20]
        i += 2 + length
    return None


def _parse_eapol(body: bytes, ap: bytes, sta: bytes) -> Optional[EapolMessage]:
    # body starts at LLC/SNAP
    if len(body) < 8:
        return None
    if body[6:8] != struct.pack(">H", EAPOL_ETHERTYPE):
        return None
    eapol = body[8:]
    if len(eapol) < 99:
        return None
    if eapol[1] != 3:  # EAPOL type 3 = EAPOL-Key
        return None
    body_len = struct.unpack(">H", eapol[2:4])[0]
    declared = 4 + body_len
    if declared > len(eapol):
        declared = len(eapol)
    frame = eapol[:declared]  # truncate to declared length (drop any trailing FCS)
    key_info = struct.unpack(">H", frame[5:7])[0]
    kdv = key_info & 0x07
    nonce = frame[17:49]
    mic = frame[81:97]
    kd_len = struct.unpack(">H", frame[97:99])[0]
    key_data = frame[99:99 + kd_len]
    pmkid = _extract_pmkid(key_data)
    msg = _classify_message(key_info, any(nonce))
    return EapolMessage(
        msg_num=msg,
        key_info=key_info,
        aa=ap,
        spa=sta,
        nonce=nonce,
        mic=mic,
        eapol_frame=frame,
        pmkid=pmkid,
        kdv=kdv,
    )


def _parse_ssid_and_rsn(frame: bytes, subtype: int, body_offset: int):
    """From beacon/probe-resp/assoc frames, return (ssid, akm_types)."""
    ssid = None
    akms: List[int] = []
    # Fixed parameters before tagged params:
    #   Beacon (8) / Probe-Resp (8): timestamp+interval+capability
    #   Assoc-Req (0): cap+listen (4); Reassoc-Req: cap+listen+currentAP (10)
    if subtype in (8, 5):      # beacon, probe response
        fixed = 12
    elif subtype == 0:          # association request
        fixed = 4
    elif subtype == 2:          # reassociation request
        fixed = 10
    elif subtype == 4:          # probe request (no fixed params)
        fixed = 0
    else:
        return ssid, akms
    i = body_offset + fixed
    n = len(frame)
    while i + 2 <= n:
        tag = frame[i]
        length = frame[i + 1]
        val = frame[i + 2 : i + 2 + length]
        if tag == 0:  # SSID
            try:
                ssid = val.decode("utf-8")
            except UnicodeDecodeError:
                ssid = val.decode("latin-1")
        elif tag == 48:  # RSN IE
            akms += _parse_rsn_akms(val)
        i += 2 + length
    return ssid, akms


def _parse_rsn_akms(rsn: bytes) -> List[int]:
    """Return the list of AKM suite type bytes from an RSN IE body."""
    try:
        off = 2  # version
        # Group cipher suite (4)
        off += 4
        pair_count = struct.unpack("<H", rsn[off:off + 2])[0]
        off += 2 + 4 * pair_count
        akm_count = struct.unpack("<H", rsn[off:off + 2])[0]
        off += 2
        akms = []
        for _ in range(akm_count):
            suite = rsn[off:off + 4]
            off += 4
            if suite[0:3] == RSN_AKM_OUI:
                akms.append(suite[3])
        return akms
    except (struct.error, IndexError):
        return []


def parse_capture(path: str) -> Dict[bytes, HandshakeRecord]:
    """Parse a capture file into per-BSSID HandshakeRecords."""
    packets = read_packets(path)
    records: Dict[bytes, HandshakeRecord] = {}
    ssid_by_bssid: Dict[bytes, str] = {}
    akm_by_bssid: Dict[bytes, List[int]] = {}

    for pkt in packets:
        frame = _strip_radio(pkt.linktype, pkt.data)
        if not frame:
            continue
        parsed = _parse_dot11(frame)
        if not parsed:
            continue
        ftype, subtype, tods, fromds, a1, a2, a3, body_off = parsed

        if ftype == 0 and subtype in (8, 5, 0, 2):  # management with SSID/RSN
            bssid = a3
            ssid, akms = _parse_ssid_and_rsn(frame, subtype, body_off)
            if ssid:
                ssid_by_bssid[bssid] = ssid
            if akms:
                akm_by_bssid[bssid] = akms
            continue

        if ftype == 2:  # data
            body = frame[body_off:]
            ap, sta = _ap_sta(tods, fromds, a1, a2, a3)
            msg = _parse_eapol(body, ap, sta)
            if not msg:
                continue
            bssid = ap
            rec = records.setdefault(bssid, HandshakeRecord(bssid=bssid))
            rec.messages.append(msg)
            rec.aa = ap
            rec.spa = sta
            if msg.msg_num in (1, 3):
                rec.anonce = msg.nonce
            elif msg.msg_num in (2, 4) and msg.msg_num == 2:
                rec.snonce = msg.nonce
            if msg.msg_num == 2 and rec.mic_msg is None:
                rec.mic_msg = msg
            elif msg.msg_num in (3, 4) and rec.mic_msg is None:
                rec.mic_msg = msg
            if msg.pmkid:
                rec.pmkid = msg.pmkid
                rec.pmkid_aa = msg.aa
                rec.pmkid_spa = msg.spa

    for bssid, rec in records.items():
        if bssid in ssid_by_bssid:
            rec.ssid = ssid_by_bssid[bssid]
    return records


def akm_map(path: str) -> Dict[bytes, List[int]]:
    """Return AKM suite types per BSSID (for defend/analyze)."""
    packets = read_packets(path)
    out: Dict[bytes, List[int]] = {}
    ssid: Dict[bytes, str] = {}
    for pkt in packets:
        frame = _strip_radio(pkt.linktype, pkt.data)
        if not frame:
            continue
        parsed = _parse_dot11(frame)
        if not parsed:
            continue
        ftype, subtype, tods, fromds, a1, a2, a3, body_off = parsed
        if ftype == 0 and subtype in (8, 5, 0, 2):
            s, akms = _parse_ssid_and_rsn(frame, subtype, body_off)
            if akms:
                out[a3] = akms
    return out
