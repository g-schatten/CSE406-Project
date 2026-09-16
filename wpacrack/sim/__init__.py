"""Synthetic WPA2 handshake / pcap generator.

Reuses wpacrack.crypto to compute a CORRECT MIC/PMKID for a chosen passphrase,
then serializes a complete, parseable capture. Deterministic, offline, and the
safest model of a "vulnerable network": the target is fabricated in software.

Emits classic pcap (linktype 105, raw 802.11). Supports:
  - KDV 2 (WPA2/HMAC-SHA1) handshakes
  - QoS and non-QoS data frames
  - full 4-way, PMKID-only (M1), and MIC-pair-only variants
  - WPA2-PSK and WPA3-SAE beacons (for the defense analyzer)
  - an optional appended 802.11 FCS (to prove frame-extent handling)

A round-trip assertion (see build_capture) guarantees every emitted EAPOL frame
re-parses to its intended message number.
"""

from __future__ import annotations

import struct
from typing import List, Optional

from .. import crypto

LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

RSN_SUITE_CCMP = b"\x00\x0f\xac\x04"
RSN_AKM_PSK = b"\x00\x0f\xac\x02"
RSN_AKM_SAE = b"\x00\x0f\xac\x08"

# Key Information base (KDV in low bits); pairwise key type bit = 0x0008
KI_PAIRWISE = 0x0008
KI_INSTALL = 0x0040
KI_ACK = 0x0080
KI_MIC = 0x0100
KI_SECURE = 0x0200


def _pcap_global_header(linktype: int = 105) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def _pcap_record(data: bytes, ts_sec: int = 0, ts_usec: int = 0) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _dot11_data(fc1_flags: int, addr1: bytes, addr2: bytes, addr3: bytes,
                qos: bool, seq: int) -> bytes:
    subtype = 0x08 if qos else 0x00
    fc0 = (subtype << 4) | (2 << 2)  # type=2 data
    hdr = bytes([fc0, fc1_flags]) + b"\x00\x00" + addr1 + addr2 + addr3
    hdr += struct.pack("<H", (seq << 4) & 0xFFFF)
    if qos:
        hdr += b"\x00\x00"
    return hdr


def _rsn_ie(akm_suites: List[bytes]) -> bytes:
    body = struct.pack("<H", 1)          # version
    body += RSN_SUITE_CCMP               # group cipher
    body += struct.pack("<H", 1) + RSN_SUITE_CCMP  # pairwise
    body += struct.pack("<H", len(akm_suites)) + b"".join(akm_suites)
    body += struct.pack("<H", 0x0000)    # RSN capabilities
    return bytes([48, len(body)]) + body


def build_beacon(bssid: bytes, ssid: str, akm: str = "psk") -> bytes:
    fc0 = (8 << 4) | (0 << 2)  # mgmt, beacon
    hdr = bytes([fc0, 0x00]) + b"\x00\x00" + b"\xff\xff\xff\xff\xff\xff" + bssid + bssid
    hdr += struct.pack("<H", 0)  # seq
    fixed = b"\x00" * 8 + struct.pack("<H", 100) + struct.pack("<H", 0x0431)
    ssid_ie = bytes([0, len(ssid)]) + ssid.encode()
    if akm == "sae":
        rsn = _rsn_ie([RSN_AKM_SAE])
    elif akm == "psk+sae":
        rsn = _rsn_ie([RSN_AKM_PSK, RSN_AKM_SAE])
    else:
        rsn = _rsn_ie([RSN_AKM_PSK])
    return hdr + fixed + ssid_ie + rsn


def _eapol_key(key_info: int, replay: int, nonce: bytes, mic: bytes,
               key_data: bytes, version: int = 1) -> bytes:
    kd_len = len(key_data)
    frame = bytes([version, 3]) + struct.pack(">H", 95 + kd_len)
    frame += bytes([2])                         # descriptor type = RSN
    frame += struct.pack(">H", key_info)
    frame += struct.pack(">H", 16)              # key length
    frame += struct.pack(">Q", replay)          # replay counter
    frame += nonce                              # 32
    frame += b"\x00" * 16                        # key iv
    frame += b"\x00" * 8                         # key rsc
    frame += b"\x00" * 8                         # key id
    frame += mic                                # 16
    frame += struct.pack(">H", kd_len) + key_data
    assert len(frame) == 99 + kd_len
    return frame


def _pmkid_kde(pmkid: bytes) -> bytes:
    val = b"\x00\x0f\xac\x04" + pmkid
    return bytes([0xDD, len(val)]) + val


def build_capture(
    path: str,
    ssid: str,
    passphrase: str,
    ap: bytes = b"\x02\x00\x00\x00\x00\x01",
    sta: bytes = b"\x02\x00\x00\x00\x00\x02",
    *,
    kdv: int = 2,
    qos: bool = False,
    include_beacon: bool = True,
    include_pmkid: bool = True,
    messages=(1, 2, 3, 4),
    append_fcs: bool = False,
    akm: str = "psk",
) -> None:
    """Generate a synthetic capture with a correct MIC/PMKID for `passphrase`."""
    anonce = bytes((i * 7 + 1) & 0xFF for i in range(32))
    snonce = bytes((i * 5 + 3) & 0xFF for i in range(32))
    pmk = crypto.compute_pmk(passphrase, ssid)
    ptk = crypto.derive_ptk(pmk, ap, sta, anonce, snonce)
    kck = crypto.kck_from_ptk(ptk)
    pmkid = crypto.compute_pmkid(pmk, ap, sta)

    version = 1  # EAPOL protocol version byte (independent of KDV)
    frames: List[bytes] = []

    def add(fc1_flags, from_ap, eapol):
        addr1 = sta if from_ap else ap
        addr2 = ap if from_ap else sta
        body = LLC_SNAP_EAPOL + eapol
        f = _dot11_data(fc1_flags, addr1, addr2, ap, qos, seq=len(frames))
        f += body
        if append_fcs:
            f += b"\xde\xad\xbe\xef"  # bogus trailing FCS the parser must ignore
        frames.append(f)

    ki_base = kdv | KI_PAIRWISE

    if 1 in messages:
        kd = _pmkid_kde(pmkid) if include_pmkid else b""
        m1 = _eapol_key(ki_base | KI_ACK, 1, anonce, b"\x00" * 16, kd, version)
        add(0x02, True, m1)  # FromDS
    if 2 in messages:
        m2 = _eapol_key(ki_base | KI_MIC, 1, snonce, b"\x00" * 16, b"", version)
        mic = crypto.compute_mic(kck, m2)
        m2 = _eapol_key(ki_base | KI_MIC, 1, snonce, mic, b"", version)
        add(0x01, False, m2)  # ToDS
    if 3 in messages:
        m3 = _eapol_key(ki_base | KI_MIC | KI_ACK | KI_INSTALL | KI_SECURE,
                        2, anonce, b"\x00" * 16, b"", version)
        mic = crypto.compute_mic(kck, m3)
        m3 = _eapol_key(ki_base | KI_MIC | KI_ACK | KI_INSTALL | KI_SECURE,
                        2, anonce, mic, b"", version)
        add(0x02, True, m3)  # FromDS
    if 4 in messages:
        m4 = _eapol_key(ki_base | KI_MIC | KI_SECURE, 2, b"\x00" * 32,
                        b"\x00" * 16, b"", version)
        mic = crypto.compute_mic(kck, m4)
        m4 = _eapol_key(ki_base | KI_MIC | KI_SECURE, 2, b"\x00" * 32, mic, b"", version)
        add(0x01, False, m4)  # ToDS

    out = _pcap_global_header(105)
    if include_beacon:
        out += _pcap_record(build_beacon(ap, ssid, akm))
    for f in frames:
        out += _pcap_record(f)
    with open(path, "wb") as fh:
        fh.write(out)

    _roundtrip_assert(path, messages, include_pmkid)


def build_sae_beacon_capture(path: str, ssid: str,
                             ap: bytes = b"\x02\x00\x00\x00\x00\x09") -> None:
    """A WPA3-SAE-only capture: beacon with SAE AKM, no crackable EAPOL PMK target."""
    out = _pcap_global_header(105)
    out += _pcap_record(build_beacon(ap, ssid, akm="sae"))
    with open(path, "wb") as fh:
        fh.write(out)


def _roundtrip_assert(path: str, messages, include_pmkid: bool) -> None:
    from ..parse import parse_capture
    recs = parse_capture(path)
    assert recs, f"generator produced an unparseable capture: {path}"
    rec = next(iter(recs.values()))
    got = sorted(m.msg_num for m in rec.messages)
    want = sorted(messages)
    assert got == want, f"round-trip message mismatch: emitted {want}, parsed {got}"
    if include_pmkid and 1 in messages:
        assert rec.has_pmkid(), "PMKID KDE emitted but not parsed back"


def write_default_fixtures(out_dir: str) -> str:
    import os

    os.makedirs(out_dir, exist_ok=True)

    def p(name):
        return os.path.join(out_dir, name)

    build_capture(p("hs_ok.pcap"), "demoAP", "password123", qos=False)
    build_capture(p("hs_ok_qos.pcap"), "demoAP", "password123", qos=True)
    build_capture(p("hs_ok_fcs.pcap"), "demoAP", "password123", append_fcs=True)
    build_capture(p("pmkid_ok.pcap"), "demoAP", "password123", messages=(1,), include_pmkid=True)
    build_capture(p("hs_short.pcap"), "demoAP", "001234", messages=(1, 2))
    build_capture(p("hs_nosalt.pcap"), "hiddenAP", "password123", include_beacon=False)
    build_sae_beacon_capture(p("wpa3_sae.pcap"), "secureAP")
    return out_dir
