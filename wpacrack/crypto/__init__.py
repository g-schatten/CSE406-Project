"""WPA2 cryptographic core.

All verifiers used by the three attacks live here so there is exactly one
implementation of PMK / PTK / MIC / PMKID. Standard library only.

Key facts baked in as unit tests (see tests/):
  - PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32); SSID is the raw salt.
  - PTK = PRF-512(PMK, "Pairwise key expansion", min|max MACs || min|max nonces).
  - MIC algorithm is chosen by Key Descriptor Version (KDV), not descriptor type.
  - PMKID is keyed by the PMK directly (not the KCK).
"""

from __future__ import annotations

import hashlib
import hmac

# ---------------------------------------------------------------------------
# PMK
# ---------------------------------------------------------------------------

def compute_pmk(passphrase: str, ssid: str) -> bytes:
    """Derive the 32-byte PMK from an ASCII passphrase and SSID.

    SSID is used verbatim as the PBKDF2 salt: no length prefix, no NUL
    terminator, case-sensitive.
    """
    return hashlib.pbkdf2_hmac(
        "sha1", passphrase.encode("ascii"), ssid.encode(), 4096, dklen=32
    )


def is_probably_hex_psk(passphrase: str) -> bool:
    """A 64-hex-char string is an already-derived PSK, not a passphrase."""
    if len(passphrase) != 64:
        return False
    try:
        int(passphrase, 16)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# PRF-512 / PTK
# ---------------------------------------------------------------------------

def prf_512(key: bytes, label: bytes, data: bytes) -> bytes:
    """IEEE 802.11i PRF producing 512 bits (64 bytes) with HMAC-SHA1."""
    result = b""
    i = 0
    while len(result) < 64:
        result += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return result[:64]


def derive_ptk(pmk: bytes, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """Derive the 64-byte PTK.

    aa  = Authenticator (AP) MAC, 6 bytes
    spa = Supplicant (station) MAC, 6 bytes
    min/max are applied BYTE-WISE and INDEPENDENTLY to the MAC pair and the
    nonce pair. Getting this ordering wrong yields a wrong KCK and silent
    100% MIC failure.
    """
    label = b"Pairwise key expansion"
    data = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return prf_512(pmk, label, data)


def kck_from_ptk(ptk: bytes) -> bytes:
    """Key Confirmation Key = first 16 bytes of the PTK."""
    return ptk[0:16]


def kek_from_ptk(ptk: bytes) -> bytes:
    """Key Encryption Key = PTK[16:32]."""
    return ptk[16:32]


def tk_from_ptk(ptk: bytes) -> bytes:
    """Temporal Key = PTK[32:48]."""
    return ptk[32:48]


# ---------------------------------------------------------------------------
# MIC
# ---------------------------------------------------------------------------

MIC_OFFSET = 81  # offset of the MIC field within the EAPOL frame
MIC_LEN = 16


def eapol_key_descriptor_version(eapol_frame: bytes) -> int:
    """Return the Key Descriptor Version (low 3 bits of Key Information).

    Key Information is a big-endian 16-bit field at EAPOL bytes 5:7
    (EAPOL header is 4 bytes; descriptor type is byte 4; key info is 5:7).
    """
    return int.from_bytes(eapol_frame[5:7], "big") & 0x07


def compute_mic(kck: bytes, eapol_frame: bytes) -> bytes:
    """Compute the MIC over an EAPOL-Key frame with the MIC field zeroed.

    The caller must pass the EAPOL frame truncated to its declared length
    (4 + body_len), NOT sliced to end-of-packet, otherwise a trailing
    802.11 FCS corrupts the digest. The MIC field is zeroed on a copy.
    """
    ver = eapol_key_descriptor_version(eapol_frame)
    buf = bytearray(eapol_frame)
    buf[MIC_OFFSET : MIC_OFFSET + MIC_LEN] = b"\x00" * MIC_LEN
    msg = bytes(buf)
    if ver == 1:
        return hmac.new(kck, msg, hashlib.md5).digest()[:16]
    if ver == 2:
        return hmac.new(kck, msg, hashlib.sha1).digest()[:16]
    if ver == 3:
        raise UnsupportedKDV(
            "KDV 3 (AES-128-CMAC / 802.11w) is out of scope for this stdlib-only tool"
        )
    raise ValueError(f"unsupported key descriptor version {ver}")


def verify_mic(kck: bytes, eapol_frame: bytes, captured_mic: bytes) -> bool:
    """Constant-time compare of computed vs captured MIC (first 16 bytes)."""
    mic = compute_mic(kck, eapol_frame)
    return hmac.compare_digest(mic, captured_mic[:16])


# ---------------------------------------------------------------------------
# PMKID
# ---------------------------------------------------------------------------

def compute_pmkid(pmk: bytes, aa: bytes, spa: bytes) -> bytes:
    """PMKID = HMAC-SHA1(PMK, "PMK Name" || AP_MAC || STA_MAC)[:16].

    Keyed by the PMK directly (not the KCK). Fixed AP-then-STA order; no
    min/max here, unlike PTK derivation.
    """
    return hmac.new(pmk, b"PMK Name" + aa + spa, hashlib.sha1).digest()[:16]


def verify_pmkid(pmk: bytes, aa: bytes, spa: bytes, captured_pmkid: bytes) -> bool:
    return hmac.compare_digest(compute_pmkid(pmk, aa, spa), captured_pmkid[:16])


class UnsupportedKDV(Exception):
    """Raised when a Key Descriptor Version we do not implement is required."""
