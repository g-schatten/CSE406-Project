"""Known-answer tests for the crypto core."""

from wpacrack import crypto


def test_pmk_ieee_vector():
    # Canonical IEEE 802.11i / WPA PSK vector.
    pmk = crypto.compute_pmk("password", "IEEE")
    assert pmk.hex() == "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"


def test_pmk_salt_is_ssid():
    # Different SSID (salt) must change the PMK.
    assert crypto.compute_pmk("password", "IEEE") != crypto.compute_pmk("password", "ieee")


def test_prf512_length():
    out = crypto.prf_512(b"\x00" * 32, b"Pairwise key expansion", b"\x00" * 76)
    assert len(out) == 64


def test_ptk_nonce_and_mac_order_symmetry():
    pmk = crypto.compute_pmk("password123", "demoAP")
    aa = b"\x02\x00\x00\x00\x00\x01"
    spa = b"\x02\x00\x00\x00\x00\x02"
    an = bytes(range(32))
    sn = bytes(range(32, 64))
    # min/max ordering => swapping roles yields the same PTK.
    assert crypto.derive_ptk(pmk, aa, spa, an, sn) == crypto.derive_ptk(pmk, spa, aa, sn, an)


def test_pmkid_keyed_by_pmk():
    pmk = crypto.compute_pmk("password123", "demoAP")
    aa = b"\x02\x00\x00\x00\x00\x01"
    spa = b"\x02\x00\x00\x00\x00\x02"
    pmkid = crypto.compute_pmkid(pmk, aa, spa)
    assert len(pmkid) == 16
    assert crypto.verify_pmkid(pmk, aa, spa, pmkid)
    assert not crypto.verify_pmkid(pmk, spa, aa, pmkid)  # order matters


def test_kdv3_out_of_scope():
    # KDV 3 (AES-CMAC) must fail loudly, not silently mis-verify.
    frame = bytearray(120)
    frame[5:7] = (3).to_bytes(2, "big")  # key info low bits = 3
    try:
        crypto.compute_mic(b"\x00" * 16, bytes(frame))
    except crypto.UnsupportedKDV:
        return
    raise AssertionError("KDV3 should raise UnsupportedKDV")
