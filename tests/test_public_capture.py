"""External-oracle test: the real wpa-Induction.pcap.

Skipped automatically if the public capture has not been downloaded.
"""

import os

import pytest

from wpacrack import parse, crypto

CAP = os.path.join(os.path.dirname(__file__), "..", "fixtures", "public", "wpa-Induction.pcap")


@pytest.mark.skipif(not os.path.exists(CAP), reason="public capture not present")
def test_induction_mic_matches_known_passphrase():
    rec = next(iter(parse.parse_capture(CAP).values()))
    assert rec.ssid == "Coherer"
    assert rec.has_mic_pair()
    pmk = crypto.compute_pmk("Induction", rec.ssid)
    ptk = crypto.derive_ptk(pmk, rec.aa, rec.spa, rec.anonce, rec.snonce)
    kck = crypto.kck_from_ptk(ptk)
    assert crypto.verify_mic(kck, rec.mic_msg.eapol_frame, rec.mic_msg.mic)
    # wrong passphrases must fail
    for wrong in ("induction", "Coherer", "password"):
        pmk_w = crypto.compute_pmk(wrong, rec.ssid)
        ptk_w = crypto.derive_ptk(pmk_w, rec.aa, rec.spa, rec.anonce, rec.snonce)
        assert not crypto.verify_mic(crypto.kck_from_ptk(ptk_w), rec.mic_msg.eapol_frame, rec.mic_msg.mic)
