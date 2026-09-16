"""Fixture generation + parse + attack integration tests."""

import os
import tempfile

import pytest

from wpacrack import sim, parse, crypto
from wpacrack import attack_mic, attack_pmkid, attack_mask
from wpacrack.candidates import iter_mask
from wpacrack.result import FOUND, EXHAUSTED, NA


@pytest.fixture(scope="module")
def fx(tmp_path_factory):
    d = tmp_path_factory.mktemp("fixtures")
    sim.write_default_fixtures(str(d))
    return str(d)


def _wl(tmp, words):
    p = os.path.join(tmp, "wl.txt")
    with open(p, "w") as fh:
        fh.write("\n".join(words) + "\n")
    return p


def test_generator_roundtrips_all_variants(fx):
    for name, msgs in [("hs_ok.pcap", [1, 2, 3, 4]), ("hs_ok_qos.pcap", [1, 2, 3, 4]),
                       ("hs_ok_fcs.pcap", [1, 2, 3, 4]), ("hs_short.pcap", [1, 2]),
                       ("pmkid_ok.pcap", [1])]:
        rec = next(iter(parse.parse_capture(os.path.join(fx, name)).values()))
        assert sorted(m.msg_num for m in rec.messages) == msgs


def test_fcs_frame_extent_handled(fx):
    # Trailing FCS must not break MIC verification.
    rec = next(iter(parse.parse_capture(os.path.join(fx, "hs_ok_fcs.pcap")).values()))
    pmk = crypto.compute_pmk("password123", rec.ssid)
    ptk = crypto.derive_ptk(pmk, rec.aa, rec.spa, rec.anonce, rec.snonce)
    assert crypto.verify_mic(crypto.kck_from_ptk(ptk), rec.mic_msg.eapol_frame, rec.mic_msg.mic)


def test_attack_mic_found(fx, tmp_path):
    wl = _wl(str(tmp_path), ["nope", "password123", "other"])
    v = attack_mic.run(os.path.join(fx, "hs_ok.pcap"), _lines(wl), ssid="demoAP")
    assert v.status == FOUND and v.passphrase == "password123"


def test_attack_mic_qos(fx, tmp_path):
    wl = _wl(str(tmp_path), ["password123"])
    v = attack_mic.run(os.path.join(fx, "hs_ok_qos.pcap"), _lines(wl), ssid="demoAP")
    assert v.status == FOUND


def test_attack_pmkid_found(fx, tmp_path):
    wl = _wl(str(tmp_path), ["password123"])
    v = attack_pmkid.run(os.path.join(fx, "pmkid_ok.pcap"), _lines(wl), ssid="demoAP")
    assert v.status == FOUND and v.passphrase == "password123"


def test_negative_control_no_false_positive(fx, tmp_path):
    wl = _wl(str(tmp_path), ["aaa", "bbb", "ccc"])
    v = attack_mic.run(os.path.join(fx, "hs_ok.pcap"), _lines(wl), ssid="demoAP")
    assert v.status == EXHAUSTED and v.passphrase is None


def test_mask_found(fx):
    v = attack_mask.run(os.path.join(fx, "hs_short.pcap"), "?d?d?d?d?d?d",
                        ssid="demoAP", timebox=60)
    assert v.status == FOUND and v.passphrase == "001234"


def test_missing_ssid_reports_error(fx, tmp_path):
    wl = _wl(str(tmp_path), ["password123"])
    v = attack_mic.run(os.path.join(fx, "hs_nosalt.pcap"), _lines(wl), ssid=None)
    assert v.status in ("ERROR",)


def test_sae_has_no_offline_target(fx):
    v = attack_pmkid.run(os.path.join(fx, "wpa3_sae.pcap"), iter([]), ssid="secureAP")
    assert v.status == NA


def _lines(path):
    with open(path) as fh:
        return [l.strip() for l in fh if l.strip()]
