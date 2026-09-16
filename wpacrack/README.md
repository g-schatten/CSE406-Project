# wpacrack — homemade WPA2-PSK offline cracker

CSE 406 Project 20. One offline pipeline, three attacks sharing one crypto core,
all fed by pcap files. **File-in / verdict-out — no sockets, no injection, no
live traffic.** Standard library only.

```
pcap -> pcap/ (reader) -> parse/ (802.11+EAPOL) -> HandshakeRecord
                                                        |
             crypto/ (PMK, PTK/PRF-512, MIC, PMKID) <---+
                                                        |
   attack_mic/   attack_pmkid/   attack_mask/  ---> cli.py -> FOUND / EXHAUSTED / N/A
                                                        |
                                            defend/ (analyze + policy + estimate)
```

## Quick start

```bash
# 1. Generate the synthetic fixtures (committed copies also exist in fixtures/)
python3 -m wpacrack.sim

# 2. Run the three attacks + defense as a single self-testing report
python3 -m wpacrack report --fixtures fixtures

# 3. Or run them individually
python3 -m wpacrack mic   --pcap fixtures/hs_ok.pcap    --wordlist wl/demo.txt --ssid demoAP
python3 -m wpacrack pmkid --pcap fixtures/pmkid_ok.pcap --wordlist wl/demo.txt --ssid demoAP
python3 -m wpacrack mask  --pcap fixtures/hs_short.pcap --mask '?d?d?d?d?d?d' --timebox 60 --ssid demoAP
python3 -m wpacrack analyze --pcap fixtures/wpa3_sae.pcap
```

## The three attacks

| # | Command | Verifier | Needs |
|---|---------|----------|-------|
| 1 | `mic` | recompute EAPOL MIC from candidate PTK | M1+M2 (or M2+M3) handshake |
| 2 | `pmkid` | recompute PMKID = HMAC-SHA1(PMK,"PMK Name"‖AA‖SPA) | just M1 with a PMKID KDE |
| 3 | `mask` | same verifiers, candidates from a `?d?l?u?s?a` mask + time-box | either of the above |

`FOUND` = a candidate verified; `EXHAUSTED` = searched, no match (the
no-false-positive control); `N/A` = the required field/handshake is absent.

## Defense (`defend/`)

- `analyze` — reads the RSN AKM suite; flags WPA2-PSK and WPA3 transition mode as
  offline-crackable, WPA3-SAE-only as no offline target.
- `policy` — strong-passphrase checklist.
- `estimate` — crack-time vs keyspace at a measured rate.

## Validation

- `crypto/` matches the canonical IEEE 802.11i PSK vector.
- The full PTK->MIC path is cross-checked against the real public
  `wpa-Induction.pcap` (SSID `Coherer`, passphrase `Induction`).
- `python3 -m pytest -q` runs 16 tests (KATs, round-trip fixtures, QoS, appended
  FCS, negative control, real capture).

## Ethics

`tools/ethics_guard.py` fails the build if any socket / injection / raw-transmit
capability appears in `wpacrack/`. Only attack captures you own or public sample
captures. Never target networks you have no right to analyze.

Fetch the (uncommitted) public oracle captures with `tools/fetch_samples.sh`.
