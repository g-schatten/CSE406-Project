# Implementation / Simulation / Demonstration Plan

**Project 20 — Wi-Fi Password Cracking Attack** · CSE 406 · Mohammad Saifuzzaman (2105088), Sayaad Muzahid Masfi (2105066) · B1 — Group 3

This plan turns the design proposal (`main.pdf`) into a concrete build. It covers the module-by-module implementation spec, the layered simulation/test-data strategy, the live demonstration script, and the project timeline. It reflects a design pass plus an adversarial technical-correctness and requirements-coverage review — every "gotcha" below is something that silently breaks a homemade WPA2 cracker if skipped.

---

## 0. Big picture

One offline pipeline, three attacks sharing one crypto core, all fed by pcap files:

```
pcap file ──▶ pcap/ (file reader) ──▶ parse/ (802.11+EAPOL) ──▶ HandshakeRecord
                                                                      │
                              ┌───────────────────────────────────────┤
                        crypto/ (PMK, PTK/PRF-512, MIC, PMKID)  ◀──────┤
                              │                                        │
      attack_mic/ ─┐   attack_pmkid/ ─┐   attack_mask/ ─┐             │
                   └──────────────────┴─────────────────┴──▶ cli.py ──▶ FOUND / NOT_FOUND / N/A
                                                                      │
                                                          defend/ (analyze + policy + estimate)
```

Everything is file-in / verdict-out. No sockets, no injection, no live-network traffic — enforce this with a CI grep-guard that fails the build if `socket`, packet-injection, or raw-transmit imports appear anywhere in the tree. This is the strongest evidence for the proposal's "Scope & Ethics" commitment.

**Module ownership split (2 people, ~4 weeks):** Dev A owns the *capture/parse* track (`pcap/`, `parse/`, the `sim/` generator, diagrams); Dev B owns the *crypto/attack* track (`crypto/`, `attack_*`, `defend/`). Both converge on `sim/` fixtures and the final demo.

**Repository layout:**

```
wpacrack/
  pcap/          # pcap/pcapng file-format reader
  parse/         # 802.11 + radiotap deframe; EAPOL/Key-Data; RSN IE; beacon SSID
  crypto/        # PBKDF2, PRF-512, MIC (v1/v2), PMKID verifiers
  attack_mic/    # Attack 1 driver
  attack_pmkid/  # Attack 2 driver
  attack_mask/   # Attack 3 mask expander + driver
  defend/        # policy.py, analyze.py, estimate.py
  sim/           # synthetic fixture generator, plot.py
  cli.py         # unified entrypoint (mic|pmkid|mask|analyze|estimate|report)
fixtures/        # hs_ok, pmkid_ok, hs_short, wpa3_sae, negative — synthetic, checked in
wl/, masks/      # pinned wordlist slices + mask files
tests/           # unit (crypto KATs) + integration (fixture -> expected verdict)
README.md, requirements.txt (stdlib-only; matplotlib optional for charts)
```

---

## 1. Implementation plan (phased, with milestone gates)

| Phase | Days | Dev A (parse) | Dev B (crypto/attack) | Exit gate |
|---|---|---|---|---|
| **P0 Setup** | 1–2 | repo skeleton, `cli.py` stub, CI + socket-guard | collect known-answer vectors | CI runs empty tests green |
| **P1 Parse+Crypto** | 3–7 | pcap reader, radiotap strip, 802.11 deframe, EAPOL extract, RSN-IE/SSID | PBKDF2 + PRF-512 pass KATs | **M1:** parser emits `HandshakeRecord`; crypto matches known vectors |
| **P2 Attack 1+2** | 8–12 | PMKID KDE extract, MIC-field zeroing helper | MIC verifier (v1+v2), PMKID verifier, dict drivers | **M2:** Attacks 1 & 2 FOUND on synthetic + public captures; **negative-control passes** |
| **P3 Attack 3 + sim** | 13–17 | synthetic fixture generator (all variants) | mask engine, time-box, perf tuning | **M3:** Attack 3 FOUND in time-box; full pytest fixture suite green |
| **P4 Defense** | 18–21 | RSN AKM analyzer (`analyze.py`) | policy checklist + strength estimator | **M4:** WPA3/transition-mode verdicts correct |
| **P5 Demo/report** | 22–26 | integration tests, charts, README | report writing, 2 demo dry-runs | **M5:** all 5 scenarios pass end-to-end |
| Buffer | 27–28 | rehearsal/fixes | rehearsal/fixes | ship |

Make the **KDV1+KDV2 MIC KAT and the negative-control (no false positive)** hard gates in P1/P2 — these are the two properties that silently break and are painful to debug at rehearsal, not the ones that show up as an obvious crash.

### Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | MIC Key-Descriptor-Version bug (wrong algorithm chosen) | High | High | Read KDV from Key Information bits 0–2; unit-test v1/v2 against known vectors; v3 explicitly scoped (see §2) |
| R2 | SSID missing from capture (salt unknown) | Med | High | Harvest from beacon/probe in the same pcap; require `--ssid` override; fail loudly, never guess |
| R3 | Performance (PBKDF2×4096 too slow) | High | Med | `hashlib.pbkdf2_hmac` (C-backed); optional C hot-loop; time-box Attack 3; benchmark early |
| R4 | Capture quality (incomplete handshake, missing M2) | Med | High | Validate M1/M2 pairing; fall back to PMKID (needs only M1); ship synthetic fixtures so the demo never depends on a flaky live capture |
| R5 | False positive in verifier | Low | High | Negative-control scenario is a required P2 gate; full-digest constant-time compare |
| R6 | pcapng/radiotap variant unhandled | Med | Med | Support linktype 105 & 127; error clearly on unsupported linktypes |
| R7 | Scope/ethics drift | Low | High | File-input only; CI grep-guard against socket/injection imports |

---

## 2. Correctness-critical spec

Get these **exact** — each one produces a silent "correct password not found" if wrong, with no error to point you at the bug. Bake every one of these into a unit test.

### 2.1 PMK

```python
PMK = hashlib.pbkdf2_hmac("sha1", passphrase.encode("ascii"), ssid.encode(), 4096, dklen=32)
```

- **SSID is the raw PBKDF2 salt** — no length prefix, no NUL terminator, case-sensitive, used exactly as it appears in the beacon.
- Passphrase is 8–63 printable ASCII; a 64-hex-char string is an already-derived PSK (out of scope) — reject/handle explicitly.
- Never hand-roll PBKDF2 in Python — `hashlib.pbkdf2_hmac` is C-backed and ~10–100x faster; it's ~99% of total attack runtime, so this is also your one big performance lever.

### 2.2 PTK / PRF-512 — the #1 bug in every homemade cracker

```python
def prf_512(K, A, B):
    R = b""
    for i in range(4):                                   # 4x20=80 bytes, keep first 64
        R += hmac.new(K, A + b"\x00" + B + bytes([i]), hashlib.sha1).digest()
    return R[:64]

def derive_ptk(pmk, aa, spa, anonce, snonce):
    A = b"Pairwise key expansion"
    # BYTE-WISE min/max, applied INDEPENDENTLY to the two MACs and the two nonces:
    B = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return prf_512(pmk, A, B)                            # KCK=PTK[0:16] KEK=[16:32] TK=[32:48]
```

Ordering nonces by role (ANonce-then-SNonce) instead of by byte value, or swapping AP/client MAC, silently yields a wrong KCK and 100% MIC failures — with no exception raised anywhere.

### 2.3 MIC verification — dispatch on Key Descriptor Version

The captured frame's MIC is computed over the **entire 802.1X/EAPOL PDU** (version byte through end of Key Data) with the 16-byte MIC field **zeroed**, keyed by **KCK**. The algorithm is selected only by Key Descriptor Version = low 3 bits of the big-endian Key Information field — never inferred from descriptor type:

| KDV | Algorithm | Take |
|---|---|---|
| 1 | HMAC-MD5 | first 16 bytes |
| 2 | HMAC-SHA1 | first 16 bytes (truncated from 20) |
| 3 | AES-128-CMAC | first 16 bytes |

```python
MIC_OFF, MIC_LEN = 81, 16                                # within the EAPOL frame

def verify_mic(kck, eapol_frame, captured_mic):
    ver = int.from_bytes(eapol_frame[5:7], "big") & 0x07
    buf = bytearray(eapol_frame)
    buf[MIC_OFF:MIC_OFF+MIC_LEN] = b"\x00" * MIC_LEN     # zero MIC on a COPY
    msg = bytes(buf)
    if   ver == 1: mic = hmac.new(kck, msg, hashlib.md5).digest()[:16]
    elif ver == 2: mic = hmac.new(kck, msg, hashlib.sha1).digest()[:16]
    elif ver == 3: mic = aes_cmac(kck, msg)[:16]
    else: raise ValueError(f"unsupported key descriptor version {ver}")
    return hmac.compare_digest(mic, captured_mic[:16])
```

**AES-CMAC / KDV3 policy (decide this up front, do not leave it ambiguous):** `hashlib` has no AES, so v3 needs either a third-party crypto dependency (violates the "stdlib-only, no aircrack-ng/Hashcat" rule in spirit) or a self-written RFC-4493 AES-CMAC over a self-written AES-128 block. **Recommended: implement v1 + v2 with stdlib only; detect v3 and report it as cleanly out-of-scope** (both public cross-validation captures below are v1, and WPA2-PSK captures in practice are overwhelmingly v2 — v3/802.11w is a stretch goal only if time allows).

**Frame-extent gotcha (breaks MIC verification on every real capture if missed):** store the EAPOL frame truncated to its **declared length** — `4 (EAPOL header) + body_len` where `body_len` is read from the EAPOL header's own Length field (equivalently `99 + KeyDataLen` for a 16-byte MIC). **Do not slice to end-of-packet.** Monitor-mode captures commonly append a 4-byte 802.11 FCS after the frame; if those bytes land inside the HMAC input, every candidate fails even with the correct passphrase. Include a fixture with an appended FCS in the test suite to prove this is handled.

### 2.4 PMKID verification

```python
def compute_pmkid(pmk, aa, spa):
    return hmac.new(pmk, b"PMK Name" + aa + spa, hashlib.sha1).digest()[:16]
```

Keyed by **PMK**, not KCK — this is the other classic key mix-up (MIC uses KCK, PMKID uses PMK directly). `aa` = AP MAC, `spa` = station MAC, in that fixed order (no min/max here, unlike PTK).

### 2.5 Parsing gotchas (all confirmed against the byte-level spec)

- **Radiotap `it_len`** (bytes 2–3) is **always little-endian**, regardless of the pcap file's own magic-number byte order. Skip exactly `it_len` bytes to reach the 802.11 header.
- **pcap magic sets endianness only for pcap headers** — 802.1X/EAPOL multi-byte fields (Key Information, Key Data Length, EtherType) are **always big-endian**; MAC addresses and nonces are raw bytes with no endianness.
- **QoS Data frames** (subtype bit `0x08` set) insert a 2-byte QoS Control field after Sequence Control, **before** LLC/SNAP — detect from the subtype, don't assume a fixed header length. This is the single most common parser bug (silently shifts every downstream offset by 2).
- **SSID is not in EAPOL frames** but is the PBKDF2 salt — harvest it from Beacon / Probe-Response / Association-Request tag 0 in the same capture, or require `--ssid`. Reassociation-Request's fixed field before tagged params is **10 bytes** (Capability+ListenInterval+CurrentAP), not 4 like Association-Request — a common mix-up.
- **M1 carries no MIC** (MIC bit = 0); the PMKID lives in M1's Key Data as an RSN PMKID KDE: `0xDD <len> 00-0F-AC 04 <16-byte PMKID>`.
- **M3/M4 are not a MIC fallback without M2** — SNonce is only ever carried in M2. The only usable pairings for the MIC attack are M1+M2 or M2+M3. A capture with only M1/M3/M4 yields N/A for the MIC attack (though PMKID may still succeed from M1).
- **Synthetic generator Key-Information bits** (if your fixture generator gets these wrong, your entire pytest suite silently breaks): `M1 = ver|0x0088` (ACK), `M2 = ver|0x0108` (MIC), `M3 = ver|0x1348` (Install|ACK|MIC|Secure), `M4 = ver|0x0308` (MIC|Secure). Add a round-trip assertion: every frame your generator emits must re-parse to its intended message number — this is exactly the kind of bug that looks like a crypto bug but is really a fixture bug.

---

## 3. Simulation strategy (5 layers)

**Primary layer = a self-written synthetic handshake generator** (`sim/gen.py`) that reuses `crypto/` to compute a *correct* MIC/PMKID for a chosen passphrase, then serializes a complete, parseable pcap. It's deterministic, needs no radio/RF/legal footprint, runs in CI on any laptop, and reaches edge cases (every Key Descriptor Version, QoS vs non-QoS, pcap vs pcapng, missing-SSID) that one real capture can't. It also doubles as the safest possible model of "a vulnerable network" — you attack a target you fabricated entirely in software.

| Layer | What | Role |
|---|---|---|
| **1. Synthetic generator** | emits KDV1/KDV2 fixtures (KDV3 flagged), QoS/non-QoS, pcap/pcapng, PMKID-only, missing-SSID | primary sim + acceptance gate |
| **2. Public known-answer captures** | Wireshark `wpa-Induction.pcap` (SSID **`Coherer`**, passphrase **`Induction`**); aircrack-ng `wpa.cap` (SSID **`test`**, passphrase **`biscotte`** — *not* Coherer, that name belongs only to the Wireshark file); hashcat mode-22000 published example (ESSID `hashcat-essid`, passphrase `hashcat!`) | external correctness anchor |
| **3. Own-lab capture** *(optional)* | TP-Link Archer C6 on an isolated throwaway SSID + known PSK, own phone as STA, Alfa AWUS036ACH in monitor mode channel-locked, **passive capture only** | matches the proposal's topology; no third party ever appears |
| **4. WPA3-SAE capture** | same passive setup, AP in SAE-only mode | defense contrast — proves there is no offline PMK/PMKID target to attack |
| **5. pytest known-answer suite** | positive per KDV/QoS/format; PMKID positive; **negative — password absent from wordlist → NOT_FOUND (no false positive)**; feature-absent → N/A; missing-SSID → requires `--ssid` | pass/fail gate; a red suite blocks the demo |

Read each public sample's SSID from its own beacon at build time rather than hardcoding — mixing up which SSID belongs to which sample (the salt) makes a **correct** implementation look broken. Both public oracles above are WPA1/TKIP = **KDV1 (HMAC-MD5)**, so treat KDV1 as first-class for external validation and rely on the synthetic generator for the KDV2 (WPA2/AES-CCMP) end-to-end happy path.

### Known-answer test vectors to freeze into `crypto/test_kat.py`

```python
assert compute_pmk("password", "IEEE").hex() == \
    "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"[:64]
# canonical IEEE 802.11i / WPA PSK vector — if this fails, salt handling is wrong

# wpa-Induction.pcap: SSID "Coherer", passphrase "Induction"
#   compute_pmk("Induction","Coherer") -> derive_ptk(...) -> verify_mic(...) == True
#   any other passphrase (e.g. "induction", "Coherer") -> False

# aircrack-ng wpa.cap: SSID "test", passphrase "biscotte"  (confirm SSID from the file's own beacon)

# RFC 4493 AES-CMAC vector (only needed if KDV3 is implemented):
#   aes_cmac(key=2b7e151628aed2a6abf7158809cf4f3c, msg=b"") == bb1d6929e95937287fa37d129b756746
```

---

## 4. Demonstration plan

Single CLI, five offline runs against checked-in fixtures, then a `--report` command re-runs all of them and prints the aggregate table (asserting each expected verdict — the demo is also a self-test):

| # | Command | Condition | Expected result |
|---|---|---|---|
| a | `mic --pcap hs_ok.pcap --wordlist wl.txt --ssid demoAP` | full 4-way handshake, PSK in list | **FOUND** (Attack 1) — print derived vs. captured MIC |
| b | `pmkid --pcap pmkid_ok.pcap --wordlist wl.txt --ssid demoAP` | PMKID present in M1, PSK in list | **FOUND** (Attack 2) — no full handshake needed |
| c | `mask --pcap hs_short.pcap --mask '?d?d?d?d?d?d' --timebox 60` | 6-digit PIN, not in any dictionary | **FOUND within time-box** (Attack 3) |
| d | `mic --pcap hs_ok.pcap --wordlist small-negative.txt --ssid demoAP` | valid handshake, PSK **absent** from list | **EXHAUSTED / NOT_FOUND** — the no-false-positive control |
| e | `analyze --pcap wpa3_sae.pcap` | WPA3-SAE beacon/handshake | **No offline target** — defense pivot |

Report scenario (d) as **EXHAUSTED / NOT_FOUND**, distinct from **N/A** (reserved for a genuinely absent field, as in scenario e) — conflating the two undermines the point of the control, which is that the verifier searched and found no match, not that it couldn't attempt the search.

**Results table** (printed by `--report`):

| Attack | Fixture | Condition | Result | Time | Rate (cand/s) |
|---|---|---|---|---|---|
| 1 MIC | hs_ok | dict hit | FOUND | ~2s | ~1,000–2,000 |
| 2 PMKID | pmkid_ok | dict hit | FOUND | ~1s | ~1,000–2,000 |
| 3 Mask | hs_short | 6×`?d` brute | FOUND | within time-box | ~1,000–2,000 |
| 1 MIC | hs_ok | dict miss | EXHAUSTED | — | — |
| — | wpa3_sae | SAE-only | N/A (no offline target) | — | — |

*(Exact time/rate figures depend on the demo machine — benchmark early in P2/P3 and use the real numbers, not placeholders, in the report.)*

**Optional visualization** (`sim/plot.py`, matplotlib): a throughput bar chart (pure-Python vs. `hashlib.pbkdf2_hmac` vs. optional C hot-loop) and a log-scale time-to-crack-vs-keyspace line for different charsets — the same cost model that powers `defend/estimate.py`, making the attack↔defense link explicit in the report. Follow the project's `dataviz` skill/guidance before writing chart code if one is available.

### `defend/` module

- **`policy.py`** — strong-passphrase checklist (≥15 chars, mixed charset, not in a leaked wordlist) + "prefer WPA3-SAE-only, disable WPA2 transition mode" + the Dragonblood caveat (keep SAE implementations patched; avoid compatibility modes that re-enable WPA2-style offline cracking).
- **`analyze.py`** — inspects the RSN Information Element's AKM suite list in a beacon/probe/assoc frame (OUI `00-0F-AC`): type `02`/`06` = PSK → **WARN: offline dictionary/PMKID attack possible**; type `08` = SAE → **OK**; **both present** → **WARN: WPA3 transition mode — WPA2 fallback still crackable** (this exact case is easy to under-report as "safe" if you only check for SAE's presence). This module powers demo scenario (e).
- **`estimate.py`** — given a charset/length, computes keyspace and expected/worst-case crack time under Attack 3 at the rate measured in your own benchmark; flags anything crackable in under a year as WEAK.

---

## 5. Requirement coverage matrix

| Proposal requirement | Implemented by | Simulated by | Demonstrated by |
|---|---|---|---|
| Parse 802.11 pcap → EAPOL | `pcap/`, `parse/` | fixture generator | prints handshake found |
| Attack 1: 4-way MIC dictionary | `attack_mic/`, `crypto/` | `hs_ok` fixture | scenario (a) FOUND |
| Attack 2: PMKID dictionary | `attack_pmkid/` | `pmkid_ok` fixture | scenario (b) FOUND |
| Attack 3: mask/limited brute | `attack_mask/` | `hs_short` fixture | scenario (c) time-boxed FOUND |
| No false positives | shared verifier compare | negative wordlist | scenario (d) EXHAUSTED |
| Shared single codebase | `crypto/` reused by all 3 attacks | — | one CLI, all attacks |
| stdlib-only, no aircrack-ng/Hashcat | `requirements.txt` = hashlib/hmac only | — | source review |
| Network Topology / Components / Timing (report §2) | — | — | reuse the diagrams already built in `main.tex` |
| Packet & Frame Structure (report §3) | — | — | reuse `main.tex` byte-layout tables/figures |
| Defense: strong PSK + WPA3-SAE-only | `defend/policy.py` | — | shown in report/demo |
| Defense: pcap AKM analyzer | `defend/analyze.py` | wpa2 + wpa3 fixtures | scenario (e) verdict |
| Defense: strength estimator | `defend/estimate.py` | uses measured rate | printed + optional chart |
| Reproducibility | fixtures + generator checked in, pinned wordlists/masks, public vector cross-check | deterministic | re-run `cli.py report` |

---

## 6. Open decisions to close before P2

1. **KDV3/AES-CMAC:** implement (self-written RFC-4493, no third-party crypto dependency) or declare cleanly out-of-scope? *(Recommendation above: out-of-scope, detected and reported cleanly.)*
2. **pcapng support:** required for at least one demo fixture, or classic-pcap-only acceptable?
3. **Own-lab capture (Layer 3):** confirm with course staff whether checked-in synthetic fixtures alone satisfy the "own lab capture" deliverable, to avoid last-minute scope ambiguity.
4. **Demo machine:** pin down cores / whether a C hot-loop is used — this sets the Attack 3 time-box and the rate baked into the strength estimator and charts.
