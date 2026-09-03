---
name: cse406-wifi-password-cracking
description: CSE 406 Project 20 (Wi-Fi password cracking) project briefing. Read this before any work in this repo. Use when implementing the lab tool, writing design/final reports, citing literature, or updating project status.
---

# CSE 406 Project 20 — Wi-Fi password cracking

This file is the agent briefing for the whole repository. Read it first. Keep it current.

## Identity

| Field | Value |
| --- | --- |
| Course | CSE 406 Computer Security (BUET), Project 2026 |
| Assignment | `CSE406ProjectJan2026.pdf` |
| Project number | **20 — Wi-Fi password cracking attack** |
| Languages | Own C / C++ / Python. Craft own 802.11 frames / packets. |
| Marks | Design report 20% · Implementation + demo 60% · Final report 20% · Defense bonus +10% |

## Current status (update this section)

- [x] Assignment PDF read; project 20 confirmed.
- [x] Literature under `others/` (gitignored).
- [x] Supervisor feedback received (see **Locked plan** below).
- [ ] Plan confirmed with student (then rewrite proposal PDF).
- [ ] Collect suitable public sample pcaps.
- [ ] Implement own tool.
- [ ] Defense bonus.
- [ ] Final report + demo.

**Repo layout today:** assignment PDF, briefing, README, `.gitignore`, draft `docs/design-proposal.*` (will rewrite after plan is confirmed). No implementation yet.

## Locked plan (supervisor-aligned; confirm before coding)

### What the supervisor decided

1. **Multiple attacks on one setup** (not one attack on many setups).
2. **Attacks run on captured pcaps** (not primarily live RF demos).
3. **Public sample pcaps from the Internet are allowed** as input.

Still required by the course PDF: **own cracker code**; do **not** use aircrack-ng / Hashcat / etc. to perform the crack.

### What “one setup” means

One toolchain on one machine:

`pcap → own parser → shared crypto (PBKDF2 / HMAC) → attack modules → passphrase or fail`

Same UI/CLI, same pcap folder, same wordlist/mask inputs. Only the **attack module** changes.

### What counts as distinct “attacks”

Need methods that are **clearly different** in the report (different verifier and/or different candidate strategy), not three names for the same loop.

| # | Attack | What differs | Difficulty | Papers |
| --- | --- | --- | --- | --- |
| **A** | WPA2-PSK **4-way handshake MIC** + dictionary | Verifier = MIC after PTK derivation | Medium (baseline) | He & Mitchell 2004/2005; RFC 2898 |
| **B** | WPA2-PSK **PMKID** + dictionary | Verifier = PMKID (no full PTK needed) | Easier than A | CERT-EU SA2018-019 |
| **C** | WPA2-PSK **mask / limited brute** | Same verifiers as A/B; candidates from a pattern, not a wordlist | Easy add-on | Same + password-attack practice (Chalyi 2025 related) |

**Recommended set: A + B + C.**  
Why: all are real password cracking; all work offline on pcaps; one crypto core; easy to demo; fits “multiple attacks / one setup.”

### What we are *not* planning (for now)

| Idea | Why not (yet) |
| --- | --- |
| KRACK / TKIP chopchop | Not password cracking |
| Dragonblood side channels | Too hard; not pcap-dictionary style |
| WPA3 offline dictionary on SAE | By design should fail; use as **defense contrast**, not as attack #3 |
| Full WEP PTW/FMS | Much harder; different stack; only add if supervisor wants protocol diversity |
| Live deauth / evil twin as graded core | Supervisor asked for **pcap-based** attacks |

### Pcaps

- Use **published sample/demo** WPA2 captures (handshake and, if possible, PMKID). Prefer ones with a **documented test passphrase**.
- Optional: record our own lab pcap later for the report screenshots.
- Store pcaps under something like `datasets/` (gitignored if large/sensitive).
- Do not use captures from networks you do not own/have no right to analyze.

### Defense (bonus; not one of the three attacks)

- Strong passphrase policy.
- Prefer **WPA3-SAE-only** (no WPA2 transition).
- Cite Dragonfly/SAE (RFC 7664; Lancrenon & Škrobot 2015) as why offline dict fails.
- Cite Dragonblood (2020) as “misconfig / old SAE still risky.”

### Demo script (success criteria)

1. Run Attack A on handshake pcap → recover known test password.  
2. Run Attack B on PMKID pcap (or same pcap if it has PMKID) → recover password.  
3. Run Attack C with a short mask matching the test password → recover password.  
4. Show a wrong wordlist/mask → fail cleanly.  
5. Defense slide: WPA3-SAE blocks this class of offline attack.

### Open choice (confirm)

- **Default:** A + B + C (all WPA2-PSK, simplest).  
- **Alternative:** replace C with a **simple WEP key-recovery** demo on a public WEP pcap if the supervisor wants an older protocol too (more code, more papers, higher risk).

**Do not regenerate the proposal PDF until this plan is confirmed.**

## Ethics and scope

Course lab / published sample pcaps only. Never target campus, neighbor, or other unauthorized networks. Do not redistribute captures that contain real third-party credentials.

## What “Wi-Fi password cracking” means here

Success = **recovering a WPA2 passphrase** (or WEP key if that alternative is chosen) from pcap material using **our** code.

KRACK and TKIP chopchop are related Wi-Fi results, not this project’s graded attacks. Dragonblood is defense/context, not the main demo.

## High-level protocol facts (for reports; not an attack cookbook)

### WEP (IEEE 802.11 original)

- Per-frame RC4 key is `IV || root_key` (24-bit IV). ICV is CRC-32, not a cryptographic MAC.
- Related-key / weak-IV structure of RC4 KSA is what Fluhrer–Mantin–Shamir exploited; Klein / PTW later removed the need to wait for special IVs.
- Borisov–Goldberg–Wagner showed confidentiality and integrity fail even before full key recovery (keystream reuse, CRC).
- **Defense:** do not use WEP.

### WPA/WPA2-Personal (PSK)

- Passphrase + SSID → PMK via **PBKDF2-HMAC-SHA1**, 4096 iterations, 256-bit output (IEEE 802.11i; PKCS #5 / RFC 2898 / RFC 8018).
- **4-way handshake** confirms both sides have the PMK and derives a fresh PTK from PMK, ANonce, SNonce, and the two MAC addresses. Message integrity uses HMAC over EAPOL-Key.
- If the PSK is in a dictionary, an **offline** guess-and-check against captured handshake fields is possible. That is a password-strength failure, not a break of AES-CCMP itself.
- PMKID (RSN, roaming/caching) is another verifier derived from the PMK; CERT-EU SA2018-019 summarizes the 2018 observation that Message 1 may carry enough to run the same offline guess.
- He–Mitchell analyzed the 4-way handshake (DoS / blocking / reflection). Vanhoef–Piessens **KRACK** is key *reinstallation*, not PSK recovery.

### WPA3-Personal (SAE / Dragonfly)

- Simultaneous Authentication of Equals is a PAKE (RFC 7664). Designed so a captured handshake should **not** allow the same offline dictionary attack as WPA2-PSK.
- Dragonblood (Vanhoef–Ronen) documents downgrade, DoS, and side-channel password-partitioning issues; Wi-Fi Alliance / vendors issued fixes. Use this for the **defense / why WPA3** section.

### Countermeasures worth implementing for the bonus

Pick something you can demo on the lab AP:

- Reject WEP/TKIP; require WPA2-CCMP or WPA3-SAE.
- Strong random passphrase (length + unpredictability; NIST SP 800-63B is about *memorized secrets*, not Wi-Fi specifically, but the “not a dictionary word” point applies).
- Disable WPA3 transition/downgrade if the lab AP supports WPA3-only.
- Optional: a small detector that flags weak PSK policy, open/WEP beacons, or missing PMF — as a *defense tool you wrote*, not an IDS product.

## Literature cache (`others/`, gitignored)

Full annotated list: `others/CATALOG.md` (local only). SKILLS.md keeps a copy so a fresh clone still has citations.

### Papers (`others/papers/`)

| File | Work |
| --- | --- |
| `2001-borisov-goldberg-wagner-insecurity-of-80211.pdf` | Borisov, Goldberg, Wagner — WEP design failures (MobiCom 2001) |
| `2001-fluhrer-mantin-shamir-rc4-ksa-wep.pdf` | Fluhrer, Mantin, Shamir — RC4 KSA / WEP related-key (SAC 2001) |
| `2002-stubblefield-ioannidis-rubin-break-wep.pdf` | First practical FMS implementation against WEP (NDSS 2002) |
| `2004-he-mitchell-analysis-80211i-4way-handshake.pdf` | He & Mitchell — 4-way handshake analysis (WiSe 2004) |
| `2005-he-mitchell-security-analysis-80211i.pdf` | He & Mitchell — 802.11i security + DoS (NDSS 2005) |
| `2005-he-sundararajan-datta-derek-mitchell-80211i-tls.pdf` | Modular correctness proof of 802.11i and TLS (CCS 2005) |
| `2006-bittau-handley-lackey-final-nail-wep.pdf` | Fragmentation / keystream expansion on WEP (S&P 2006) |
| `2007-tews-weinmann-pyshkin-breaking-104bit-wep.pdf` | PTW attack (IACR ePrint 2007/120) |
| `2007-tews-ptw-wep-slides.pdf` | PTW talk slides (history of WEP breaks) |
| `2008-klein-attacks-on-rc4.pdf` | Klein — RC4 correlations used by PTW (DCC 2008) |
| `2008-tews-beck-practical-attacks-wep-wpa.pdf` | Improved WEP + first practical WPA-TKIP result (WiSec 2009 / ePrint 2008/472) |
| `2009-ohigashi-morii-wpa-message-falsification.pdf` | TKIP message falsification follow-up (related, not PSK crack) |
| `2015-lancrenon-skrobot-provable-security-dragonfly.pdf` | Provable security of Dragonfly (ISC 2015) |
| `2017-vanhoef-piessens-krack-wpa2.pdf` | KRACK — key reinstallation (CCS 2017) |
| `2020-vanhoef-ronen-dragonblood-wpa3.pdf` | Dragonblood — WPA3 SAE / EAP-pwd (S&P 2020) |

### Specs (`others/specs/`)

| File | Work |
| --- | --- |
| `rfc2104-hmac.txt` | HMAC |
| `rfc2898-pkcs5-pbkdf2.txt` | PBKDF2 (PKCS #5 v2.0) |
| `rfc8018-pkcs5-v21.txt` | PKCS #5 v2.1 (current PBKDF2 text) |
| `rfc3748-eap.txt` | EAP |
| `rfc4017-eap-method-requirements-80211.txt` | EAP method requirements for 802.11 |
| `rfc7664-dragonfly-key-exchange.txt` | Dragonfly (basis of SAE) |
| `nist-sp800-63b-digital-identity-authentication.pdf` | Memorized-secret / authenticator guidance (defense writeup) |

### Advisories (`others/advisories/`)

| File | Work |
| --- | --- |
| `2018-cert-eu-wpa-wpa2-pmkid.pdf` | CERT-EU SA2018-019 — PMKID as offline-crack verifier |

IEEE Std 802.11 / 802.11i is paywalled; cite the standard, do not commit a pirated copy.

## Reports (required sections)

### Design report (week 11) — 20%

- **a.** Definition of the attack + topology diagram (lab AP, victim STA, attacker STA; mark channels and who owns what).
- **b.** Timing diagram of the *original* protocol **and** of the attack, with strategies.
- **c.** Packet / frame details and any header fields you use or modify.
- **d.** Justification: why the design should work (cite papers above).

### Final report + demo (weeks 13–14) — 20% + 60%

- **a.** Steps, snapshots, victim screen.
- **b.** Was it successful? Why / why not.
- **c.** Observed output on attacker, victim, and related hosts.
- **d.** Countermeasure: did you design one, and how.

Name group-member ownership in both reports.

## Agent working rules

1. Read this file and the assignment PDF before coding or writing reports.
2. **Do not** vendor, wrap, or paste aircrack-ng / hashcat / hcx* / similar.
3. **Do not** write exploits aimed at networks outside the group lab.
4. Prefer architecture, protocol field layouts, lab topology, tests against a **local pcap the group captured**, and report prose.
5. When adding source, tests, or design decisions, update **Current status** and the repo-layout note in this file.
6. Literature PDFs stay in `others/` and stay gitignored. New citations go here **and** in `others/CATALOG.md` if the cache is present.
7. Python crypto: implement PBKDF2/HMAC usage yourself on top of `hashlib`/`hmac`; do not call a “WPA cracker” package.

## Suggested own-tool shape (after the group picks a variant)

Keep modules boring and auditable, for example:

- `capture/` — receive 802.11 + radiotap (or a group-recorded pcap) and split frames.
- `parse/` — your MAC header, LLC, EAPOL-Key, RSN IE parsers.
- `crypto/` — PBKDF2-HMAC-SHA1, PRF/PTK derivation, MIC verify (or RC4 + IV stats for WEP).
- `crack/` — dictionary loop over **lab** wordlist, stop on first MIC/PMKID match.
- `defend/` — bonus policy / detector.
- `docs/` or `reports/` — design + final reports.

Do not start from a public cracker and “rewrite names.”

## Related links (not downloaded)

- KRACK site: https://www.krackattacks.com/
- Dragonblood site: https://wpa3.mathyvanhoef.com/
- IACR ePrint 2007/120: https://eprint.iacr.org/2007/120
- IACR ePrint 2008/472: https://eprint.iacr.org/2008/472
- IACR ePrint 2019/383: https://eprint.iacr.org/2019/383
