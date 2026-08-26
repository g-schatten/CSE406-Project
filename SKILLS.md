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
- [x] Public academic papers / RFCs / advisories collected under `others/` (gitignored).
- [ ] Attack variant chosen (WEP key recovery vs WPA/WPA2-PSK offline dictionary vs other).
- [ ] Isolated lab topology defined (own AP + own clients only).
- [ ] Design report (week 11): definition, topology, timing diagrams, frame details, justification.
- [ ] Own tool implemented (no internet attack tools).
- [ ] Countermeasure designed (bonus).
- [ ] Final report + demo (weeks 13–14).

**Repo layout today:** assignment PDF, this briefing, README, `.gitignore`. No implementation yet. `others/` exists only on machines that have fetched the literature cache.

## Hard course rules

Quoted in substance from the assignment:

1. **You MUST program your OWN attack tool.**
2. **You MUST NOT use any tool available on the Internet** (no aircrack-ng, hashcat, hcxdumptool, aireplay-ng, cowpatty, reaver, etc., and do not wrap or copy their source).
3. Code is **mostly C / C++ / Python**.
4. **Craft your own frame / packet / segment** in your own code.
5. The report must say **which group member did which part**.
6. Bonus: design **and implement** a defense for this attack.

Allowed building blocks (environment, not a ready-made attack): OS sockets / raw 802.11 IO, Python stdlib (`hashlib`, `hmac`, `socket`, `struct`), and similar crypto primitives. Using a packet-crafting *library* as the whole attack is against the spirit of “craft your own frame.” Parse and build MAC/EAPOL fields yourself.

## Ethics and scope

This is a **controlled course lab**. Work only against an access point and clients **owned by the group**, on an isolated network, with explicit permission.

Never target campus Wi-Fi, neighbors, public APs, or any network you do not own. Do not publish working attack binaries or captures that contain real credentials.

## What “Wi-Fi password cracking” means here

The assignment title is password *cracking*, not “any Wi-Fi attack.” Prefer a design whose **success criterion is recovering the lab passphrase / WEP key**.

Pedagogically standard, own-code-friendly variants (choose one and justify in the design report):

| Variant | Recovered secret | Why it fits “password cracking” | Course-fit notes |
| --- | --- | --- | --- |
| **WPA/WPA2-PSK offline dictionary** | ASCII passphrase | Classic PSK crack: derive PMK, check against handshake material | Best match for the title. Needs EAPOL parse + PBKDF2/HMAC implemented by you. |
| **WEP statistical key recovery** | WEP root key | Recovers the shared secret from IVs + keystream | Strong crypto-lab story (FMS / Klein / PTW). More statistics than “password.” |
| **WPA3 SAE (Dragonblood-class)** | Passphrase via side channels | Password recovery against SAE | Hard for a 2-week demo; cite as related / defense motivation, not default target. |

KRACK (nonce reuse) and TKIP chopchop **are not password cracking**. Cite them as related WPA(2) results, do not make them the graded attack unless the instructor agrees.

**Recommended default for this course:** WPA2-Personal (PSK) offline dictionary against a **lab AP with a deliberately weak passphrase**, using a 4-way handshake (or PMKID) that **your code** extracts from frames **your code** parsed. Keep the wordlist tiny and local so the demo finishes live.

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
