# CSE 406 — Project 20: Wi-Fi password cracking

Course lab for **CSE 406 Computer Security**. Assigned tool: **Wi-Fi password cracking attack** (project 20 in `CSE406ProjectJan2026.pdf`).

The tool is **written by the group** in Python (own 802.11/EAPOL parsing, own frame generation, own crypto core). It uses the **standard library only** — no aircrack-ng, hashcat, scapy, or other internet attack tools.

Per the supervisor: **multiple attacks on one setup**, run on **captured pcap files**. The tool is strictly **file-in / verdict-out** — no sockets, no packet injection, no live traffic.

## For the AI agent

Read **[SKILLS.md](SKILLS.md)** first. It is the living briefing: assignment rules, ethics, protocol notes, citations, report sections, and current status.

## The tool: `wpacrack/`

One offline pipeline, three attacks sharing one crypto core, all fed by pcap files:

```
pcap -> pcap/ (reader) -> parse/ (802.11+EAPOL) -> HandshakeRecord
                                                        |
             crypto/ (PMK, PTK/PRF-512, MIC, PMKID) <---+
                                                        |
   attack_mic/   attack_pmkid/   attack_mask/  ---> cli.py -> FOUND / EXHAUSTED / N/A
                                                        |
                                            defend/ (analyze + policy + estimate)
```

| Attack | Command | Verifier |
| --- | --- | --- |
| 1. Handshake MIC | `mic` | recompute EAPOL MIC from candidate PTK |
| 2. PMKID | `pmkid` | recompute PMKID (needs only M1) |
| 3. Mask / brute | `mask` | same verifiers, candidates from a `?d?l?u?s?a` mask + time-box |

See **[wpacrack/README.md](wpacrack/README.md)** for the full module and command reference.

## Quick start

```bash
python3 -m wpacrack.sim                          # generate the synthetic fixture captures
python3 -m wpacrack report --fixtures fixtures   # run all 3 attacks + defense as a self-test
```

Run an attack on its own:

```bash
python3 -m wpacrack mic   --pcap fixtures/hs_ok.pcap    --wordlist wl/demo.txt --ssid demoAP
python3 -m wpacrack pmkid --pcap fixtures/pmkid_ok.pcap --wordlist wl/demo.txt --ssid demoAP
python3 -m wpacrack mask  --pcap fixtures/hs_short.pcap --mask '?d?d?d?d?d?d' --timebox 60 --ssid demoAP
python3 -m wpacrack analyze --pcap fixtures/wpa3_sae.pcap
```

## Testing

`pytest` needs a virtualenv (system `pip` is blocked by PEP 668):

```bash
. .venv/bin/activate
python -m pytest -q            # 16 tests: KATs, round-trip fixtures, QoS, FCS, negative control, real capture
deactivate

python3 tools/ethics_guard.py  # CI guard: fails if any socket/injection code appears
```

The crypto is cross-checked against the real public `wpa-Induction.pcap` (SSID `Coherer`, passphrase `Induction`); fetch it with `tools/fetch_samples.sh`.

## Layout

| Path | What |
| --- | --- |
| `CSE406ProjectJan2026.pdf` | Official assignment |
| `SKILLS.md` | Agent + group briefing (keep updated) |
| `IMPLEMENTATION_PLAN.md` | The build plan this tool implements |
| `wpacrack/` | The tool (crypto, pcap, parse, 3 attacks, defend, sim, cli) |
| `tests/` | pytest suite (unit KATs + integration + real capture) |
| `fixtures/` | Synthetic captures (committed); `fixtures/public/` is downloaded and gitignored |
| `wl/`, `masks/` | Wordlist slices and mask files |
| `tools/` | `ethics_guard.py`, `fetch_samples.sh` |
| `docs/` | Design proposal (`.tex` / `.pdf`) |
| `others/` | Local paper/RFC cache — **gitignored, not pushed** |
| `.cursor/rules/` | Cursor rule that always loads `SKILLS.md` |

## Reports

- Design report (week 11): definition, topology, timing diagrams, frame details, justification.
- Final report + demo (weeks 13–14): steps, success analysis, host outputs, countermeasure.
- Bonus: implemented in `defend/` (RSN AKM analyzer, passphrase policy, crack-time estimator).

Work only on captures you own or public sample captures. Never target networks you have no right to analyze.
