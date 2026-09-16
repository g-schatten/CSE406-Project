"""Unified CLI: mic | pmkid | mask | analyze | policy | estimate | report.

File-in / verdict-out. No sockets, no injection, no live traffic.

Examples:
  python -m wpacrack mic   --pcap fixtures/hs_ok.pcap --wordlist wl/demo.txt --ssid demoAP
  python -m wpacrack pmkid --pcap fixtures/pmkid_ok.pcap --wordlist wl/demo.txt --ssid demoAP
  python -m wpacrack mask  --pcap fixtures/hs_short.pcap --mask '?d?d?d?d?d?d' --timebox 60 --ssid demoAP
  python -m wpacrack analyze --pcap fixtures/wpa3_sae.pcap
  python -m wpacrack report --fixtures fixtures
"""

from __future__ import annotations

import argparse
import os
import sys

from . import attack_mic, attack_pmkid, attack_mask
from .candidates import iter_wordlist, iter_mask
from .defend import analyze as defend_analyze, policy as defend_policy, estimate as defend_estimate
from .result import FOUND, EXHAUSTED, NA


def _cmd_mic(args) -> int:
    v = attack_mic.run(args.pcap, iter_wordlist(args.wordlist), ssid=args.ssid, bssid=args.bssid)
    print(v.line())
    return 0 if v.status == FOUND else 1


def _cmd_pmkid(args) -> int:
    v = attack_pmkid.run(args.pcap, iter_wordlist(args.wordlist), ssid=args.ssid, bssid=args.bssid)
    print(v.line())
    return 0 if v.status == FOUND else 1


def _cmd_mask(args) -> int:
    v = attack_mask.run(args.pcap, args.mask, ssid=args.ssid, bssid=args.bssid, timebox=args.timebox)
    print(v.line())
    return 0 if v.status == FOUND else 1


def _cmd_analyze(args) -> int:
    verdicts = defend_analyze.analyze(args.pcap)
    if not verdicts:
        print("[ANALYZE] N/A  (no RSN AKM information in capture)")
        return 1
    for v in verdicts:
        print(f"[ANALYZE] {v.verdict}  bssid={v.bssid} akms={v.akms}  {v.message}")
    return 0


def _cmd_policy(args) -> int:
    print(defend_policy.evaluate(args.passphrase).report())
    return 0


def _cmd_estimate(args) -> int:
    print(defend_estimate.estimate(args.charset, args.length, args.rate).report())
    return 0


def _cmd_report(args) -> int:
    fx = args.fixtures
    demo_wl = os.path.join("wl", "demo.txt")
    neg_wl = os.path.join("wl", "negative.txt")
    rows = []

    def add(label, verdict, expect):
        ok = verdict.status == expect
        rows.append((label, verdict, expect, ok))

    add("1 MIC (dict hit)",
        attack_mic.run(os.path.join(fx, "hs_ok.pcap"), iter_wordlist(demo_wl), ssid="demoAP"),
        FOUND)
    add("2 PMKID (dict hit)",
        attack_pmkid.run(os.path.join(fx, "pmkid_ok.pcap"), iter_wordlist(demo_wl), ssid="demoAP"),
        FOUND)
    add("3 MASK (6-digit)",
        attack_mask.run(os.path.join(fx, "hs_short.pcap"), "?d?d?d?d?d?d", ssid="demoAP", timebox=120),
        FOUND)
    add("1 MIC (negative control)",
        attack_mic.run(os.path.join(fx, "hs_ok.pcap"), iter_wordlist(neg_wl), ssid="demoAP"),
        EXHAUSTED)

    print("\n=== attack results ===")
    all_ok = True
    for label, v, expect, ok in rows:
        all_ok = all_ok and ok
        flag = "PASS" if ok else "FAIL"
        extra = f" pw={v.passphrase!r}" if v.status == FOUND else ""
        rate = f" {v.rate:,.0f}/s" if v.tried and v.elapsed else ""
        print(f"  [{flag}] {label:<26} -> {v.status}{extra} (tried={v.tried}{rate})")

    print("\n=== defense analyzer ===")
    for v in defend_analyze.analyze(os.path.join(fx, "wpa3_sae.pcap")):
        print(f"  [{v.verdict}] bssid={v.bssid} {v.message}")
    for v in defend_analyze.analyze(os.path.join(fx, "hs_ok.pcap")):
        print(f"  [{v.verdict}] bssid={v.bssid} {v.message}")

    print("\nSELF-TEST:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wpacrack", description="Homemade WPA2-PSK offline cracker (file-in only).")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mic", help="Attack 1: 4-way handshake MIC dictionary")
    m.add_argument("--pcap", required=True)
    m.add_argument("--wordlist", required=True)
    m.add_argument("--ssid")
    m.add_argument("--bssid")
    m.set_defaults(func=_cmd_mic)

    k = sub.add_parser("pmkid", help="Attack 2: PMKID dictionary")
    k.add_argument("--pcap", required=True)
    k.add_argument("--wordlist", required=True)
    k.add_argument("--ssid")
    k.add_argument("--bssid")
    k.set_defaults(func=_cmd_pmkid)

    s = sub.add_parser("mask", help="Attack 3: mask / limited brute")
    s.add_argument("--pcap", required=True)
    s.add_argument("--mask", required=True)
    s.add_argument("--ssid")
    s.add_argument("--bssid")
    s.add_argument("--timebox", type=float, default=None)
    s.set_defaults(func=_cmd_mask)

    a = sub.add_parser("analyze", help="Defense: RSN AKM analyzer")
    a.add_argument("--pcap", required=True)
    a.set_defaults(func=_cmd_analyze)

    po = sub.add_parser("policy", help="Defense: passphrase policy check")
    po.add_argument("--passphrase", required=True)
    po.set_defaults(func=_cmd_policy)

    e = sub.add_parser("estimate", help="Defense: crack-time estimate")
    e.add_argument("--charset", required=True, choices=list("dlusa"))
    e.add_argument("--length", type=int, required=True)
    e.add_argument("--rate", type=float, required=True)
    e.set_defaults(func=_cmd_estimate)

    r = sub.add_parser("report", help="Run all demo scenarios as a self-test")
    r.add_argument("--fixtures", default="fixtures")
    r.set_defaults(func=_cmd_report)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
