#!/usr/bin/env python3
"""Generate demo data + figures for the report from the wpacrack tool itself.

Outputs (all under report/):
  data.tex            LaTeX \\newcommand macros with measured numbers
  results_table.tex   the demo results table body
  figures/throughput.pdf   naive pure-Python vs hashlib PBKDF2 bar chart
  figures/timecrack.pdf    time-to-crack vs passphrase length, per charset

Run:  . .venv/bin/activate && python report/make_data.py
"""

from __future__ import annotations

import hmac
import os
import platform
import struct
import sys
import time
from hashlib import sha1

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# make wpacrack importable when run from repo root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from wpacrack import sim, attack_mic, attack_pmkid, attack_mask  # noqa: E402
from wpacrack.candidates import iter_wordlist  # noqa: E402
from wpacrack.defend import analyze as defend_analyze, estimate as defend_estimate  # noqa: E402
from wpacrack.result import FOUND, EXHAUSTED  # noqa: E402

REPORT = os.path.join(ROOT, "report")
FIGDIR = os.path.join(REPORT, "figures")
FIXTURES = os.path.join(ROOT, "fixtures")
os.makedirs(FIGDIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

def bench_hashlib(n: int = 800) -> float:
    import hashlib
    t = time.time()
    for i in range(n):
        hashlib.pbkdf2_hmac("sha1", b"cand%06d" % i, b"demoAP", 4096, dklen=32)
    return n / (time.time() - t)


def _naive_pbkdf2(passphrase: bytes, salt: bytes, iters: int, dklen: int) -> bytes:
    """Deliberately naive PBKDF2-HMAC-SHA1: the 4096-iteration loop lives in
    Python instead of the single C call hashlib.pbkdf2_hmac makes."""
    out = b""
    block = 1
    while len(out) < dklen:
        u = hmac.new(passphrase, salt + struct.pack(">I", block), sha1).digest()
        t = bytearray(u)
        for _ in range(iters - 1):
            u = hmac.new(passphrase, u, sha1).digest()
            for i in range(len(t)):
                t[i] ^= u[i]
        out += bytes(t)
        block += 1
    return out[:dklen]


def bench_naive(n: int = 60) -> float:
    t = time.time()
    for i in range(n):
        _naive_pbkdf2(b"cand%06d" % i, b"demoAP", 4096, 32)
    return n / (time.time() - t)


# ---------------------------------------------------------------------------
# Run the demo scenarios
# ---------------------------------------------------------------------------

def run_scenarios():
    wl = os.path.join(ROOT, "wl", "demo.txt")
    neg = os.path.join(ROOT, "wl", "negative.txt")
    rows = []
    v = attack_mic.run(os.path.join(FIXTURES, "hs_ok.pcap"), iter_wordlist(wl), ssid="demoAP")
    rows.append(("Attack 1: Handshake MIC", "dict hit", v, FOUND))
    v = attack_pmkid.run(os.path.join(FIXTURES, "pmkid_ok.pcap"), iter_wordlist(wl), ssid="demoAP")
    rows.append(("Attack 2: PMKID", "dict hit", v, FOUND))
    v = attack_mask.run(os.path.join(FIXTURES, "hs_short.pcap"), "?d?d?d?d?d?d", ssid="demoAP", timebox=120)
    rows.append(("Attack 3: Mask brute", "6-digit PIN", v, FOUND))
    v = attack_mic.run(os.path.join(FIXTURES, "hs_ok.pcap"), iter_wordlist(neg), ssid="demoAP")
    rows.append(("Attack 1: negative control", "dict miss", v, EXHAUSTED))
    return rows


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------

def fig_throughput(rate_naive: float, rate_hashlib: float):
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    labels = ["Naive\n(pure-Python loop)", "hashlib\n(C-backed)"]
    vals = [rate_naive, rate_hashlib]
    bars = ax.bar(labels, vals, color=["#c0504d", "#4f81bd"], width=0.55)
    ax.set_ylabel("candidates / second (log scale)")
    ax.set_yscale("log")
    ax.set_title("WPA2 PBKDF2 throughput: implementation matters")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:,.0f}/s",
                ha="center", va="bottom", fontsize=9)
    ax.text(0.5, 0.92, f"~{rate_hashlib / rate_naive:.0f}x faster",
            transform=ax.transAxes, ha="center", fontsize=10, color="#333")
    fig.tight_layout()
    fig.savefig(os.path.join(FIGDIR, "throughput.pdf"))
    plt.close(fig)


def fig_timecrack(rate: float):
    charsets = [("digits (10)", 10), ("lower (26)", 26),
                ("lower+digits (36)", 36), ("alnum mixed (62)", 62),
                ("full ASCII (95)", 95)]
    lengths = list(range(6, 17))
    fig, ax = plt.subplots(figsize=(6.0, 3.8))
    year = 365 * 24 * 3600
    for label, size in charsets:
        ys = [(size ** L) / rate / 2 for L in lengths]  # expected (half keyspace)
        ax.plot(lengths, ys, marker="o", markersize=3, label=label)
    ax.axhline(year, color="black", linestyle="--", linewidth=1)
    ax.text(lengths[0], year * 1.5, "1 year", fontsize=8)
    ax.axhline(year * 100, color="gray", linestyle=":", linewidth=1)
    ax.text(lengths[0], year * 150, "100 years", fontsize=8, color="gray")
    ax.set_yscale("log")
    ax.set_xlabel("passphrase length (characters)")
    ax.set_ylabel("expected crack time (seconds, log)")
    ax.set_title(f"Offline crack time vs length @ {rate:,.0f} cand/s")
    ax.legend(fontsize=7, loc="lower right")
    ax.grid(True, which="both", linestyle=":", alpha=0.4)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGDIR, "timecrack.pdf"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# Emit LaTeX
# ---------------------------------------------------------------------------

def tex_escape(s: str) -> str:
    return s.replace("_", "\\_").replace("#", "\\#").replace("&", "\\&")


def write_data_tex(rate_naive, rate_hashlib, rows):
    macros = [
        f"\\newcommand{{\\gendate}}{{{tex_escape(time.strftime('%Y-%m-%d %H:%M'))}}}",
        f"\\newcommand{{\\genhost}}{{{tex_escape(platform.node())}}}",
        f"\\newcommand{{\\genpython}}{{{tex_escape(platform.python_version())}}}",
        f"\\newcommand{{\\ratehashlib}}{{{rate_hashlib:,.0f}}}",
        f"\\newcommand{{\\ratenaive}}{{{rate_naive:,.1f}}}",
        f"\\newcommand{{\\speedup}}{{{rate_hashlib / rate_naive:.0f}}}",
    ]
    with open(os.path.join(REPORT, "data.tex"), "w") as fh:
        fh.write("% Auto-generated by report/make_data.py. Do not edit by hand.\n")
        fh.write("\n".join(macros) + "\n")

    lines = []
    for name, cond, v, expect in rows:
        status = v.status
        pw = tex_escape(v.passphrase) if v.passphrase else "--"
        rate = f"{v.rate:,.0f}" if (v.tried and v.elapsed) else "--"
        tried = f"{v.tried:,}" if v.tried else "--"
        ttime = f"{v.elapsed:.2f}" if v.elapsed else "--"
        lines.append(
            f"{tex_escape(name)} & {tex_escape(cond)} & {status} & {pw} & "
            f"{tried} & {ttime} & {rate}"
        )
    with open(os.path.join(REPORT, "results_table.tex"), "w") as fh:
        fh.write("% Auto-generated by report/make_data.py.\n")
        fh.write("\\begin{tabular}{@{}p{3.6cm} l l l r r r@{}}\n")
        fh.write("\\toprule\n")
        fh.write("\\textbf{Scenario} & \\textbf{Cond.} & \\textbf{Result} & "
                 "\\textbf{Password} & \\textbf{Tried} & \\textbf{Time} & \\textbf{Rate/s} \\\\\n")
        fh.write("\\midrule\n")
        fh.write("".join(f"{line} \\\\\n" for line in lines))
        fh.write("\\bottomrule\n\\end{tabular}\n")

    # crack-time estimate examples table
    import math
    examples = [("d", 6), ("d", 8), ("l", 8), ("a", 8), ("a", 12), ("a", 16)]
    est_lines = []
    for cs, L in examples:
        e = defend_estimate.estimate(cs, L, rate_hashlib)
        years = e.expected_seconds / (365 * 24 * 3600)
        human = "$>10^{6}$ yr" if years > 1e6 else defend_estimate.human_time(e.expected_seconds)
        exp = int(math.floor(math.log10(e.keyspace))) if e.keyspace > 0 else 0
        mant = e.keyspace / (10 ** exp)
        ks = f"${mant:.1f}\\times 10^{{{exp}}}$"
        est_lines.append(f"{cs} & {L} & {ks} & {human} & {e.verdict}")
    with open(os.path.join(REPORT, "estimate_table.tex"), "w") as fh:
        fh.write("% Auto-generated by report/make_data.py.\n")
        fh.write("\\begin{tabular}{@{}c c r l l@{}}\n")
        fh.write("\\toprule\n")
        fh.write("\\textbf{Charset} & \\textbf{Len} & \\textbf{Keyspace} & "
                 "\\textbf{Expected time} & \\textbf{Verdict} \\\\\n")
        fh.write("\\midrule\n")
        fh.write("".join(f"{line} \\\\\n" for line in est_lines))
        fh.write("\\bottomrule\n\\end{tabular}\n")


def main():
    print("generating fixtures...")
    sim.write_default_fixtures(FIXTURES)
    print("benchmarking hashlib PBKDF2...")
    rate_hashlib = bench_hashlib()
    print(f"  hashlib: {rate_hashlib:,.0f} cand/s")
    print("benchmarking naive pure-Python PBKDF2...")
    rate_naive = bench_naive()
    print(f"  naive:   {rate_naive:,.1f} cand/s  (speedup ~{rate_hashlib / rate_naive:.0f}x)")
    print("running demo scenarios...")
    rows = run_scenarios()
    for name, cond, v, _ in rows:
        print(f"  {name:<28} {v.status:<10} {v.passphrase or ''}")
    print("rendering figures...")
    fig_throughput(rate_naive, rate_hashlib)
    fig_timecrack(rate_hashlib)
    print("writing LaTeX data...")
    write_data_tex(rate_naive, rate_hashlib, rows)
    print("done.")


if __name__ == "__main__":
    main()
