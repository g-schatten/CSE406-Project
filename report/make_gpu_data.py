#!/usr/bin/env python3
"""Generate the GPU-acceleration section's data + figures for the report.

Unlike make_data.py, this does NOT re-run anything -- there is no GPU on the machines that
build this report. Instead it records the real, independently-verified measurements gathered
during this project's GPU experiment (notebooks/gpu_pbkdf2_benchmark.ipynb and
notebooks/gpu_real_capture_crack.ipynb, run on Kaggle, GPU accelerator = T4 x2), plus this
repo's own machine's real full-wordlist CPU cross-check, and turns them into the same kind of
LaTeX macros/tables/figures make_data.py produces for the CPU-only results.

Every number below is a REAL measurement, not an estimate:
  - Kaggle numbers: both notebooks' kernel was validated byte-for-byte against
    hashlib.pbkdf2_hmac before any timing was trusted (see notebooks/*.ipynb, Step 1).
  - This-machine numbers: a genuine full scan of the real 100k-entry SecLists wordlist against
    two real internet-sourced captures (wpa2.eapol.cap, test-pmkid.pcap), target password
    excluded/confirmed-absent so the scan cannot early-exit -- see the run notes inline below.

Run:  python report/make_gpu_data.py
Outputs (all under report/):
  gpu_data.tex              LaTeX \\newcommand macros with the measured numbers
  gpu_comparison_table.tex  estimate-only vs measured-CPU vs measured-GPU, per target
  gpu_fullscale_table.tex   the headline full-realistic-wordlist result
  figures/gpu_throughput.pdf   CPU (1/4 core) vs GPU (single/dual) bar chart
  figures/gpu_crossover.pdf    CPU (linear in N) vs GPU (~flat in N) crossover chart
"""

from __future__ import annotations

import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from wpacrack.defend import estimate as defend_estimate  # noqa: E402

REPORT = os.path.join(ROOT, "report")
FIGDIR = os.path.join(REPORT, "figures")
os.makedirs(FIGDIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Real measurements (see notebooks/gpu_pbkdf2_benchmark.ipynb, "compile:default" backend,
# validated run on Kaggle, 2x Tesla T4). Kernel is our own PyTorch PBKDF2-HMAC-SHA1
# implementation (RFC 2898 / IEEE 802.11i), not aircrack-ng/Hashcat -- see the notebook's
# own Step 1 validation cell, which passed before any of these numbers were trusted.
# ---------------------------------------------------------------------------
RATE_ESTIMATE_ONLY = 255.0          # the report's original, never-measured assumed rate
RATE_CPU_1CORE = 240.0              # measured: hashlib.pbkdf2_hmac, 1 core, Kaggle CPU
RATE_CPU_4CORE = 455.0              # measured: multiprocessing.Pool(4), Kaggle CPU
RATE_GPU_SINGLE = 2486.0            # measured: single Tesla T4, best batch (524,288)
RATE_GPU_DUAL = 2927.0              # measured: both Tesla T4s, concurrent threads (batch 1,048,576)

# notebooks/gpu_real_capture_crack.ipynb: real capture wpa2.eapol.cap (SSID Harkonen,
# passphrase 12345678), Attack 1 (MIC), real 100k-entry SecLists wordlist, target excluded
# so the scan cannot early-exit (see the notebook's exclude_target()).
RATE_CPU_REALCAP = 264.0            # measured on Kaggle CPU, same real capture
CROSSOVER_N = 7564                  # analytic: GPU per-call time x CPU rate

# Full realistic wordlist (5,189,454 real entries, SecLists xato-net-10-million-passwords.txt).
N_FULL = 5_189_454
T_GPU_FULL_EXECUTED = 1379.4        # seconds -- GPU actually ran this, full scan, no match
T_CPU_FULL_CALCULATED = 19683.0     # seconds -- CALCULATED (N/RATE_CPU_REALCAP), not executed

# This repo's own machine: independent, second-machine cross-check -- genuine full scans of
# the same real 100k wordlist, target excluded/confirmed-absent, against TWO different real
# captures and TWO different attacks (MIC and PMKID), run locally with this project's own
# wpacrack.crypto (not a synthetic stand-in).
RATE_CPU_THISMACHINE_MIC = 144.0    # wpa2.eapol.cap, Attack 1 (MIC), 99,999 candidates, 692.64s
RATE_CPU_THISMACHINE_PMKID = 175.0  # test-pmkid.pcap, Attack 2 (PMKID), 100,000 candidates, 570.56s


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------

def fig_gpu_throughput():
    fig, ax = plt.subplots(figsize=(5.6, 3.6))
    labels = ["CPU\n1 core", "CPU\n4 cores", "GPU\nsingle (T4)", "GPU\ndual (T4x2)"]
    vals = [RATE_CPU_1CORE, RATE_CPU_4CORE, RATE_GPU_SINGLE, RATE_GPU_DUAL]
    colors = ["#8c8c8c", "#4f4f4f", "#4f81bd", "#c0504d"]
    bars = ax.bar(labels, vals, color=colors, width=0.6)
    ax.set_yscale("log")
    ax.set_ylabel("candidates / second (log scale)")
    ax.set_title("PBKDF2-HMAC-SHA1 throughput: CPU vs GPU (Kaggle T4x2)")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:,.0f}/s", ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGDIR, "gpu_throughput.pdf"))
    plt.close(fig)


def fig_gpu_crossover():
    # CPU is confirmed linear in N (constant per-candidate cost) -- an analytic line is honest.
    # GPU's measured rate is NOT flat/monotonic across the sizes we actually measured
    # (697/s at N=20k, 5,404/s at N=200k, 3,762/s at N=5.19M) -- torch.compile's fixed-cost-vs-N
    # behavior is more complex than a single extrapolated rate would suggest, so rather than
    # invent a smooth GPU curve from one point, we plot ONLY the three real measured points,
    # connected by straight (log-log) segments -- no extrapolation beyond what was measured.
    n_range = np.logspace(np.log10(100), np.log10(N_FULL * 1.3), 200)
    cpu_line = n_range / RATE_CPU_REALCAP

    meas_n = [20_000, 200_000, N_FULL]
    meas_t = [20_000 / 697.0, 200_000 / 5404.0, T_GPU_FULL_EXECUTED]

    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.plot(n_range, cpu_line, color="#4f4f4f", label="CPU (real capture, measured rate, analytic)")
    ax.plot(meas_n, meas_t, color="#c0504d", marker="o", label="GPU (real capture, measured points only)")
    ax.axvline(CROSSOVER_N, color="black", linestyle="--", linewidth=1)
    y_lo, y_hi = ax.get_ylim()
    ax.annotate(f"crossover\n~{CROSSOVER_N:,} candidates", xy=(CROSSOVER_N, y_lo),
                xytext=(CROSSOVER_N * 2, (y_lo * y_hi) ** 0.5), fontsize=8)
    ax.set_xlabel("N candidates (log scale)")
    ax.set_ylabel("time to process N candidates, seconds (log scale)")
    ax.set_title("CPU/GPU crossover -- real capture (wpa2.eapol.cap)")
    ax.legend(fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIGDIR, "gpu_crossover.pdf"))
    plt.close(fig)


# ---------------------------------------------------------------------------
# LaTeX
# ---------------------------------------------------------------------------

def write_gpu_data_tex():
    macros = [
        f"\\newcommand{{\\ratecpuone}}{{{RATE_CPU_1CORE:,.0f}}}",
        f"\\newcommand{{\\ratecpufour}}{{{RATE_CPU_4CORE:,.0f}}}",
        f"\\newcommand{{\\rategpusingle}}{{{RATE_GPU_SINGLE:,.0f}}}",
        f"\\newcommand{{\\rategpudual}}{{{RATE_GPU_DUAL:,.0f}}}",
        f"\\newcommand{{\\gpuspeedup}}{{{RATE_GPU_DUAL / RATE_CPU_1CORE:.1f}}}",
        f"\\newcommand{{\\crossovern}}{{{CROSSOVER_N:,}}}",
        f"\\newcommand{{\\nfull}}{{{N_FULL:,}}}",
        f"\\newcommand{{\\tgpufull}}{{{T_GPU_FULL_EXECUTED / 60:.1f}}}",
        f"\\newcommand{{\\tcpufull}}{{{T_CPU_FULL_CALCULATED / 3600:.1f}}}",
        f"\\newcommand{{\\fullscalespeedup}}{{{T_CPU_FULL_CALCULATED / T_GPU_FULL_EXECUTED:.0f}}}",
        f"\\newcommand{{\\ratethismachinemic}}{{{RATE_CPU_THISMACHINE_MIC:,.0f}}}",
        f"\\newcommand{{\\ratethismachinepmkid}}{{{RATE_CPU_THISMACHINE_PMKID:,.0f}}}",
    ]
    with open(os.path.join(REPORT, "gpu_data.tex"), "w") as fh:
        fh.write("% Auto-generated by report/make_gpu_data.py from real, recorded measurements\n")
        fh.write("% (see notebooks/*.ipynb for the Kaggle runs). Do not edit by hand.\n")
        fh.write("\n".join(macros) + "\n")


def write_gpu_comparison_table():
    targets = [("d", 6, "6-digit PIN"), ("d", 8, "8-digit PIN"), ("a", 8, "8-char alnum")]
    rates = [("Estimate-only (never measured)", RATE_ESTIMATE_ONLY),
             ("Measured: CPU, 1 core", RATE_CPU_1CORE),
             ("Measured: CPU, 4 cores", RATE_CPU_4CORE),
             ("Measured: GPU, single T4", RATE_GPU_SINGLE),
             ("Measured: GPU, dual T4x2", RATE_GPU_DUAL)]
    lines = []
    for label, rate in rates:
        cells = [label]
        for cs, L, _name in targets:
            e = defend_estimate.estimate(cs, L, rate)
            cells.append(defend_estimate.human_time(e.expected_seconds))
        lines.append(" & ".join(cells))
    with open(os.path.join(REPORT, "gpu_comparison_table.tex"), "w") as fh:
        fh.write("% Auto-generated by report/make_gpu_data.py.\n")
        fh.write("\\begin{tabular}{@{}l r r r@{}}\n")
        fh.write("\\toprule\n")
        fh.write("\\textbf{Rate source} & \\textbf{6-digit PIN} & \\textbf{8-digit PIN} & \\textbf{8-char alnum} \\\\\n")
        fh.write("\\midrule\n")
        fh.write("".join(f"{line} \\\\\n" for line in lines))
        fh.write("\\bottomrule\n\\end{tabular}\n")


def write_gpu_fullscale_table():
    rows = [
        ("GPU, dual T4x2 (EXECUTED)", f"{N_FULL:,}", f"{T_GPU_FULL_EXECUTED/60:.1f} min", "measured"),
        ("CPU, 1 core (CALCULATED)", f"{N_FULL:,}", f"{T_CPU_FULL_CALCULATED/3600:.1f} h", "calculated from measured rate"),
        ("CPU, this machine, MIC (cross-check)", "99,999", "11.5 min (100k only)", "measured, independent 2nd machine"),
        ("CPU, this machine, PMKID (cross-check)", "100,000", "9.5 min (100k only)", "measured, independent 2nd machine"),
    ]
    with open(os.path.join(REPORT, "gpu_fullscale_table.tex"), "w") as fh:
        fh.write("% Auto-generated by report/make_gpu_data.py.\n")
        fh.write("\\begin{tabular}{@{}l r r l@{}}\n")
        fh.write("\\toprule\n")
        fh.write("\\textbf{Run} & \\textbf{Candidates} & \\textbf{Time} & \\textbf{Basis} \\\\\n")
        fh.write("\\midrule\n")
        for name, n, t, basis in rows:
            fh.write(f"{name} & {n} & {t} & {basis} \\\\\n")
        fh.write("\\bottomrule\n\\end{tabular}\n")


def main():
    print("rendering GPU figures...")
    fig_gpu_throughput()
    fig_gpu_crossover()
    print("writing GPU LaTeX data...")
    write_gpu_data_tex()
    write_gpu_comparison_table()
    write_gpu_fullscale_table()
    print("done. Outputs: gpu_data.tex, gpu_comparison_table.tex, gpu_fullscale_table.tex,")
    print("               figures/gpu_throughput.pdf, figures/gpu_crossover.pdf")


if __name__ == "__main__":
    main()
