#!/usr/bin/env python3
"""Generate the three figures used by report/report.tex.

Every number below is a REAL measurement recorded during this project, with its source noted.
Nothing here is estimated or invented:

  * CPU / GPU throughput and the real-capture crossover come from the two Kaggle notebooks
    (notebooks/gpu_pbkdf2_benchmark.ipynb and notebooks/gpu_real_capture_crack.ipynb), run on a
    Kaggle instance with 2x Tesla T4 GPUs. In both notebooks the GPU kernel is validated
    byte-for-byte against hashlib.pbkdf2_hmac (Step 1) before any timing is trusted, and the
    active backend for these numbers was torch.compile default mode.
  * The two figures need matplotlib only (a dev-time dependency); the wpacrack tool itself is
    standard-library-only and is not imported here.

Run:  python3 report/make_figures.py
"""

from __future__ import annotations

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

FIGDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures")
os.makedirs(FIGDIR, exist_ok=True)

# --- Measured throughput (Kaggle, 2x Tesla T4, notebook gpu_pbkdf2_benchmark.ipynb) ----------
RATE_CPU_1CORE = 240.0      # hashlib.pbkdf2_hmac, single core
RATE_CPU_4CORE = 455.0      # multiprocessing.Pool over 4 cores
RATE_GPU_SINGLE = 2486.0    # one Tesla T4, best batch (524,288)
RATE_GPU_DUAL = 2927.0      # both Tesla T4s, two concurrent threads (batch 1,048,576)

# --- Real-capture crossover (Kaggle, notebook gpu_real_capture_crack.ipynb, wpa2.eapol.cap) ---
RATE_CPU_REALCAP = 264.0    # CPU, forced full scan, target excluded so no early exit
CROSSOVER_N = 7564          # analytic break-even (GPU per-call time / CPU rate)
# (N candidates, GPU wall-clock seconds) actually measured, no extrapolation:
GPU_POINTS = [(20_000, 20_000 / 697.0), (200_000, 200_000 / 5404.0), (5_189_454, 1379.4)]


def fig_throughput():
    fig, ax = plt.subplots(figsize=(5.6, 3.5))
    labels = ["CPU\n1 core", "CPU\n4 cores", "GPU\nsingle T4", "GPU\ndual T4x2"]
    vals = [RATE_CPU_1CORE, RATE_CPU_4CORE, RATE_GPU_SINGLE, RATE_GPU_DUAL]
    colors = ["#8c8c8c", "#5b5b5b", "#4f81bd", "#c0504d"]
    bars = ax.bar(labels, vals, color=colors, width=0.62)
    ax.set_yscale("log")
    ax.set_ylabel("PBKDF2-HMAC-SHA1 candidates / second (log)")
    ax.set_title("Measured PMK-derivation throughput (Kaggle 2x Tesla T4)")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:,.0f}/s", ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGDIR, "throughput.pdf"))
    plt.close(fig)


def fig_crossover():
    import numpy as np
    n = np.logspace(2, np.log10(5_189_454 * 1.4), 200)
    cpu_line = n / RATE_CPU_REALCAP  # CPU is linear in N (constant per-candidate cost)
    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.plot(n, cpu_line, color="#5b5b5b", label=f"CPU (measured {RATE_CPU_REALCAP:,.0f}/s, linear in N)")
    gx = [p[0] for p in GPU_POINTS]
    gy = [p[1] for p in GPU_POINTS]
    ax.plot(gx, gy, color="#c0504d", marker="o", label="GPU (measured points only)")
    ax.axvline(CROSSOVER_N, color="black", linestyle="--", linewidth=1)
    y_lo, y_hi = ax.get_ylim()
    ax.annotate(f"crossover ~{CROSSOVER_N:,}", xy=(CROSSOVER_N, y_lo),
                xytext=(CROSSOVER_N * 1.8, (y_lo * y_hi) ** 0.5), fontsize=8)
    ax.set_xlabel("N candidates (log)")
    ax.set_ylabel("time to process N candidates, s (log)")
    ax.set_title("CPU vs GPU crossover on a real capture (wpa2.eapol.cap)")
    ax.legend(fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIGDIR, "crossover.pdf"))
    plt.close(fig)


def fig_timecrack():
    # Defense view: expected offline crack time vs passphrase length, at the fastest rate we
    # actually measured (dual-GPU, 2,927 cand/s). keyspace/rate/2 (expected = half the space).
    rate = RATE_GPU_DUAL
    charsets = [("digits (10)", 10), ("lower (26)", 26), ("lower+digits (36)", 36),
                ("alphanum (62)", 62), ("full ASCII (95)", 95)]
    lengths = list(range(8, 17))  # WPA2-PSK minimum is 8
    year = 365 * 24 * 3600
    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    for label, size in charsets:
        ys = [(size ** L) / rate / 2 for L in lengths]
        ax.plot(lengths, ys, marker="o", markersize=3, label=label)
    ax.axhline(year, color="black", linestyle="--", linewidth=1)
    ax.text(lengths[0], year * 1.6, "1 year", fontsize=8)
    ax.axhline(year * 1000, color="gray", linestyle=":", linewidth=1)
    ax.text(lengths[0], year * 1600, "1000 years", fontsize=8, color="gray")
    ax.set_yscale("log")
    ax.set_xlabel("passphrase length (characters)")
    ax.set_ylabel("expected offline crack time, s (log)")
    ax.set_title(f"Crack time vs length at the fastest measured rate ({rate:,.0f} cand/s, dual T4)")
    ax.legend(fontsize=7, loc="lower right")
    ax.grid(True, which="both", linestyle=":", alpha=0.4)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGDIR, "timecrack.pdf"))
    plt.close(fig)


if __name__ == "__main__":
    fig_throughput()
    fig_crossover()
    fig_timecrack()
    print("wrote figures/throughput.pdf, figures/crossover.pdf, figures/timecrack.pdf")
