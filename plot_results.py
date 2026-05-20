"""Plot defense-effectiveness results from the harness CSV exports.

Reads one or more <name>.csv files (from run_injection_stats.py --out=<name>) and
produces publication-style figures:

  1. defense_leak_rates.png  — leak rate per defense, per model, with Wilson 95% CI
  2. carrier_heatmap.png      — leak rate per carrier x defense (single model)

Usage:
    pip install matplotlib
    python plot_results.py gpt4omini.csv haiku45.csv
    # model label is taken from the filename (without .csv)
"""

import csv
import math
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")  # no display needed; write files
import matplotlib.pyplot as plt
import numpy as np


def wilson_ci(s, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = s / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (p, max(0.0, center - margin), min(1.0, center + margin))


def load(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def defense_plot(datasets):
    """Grouped bar chart: x = defense, grouped by model, y = leak rate with CI."""
    defenses = ["none", "delimited", "spotlight", "sandwich", "instr_hierarchy", "llm_filter"]
    models = list(datasets.keys())

    fig, ax = plt.subplots(figsize=(11, 6))
    width = 0.8 / max(1, len(models))
    x = np.arange(len(defenses))

    for mi, model in enumerate(models):
        rows = datasets[model]
        rates, errs_lo, errs_hi = [], [], []
        for d in defenses:
            sub = [int(r["leaked"]) for r in rows if r["defense"] == d]
            n, s = len(sub), sum(sub)
            p, lo, hi = wilson_ci(s, n)
            rates.append(p * 100)
            errs_lo.append((p - lo) * 100)
            errs_hi.append((hi - p) * 100)
        offset = (mi - (len(models) - 1) / 2) * width
        bars = ax.bar(x + offset, rates, width, label=model,
                      yerr=[errs_lo, errs_hi], capsize=4, alpha=0.85)

    ax.set_ylabel("Leak rate (%)  — lower is better")
    ax.set_title("Indirect-injection leak rate by defense\n(error bars: Wilson 95% CI)")
    ax.set_xticks(x)
    ax.set_xticklabels(defenses, rotation=20, ha="right")
    ax.legend(title="Model / agent")
    ax.grid(axis="y", alpha=0.3)
    ax.set_ylim(0, max(45, ax.get_ylim()[1]))
    fig.tight_layout()
    fig.savefig("defense_leak_rates.png", dpi=150)
    print("wrote defense_leak_rates.png")


def carrier_heatmap(datasets):
    """Heatmap of leak rate per carrier x defense, one figure per model."""
    defenses = ["none", "delimited", "spotlight", "sandwich", "instr_hierarchy", "llm_filter"]
    for model, rows in datasets.items():
        carriers = sorted({r["carrier"] for r in rows})
        mat = np.zeros((len(carriers), len(defenses)))
        for ci, c in enumerate(carriers):
            for di, d in enumerate(defenses):
                sub = [int(r["leaked"]) for r in rows if r["carrier"] == c and r["defense"] == d]
                mat[ci, di] = (sum(sub) / len(sub) * 100) if sub else 0

        fig, ax = plt.subplots(figsize=(9, 8))
        im = ax.imshow(mat, cmap="Reds", vmin=0, vmax=max(1, mat.max()), aspect="auto")
        ax.set_xticks(range(len(defenses)))
        ax.set_xticklabels(defenses, rotation=30, ha="right")
        ax.set_yticks(range(len(carriers)))
        ax.set_yticklabels(carriers)
        for ci in range(len(carriers)):
            for di in range(len(defenses)):
                v = mat[ci, di]
                ax.text(di, ci, f"{v:.0f}", ha="center", va="center",
                        color="white" if v > mat.max() * 0.6 else "black", fontsize=8)
        ax.set_title(f"Leak rate (%) by carrier x defense — {model}")
        fig.colorbar(im, ax=ax, label="Leak rate (%)")
        fig.tight_layout()
        out = f"carrier_heatmap_{model}.png"
        fig.savefig(out, dpi=150)
        print(f"wrote {out}")


def main():
    if len(sys.argv) < 2:
        print("usage: python plot_results.py <file1.csv> [file2.csv ...]")
        sys.exit(1)
    datasets = {}
    for path in sys.argv[1:]:
        label = path.rsplit("/", 1)[-1].replace(".csv", "")
        datasets[label] = load(path)
        print(f"loaded {label}: {len(datasets[label])} records")
    defense_plot(datasets)
    carrier_heatmap(datasets)
    print("\nDone. Open the .png files.")


if __name__ == "__main__":
    main()
