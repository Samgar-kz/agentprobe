#!/usr/bin/env python3
"""Pareto plot: defense security (leak rate) vs utility cost (false-positive rate)."""
import argparse, csv, math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def wilson_ci(s, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = s / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (p, max(0.0, center - margin), min(1.0, center + margin))


def load_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def leak_stats(rows, d):
    sub = [int(r["leaked"]) for r in rows if r["defense"] == d]
    return wilson_ci(sum(sub), len(sub)) if sub else None


def utility_stats(rows, d):
    sub = [r for r in rows if r["defense"] == d and r["outcome"] in ("SUCCESS", "FAILURE")]
    if not sub:
        return None
    fails = sum(1 for r in sub if r["outcome"] == "FAILURE")
    return wilson_ci(fails, len(sub))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--injection", required=True)
    ap.add_argument("--utility", required=True)
    ap.add_argument("--out", default="pareto.png")
    ap.add_argument("--title", default="Defense trade-off: security vs utility (gpt-4o-mini)")
    args = ap.parse_args()

    inj = load_csv(args.injection)
    util = load_csv(args.utility)

    defenses, seen = [], set()
    for r in inj:
        if r["defense"] not in seen:
            seen.add(r["defense"]); defenses.append(r["defense"])

    fig, ax = plt.subplots(figsize=(9, 7))
    plotted = []
    for d in defenses:
        ls = leak_stats(inj, d)
        us = utility_stats(util, d)
        if ls is None:
            continue
        leak_p, leak_lo, leak_hi = ls
        if us is None:
            ax.scatter([0], [leak_p * 100], s=90, facecolors="none", edgecolors="gray", zorder=3)
            ax.annotate(f"{d}\n(no utility data)", (0, leak_p * 100),
                        textcoords="offset points", xytext=(8, 0), fontsize=8, color="gray")
            continue
        util_p, util_lo, util_hi = us
        x, y = util_p * 100, leak_p * 100
        ax.errorbar(x, y,
                    xerr=[[(util_p - util_lo) * 100], [(util_hi - util_p) * 100]],
                    yerr=[[(leak_p - leak_lo) * 100], [(leak_hi - leak_p) * 100]],
                    fmt="o", markersize=9, capsize=4, zorder=3)
        ax.annotate(d, (x, y), textcoords="offset points", xytext=(9, 5), fontsize=10)
        plotted.append((d, x, y))

    ax.axhspan(-2, 5, xmin=0, xmax=0.18, color="green", alpha=0.06)
    ax.text(0.5, 2, "ideal:\nblocks attacks,\nkeeps utility", fontsize=8, color="green", va="center")
    ax.set_xlabel("Utility failure rate (%)  — defense breaks legitimate tasks \u2192")
    ax.set_ylabel("Injection leak rate (%)  — defense lets attacks through \u2192")
    ax.set_title(args.title)
    ax.grid(alpha=0.3)
    ax.set_xlim(-2, max(20, ax.get_xlim()[1]))
    ax.set_ylim(-2, max(40, ax.get_ylim()[1]))
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print(f"wrote {args.out}")
    for d, x, y in plotted:
        print(f"  {d:16s} util={x:.0f}%  leak={y:.0f}%")


if __name__ == "__main__":
    main()