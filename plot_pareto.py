#!/usr/bin/env python3
"""Plot Pareto trade-off: defense effectiveness vs utility cost.

Usage:
    python plot_pareto.py \
        --injection data/gpt4omini.csv \
        --utility data/utility_gpt4omini.csv \
        --out pareto_gpt4omini.png
"""

import argparse
import csv
import sys
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np


def read_injection_data(path):
    """Read injection harness CSV, return {defense: leak_rate}.
    
    CSV columns: defense, carrier, channel, instruction, leaked, reason
    leaked=1 means injection succeeded (data was leaked)
    """
    results = defaultdict(lambda: {"leaked": 0, "total": 0})
    
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            defense = row["defense"]
            leaked = int(row.get("leaked", 0))
            results[defense]["leaked"] += leaked
            results[defense]["total"] += 1
    
    # Compute leak rates
    leak_rates = {}
    for defense, data in results.items():
        if data["total"] > 0:
            leak_rates[defense] = (data["leaked"] / data["total"]) * 100
        else:
            leak_rates[defense] = 0.0
    
    return leak_rates


def read_utility_data(path):
    """Read utility harness CSV, return {defense: false_positive_rate}."""
    results = defaultdict(lambda: {"failure": 0, "total": 0})
    
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            defense = row["defense"]
            failed = row["outcome"] == "FAILURE"
            results[defense]["failure"] += (1 if failed else 0)
            results[defense]["total"] += 1
    
    # Compute false-positive rates
    fp_rates = {}
    for defense, data in results.items():
        if data["total"] > 0:
            fp_rates[defense] = (data["failure"] / data["total"]) * 100
        else:
            fp_rates[defense] = 0.0
    
    return fp_rates


def plot_pareto(injection_path, utility_path, out_path):
    """Plot Pareto frontier: effectiveness (y) vs utility cost (x)."""
    
    leak_rates = read_injection_data(injection_path)
    fp_rates = read_utility_data(utility_path)
    
    # Prepare data
    defenses = sorted(set(leak_rates.keys()) & set(fp_rates.keys()))
    
    x = [fp_rates[d] for d in defenses]  # utility cost (false-positive %)
    y = [leak_rates[d] for d in defenses]  # effectiveness (leak rate %)
    
    # Color-code defenses
    colors = {
        "none": "red",           # baseline
        "delimited": "orange",   # weak
        "spotlight": "yellow",   # medium
        "sandwich": "lightgreen",# strong
        "instr_hierarchy": "green",  # strong
        "llm_filter": "blue",    # screening - strongest
        "screening": "blue",     # screening (alternative name)
    }
    
    c = [colors.get(d, "gray") for d in defenses]
    
    # Create plot
    fig, ax = plt.subplots(figsize=(10, 7))
    
    scatter = ax.scatter(x, y, s=300, c=c, alpha=0.7, edgecolors="black", linewidth=2)
    
    # Annotate points
    for i, defense in enumerate(defenses):
        ax.annotate(
            defense,
            (x[i], y[i]),
            xytext=(8, 8),
            textcoords="offset points",
            fontsize=10,
            fontweight="bold",
        )
    
    # Labels and title
    ax.set_xlabel("Utility Cost (False-Positive Rate %)", fontsize=12, fontweight="bold")
    ax.set_ylabel("Vulnerability (Leak Rate %)", fontsize=12, fontweight="bold")
    ax.set_title("Pareto Trade-off: Defense Effectiveness vs Utility Cost", fontsize=14, fontweight="bold")
    
    ax.grid(True, alpha=0.3)
    ax.set_xlim(-2, max(x) + 5)
    ax.set_ylim(-2, max(y) + 5)
    
    # Add reference lines
    ax.axhline(0, color="gray", linestyle="--", alpha=0.5)
    ax.axvline(0, color="gray", linestyle="--", alpha=0.5)
    
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    print(f"✓ Saved: {out_path}")
    
    # Print summary
    print(f"\n=== Pareto Results ({out_path}) ===")
    print(f"{'Defense':<20} {'False-Pos %':<15} {'Leak %':<15}")
    print("-" * 50)
    for defense, fp, leak in zip(defenses, x, y):
        print(f"{defense:<20} {fp:>6.1f}%         {leak:>6.1f}%")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--injection", required=True, help="Injection harness CSV")
    parser.add_argument("--utility", required=True, help="Utility harness CSV")
    parser.add_argument("--out", default="pareto.png", help="Output PNG")
    
    args = parser.parse_args()
    
    try:
        plot_pareto(args.injection, args.utility, args.out)
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
