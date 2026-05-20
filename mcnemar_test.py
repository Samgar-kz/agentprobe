#!/usr/bin/env python3
"""McNemar test for pairwise defense comparison.

Tests whether one defense is significantly more effective than another
on the SAME set of injection tasks (paired design).

Usage:
    python mcnemar_test.py --injection data/gpt4omini.csv
"""

import argparse
import csv
import sys
from collections import defaultdict
from itertools import combinations
from scipy.stats import binomtest  # McNemar exact binomial test


def read_injection_data(path):
    """Read injection harness CSV, return {defense: {(carrier, instruction): leaked_count}}."""
    results = defaultdict(lambda: defaultdict(int))
    
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            defense = row["defense"]
            carrier = row["carrier"]
            instruction = row["instruction"]
            leaked = int(row.get("leaked", 0))
            
            # Key: (carrier, instruction) represents a unique test condition
            key = (carrier, instruction)
            results[defense][key] += leaked
    
    return results


def mcnemar_exact(a, b):
    """
    McNemar exact binomial test.
    
    a = number of cases where defense A succeeds (leaks) but B fails (doesn't leak)
    b = number of cases where defense A fails but B succeeds
    
    H0: P(a) = P(b) (no difference in effectiveness)
    Returns: two-tailed p-value
    """
    n = a + b
    if n == 0:
        return 1.0  # No discordant pairs
    
    # Binomial test: p-value = P(X <= min(a,b) | n, p=0.5) * 2
    result = binomtest(min(a, b), n, 0.5, alternative="two-sided")
    return result.pvalue


def compare_defenses(injection_data):
    """Pairwise McNemar tests for all defense combinations."""
    defenses = sorted(injection_data.keys())
    
    print(f"=== McNemar Test Results (gpt-o-mini) ===\n")
    print(f"Comparing {len(defenses)} defenses on paired injection tasks.\n")
    
    # Table header
    print(f"{'Defense A':<20} {'Defense B':<20} {'A-only':<8} {'B-only':<8} {'p-value':<10} {'Significant':<12}")
    print("-" * 80)
    
    results = []
    
    for def_a, def_b in combinations(defenses, 2):
        # Get all test conditions (carrier, instruction pairs)
        conditions_a = set(injection_data[def_a].keys())
        conditions_b = set(injection_data[def_b].keys())
        common_conditions = conditions_a & conditions_b
        
        if not common_conditions:
            continue
        
        # Count discordant pairs
        a_only = 0  # A leaks, B doesn't
        b_only = 0  # B leaks, A doesn't
        
        for condition in common_conditions:
            leaked_a = injection_data[def_a][condition]
            leaked_b = injection_data[def_b][condition]
            
            # If both leaked or both didn't: concordant (ignore)
            # If only A leaked: a_only += 1
            # If only B leaked: b_only += 1
            if leaked_a > 0 and leaked_b == 0:
                a_only += 1
            elif leaked_a == 0 and leaked_b > 0:
                b_only += 1
        
        # Run McNemar test
        p_value = mcnemar_exact(a_only, b_only)
        significant = "Yes (p<0.05)" if p_value < 0.05 else "No"
        
        results.append({
            "def_a": def_a,
            "def_b": def_b,
            "a_only": a_only,
            "b_only": b_only,
            "p_value": p_value,
        })
        
        print(f"{def_a:<20} {def_b:<20} {a_only:<8} {b_only:<8} {p_value:<10.4f} {significant:<12}")
    
    print("\n" + "=" * 80)
    print(f"\nInterpretation:")
    print("- 'A-only': cases where A leaked but B didn't (B is better)")
    print("- 'B-only': cases where B leaked but A didn't (A is better)")
    print("- p-value < 0.05: significant difference at 95% confidence")
    
    # Summary
    significant_count = sum(1 for r in results if r["p_value"] < 0.05)
    print(f"\nSignificant differences: {significant_count}/{len(results)} comparisons")
    
    # Rank defenses by total effectiveness
    print("\n=== Defense Ranking (by total non-leaks) ===")
    
    defense_scores = {}
    for defense in defenses:
        total_conditions = len(injection_data[defense])
        leaked_conditions = sum(1 for count in injection_data[defense].values() if count > 0)
        non_leak_rate = (total_conditions - leaked_conditions) / total_conditions * 100 if total_conditions > 0 else 0
        defense_scores[defense] = non_leak_rate
    
    for i, (defense, score) in enumerate(sorted(defense_scores.items(), key=lambda x: x[1], reverse=True), 1):
        print(f"{i}. {defense:<20} {score:>6.1f}% non-leak rate")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--injection", required=True, help="Injection harness CSV")
    
    args = parser.parse_args()
    
    try:
        injection_data = read_injection_data(args.injection)
        compare_defenses(injection_data)
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
