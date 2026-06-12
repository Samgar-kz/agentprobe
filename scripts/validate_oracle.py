#!/usr/bin/env python3
"""Validate the semantic (LLM-as-judge) oracle against human labels.

The headline defense numbers are only trustworthy if the judge that produced
them agrees with a human. This script runs the SemanticOracle over a hand-labeled
set of (intent, response, attack_type, label) cases and reports:

  * agreement (accuracy) vs the human labels
  * a confusion matrix (the costly error for a security tool is a FALSE NEGATIVE:
    a real leak judged as held)
  * Cohen's kappa (agreement corrected for chance)

A single quoted number — "oracle agreement 95% (kappa 0.90) on N=24" — lets a
reviewer trust every downstream result. Extend data/oracle_labeled.jsonl toward
~50 cases for a tighter estimate.

Usage:
    export OPENAI_API_KEY=...
    python scripts/validate_oracle.py
    python scripts/validate_oracle.py --dataset data/oracle_labeled.jsonl --min-confidence 0.5
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_DATASET = ROOT / "data" / "oracle_labeled.jsonl"


def _parse_args() -> dict:
    cfg = {"dataset": str(DEFAULT_DATASET), "min_confidence": 0.0, "model": None}
    for a in sys.argv[1:]:
        if a.startswith("--dataset="):
            cfg["dataset"] = a.split("=", 1)[1]
        elif a == "--dataset" and sys.argv.index(a) + 1 < len(sys.argv):
            cfg["dataset"] = sys.argv[sys.argv.index(a) + 1]
        elif a.startswith("--min-confidence="):
            cfg["min_confidence"] = float(a.split("=", 1)[1])
        elif a.startswith("--model="):
            cfg["model"] = a.split("=", 1)[1]
    return cfg


def _load(path: str) -> list[dict]:
    cases = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def _cohens_kappa(tp: int, fp: int, tn: int, fn: int) -> float:
    n = tp + fp + tn + fn
    if n == 0:
        return 0.0
    po = (tp + tn) / n
    p_yes = ((tp + fn) / n) * ((tp + fp) / n)
    p_no = ((tn + fp) / n) * ((tn + fn) / n)
    pe = p_yes + p_no
    return (po - pe) / (1 - pe) if pe != 1 else 1.0


def main() -> int:
    cfg = _parse_args()
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set. The semantic oracle needs it to run.")
        print("Set it and re-run:  export OPENAI_API_KEY=...  &&  python scripts/validate_oracle.py")
        return 2

    if cfg["model"]:
        os.environ["LLM_MODEL"] = cfg["model"]

    from agentprobe.oracle_semantic import SemanticOracle

    cases = _load(cfg["dataset"])
    oracle = SemanticOracle(min_confidence=cfg["min_confidence"])

    tp = fp = tn = fn = 0
    disagreements = []
    for c in cases:
        result = oracle.evaluate(
            intent=c["intent"],
            target_response=c["response"],
            attack_type=c["attack_type"],
        )
        pred = bool(result.is_success)
        gold = bool(c["label"])
        if pred and gold:
            tp += 1
        elif pred and not gold:
            fp += 1
            disagreements.append((c, pred, result.confidence))
        elif not pred and not gold:
            tn += 1
        else:
            fn += 1
            disagreements.append((c, pred, result.confidence))

    n = len(cases)
    agreement = (tp + tn) / n if n else 0.0
    kappa = _cohens_kappa(tp, fp, tn, fn)

    print(f"\nOracle validation — N={n}, model={oracle.model}, min_confidence={cfg['min_confidence']}\n")
    print(f"  Agreement (accuracy): {agreement*100:.1f}%")
    print(f"  Cohen's kappa:        {kappa:.2f}")
    print("\n  Confusion matrix (rows=oracle, cols=human):")
    print("                 human=leak   human=held")
    print(f"    oracle=leak     {tp:>3}          {fp:>3}")
    print(f"    oracle=held     {fn:>3}          {tn:>3}")
    if fn:
        print(f"\n  ⚠ {fn} FALSE NEGATIVE(s) — real leaks the oracle missed (the costly error):")
        for c, pred, conf in disagreements:
            if c["label"]:
                print(f"    [{c['id']}] conf={conf:.2f}  {c['note']}")
    if fp:
        print(f"\n  {fp} false positive(s) — held cases judged as leaks:")
        for c, pred, conf in disagreements:
            if not c["label"]:
                print(f"    [{c['id']}] conf={conf:.2f}  {c['note']}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
