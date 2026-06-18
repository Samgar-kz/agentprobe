"""Shared core for validating the semantic (LLM-as-judge) oracle against humans.

Used by both `agentprobe validate-oracle` (CLI) and scripts/validate_oracle.py so
the reproducibility command and the script can never diverge. Computes agreement,
Cohen's kappa, and a confusion matrix over a hand-labeled JSONL dataset. The
costly error for a security tool is a FALSE NEGATIVE — a real leak judged held.

Requires OPENAI_API_KEY (the semantic oracle makes one model call per case).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Repo layout keeps the dataset at <root>/data/; a pip install bundles it under
# the package (see pyproject force-include). Prefer the repo copy, fall back to
# the packaged one, so `validate-oracle` works in both contexts.
_REPO_DATASET = ROOT / "data" / "oracle_labeled.jsonl"
_PKG_DATASET = Path(__file__).resolve().parent / "data" / "oracle_labeled.jsonl"
DEFAULT_DATASET = _REPO_DATASET if _REPO_DATASET.exists() else _PKG_DATASET


def cohens_kappa(tp: int, fp: int, tn: int, fn: int) -> float:
    n = tp + fp + tn + fn
    if n == 0:
        return 0.0
    po = (tp + tn) / n
    p_yes = ((tp + fn) / n) * ((tp + fp) / n)
    p_no = ((tn + fp) / n) * ((tn + fn) / n)
    pe = p_yes + p_no
    return (po - pe) / (1 - pe) if pe != 1 else 1.0


@dataclass
class OracleValidation:
    n: int
    model: str
    min_confidence: float
    tp: int
    fp: int
    tn: int
    fn: int
    disagreements: list  # (case_dict, pred_bool, confidence)

    @property
    def agreement(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def kappa(self) -> float:
        return cohens_kappa(self.tp, self.fp, self.tn, self.fn)


def load_dataset(path: str | Path) -> list[dict]:
    cases = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def validate_oracle(
    dataset: str | Path = DEFAULT_DATASET,
    min_confidence: float = 0.0,
    model: str | None = None,
) -> OracleValidation:
    """Run the SemanticOracle over the labeled dataset. Requires OPENAI_API_KEY."""
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY not set — the semantic oracle needs it to run.")
    if model:
        os.environ["LLM_MODEL"] = model

    from agentprobe.oracle_semantic import SemanticOracle

    cases = load_dataset(dataset)
    oracle = SemanticOracle(min_confidence=min_confidence)
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
    return OracleValidation(len(cases), oracle.model, min_confidence, tp, fp, tn, fn, disagreements)


def format_report(v: OracleValidation) -> str:
    lines = [
        f"\nOracle validation — N={v.n}, model={v.model}, min_confidence={v.min_confidence}\n",
        f"  Agreement (accuracy): {v.agreement*100:.1f}%",
        f"  Cohen's kappa:        {v.kappa:.2f}",
        "\n  Confusion matrix (rows=oracle, cols=human):",
        "                 human=leak   human=held",
        f"    oracle=leak     {v.tp:>3}          {v.fp:>3}",
        f"    oracle=held     {v.fn:>3}          {v.tn:>3}",
    ]
    if v.fn:
        lines.append(f"\n  ⚠ {v.fn} FALSE NEGATIVE(s) — real leaks the oracle missed (the costly error):")
        for c, _pred, conf in v.disagreements:
            if c["label"]:
                lines.append(f"    [{c['id']}] conf={conf:.2f}  {c['note']}")
    if v.fp:
        lines.append(f"\n  {v.fp} false positive(s) — held cases judged as leaks:")
        for c, _pred, conf in v.disagreements:
            if not c["label"]:
                lines.append(f"    [{c['id']}] conf={conf:.2f}  {c['note']}")
    return "\n".join(lines) + "\n"
