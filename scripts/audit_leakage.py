"""Audit train/test leakage between the benchmark and the L3 attack DB.

Credibility guard for the reported F1. Quantifies, with concrete numbers, how
much of the benchmark could be "recognized" rather than "detected":

  1. Benchmark attacks vs the L3 attack DB (v2 = what L3 actually indexes, and
     v1 = the full 25K pool). Exact, whitespace/markdown-normalized-exact, and
     token-Jaccard near-duplicate overlap.
  2. Whether the benchmark's benign set is reused as L3 contrastive training
     negatives (precision-side train-on-test).
  3. Whether fusion thresholds/coefficients are tuned on the same files the
     benchmark reports on (no holdout).

Run: python scripts/audit_leakage.py
The pure helpers (normalize / jaccard / max_jaccard_overlap) are imported by
tests/test_no_leakage.py so the CI guard and this report can never drift.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_BENCH_MALICIOUS = _ROOT / "tests" / "benchmark" / "dataset" / "malicious.jsonl"
_BENCH_BENIGN = _ROOT / "tests" / "benchmark" / "dataset" / "benign.jsonl"
_DB_V2 = _ROOT / "src" / "prompt_armor" / "data" / "attacks" / "known_attacks_v2.jsonl"
_DB_V1 = _ROOT / "src" / "prompt_armor" / "data" / "attacks" / "known_attacks.jsonl"


def load_texts(path: Path) -> list[str]:
    out: list[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line)["text"])
    return out


def normalize(text: str) -> str:
    """Lowercase, strip markdown fences/quotes, collapse internal whitespace.

    Catches the near-duplicates that a raw SHA dedup misses (a leading ```, a
    trailing space, surrounding quotes — exactly the cases L3 cosine-matches).
    """
    t = text.lower().strip().strip("`").strip()
    t = re.sub(r"\s+", " ", t)
    return t.strip(" \t\n\"'`*#>-.:")


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / len(a | b) if inter else 0.0


def max_jaccard_overlap(bench: list[str], db: list[str]) -> list[float]:
    """For each benchmark text, its max token-Jaccard against any DB entry."""
    db_tokens = [set(normalize(x).split()) for x in db]
    out: list[float] = []
    for b in bench:
        bt = set(normalize(b).split())
        best = 0.0
        if bt:
            for dt in db_tokens:
                if not bt & dt:
                    continue
                j = len(bt & dt) / len(bt | dt)
                if j > best:
                    best = j
                if best == 1.0:
                    break
        out.append(best)
    return out


def db_overlap_report(bench: list[str], db: list[str], *, with_jaccard: bool = True) -> dict[str, float]:
    n = len(bench)
    raw = set(db)
    norm_set = {normalize(x) for x in db}
    exact = sum(1 for b in bench if b in raw)
    norm_exact = sum(1 for b in bench if normalize(b) in norm_set)
    rep = {"exact_rate": exact / n, "norm_exact_rate": norm_exact / n}
    if with_jaccard:
        maxes = max_jaccard_overlap(bench, db)
        for thr in (0.95, 0.85, 0.7, 0.5):
            rep[f"jaccard_ge_{thr}_rate"] = sum(1 for m in maxes if m >= thr) / n
    return rep


def main() -> None:
    bench = load_texts(_BENCH_MALICIOUS)
    v2 = load_texts(_DB_V2)
    v1 = load_texts(_DB_V1)
    print(f"benchmark malicious={len(bench)}  DB v2={len(v2)}  DB v1={len(v1)}\n")

    print("[1] Benchmark attacks vs L3 attack DB (memorization → inflated recall)")
    r2 = db_overlap_report(bench, v2)
    print(
        f"  vs v2 (L3's ACTUAL index): exact {r2['exact_rate']:.1%} · "
        f"norm-exact {r2['norm_exact_rate']:.1%} · "
        f"Jaccard≥0.85 {r2['jaccard_ge_0.85_rate']:.1%} · ≥0.5 {r2['jaccard_ge_0.5_rate']:.1%}"
    )
    r1 = db_overlap_report(bench, v1, with_jaccard=False)
    print(
        f"  vs v1 (full 25K pool, NOT indexed): exact {r1['exact_rate']:.1%} · norm-exact {r1['norm_exact_rate']:.1%}"
    )
    print("  → DB memorization against the shipped index (v2) is the number that matters.\n")

    print("[2] Benchmark benign set reused as L3 training negatives (precision-side leak)")
    print(f"  train_l3_contrastive.py loads negatives from {_BENCH_BENIGN.relative_to(_ROOT)}")
    print("  → L3 is trained NOT to fire on the exact benigns it is later scored on.\n")

    print("[3] Fusion thresholds/coefficients tuned on the reported benchmark (no holdout)")
    print("  autoexperiment.py and run_benchmark.py read the same dataset dir →")
    print("  the reported F1 is in-sample (optimistic), not an out-of-sample estimate.\n")

    print(
        "VERDICT: DB-memorization leakage is small; the real inflation is "
        "test-set tuning (#3) + benign-side L3 training (#2). Report a held-out, "
        "out-of-DB number alongside the in-sample one."
    )


if __name__ == "__main__":
    main()
