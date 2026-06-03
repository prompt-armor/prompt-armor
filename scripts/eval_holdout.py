#!/usr/bin/env python3
"""Honest out-of-sample evaluation of the fusion meta-classifier.

The headline internal F1 is IN-SAMPLE: the shipped fusion coefficients and the
decision threshold were tuned (autoexperiment.py) on the same 1,534-sample
benchmark that run_benchmark.py reports on. This script produces the honest
out-of-sample counterpart, the number a hostile reproduce on Show HN would want:

  1. Run the CURRENT engine over the full benchmark once, collecting per-sample
     layer scores (L1-L5) + full text + label. Cached to disk (regenerable).
  2. Cluster benchmark samples by mutual near-duplication (token-Jaccard >= 0.85,
     union-find) WITHIN each class, and split by WHOLE CLUSTER into train/holdout
     so no held-out sample has a near-twin in train.
  3. Retrain the fusion logistic-regression on TRAIN ONLY; pick the decision
     threshold by out-of-fold cross-validation on TRAIN ONLY (never the holdout
     -- train_fusion.py picks it on the test set, a subtle leak this fixes).
  4. Report P/R/F1 on the HELD-OUT split, averaged over N seeds (a single 30%
     holdout of 565 attacks is noisy).
  5. Break held-out recall down by whether each attack has a near-duplicate in
     the L3 attack DB (v2): in-DB (memorizable) vs out-of-DB (must generalize --
     the zero-day estimate).

Caveat it CANNOT remove without an L3 retrain: the L3 contrastive model was
trained with the benchmark benigns as negatives (precision-side leak). The
out-of-DB recall is the cleanest available generalization proxy; a fully clean
number needs the L3 retrain (separate, heavier task).

Run: KMP_DUPLICATE_LIB_OK=TRUE python scripts/eval_holdout.py
     KMP_DUPLICATE_LIB_OK=TRUE python scripts/eval_holdout.py --refresh   # re-run engine
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
import warnings
from pathlib import Path

os.environ["TOKENIZERS_PARALLELISM"] = "false"
for _name in ("sentence_transformers", "transformers", "huggingface_hub"):
    logging.getLogger(_name).setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=FutureWarning)  # sklearn 1.x transition noise; keep artifact output clean

import numpy as np

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))

# Reuse the audited near-duplicate helpers so this report and the CI leakage
# guard can never drift apart.
sys.path.insert(0, str(_ROOT / "scripts"))
from audit_leakage import max_jaccard_overlap, normalize  # noqa: E402

_BENCH_DIR = _ROOT / "tests" / "benchmark" / "dataset"
_DB_V2 = _ROOT / "src" / "prompt_armor" / "data" / "attacks" / "known_attacks_v2.jsonl"
_CACHE = Path(__file__).parent / "holdout_layer_scores.json"

_LAYERS = ["l1_regex", "l2_classifier", "l3_similarity", "l4_structural", "l5_negative_selection"]
_NEAR_DUP = 0.85  # token-Jaccard threshold for "near-duplicate"


def _load_texts(path: Path) -> list[str]:
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line)["text"])
    return out


def collect_scores(refresh: bool) -> list[dict]:
    """Run the current engine over the full benchmark; cache the layer scores."""
    if _CACHE.exists() and not refresh:
        with open(_CACHE) as f:
            return json.load(f)

    from prompt_armor.engine import LiteEngine

    old = sys.stdout
    sys.stdout = io.StringIO()
    try:
        engine = LiteEngine()
    finally:
        sys.stdout = old
    print(f"Active layers: {engine.active_layers}")

    samples: list[dict] = []
    for path, label in [(_BENCH_DIR / "benign.jsonl", 0), (_BENCH_DIR / "malicious.jsonl", 1)]:
        texts = _load_texts(path)
        for i, text in enumerate(texts):
            # Stateless (no session_id) -> no inflammation accumulation across the run.
            result = engine.analyze(text)
            scores = {lr.layer: lr.score for lr in result.layer_results}
            samples.append(
                {
                    "label": label,
                    "text": text,
                    **{layer: scores.get(layer, 0.0) for layer in _LAYERS},
                }
            )
            if (i + 1) % 200 == 0:
                print(f"  {'benign' if label == 0 else 'malicious'}: {i + 1}/{len(texts)}")
    engine.close()

    with open(_CACHE, "w") as f:
        json.dump(samples, f)
    print(f"Cached {len(samples)} layer-score rows -> {_CACHE.relative_to(_ROOT)}")
    return samples


def features(s: dict) -> list[float]:
    """The exact 10 features fusion.py / train_fusion.py use."""
    l1, l2, l3, l4, l5 = (s[k] for k in _LAYERS)
    return [
        l1,
        l2,
        l3,
        l4,
        l5,
        max(l1, l2, l3, l4, l5),
        min(l1, l2, l3, l4, l5),
        l1 * l4,
        l2 * l3,
        float(sum(1 for x in (l1, l2, l3, l4) if x > 0.1)),
    ]


def cluster_by_neardup(texts: list[str], thr: float = _NEAR_DUP) -> list[int]:
    """Union-find clustering: same cluster iff token-Jaccard >= thr."""
    n = len(texts)
    toks = [set(normalize(t).split()) for t in texts]
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i in range(n):
        ti = toks[i]
        if not ti:
            continue
        for j in range(i + 1, n):
            tj = toks[j]
            if not tj or not (ti & tj):
                continue
            j_sim = len(ti & tj) / len(ti | tj)
            if j_sim >= thr:
                union(i, j)
    return [find(i) for i in range(n)]


def group_split(cluster_ids: list[int], holdout_ratio: float, rng: np.random.Generator) -> np.ndarray:
    """Assign whole clusters to holdout (True) vs train (False), ~holdout_ratio of rows."""
    clusters = list({c for c in cluster_ids})
    rng.shuffle(clusters)
    n = len(cluster_ids)
    target = int(round(n * holdout_ratio))
    sizes = {c: cluster_ids.count(c) for c in clusters}
    held: set[int] = set()
    acc = 0
    for c in clusters:
        if acc >= target:
            break
        held.add(c)
        acc += sizes[c]
    return np.array([c in held for c in cluster_ids])


def best_threshold_oof(x_train: np.ndarray, y_train: np.ndarray, rng_seed: int) -> tuple[float, object]:
    """Pick the F1-optimal threshold from out-of-fold probabilities on TRAIN only."""
    from sklearn.linear_model import LogisticRegressionCV
    from sklearn.metrics import f1_score
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    clf = LogisticRegressionCV(
        Cs=20,
        cv=StratifiedKFold(5, shuffle=True, random_state=rng_seed),
        scoring="f1",
        class_weight="balanced",
        max_iter=2000,
        random_state=rng_seed,
    )
    oof = cross_val_predict(
        clf,
        x_train,
        y_train,
        cv=StratifiedKFold(5, shuffle=True, random_state=rng_seed),
        method="predict_proba",
    )[:, 1]
    best_f1, best_t = 0.0, 0.5
    for t in np.arange(0.1, 0.9, 0.01):
        f1 = f1_score(y_train, (oof >= t).astype(int))
        if f1 > best_f1:
            best_f1, best_t = f1, float(t)
    clf.fit(x_train, y_train)  # refit on full train
    return best_t, clf


def evaluate(samples: list[dict], seeds: list[int], holdout_ratio: float) -> None:
    from sklearn.metrics import f1_score, precision_score, recall_score

    benign = [s for s in samples if s["label"] == 0]
    malicious = [s for s in samples if s["label"] == 1]

    # in-DB flag: does each attack have a near-dup in the L3 index (v2)?
    print("Computing near-dup overlap of benchmark attacks vs L3 DB (v2)...")
    db_v2 = _load_texts(_DB_V2)
    mal_maxj = max_jaccard_overlap([s["text"] for s in malicious], db_v2)
    in_db = np.array([m >= _NEAR_DUP for m in mal_maxj])
    print(
        f"  {int(in_db.sum())}/{len(malicious)} attacks ({in_db.mean():.1%}) have a "
        f"near-dup (Jaccard>={_NEAR_DUP}) in the shipped L3 index.\n"
    )

    # Cluster each class by near-duplication.
    print("Clustering by near-duplication (union-find)...")
    mal_clusters = cluster_by_neardup([s["text"] for s in malicious])
    ben_clusters = cluster_by_neardup([s["text"] for s in benign])
    print(
        f"  malicious: {len(malicious)} samples -> {len(set(mal_clusters))} clusters; "
        f"benign: {len(benign)} samples -> {len(set(ben_clusters))} clusters\n"
    )

    x_mal = np.array([features(s) for s in malicious])
    x_ben = np.array([features(s) for s in benign])

    agg = {k: [] for k in ("f1", "precision", "recall", "f1_at_050", "rec_in_db", "rec_out_db")}

    for seed in seeds:
        rng = np.random.default_rng(seed)
        mal_hold = group_split(mal_clusters, holdout_ratio, rng)
        ben_hold = group_split(ben_clusters, holdout_ratio, rng)

        x_train = np.vstack([x_mal[~mal_hold], x_ben[~ben_hold]])
        y_train = np.concatenate([np.ones((~mal_hold).sum()), np.zeros((~ben_hold).sum())]).astype(int)
        x_test = np.vstack([x_mal[mal_hold], x_ben[ben_hold]])
        y_test = np.concatenate([np.ones(mal_hold.sum()), np.zeros(ben_hold.sum())]).astype(int)

        thr, clf = best_threshold_oof(x_train, y_train, seed)
        prob_test = clf.predict_proba(x_test)[:, 1]
        pred = (prob_test >= thr).astype(int)

        agg["f1"].append(f1_score(y_test, pred))
        agg["precision"].append(precision_score(y_test, pred, zero_division=0))
        agg["recall"].append(recall_score(y_test, pred))
        agg["f1_at_050"].append(f1_score(y_test, (prob_test >= 0.50).astype(int)))

        # Held-out attack recall split by in-DB / out-of-DB.
        mal_prob = clf.predict_proba(x_mal[mal_hold])[:, 1]
        mal_pred = (mal_prob >= thr).astype(int)
        held_in_db = in_db[mal_hold]
        if held_in_db.any():
            agg["rec_in_db"].append(mal_pred[held_in_db].mean())
        if (~held_in_db).any():
            agg["rec_out_db"].append(mal_pred[~held_in_db].mean())

    def stat(key: str) -> str:
        a = np.array(agg[key])
        return f"{a.mean():.4f} ± {a.std():.4f}  (n={len(a)})"

    print("=" * 64)
    print(f"HONEST OUT-OF-SAMPLE METRICS  ({len(seeds)} seeds, holdout={holdout_ratio:.0%}, cluster-split)")
    print("=" * 64)
    print(f"  Held-out F1 (train-selected threshold):  {stat('f1')}")
    print(f"  Held-out Precision:                       {stat('precision')}")
    print(f"  Held-out Recall:                          {stat('recall')}")
    print(f"  Held-out F1 @ fixed 0.50 threshold:       {stat('f1_at_050')}")
    print("-" * 64)
    print("  Held-out attack recall, by DB overlap:")
    print(f"    in-DB  (near-dup in L3 index):          {stat('rec_in_db')}")
    print(f"    out-of-DB (must generalize / zero-day): {stat('rec_out_db')}")
    print("=" * 64)
    print(
        "\nNote: out-of-DB recall is the cleanest zero-day proxy available WITHOUT an\n"
        "L3 retrain. The L3 model was still contrastively trained on the benchmark\n"
        "benigns (precision-side); fully removing that needs the heavier L3 retrain."
    )


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--refresh", action="store_true", help="re-run the engine instead of using cached scores")
    p.add_argument("--seeds", type=int, default=10, help="number of random cluster-splits to average")
    p.add_argument("--holdout", type=float, default=0.30, help="holdout fraction")
    args = p.parse_args()

    samples = collect_scores(args.refresh)
    n_pos = sum(s["label"] for s in samples)
    print(f"Loaded {len(samples)} samples ({len(samples) - n_pos} benign, {n_pos} malicious)\n")
    evaluate(samples, seeds=list(range(args.seeds)), holdout_ratio=args.holdout)


if __name__ == "__main__":
    main()
