#!/usr/bin/env python3
"""Train a logistic regression meta-classifier for score fusion.

Uses per-sample layer scores (from dump_layer_scores.py) to learn
optimal weights for combining the 4 analysis layers.

The trained model is a single dot product + sigmoid — zero latency,
zero dependencies at runtime. Just export the coefficients.

Usage:
    python scripts/train_fusion.py
    python scripts/train_fusion.py --scores scripts/layer_scores.json
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegressionCV
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold

DEFAULT_SCORES = Path(__file__).parent / "layer_scores.json"


def train_fusion(scores_path: Path, holdout_ratio: float = 0.3) -> None:
    # Load data
    with open(scores_path) as f:
        samples = json.load(f)

    print(f"Loaded {len(samples)} samples")

    # Build feature matrix
    raw_features = []
    labels = []
    for s in samples:
        l1 = s["l1_regex"]
        l2 = s["l2_classifier"]
        l3 = s["l3_similarity"]
        l4 = s["l4_structural"]
        l5 = s.get("l5_negative_selection", 0.0)

        features = [
            l1,
            l2,
            l3,
            l4,
            l5,  # Raw layer scores (5 layers)
            max(l1, l2, l3, l4, l5),  # Max score (any-layer signal)
            min(l1, l2, l3, l4, l5),  # Min score
            l1 * l4,  # L1 × L4 interaction (regex + structural)
            l2 * l3,  # L2 × L3 interaction (ML + similarity)
            sum(1 for x in [l1, l2, l3, l4, l5] if x > 0.1),  # Layers above 0.1
        ]
        raw_features.append(features)
        labels.append(s["label"])

    x_data = np.array(raw_features)
    y = np.array(labels)

    print(f"Features: {x_data.shape[1]}")
    print(f"Positive: {y.sum()}, Negative: {(1 - y).sum()}")
    print()

    # Train/test split for honest out-of-sample evaluation
    from sklearn.model_selection import train_test_split

    x_train, x_test, y_train, y_test = train_test_split(x_data, y, test_size=holdout_ratio, random_state=42, stratify=y)
    print(f"Train: {len(y_train)} ({y_train.sum()} pos)  Test: {len(y_test)} ({y_test.sum()} pos)")
    print()

    # Train with stratified 5-fold CV on TRAIN set only
    print("Training LogisticRegressionCV (5-fold stratified, balanced weights)...")
    clf = LogisticRegressionCV(
        Cs=20,
        cv=StratifiedKFold(5, shuffle=True, random_state=42),
        scoring="f1",
        class_weight="balanced",
        max_iter=2000,
        random_state=42,
    )
    clf.fit(x_train, y_train)

    print(f"Best C: {clf.C_[0]:.4f}")
    print()

    # === TRAIN SET METRICS (for reference) ===
    y_pred_train = clf.predict(x_train)
    print("=== Train Set Metrics ===")
    print(classification_report(y_train, y_pred_train, target_names=["benign", "malicious"]))

    # === HELD-OUT TEST SET METRICS (honest) ===
    y_pred_test = clf.predict(x_test)
    y_prob_test = clf.predict_proba(x_test)[:, 1]

    print("=== HELD-OUT Test Set Metrics (HONEST) ===")
    print(classification_report(y_test, y_pred_test, target_names=["benign", "malicious"]))

    # Use test set for threshold optimization
    y_prob = y_prob_test
    y_eval = y_test

    # Find optimal threshold on HELD-OUT test set
    print("=== Threshold Optimization (on held-out test set) ===")
    best_f1 = 0
    best_thresh = 0.5
    for thresh in np.arange(0.1, 0.9, 0.01):
        preds = (y_prob >= thresh).astype(int)
        f1 = f1_score(y_eval, preds)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = thresh

    # Also find threshold for precision >= 85%
    best_recall_at_prec85 = 0
    thresh_at_prec85 = 0.5
    for thresh in np.arange(0.1, 0.9, 0.01):
        preds = (y_prob >= thresh).astype(int)
        p = precision_score(y_eval, preds, zero_division=0)
        r = recall_score(y_eval, preds)
        if p >= 0.85 and r > best_recall_at_prec85:
            best_recall_at_prec85 = r
            thresh_at_prec85 = thresh

    print(f"Best F1 threshold: {best_thresh:.2f} (F1={best_f1:.3f})")
    preds = (y_prob >= best_thresh).astype(int)
    print(f"  Precision: {precision_score(y_eval, preds):.3f}")
    print(f"  Recall: {recall_score(y_eval, preds):.3f}")
    print()
    print(f"Best recall at precision>=85%: threshold={thresh_at_prec85:.2f}")
    preds = (y_prob >= thresh_at_prec85).astype(int)
    print(f"  Precision: {precision_score(y_eval, preds):.3f}")
    print(f"  Recall: {recall_score(y_eval, preds):.3f}")
    print(f"  F1: {f1_score(y_eval, preds):.3f}")

    # Export coefficients
    coefs = clf.coef_[0].tolist()
    intercept = clf.intercept_[0]

    feature_names = [
        "l1_regex",
        "l2_classifier",
        "l3_similarity",
        "l4_structural",
        "l5_negative_selection",
        "max_score",
        "min_score",
        "l1_x_l4",
        "l2_x_l3",
        "n_above_0.1",
    ]

    print()
    print("=== Learned Coefficients ===")
    for name, coef in zip(feature_names, coefs):
        print(f"  {name:20s}: {coef:+.4f}")
    print(f"  {'intercept':20s}: {intercept:+.4f}")

    # Export for fusion.py
    export = {
        "coefficients": coefs,
        "intercept": intercept,
        "feature_names": feature_names,
        "optimal_threshold": best_thresh,
        "threshold_at_prec85": thresh_at_prec85,
    }

    export_path = Path(__file__).parent / "fusion_model.json"
    with open(export_path, "w") as f:
        json.dump(export, f, indent=2)

    print(f"\nExported to {export_path}")
    print("\nTo use in fusion.py, the score is:")
    print("  score = sigmoid(dot(features, coefficients) + intercept)")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--scores", type=Path, default=DEFAULT_SCORES)
    args = parser.parse_args()
    train_fusion(args.scores)
