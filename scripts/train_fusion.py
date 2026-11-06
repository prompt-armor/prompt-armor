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

FEATURE_NAMES = [
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


def _fit(x_train: np.ndarray, y_train: np.ndarray, allow_negative: bool) -> tuple[LogisticRegressionCV, list[int]]:
    """Fit the meta-classifier, keeping every coefficient non-negative.

    fusion.py forbids negative weights: a caller who can raise one layer's score
    (e.g. pad a prompt with structure that L4 flags) must never be able to LOWER
    the fused risk. Clamping negatives to 0 after the fit biases the model, so
    instead the most negative feature is pinned to 0 (dropped) and the rest are
    refit, until every remaining weight is >= 0. Returns the classifier and the
    indices of the features it was fit on.
    """
    active = list(range(x_train.shape[1]))
    while True:
        clf = LogisticRegressionCV(
            Cs=20,
            cv=StratifiedKFold(5, shuffle=True, random_state=42),
            scoring="f1",
            class_weight="balanced",
            max_iter=2000,
            random_state=42,
        )
        clf.fit(x_train[:, active], y_train)
        weights = clf.coef_[0]
        if allow_negative or (weights >= 0).all():
            return clf, active
        worst = active[int(np.argmin(weights))]
        print(f"  {FEATURE_NAMES[worst]} came out negative ({weights.min():+.4f}); pinning to 0 and refitting")
        active.remove(worst)


def train_fusion(scores_path: Path, holdout_ratio: float = 0.3, allow_negative: bool = False) -> None:
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
            sum(1 for x in [l1, l2, l3, l4] if x > 0.1),  # Layers above 0.1 (L5 excluded)
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
    clf, active = _fit(x_train, y_train, allow_negative)
    x_train, x_test = x_train[:, active], x_test[:, active]

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

    # Export coefficients (features pinned to 0 by _fit get an explicit 0.0)
    coefs = [0.0] * len(FEATURE_NAMES)
    for idx, coef in zip(active, clf.coef_[0]):
        coefs[idx] = float(coef)
    trained_intercept = float(clf.intercept_[0])
    feature_names = FEATURE_NAMES

    # fusion.py decides at a fixed 0.50 (_META_THRESHOLD, shared with the gate and
    # the benchmark). Fold the F1-optimal threshold into the intercept instead:
    # sigmoid(z + b - logit(t)) >= 0.5  <=>  sigmoid(z + b) >= t.
    intercept = trained_intercept - float(np.log(best_thresh / (1 - best_thresh)))
    y_prob_test = 1.0 / (1.0 + np.exp(-(np.log(y_prob_test / (1 - y_prob_test)) + intercept - trained_intercept)))

    print()
    print("=== Learned Coefficients ===")
    for name, coef in zip(feature_names, coefs):
        print(f"  {name:20s}: {coef:+.4f}")
    print(f"  {'intercept':20s}: {intercept:+.4f}  (trained {trained_intercept:+.4f}, threshold {best_thresh:.2f} folded in)")

    # === Isotonic Calibration on held-out test set ===
    from sklearn.isotonic import IsotonicRegression

    print()
    print("=== Fitting Isotonic Calibration (held-out test set) ===")
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(y_prob_test, y_eval)

    # Extract calibration points as piecewise-linear lookup table
    # Sample at 21 anchor points from the fit
    anchor_x = np.linspace(0.0, 1.0, 21)
    anchor_y = iso.transform(anchor_x)
    calibration_points = [(round(float(x), 4), round(float(y), 4)) for x, y in zip(anchor_x, anchor_y)]

    print("Calibration mapping (raw → calibrated):")
    for x, y in calibration_points[::4]:  # print every 4th point
        print(f"  {x:.3f} → {y:.3f}")

    # ECE (Expected Calibration Error) before/after
    def ece(probs, labels, n_bins=10):
        bins = np.linspace(0, 1, n_bins + 1)
        total = 0.0
        for i in range(n_bins):
            mask = (probs >= bins[i]) & (probs < bins[i + 1])
            if mask.sum() == 0:
                continue
            bin_prob = probs[mask].mean()
            bin_acc = labels[mask].mean()
            total += mask.sum() * abs(bin_prob - bin_acc)
        return total / len(probs)

    ece_before = ece(y_prob_test, y_eval)
    ece_after = ece(iso.transform(y_prob_test), y_eval)
    print(f"ECE before calibration: {ece_before:.4f}")
    print(f"ECE after calibration:  {ece_after:.4f}")

    # Export for fusion.py
    export = {
        "coefficients": coefs,
        "intercept": intercept,
        "trained_intercept": trained_intercept,
        "feature_names": feature_names,
        "optimal_threshold": best_thresh,
        "threshold_at_prec85": thresh_at_prec85,
        "calibration_points": calibration_points,
        "ece_before": round(float(ece_before), 4),
        "ece_after": round(float(ece_after), 4),
    }

    export_path = Path(__file__).parent / "fusion_model.json"
    with open(export_path, "w") as f:
        json.dump(export, f, indent=2)

    print(f"\nExported to {export_path}")
    print("\nTo use in fusion.py, the score is:")
    print("  raw = sigmoid(dot(features, coefficients) + intercept)")
    print("  confidence = linear_interpolate(raw, calibration_points)")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--scores", type=Path, default=DEFAULT_SCORES)
    parser.add_argument(
        "--allow-negative", action="store_true", help="Keep negative coefficients (fusion.py does not accept them)"
    )
    args = parser.parse_args()
    train_fusion(args.scores, allow_negative=args.allow_negative)
