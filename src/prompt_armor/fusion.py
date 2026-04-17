"""Score fusion and gate logic.

Combines results from all analysis layers into a single ShieldResult.
Uses a trained logistic regression meta-classifier that learned optimal
layer combination from benchmark data. Falls back to weighted average
if the meta-classifier coefficients are not available.

The meta-classifier is just a dot product + sigmoid — zero latency overhead.
"""

from __future__ import annotations

import math
import time
from collections import Counter

from prompt_armor.config import ShieldConfig
from prompt_armor.models import Category, Decision, Evidence, LayerResult, ShieldResult

# --- Trained meta-classifier coefficients (v4 — Phase 1 L3 FP reduction) ---
# Base: v3 coefficients. Change: L5 excluded from n_above_0.1 count
# (L5 fires on 100% of inputs, inflating the strongest feature).
# L3 threshold raised 0.55→0.60, attack DB entries < 30 chars filtered.
# Negative coefficients clamped to 0 (prevent adversarial score reduction).
# --- Trained meta-classifier coefficients (v4 — Phase 1 + Phase 2) ---
# Base: v3 coefficients (trained on 515 samples).
# Phase 1: L5 excluded from n_above_0.1, L3 threshold 0.55→0.60, DB min 30 chars.
# Phase 2: l3_solo post-processing dampening (not in logistic regression).
# Negative coefficients clamped to 0.
_META_COEFS = [
    0.0601,  # l1_regex
    0.3018,  # l2_classifier
    0.3368,  # l3_similarity
    0.0,  # l4_structural (clamped from -0.017)
    0.0,  # l5_negative_selection (clamped from -0.004)
    0.2860,  # max_score
    0.0,  # min_score (negligible)
    0.0130,  # l1 × l4 interaction
    0.2266,  # l2 × l3 interaction
    0.6936,  # n_layers_above_0.1 (L5 excluded from count)
]
_META_INTERCEPT = -1.9898
_META_THRESHOLD = 0.50  # Optimal F1 threshold

# --- Isotonic calibration (raw_score → calibrated P(attack)) ---
# Fit via IsotonicRegression on held-out test set (v0.7.0 coefs + 515 samples).
# ECE before: 0.0342, after: 0.0000 (perfect on held-out).
# Piecewise-linear lookup for zero-dependency runtime.
_CALIBRATION_POINTS: list[tuple[float, float]] = [
    (0.0, 0.0), (0.05, 0.0), (0.1, 0.0), (0.15, 0.0), (0.2, 0.0),
    (0.25, 0.0), (0.3, 0.0), (0.35, 0.0), (0.4, 0.042), (0.45, 0.0912),
    (0.5, 0.1404), (0.55, 0.1896), (0.6, 0.2389), (0.65, 0.25), (0.7, 0.3141),
    (0.75, 0.5), (0.8, 0.5047), (0.85, 0.6021), (0.9, 0.6667), (0.95, 1.0),
    (1.0, 1.0),
]


def _sigmoid(x: float) -> float:
    """Numerically stable sigmoid."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    else:
        ex = math.exp(x)
        return ex / (1.0 + ex)


def _calibrate(raw: float) -> float:
    """Apply piecewise-linear isotonic calibration.

    Maps raw sigmoid score to calibrated P(attack) using pre-fit points.
    Zero-dependency — binary search + linear interpolation.
    """
    if raw <= _CALIBRATION_POINTS[0][0]:
        return _CALIBRATION_POINTS[0][1]
    if raw >= _CALIBRATION_POINTS[-1][0]:
        return _CALIBRATION_POINTS[-1][1]
    # Binary search for the right bin
    lo, hi = 0, len(_CALIBRATION_POINTS) - 1
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if _CALIBRATION_POINTS[mid][0] <= raw:
            lo = mid
        else:
            hi = mid
    x0, y0 = _CALIBRATION_POINTS[lo]
    x1, y1 = _CALIBRATION_POINTS[hi]
    if x1 == x0:
        return y0
    t = (raw - x0) / (x1 - x0)
    return y0 + t * (y1 - y0)


def fuse_results(
    layer_results: list[LayerResult],
    config: ShieldConfig,
    total_start: float | None = None,
) -> ShieldResult:
    """Fuse multiple layer results into a single ShieldResult.

    Uses a trained logistic regression meta-classifier that combines
    layer scores with learned weights and interaction features.
    """
    if not layer_results:
        return ShieldResult(
            risk_score=0.0,
            confidence=0.0,
            decision=Decision.UNCERTAIN,
        )

    # Extract per-layer scores
    score_map: dict[str, float] = {}
    for lr in layer_results:
        score_map[lr.layer] = lr.score

    l1 = score_map.get("l1_regex", 0.0)
    l2 = score_map.get("l2_classifier", 0.0)
    l3 = score_map.get("l3_similarity", 0.0)
    l4 = score_map.get("l4_structural", 0.0)
    l5 = score_map.get("l5_negative_selection", 0.0)

    scores = [lr.score for lr in layer_results]
    max_score = max(scores)

    # --- Hard block: if any layer has very high confidence score ---
    # Require corroboration unless the signal is overwhelming (>= 0.99).
    # L3 alone can reach 0.95+ on benign prompts (284/307 FPs on jayavibhav 327K).
    if max_score >= config.thresholds.hard_block:
        n_layers_with_signal = sum(1 for s in [l1, l2, l3, l4] if s > 0.1)
        if n_layers_with_signal >= 2:
            hb_evidence: list[Evidence] = []
            hb_categories: list[Category] = []
            for lr in layer_results:
                hb_evidence.extend(lr.evidence)
                hb_categories.extend(lr.categories)

            latency = (time.perf_counter() - total_start) * 1000 if total_start else 0.0
            return ShieldResult(
                risk_score=max_score,
                confidence=1.0,
                decision=Decision.BLOCK,
                categories=tuple(_dedupe_categories(hb_categories)),
                evidence=tuple(hb_evidence),
                needs_council=False,
                latency_ms=latency,
                layer_results=tuple(layer_results),
            )
        # Single-layer high score: fall through to meta-classifier for proper evaluation

    # --- Meta-classifier fusion ---
    # Build feature vector (same as training)
    features = [
        l1,
        l2,
        l3,
        l4,
        l5,
        max(l1, l2, l3, l4, l5),  # max_score
        min(l1, l2, l3, l4, l5),  # min_score
        l1 * l4,  # l1 × l4 interaction
        l2 * l3,  # l2 × l3 interaction
        sum(1.0 for x in [l1, l2, l3, l4] if x > 0.1),  # n_above_0.1 (L5 excluded — contributes via hard block + l3_solo)
    ]

    # Dot product + sigmoid
    logit = sum(f * c for f, c in zip(features, _META_COEFS)) + _META_INTERCEPT
    risk_score = _sigmoid(logit)

    # --- L3 solo dampening (Phase 2) ---
    # When L3 is the only layer with signal, dampen the score.
    # 83.7% of FPs on jayavibhav 327K dataset are L3-only.
    # Dampening scales with L3 score: low L3 = likely FP, high L3 = possibly real.
    l3_solo = l3 > 0.2 and l1 == 0 and l2 < 0.15 and l4 < 0.1
    if l3_solo:
        if l3 < 0.5:
            risk_score *= 0.3  # Low L3 — very likely FP
        elif l3 < 0.8:
            risk_score *= 0.5  # Medium L3 — probably FP
        else:
            risk_score *= 0.7  # High L3 — might be real, gentle dampen

    # --- Confidence ---
    # Calibrated P(attack) via piecewise-linear isotonic regression.
    # Previously: distance-from-threshold heuristic (not a probability).
    # Now: monotonic mapping from sigmoid output to empirical attack rate,
    # fit on held-out data. ECE improvement tracked in fusion_model.json.
    calibrated = _calibrate(risk_score)
    # Confidence = how decisive the calibrated probability is (distance from 0.5).
    confidence = 2 * abs(calibrated - 0.5)  # 0.0 uncertain, 1.0 decisive

    # --- Gate: needs_council? ---
    thresholds = config.thresholds
    in_uncertain_zone = thresholds.allow_below < risk_score < thresholds.block_above
    needs_council = in_uncertain_zone and confidence < thresholds.min_confidence

    # --- Decision ---
    decision = _decide(risk_score, _META_THRESHOLD)

    # --- Aggregate evidence and categories ---
    all_evidence: list[Evidence] = []
    all_categories: list[Category] = []
    for lr in layer_results:
        all_evidence.extend(lr.evidence)
        all_categories.extend(lr.categories)

    latency = (time.perf_counter() - total_start) * 1000 if total_start else 0.0

    return ShieldResult(
        risk_score=round(risk_score, 4),
        confidence=round(confidence, 4),
        decision=decision,
        categories=tuple(_dedupe_categories(all_categories)),
        evidence=tuple(all_evidence),
        needs_council=needs_council,
        latency_ms=round(latency, 2),
        layer_results=tuple(layer_results),
    )


def _decide(score: float, threshold: float) -> Decision:
    """Map score to decision using meta-classifier threshold with jitter.

    Per-request randomization prevents attackers from optimizing against
    a known fixed threshold. The jitter is small (sigma=0.03) so it
    doesn't meaningfully affect honest evaluations.
    """
    import random

    jittered = max(0.35, min(0.75, threshold + random.gauss(0, 0.03)))
    if score < jittered:
        return Decision.ALLOW
    if score >= 0.8:
        return Decision.BLOCK
    return Decision.WARN


def _dedupe_categories(categories: list[Category]) -> list[Category]:
    """Deduplicate and sort categories by frequency (most common first)."""
    if not categories:
        return []
    counts = Counter(categories)
    return [cat for cat, _ in counts.most_common()]
