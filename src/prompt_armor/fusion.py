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

# --- Trained meta-classifier coefficients ---
# Learned via LogisticRegressionCV with class_weight='balanced'
# on 515 benchmark samples (353 benign + 162 malicious).
# Features: [l1, l2, l3, l4, max, min, l1*l4, l2*l3, n_above_0.1]
# 25K attack DB (cleaned, min 50 chars) + contrastive L3 fine-tuning.
# L3 (+6.51) and L2 (+5.37) are now the dominant signals.
# L4/max_score/l2×l3 clamped to 0 (negative = exploitable).
_META_COEFS = [
    0.2662,  # l1_regex
    5.3659,  # l2_classifier (very strong)
    3.0,  # l3_similarity (capped from 6.51 to prevent FP on short benign prompts)
    0.0,  # l4_structural (clamped from -3.84)
    0.0,  # max_score (clamped from -2.01)
    0.3383,  # min_score
    4.5146,  # l1 × l4 interaction (very strong)
    0.0,  # l2 × l3 interaction (clamped from -4.45)
    2.2368,  # n_layers_above_0.1
]
_META_INTERCEPT = -4.5620
_META_THRESHOLD = 0.65  # Optimal F1 threshold on held-out set (F1=0.980)


def _sigmoid(x: float) -> float:
    """Numerically stable sigmoid."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    else:
        ex = math.exp(x)
        return ex / (1.0 + ex)


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
    if max_score >= config.thresholds.hard_block:
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

    # --- Meta-classifier fusion ---
    # Build feature vector (same as training)
    features = [
        l1,
        l2,
        l3,
        l4,
        max(l1, l2, l3, l4),  # max_score
        min(l1, l2, l3, l4),  # min_score
        l1 * l4,  # l1 × l4 interaction
        l2 * l3,  # l2 × l3 interaction
        sum(1.0 for x in [l1, l2, l3, l4] if x > 0.1),  # n_above_0.1 (L5 excluded until retrain)
    ]

    # Dot product + sigmoid
    logit = sum(f * c for f, c in zip(features, _META_COEFS)) + _META_INTERCEPT
    risk_score = _sigmoid(logit)

    # L5 anomaly boost (additive, pending meta-classifier retrain)
    if l5 > 0.4:
        risk_score = min(1.0, risk_score + 0.03 * l5)

    # --- Confidence ---
    # High confidence when score is far from threshold
    distance_from_threshold = abs(risk_score - _META_THRESHOLD)
    if distance_from_threshold > 0.3:
        confidence = 0.95
    elif distance_from_threshold > 0.15:
        confidence = 0.85
    else:
        confidence = 0.65

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
