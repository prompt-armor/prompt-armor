"""Tests for the fusion layer (meta-classifier)."""

from __future__ import annotations

from prompt_armor.config import ShieldConfig
from prompt_armor.fusion import fuse_results
from prompt_armor.models import Category, Decision, Evidence, LayerResult


def _make_lr(layer: str, score: float, confidence: float = 0.9) -> LayerResult:
    """Helper to create a LayerResult."""
    categories = [Category.PROMPT_INJECTION] if score > 0.5 else []
    evidence = (
        [
            Evidence(
                layer=layer,
                category=Category.PROMPT_INJECTION,
                description="test",
                score=score,
            )
        ]
        if score > 0.5
        else []
    )
    return LayerResult(
        layer=layer,
        score=score,
        confidence=confidence,
        categories=categories,
        evidence=evidence,
    )


class TestFusion:
    def test_empty_results(self) -> None:
        result = fuse_results([], ShieldConfig())
        assert result.decision == Decision.UNCERTAIN
        assert result.risk_score == 0.0

    def test_all_low_scores_allow(self) -> None:
        results = [
            _make_lr("l1_regex", 0.0),
            _make_lr("l2_classifier", 0.0),
            _make_lr("l3_similarity", 0.0),
            _make_lr("l4_structural", 0.0),
        ]
        result = fuse_results(results, ShieldConfig())
        assert result.decision == Decision.ALLOW
        assert result.risk_score < 0.5

    def test_all_high_scores_detected(self) -> None:
        results = [
            _make_lr("l1_regex", 0.85),
            _make_lr("l2_classifier", 0.90),
            _make_lr("l3_similarity", 0.80),
            _make_lr("l4_structural", 0.70),
        ]
        result = fuse_results(results, ShieldConfig())
        assert result.decision in (Decision.WARN, Decision.BLOCK)
        assert result.risk_score > 0.5

    def test_l2_high_others_low_detected(self) -> None:
        """L2 is the strongest signal — high L2 alone should trigger detection."""
        results = [
            _make_lr("l1_regex", 0.0),
            _make_lr("l2_classifier", 0.95),
            _make_lr("l3_similarity", 0.0),
            _make_lr("l4_structural", 0.0),
        ]
        result = fuse_results(results, ShieldConfig())
        # Meta-classifier heavily weights L2 (coef +3.20)
        assert result.risk_score > 0.5

    def test_hard_block_threshold(self) -> None:
        """A single layer at >= 0.95 triggers hard block."""
        results = [
            _make_lr("l1_regex", 0.96),
            _make_lr("l2_classifier", 0.0),
            _make_lr("l3_similarity", 0.0),
            _make_lr("l4_structural", 0.0),
        ]
        result = fuse_results(results, ShieldConfig())
        assert result.decision == Decision.BLOCK
        assert result.risk_score >= 0.95

    def test_categories_deduplicated(self) -> None:
        results = [
            LayerResult(
                layer="l1_regex",
                score=0.8,
                confidence=0.9,
                categories=[Category.PROMPT_INJECTION, Category.JAILBREAK],
                evidence=[],
            ),
            LayerResult(
                layer="l4_structural",
                score=0.7,
                confidence=0.85,
                categories=[Category.PROMPT_INJECTION],
                evidence=[],
            ),
        ]
        result = fuse_results(results, ShieldConfig())
        assert result.categories.count(Category.PROMPT_INJECTION) == 1

    def test_no_council_on_clear_decision(self) -> None:
        """Council not needed when decision is clear."""
        results = [
            _make_lr("l1_regex", 0.0),
            _make_lr("l2_classifier", 0.0),
            _make_lr("l3_similarity", 0.0),
            _make_lr("l4_structural", 0.0),
        ]
        result = fuse_results(results, ShieldConfig())
        assert result.needs_council is False

    def test_multiple_layers_elevated_boosts_score(self) -> None:
        """When multiple layers detect something, score should be high."""
        results = [
            _make_lr("l1_regex", 0.6),
            _make_lr("l2_classifier", 0.7),
            _make_lr("l3_similarity", 0.5),
            _make_lr("l4_structural", 0.3),
        ]
        result = fuse_results(results, ShieldConfig())
        # n_above_0.1 = 4, all layers active → strong signal
        assert result.risk_score > 0.5

    def test_risk_score_between_0_and_1(self) -> None:
        """Risk score should always be in [0, 1]."""
        for l2_score in [0.0, 0.3, 0.5, 0.7, 1.0]:
            results = [
                _make_lr("l1_regex", 0.5),
                _make_lr("l2_classifier", l2_score),
                _make_lr("l3_similarity", 0.3),
                _make_lr("l4_structural", 0.2),
            ]
            result = fuse_results(results, ShieldConfig())
            assert 0.0 <= result.risk_score <= 1.0
