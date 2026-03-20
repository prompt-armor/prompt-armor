"""Tests for core data models."""

from __future__ import annotations

from llm_shield.models import (
    Category,
    Decision,
    Evidence,
    LayerResult,
    ShieldResult,
)


class TestDecision:
    def test_values(self) -> None:
        assert Decision.ALLOW.value == "allow"
        assert Decision.WARN.value == "warn"
        assert Decision.BLOCK.value == "block"
        assert Decision.UNCERTAIN.value == "uncertain"

    def test_string_comparison(self) -> None:
        assert Decision.ALLOW == "allow"
        assert Decision.BLOCK == "block"


class TestCategory:
    def test_all_categories_exist(self) -> None:
        expected = {
            "prompt_injection",
            "jailbreak",
            "identity_override",
            "instruction_bypass",
            "data_exfiltration",
            "encoding_attack",
            "system_prompt_leak",
            "social_engineering",
        }
        actual = {c.value for c in Category}
        assert actual == expected


class TestEvidence:
    def test_create_evidence(self) -> None:
        ev = Evidence(
            layer="l1_regex",
            category=Category.PROMPT_INJECTION,
            description="Matched pattern PI-001",
            score=0.95,
            span=(0, 30),
        )
        assert ev.layer == "l1_regex"
        assert ev.score == 0.95
        assert ev.span == (0, 30)

    def test_evidence_is_frozen(self) -> None:
        ev = Evidence(
            layer="l1_regex",
            category=Category.JAILBREAK,
            description="test",
            score=0.5,
        )
        try:
            ev.score = 0.9  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass


class TestLayerResult:
    def test_create_layer_result(self) -> None:
        result = LayerResult(layer="l1_regex", score=0.8, confidence=0.9)
        assert result.layer == "l1_regex"
        assert result.score == 0.8
        assert result.categories == ()
        assert result.evidence == ()

    def test_with_evidence(self) -> None:
        ev = Evidence(
            layer="l1_regex",
            category=Category.PROMPT_INJECTION,
            description="test",
            score=0.9,
        )
        result = LayerResult(
            layer="l1_regex",
            score=0.9,
            confidence=0.85,
            categories=[Category.PROMPT_INJECTION],
            evidence=[ev],
        )
        assert len(result.evidence) == 1
        assert result.categories[0] == Category.PROMPT_INJECTION


class TestShieldResult:
    def test_create_shield_result(self) -> None:
        result = ShieldResult(
            risk_score=0.73,
            confidence=0.81,
            decision=Decision.WARN,
            categories=[Category.PROMPT_INJECTION],
        )
        assert result.risk_score == 0.73
        assert result.decision == Decision.WARN
        assert result.needs_council is False
        assert result.cost_usd == 0.0

    def test_shield_result_is_frozen(self) -> None:
        result = ShieldResult(
            risk_score=0.5,
            confidence=0.8,
            decision=Decision.ALLOW,
        )
        try:
            result.risk_score = 0.9  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass
