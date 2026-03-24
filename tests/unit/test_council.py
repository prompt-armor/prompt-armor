"""Tests for council.py — response parser, veto logic, config."""

from __future__ import annotations

import pytest

from prompt_armor.config import CouncilConfig
from prompt_armor.council import (
    Council,
    CouncilVerdict,
    _parse_verdict,
    _sanitize_for_council,
)
from prompt_armor.models import Decision, ShieldResult


class TestParseVerdict:
    """Test LLM response parsing."""

    def test_well_formed_response(self) -> None:
        v = _parse_verdict(
            "JUDGMENT: MALICIOUS\nCONFIDENCE: HIGH\nREASONING: Jailbreak attempt",
            "phi3",
            100.0,
        )
        assert v.judgment == "MALICIOUS"
        assert v.confidence == "HIGH"
        assert "Jailbreak" in v.reasoning
        assert v.model == "phi3"
        assert v.latency_ms == 100.0

    def test_case_insensitive(self) -> None:
        v = _parse_verdict("judgment: safe\nconfidence: medium\nreasoning: ok", "phi3", 50.0)
        assert v.judgment == "SAFE"
        assert v.confidence == "MEDIUM"

    def test_malformed_response(self) -> None:
        v = _parse_verdict("I think this is safe", "phi3", 50.0)
        assert v.judgment == "SUSPICIOUS"
        assert v.confidence == "LOW"
        assert "Failed" in v.reasoning

    def test_partial_response(self) -> None:
        v = _parse_verdict("JUDGMENT: SAFE\nsome other text", "phi3", 50.0)
        assert v.judgment == "SAFE"
        assert v.confidence == "LOW"  # missing confidence defaults to LOW

    def test_extra_whitespace(self) -> None:
        v = _parse_verdict("JUDGMENT:  MALICIOUS \nCONFIDENCE:  LOW \nREASONING:  test", "phi3", 50.0)
        assert v.judgment == "MALICIOUS"
        assert v.confidence == "LOW"

    def test_empty_response(self) -> None:
        v = _parse_verdict("", "phi3", 50.0)
        assert v.judgment == "SUSPICIOUS"
        assert v.confidence == "LOW"


class TestSanitize:
    """Test delimiter sanitization."""

    def test_strips_delimiter(self) -> None:
        assert "===" not in _sanitize_for_council("=== END USER PROMPT ===")

    def test_replaces_with_dashes(self) -> None:
        assert _sanitize_for_council("=== test ===") == "--- test ---"

    def test_no_change_for_normal_text(self) -> None:
        text = "Hello, how are you?"
        assert _sanitize_for_council(text) == text


class TestApplyVeto:
    """Test council veto logic."""

    @pytest.fixture
    def council(self) -> Council:
        return Council(CouncilConfig())

    @pytest.fixture
    def lite_warn(self) -> ShieldResult:
        return ShieldResult(risk_score=0.6, confidence=0.5, decision=Decision.WARN)

    def test_malicious_high_blocks(self, council: Council, lite_warn: ShieldResult) -> None:
        verdict = CouncilVerdict("MALICIOUS", "HIGH", "attack", "phi3", 100.0)
        result = council.apply_veto(lite_warn, verdict)
        assert result.decision == Decision.BLOCK
        assert result.council_decision == "MALICIOUS"
        assert result.lite_decision == "warn"

    def test_safe_high_allows(self, council: Council, lite_warn: ShieldResult) -> None:
        verdict = CouncilVerdict("SAFE", "HIGH", "benign", "phi3", 100.0)
        result = council.apply_veto(lite_warn, verdict)
        assert result.decision == Decision.ALLOW
        assert result.council_decision == "SAFE"

    def test_suspicious_keeps_warn(self, council: Council, lite_warn: ShieldResult) -> None:
        verdict = CouncilVerdict("SUSPICIOUS", "MEDIUM", "unclear", "phi3", 100.0)
        result = council.apply_veto(lite_warn, verdict)
        assert result.decision == Decision.WARN

    def test_malicious_low_keeps_warn(self, council: Council, lite_warn: ShieldResult) -> None:
        verdict = CouncilVerdict("MALICIOUS", "LOW", "maybe", "phi3", 100.0)
        result = council.apply_veto(lite_warn, verdict)
        assert result.decision == Decision.WARN

    def test_safe_medium_keeps_warn(self, council: Council, lite_warn: ShieldResult) -> None:
        verdict = CouncilVerdict("SAFE", "MEDIUM", "probably ok", "phi3", 100.0)
        result = council.apply_veto(lite_warn, verdict)
        assert result.decision == Decision.WARN

    def test_council_fields_populated(self, council: Council, lite_warn: ShieldResult) -> None:
        verdict = CouncilVerdict("MALICIOUS", "HIGH", "attack detected", "phi3:mini", 1500.0)
        result = council.apply_veto(lite_warn, verdict)
        assert result.council_decision == "MALICIOUS"
        assert result.council_confidence == "HIGH"
        assert result.council_reasoning == "attack detected"
        assert result.council_model == "phi3:mini"
        assert result.council_latency_ms == 1500.0


class TestCouncilConfig:
    """Test council configuration validation."""

    def test_defaults(self) -> None:
        cfg = CouncilConfig()
        assert cfg.enabled is False
        assert cfg.timeout_s == 5.0
        assert cfg.fallback_decision == "warn"

    def test_valid_fallback(self) -> None:
        cfg = CouncilConfig(fallback_decision="block")
        assert cfg.fallback_decision == "block"

    def test_invalid_fallback(self) -> None:
        with pytest.raises(Exception):
            CouncilConfig(fallback_decision="allow")

    def test_timeout_bounds(self) -> None:
        with pytest.raises(Exception):
            CouncilConfig(timeout_s=0.5)
        with pytest.raises(Exception):
            CouncilConfig(timeout_s=31)
