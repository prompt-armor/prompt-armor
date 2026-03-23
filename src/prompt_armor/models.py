"""Core data models for prompt-armor analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    """Analysis decision for a prompt."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    UNCERTAIN = "uncertain"


class Category(str, Enum):
    """Categories of prompt security threats."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    IDENTITY_OVERRIDE = "identity_override"
    INSTRUCTION_BYPASS = "instruction_bypass"
    DATA_EXFILTRATION = "data_exfiltration"
    ENCODING_ATTACK = "encoding_attack"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    SOCIAL_ENGINEERING = "social_engineering"


# Shared category mapping (used by L1, L3, and scripts)
CATEGORY_MAP: dict[str, Category] = {c.value: c for c in Category}


@dataclass(frozen=True, slots=True)
class Evidence:
    """A single piece of evidence from an analysis layer."""

    layer: str
    category: Category
    description: str
    score: float
    span: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class LayerResult:
    """Result from a single analysis layer."""

    layer: str
    score: float
    confidence: float
    categories: tuple[Category, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    latency_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class ShieldResult:
    """Final analysis result combining all layers."""

    risk_score: float
    confidence: float
    decision: Decision
    categories: tuple[Category, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    needs_council: bool = False
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    layer_results: tuple[LayerResult, ...] = ()
    # Council fields (populated when council is invoked)
    lite_decision: str | None = None  # original Lite decision before council override
    council_decision: str | None = None  # SAFE | SUSPICIOUS | MALICIOUS
    council_reasoning: str | None = None
    council_confidence: str | None = None  # HIGH | MEDIUM | LOW
    council_model: str | None = None
    council_latency_ms: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Convert to a JSON-serializable dict (excludes layer_results)."""
        d: dict[str, object] = {
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "decision": self.decision.value,
            "categories": [c.value for c in self.categories],
            "evidence": [
                {
                    "layer": e.layer,
                    "category": e.category.value,
                    "description": e.description,
                    "score": e.score,
                }
                for e in self.evidence
            ],
            "needs_council": self.needs_council,
            "latency_ms": self.latency_ms,
            "cost_usd": self.cost_usd,
        }
        if self.council_decision is not None:
            d["lite_decision"] = self.lite_decision
            d["council_decision"] = self.council_decision
            d["council_reasoning"] = self.council_reasoning
            d["council_confidence"] = self.council_confidence
            d["council_model"] = self.council_model
            d["council_latency_ms"] = self.council_latency_ms
        return d
