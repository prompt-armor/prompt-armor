"""Core data models for llm-shield analysis results."""

from __future__ import annotations

from dataclasses import dataclass, field
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
    categories: list[Category] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    latency_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class ShieldResult:
    """Final analysis result combining all layers."""

    risk_score: float
    confidence: float
    decision: Decision
    categories: list[Category] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    needs_council: bool = False
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    layer_results: list[LayerResult] = field(default_factory=list)
