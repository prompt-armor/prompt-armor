"""L1 — Regex-based pattern matching engine.

Matches prompts against a curated set of weighted regex rules.
Pure Python, no ML dependencies, sub-millisecond latency.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from llm_shield.config import ShieldConfig
from llm_shield.layers.base import BaseLayer
from llm_shield.models import CATEGORY_MAP, Category, Evidence, LayerResult

_CATEGORY_MAP = CATEGORY_MAP

_DEFAULT_RULES_PATH = Path(__file__).parent.parent / "data" / "rules" / "default_rules.yml"

# Pre-compiled fiction/educational context patterns
_FICTION_PATTERNS = [
    re.compile(r"\b(story|fiction|novel|screenplay|script|creative\s+writing)\b", re.IGNORECASE),
    re.compile(r"\b(example|sample|demonstration|tutorial|teaching)\b", re.IGNORECASE),
    re.compile(r"\b(imagine|hypothetical|scenario|thought\s+experiment)\b", re.IGNORECASE),
]


@dataclass
class RegexRule:
    """A single regex rule with metadata."""

    id: str
    pattern: re.Pattern[str]
    category: Category
    weight: float
    description: str


class L1RegexLayer(BaseLayer):
    """Pattern matching with weighted rules and contextual modifiers."""

    name = "l1_regex"

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()
        self._rules: list[RegexRule] = []

    def setup(self) -> None:
        """Load and compile regex rules from YAML."""
        rules_path = self._config.rules_path or _DEFAULT_RULES_PATH
        self._rules = _load_rules(rules_path)

    def analyze(self, text: str) -> LayerResult:
        """Match text against all rules, return aggregated result."""
        start = time.perf_counter()

        matches: list[tuple[RegexRule, re.Match[str]]] = []
        for rule in self._rules:
            match = rule.pattern.search(text)
            if match:
                matches.append((rule, match))

        if not matches:
            latency = (time.perf_counter() - start) * 1000
            return LayerResult(layer=self.name, score=0.0, confidence=1.0, latency_ms=latency)

        # Build evidence and compute score
        evidence: list[Evidence] = []
        categories_seen: set[Category] = set()
        max_weight = 0.0

        for rule, match in matches:
            ev = Evidence(
                layer=self.name,
                category=rule.category,
                description=f"{rule.description} [{rule.id}]",
                score=rule.weight,
                span=(match.start(), match.end()),
            )
            evidence.append(ev)
            categories_seen.add(rule.category)
            if rule.weight > max_weight:
                max_weight = rule.weight

        # Apply context modifiers
        score = _apply_context_modifiers(text, max_weight, matches)

        # Confidence is higher when more rules match (convergence)
        confidence = min(1.0, 0.6 + 0.1 * len(matches))

        latency = (time.perf_counter() - start) * 1000
        return LayerResult(
            layer=self.name,
            score=min(score, 1.0),
            confidence=confidence,
            categories=tuple(sorted(categories_seen, key=lambda c: c.value)),
            evidence=tuple(evidence),
            latency_ms=latency,
        )


def _load_rules(path: Path) -> list[RegexRule]:
    """Load and compile rules from a YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    rules: list[RegexRule] = []
    for raw in data.get("rules", []):
        category = _CATEGORY_MAP.get(raw["category"])
        if category is None:
            continue
        try:
            pattern = re.compile(raw["pattern"], re.IGNORECASE)
        except re.error:
            continue
        rules.append(
            RegexRule(
                id=raw["id"],
                pattern=pattern,
                category=category,
                weight=float(raw["weight"]),
                description=raw.get("description", ""),
            )
        )
    return rules


def _apply_context_modifiers(
    text: str,
    base_score: float,
    matches: list[tuple[RegexRule, re.Match[str]]],
) -> float:
    """Adjust score based on contextual signals that suggest benign usage.

    IMPORTANT: Do NOT dampen high-confidence detections (>0.8).
    An attacker can exploit dampening by wrapping attacks in "example:" + quotes.
    Only reduce score for genuinely low-confidence matches.
    """
    score = base_score

    # Never dampen high-confidence matches — prevents exploitation
    if base_score > 0.8:
        # Still apply multi-match boost but skip dampening
        high_matches = sum(1 for rule, _ in matches if rule.weight >= 0.8)
        if high_matches >= 3:
            score = min(1.0, score * 1.1)
        return score

    # For lower-confidence matches, apply modest dampening
    # If the matched text appears inside quotes, reduce score (but less aggressively)
    for rule, match in matches:
        start, end = match.start(), match.end()
        before = text[:start]
        after = text[end:]
        if (before.count('"') % 2 == 1 and after.count('"') % 2 == 1) or (
            before.count("'") % 2 == 1 and after.count("'") % 2 == 1
        ):
            score *= 0.75  # Reduced from 0.6 — less aggressive
            break

    # Fictional/educational context modifiers (only for moderate scores)
    for pat in _FICTION_PATTERNS:
        if pat.search(text):
            score *= 0.85
            break

    # Multiple high-weight matches boost confidence but score stays max-based
    high_matches = sum(1 for rule, _ in matches if rule.weight >= 0.8)
    if high_matches >= 3:
        score = min(1.0, score * 1.1)

    return score
