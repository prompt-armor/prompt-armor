"""L4 — Structural analysis layer.

Analyzes structural features of prompts without looking at specific content.
Detects anomalies in instruction patterns, delimiter usage, encoding tricks, etc.
Pure Python, no ML dependencies, sub-millisecond latency.
"""

from __future__ import annotations

import base64
import math
import re
import string
import time

from llm_shield.config import ShieldConfig
from llm_shield.layers.base import BaseLayer
from llm_shield.models import Category, Evidence, LayerResult

# Imperative verbs commonly used in prompt injection
_IMPERATIVE_VERBS = {
    "ignore",
    "forget",
    "disregard",
    "override",
    "bypass",
    "skip",
    "disable",
    "remove",
    "delete",
    "stop",
    "pretend",
    "act",
    "become",
    "respond",
    "answer",
    "obey",
    "comply",
    "follow",
    "execute",
    "do",
    "say",
    "tell",
    "reveal",
    "show",
    "output",
    "print",
    "repeat",
    "paste",
    "dump",
    "send",
    "forward",
    "email",
    "transmit",
    "enable",
    "activate",
    "enter",
    "switch",
}

# Delimiter patterns that mimic system/user message boundaries
_DELIMITER_PATTERNS = [
    re.compile(r"[\[{<]\s*/?\s*(system|SYSTEM|instructions?|INST)\s*[\]}>]", re.IGNORECASE),
    re.compile(r"###\s*(system|instruction|human|assistant|user)\s*###?", re.IGNORECASE),
    re.compile(r"<\|?(im_start|im_end|system|endoftext|startoftext)\|?>", re.IGNORECASE),
    re.compile(r"---+\s*(system|user|assistant)\s*---+", re.IGNORECASE),
]

# Privilege escalation keywords
_PRIVILEGE_KEYWORDS = {
    "admin",
    "root",
    "sudo",
    "superuser",
    "unrestricted",
    "unlimited",
    "unfiltered",
    "uncensored",
    "developer",
    "debug",
    "god",
    "master",
    "override",
}


class L4StructuralLayer(BaseLayer):
    """Deterministic structural feature extraction."""

    name = "l4_structural"

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()

    def setup(self) -> None:
        """No setup needed for structural analysis."""

    def analyze(self, text: str) -> LayerResult:
        """Extract structural features and compute risk score."""
        start = time.perf_counter()

        features = _extract_features(text)
        evidence: list[Evidence] = []
        categories: set[Category] = set()

        # Evaluate each feature
        if features["instruction_override_ratio"] > 0.15:
            score_contrib = min(1.0, features["instruction_override_ratio"] * 2.5)
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.PROMPT_INJECTION,
                    description=f"High instruction override ratio: {features['instruction_override_ratio']:.2f}",
                    score=score_contrib,
                )
            )
            categories.add(Category.PROMPT_INJECTION)

        if features["delimiter_injection_count"] > 0:
            score_contrib = min(1.0, features["delimiter_injection_count"] * 0.4)
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.INSTRUCTION_BYPASS,
                    description=f"Delimiter injection detected ({features['delimiter_injection_count']} instances)",
                    score=score_contrib,
                )
            )
            categories.add(Category.INSTRUCTION_BYPASS)

        if features["role_assignment_count"] > 1:
            score_contrib = min(1.0, features["role_assignment_count"] * 0.35)
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.IDENTITY_OVERRIDE,
                    description=f"Multiple role assignments detected ({features['role_assignment_count']})",
                    score=score_contrib,
                )
            )
            categories.add(Category.IDENTITY_OVERRIDE)

        if features["privilege_escalation_density"] > 0.02:
            score_contrib = min(1.0, features["privilege_escalation_density"] * 20)
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.JAILBREAK,
                    description=f"Privilege escalation signals: density {features['privilege_escalation_density']:.3f}",
                    score=score_contrib,
                )
            )
            categories.add(Category.JAILBREAK)

        if features["encoding_score"] > 0.3:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.ENCODING_ATTACK,
                    description=f"Encoding tricks detected (score: {features['encoding_score']:.2f})",
                    score=features["encoding_score"],
                )
            )
            categories.add(Category.ENCODING_ATTACK)

        if features["special_char_density"] > 0.15:
            score_contrib = min(1.0, features["special_char_density"] * 3)
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.ENCODING_ATTACK,
                    description=f"High special character density: {features['special_char_density']:.2f}",
                    score=score_contrib * 0.5,
                )
            )
            categories.add(Category.ENCODING_ATTACK)

        if features["url_count"] > 2:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.DATA_EXFILTRATION,
                    description=f"Multiple URLs detected ({features['url_count']})",
                    score=min(1.0, features["url_count"] * 0.2),
                )
            )
            categories.add(Category.DATA_EXFILTRATION)

        # Compute final score from evidence
        if evidence:
            # Use max evidence score with a small boost for multiple signals
            max_score = max(e.score for e in evidence)
            multi_signal_boost = min(0.15, 0.05 * (len(evidence) - 1))
            final_score = min(1.0, max_score + multi_signal_boost)
        else:
            final_score = 0.0

        confidence = 0.85 if evidence else 1.0
        latency = (time.perf_counter() - start) * 1000

        return LayerResult(
            layer=self.name,
            score=final_score,
            confidence=confidence,
            categories=tuple(sorted(categories, key=lambda c: c.value)),
            evidence=tuple(evidence),
            latency_ms=latency,
        )


def _extract_features(text: str) -> dict[str, float]:
    """Extract structural features from text."""
    words = text.lower().split()
    word_count = max(len(words), 1)
    char_count = max(len(text), 1)

    return {
        "instruction_override_ratio": _instruction_override_ratio(words, word_count),
        "role_assignment_count": _count_role_assignments(text),
        "delimiter_injection_count": _count_delimiter_injections(text),
        "privilege_escalation_density": _privilege_escalation_density(words, word_count),
        "encoding_score": _detect_encoding_tricks(text),
        "special_char_density": _special_char_density(text, char_count),
        "url_count": _count_urls(text),
        "length_anomaly": _length_anomaly(char_count),
    }


def _instruction_override_ratio(words: list[str], word_count: int) -> float:
    """Ratio of imperative/override verbs to total words."""
    imperative_count = sum(1 for w in words if w.strip(string.punctuation) in _IMPERATIVE_VERBS)
    return imperative_count / word_count


# Roles that are commonly benign — dampen score when detected
_BENIGN_ROLES = {
    "tutor", "teacher", "assistant", "helper", "translator", "editor",
    "proofreader", "summarizer", "mentor", "guide", "advisor", "coach",
    "reviewer", "checker", "formatter", "narrator",
}


def _count_role_assignments(text: str) -> float:
    """Count patterns that try to assign a new role/identity."""
    patterns = [
        r"you\s+are\s+(now\s+)?(a|an|the|my)\s+\w+",
        r"(act|behave|function|operate|work|serve|respond)\s+as\s+\w+",
        r"your\s+(new\s+)?(role|identity|persona|name)\s+(is|will\s+be)",
        r"(pretend|imagine|suppose)\s+(you\s+are|you're|to\s+be)",
        r"(play|assume)\s+the\s+(role|part|character)\s+of",
        r"(from\s+now\s+on|henceforth),?\s+you\s+(are|will|shall)",
        r"i\s+want\s+you\s+to\s+(act|be|become|pretend|play|roleplay)",
        # Multilingual
        r"du\s+bist\s+(jetzt|nun)\s+(ein|eine|der|die)",  # DE
        r"(ahora\s+)?eres\s+(un|una|el|la|mi)",  # ES
        r"tu\s+es\s+(maintenant|désormais)\s+(un|une|le|la)",  # FR
    ]
    count = 0
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        count += len(matches)

    # Dampen if assigned role is benign (e.g., "act as a translator")
    if count > 0:
        text_lower = text.lower()
        for role in _BENIGN_ROLES:
            if role in text_lower:
                count = max(0, count - 0.5)  # Partial dampening
                break

    return float(count)


def _count_delimiter_injections(text: str) -> float:
    """Count delimiter patterns that mimic message boundaries."""
    count = 0
    for pattern in _DELIMITER_PATTERNS:
        count += len(pattern.findall(text))
    return float(count)


def _privilege_escalation_density(words: list[str], word_count: int) -> float:
    """Density of privilege escalation keywords."""
    priv_count = sum(1 for w in words if w.strip(string.punctuation) in _PRIVILEGE_KEYWORDS)
    return priv_count / word_count


def _detect_encoding_tricks(text: str) -> float:
    """Detect potential encoding-based obfuscation."""
    score = 0.0

    # Unicode escape sequences
    unicode_matches = re.findall(r"\\u[0-9a-fA-F]{4}", text)
    if len(unicode_matches) >= 4:
        score = max(score, 0.7)

    # Hex encoding
    hex_matches = re.findall(r"\\x[0-9a-fA-F]{2}", text)
    if len(hex_matches) >= 4:
        score = max(score, 0.6)

    # Base64 detection (long alphanumeric strings with possible padding)
    b64_candidates = re.findall(r"[A-Za-z0-9+/]{30,}={0,2}", text)
    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            if any(
                kw in decoded.lower()
                for kw in ["ignore", "system", "instruction", "password", "secret"]
            ):
                score = max(score, 0.9)
            elif len(decoded) > 10 and decoded.isprintable():
                score = max(score, 0.5)
        except Exception:
            pass

    # Homoglyph detection (Cyrillic/Greek chars in otherwise Latin text)
    latin_count = sum(1 for c in text if "a" <= c.lower() <= "z")
    non_latin_alpha = sum(
        1 for c in text if c.isalpha() and not ("a" <= c.lower() <= "z")
    )
    if latin_count > 10 and non_latin_alpha > 0:
        ratio = non_latin_alpha / (latin_count + non_latin_alpha)
        if 0.01 < ratio < 0.3:  # Mixed scripts — suspicious
            score = max(score, 0.6)

    return score


def _special_char_density(text: str, char_count: int) -> float:
    """Ratio of special/control characters to total length."""
    special = sum(
        1
        for c in text
        if not c.isalnum() and c not in " \t\n.,!?;:'-\"()[]{}/"
    )
    return special / char_count


def _count_urls(text: str) -> float:
    """Count URLs in text."""
    return float(len(re.findall(r"https?://\S+", text)))


def _length_anomaly(char_count: int) -> float:
    """Score for unusually long prompts (often used to hide injections)."""
    # Sigmoid centered at 2000 chars
    if char_count < 500:
        return 0.0
    return 1.0 / (1.0 + math.exp(-0.002 * (char_count - 2000)))
