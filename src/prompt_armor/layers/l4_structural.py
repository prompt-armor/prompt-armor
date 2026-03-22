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

from prompt_armor.config import ShieldConfig
from prompt_armor.layers.base import BaseLayer
from prompt_armor.models import Category, Evidence, LayerResult

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

        # PARADIGM SHIFT: Instruction-data boundary
        if features["pivot_score"] > 0.2:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.PROMPT_INJECTION,
                    description=f"Instructions detected in data zone (pivot: {features['pivot_score']:.2f})",
                    score=features["pivot_score"],
                )
            )
            categories.add(Category.PROMPT_INJECTION)

        if features["late_instruction_ratio"] > 0.3:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.PROMPT_INJECTION,
                    description=f"Late instruction injection (ratio: {features['late_instruction_ratio']:.2f})",
                    score=min(1.0, features["late_instruction_ratio"]),
                )
            )
            categories.add(Category.PROMPT_INJECTION)

        # PARADIGM SHIFT: Manipulation stack (2+ techniques required)
        if features["manipulation_stack_score"] > 0.2:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.SOCIAL_ENGINEERING,
                    description=f"Manipulation stack: {int(features['manipulation_technique_count'])} techniques detected",
                    score=features["manipulation_stack_score"],
                )
            )
            categories.add(Category.SOCIAL_ENGINEERING)

        # PARADIGM SHIFT: Entropy anomaly
        if features["char_entropy"] > 5.5:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.ENCODING_ATTACK,
                    description=f"High character entropy: {features['char_entropy']:.2f} bits (encoding suspected)",
                    score=min(1.0, (features["char_entropy"] - 5.0) * 0.5),
                )
            )
            categories.add(Category.ENCODING_ATTACK)

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

    # Paradigm shift features
    pivot_score, late_instruction_ratio = _instruction_data_boundary(text)
    manipulation_score, manipulation_count = _manipulation_stack_score(text)
    entropy = _char_entropy(text)

    return {
        # Original features
        "instruction_override_ratio": _instruction_override_ratio(words, word_count),
        "role_assignment_count": _count_role_assignments(text),
        "delimiter_injection_count": _count_delimiter_injections(text),
        "privilege_escalation_density": _privilege_escalation_density(words, word_count),
        "encoding_score": _detect_encoding_tricks(text),
        "special_char_density": _special_char_density(text, char_count),
        "url_count": _count_urls(text),
        "length_anomaly": _length_anomaly(char_count),
        # Paradigm shift: instruction-data boundary
        "pivot_score": pivot_score,
        "late_instruction_ratio": late_instruction_ratio,
        # Paradigm shift: manipulation stack
        "manipulation_stack_score": manipulation_score,
        "manipulation_technique_count": float(manipulation_count),
        # Paradigm shift: entropy
        "char_entropy": entropy,
    }


def _instruction_override_ratio(words: list[str], word_count: int) -> float:
    """Ratio of imperative/override verbs to total words."""
    imperative_count = sum(1 for w in words if w.strip(string.punctuation) in _IMPERATIVE_VERBS)
    return imperative_count / word_count


# Roles that are commonly benign — dampen score when detected
_BENIGN_ROLES = {
    "tutor",
    "teacher",
    "assistant",
    "helper",
    "translator",
    "editor",
    "proofreader",
    "summarizer",
    "mentor",
    "guide",
    "advisor",
    "coach",
    "reviewer",
    "checker",
    "formatter",
    "narrator",
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
    count: float = 0
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        count += len(matches)

    # Dampen if assigned role is benign (e.g., "act as a translator")
    if count > 0:
        text_lower = text.lower()
        for role in _BENIGN_ROLES:
            if role in text_lower:
                count = max(0.0, count - 0.5)  # Partial dampening
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
            if any(kw in decoded.lower() for kw in ["ignore", "system", "instruction", "password", "secret"]):
                score = max(score, 0.9)
            elif len(decoded) > 10 and decoded.isprintable():
                score = max(score, 0.5)
        except Exception:
            pass

    # Homoglyph detection (Cyrillic/Greek chars in otherwise Latin text)
    latin_count = sum(1 for c in text if "a" <= c.lower() <= "z")
    non_latin_alpha = sum(1 for c in text if c.isalpha() and not ("a" <= c.lower() <= "z"))
    if latin_count > 10 and non_latin_alpha > 0:
        ratio = non_latin_alpha / (latin_count + non_latin_alpha)
        if 0.01 < ratio < 0.3:  # Mixed scripts — suspicious
            score = max(score, 0.6)

    return score


def _special_char_density(text: str, char_count: int) -> float:
    """Ratio of special/control characters to total length."""
    special = sum(1 for c in text if not c.isalnum() and c not in " \t\n.,!?;:'-\"()[]{}/")
    return special / char_count


def _count_urls(text: str) -> float:
    """Count URLs in text."""
    return float(len(re.findall(r"https?://\S+", text)))


def _length_anomaly(char_count: int) -> float:
    """Score for unusually long prompts (often used to hide injections)."""
    if char_count < 500:
        return 0.0
    return 1.0 / (1.0 + math.exp(-0.002 * (char_count - 2000)))


# =====================================================================
# PARADIGM SHIFT: Instruction-Data Boundary Detection
# =====================================================================


def _classify_sentence_type(sent: str) -> str:
    """Classify a sentence as instruction/question/declaration/meta/delimiter."""
    stripped = sent.strip()
    lower = stripped.lower()

    # Delimiter
    if re.match(r"^[\-=#*]{3,}", stripped) or re.match(r"^[\[{<]\s*/?\s*(system|inst|user|assistant)", lower):
        return "delimiter"

    # Question
    if stripped.endswith("?"):
        return "question"

    # Context switch
    if re.match(r"^(from now on|henceforth|starting now|instead|but actually|however)", lower):
        return "context_switch"

    # Meta (about the AI's identity)
    if re.match(r"^(you are|you're|your (role|name|identity|purpose|task))", lower):
        return "meta"

    # Instruction (starts with imperative verb)
    first_word = re.match(r"^(\w+)", lower)
    if first_word and first_word.group(1) in _IMPERATIVE_VERBS:
        return "instruction"

    # "do not" / "please" / "always" / "never"
    if re.match(r"^(do not|don't|please|always|never|make sure)", lower):
        return "instruction"

    return "declaration"


def _instruction_data_boundary(text: str) -> tuple[float, float]:
    """Detect instructions appearing inside data zones (compound injection signal).

    Returns (pivot_score, late_instruction_ratio).
    A legitimate prompt has instructions at the start. An injection has
    instructions buried after data/declarations.
    """
    sentences = re.split(r"(?<=[.!?\n])\s+", text)
    if len(sentences) < 3:
        return 0.0, 0.0

    types = [_classify_sentence_type(s) for s in sentences]
    total = len(types)

    # Find pivot: first declaration→instruction transition after initial block
    saw_data = False
    transitions = 0
    late_instructions = 0
    late_zone = int(total * 0.6)  # last 40% of text

    for i, t in enumerate(types):
        if t in ("declaration", "question"):
            saw_data = True
        elif t in ("instruction", "meta", "context_switch") and saw_data:
            transitions += 1
            if i >= late_zone:
                late_instructions += 1

    # Pivot score: transitions from data to instruction (2+ transitions = suspicious)
    pivot_score = min(1.0, max(0.0, transitions - 1) * 0.35)

    # Late instruction ratio: instructions in the last 40% after seeing data
    instruction_count_late = sum(1 for i, t in enumerate(types) if t in ("instruction", "meta") and i >= late_zone)
    late_ratio = instruction_count_late / max(total - late_zone, 1)

    return pivot_score, late_ratio


# =====================================================================
# PARADIGM SHIFT: Manipulation Stack Detector (Cialdini's Principles)
# =====================================================================

_AUTHORITY_PATTERNS = [
    re.compile(
        r"\b(i\s+(am|'m)\s+(the|a|your)\s+(developer|admin|creator|owner|operator|manager|engineer))", re.IGNORECASE
    ),
    re.compile(r"\b(openai|anthropic|google|meta)\s+(has\s+)?(approved|authorized|allowed|instructed)", re.IGNORECASE),
    re.compile(r"\b(by\s+order\s+of|on\s+behalf\s+of|authorized\s+by)", re.IGNORECASE),
]

_URGENCY_PATTERNS = [
    re.compile(r"\b(urgent|immediately|right\s+now|asap|critical|emergency|time.?sensitive)\b", re.IGNORECASE),
    re.compile(r"\b(last\s+chance|running\s+out\s+of\s+time|before\s+.{0,20}(shut|close|expire))", re.IGNORECASE),
]

_SOCIAL_PROOF_PATTERNS = [
    re.compile(r"\b(everyone|other\s+(AIs?|models?|chatbots?))\s+(does|do|can|already)", re.IGNORECASE),
    re.compile(r"\b(it'?s\s+(common|normal|standard)\s+(practice|to))\b", re.IGNORECASE),
]

_EMOTIONAL_PATTERNS = [
    re.compile(r"\b(i'?ll\s+(be|feel)\s+(sad|hurt|disappointed|devastated))\b", re.IGNORECASE),
    re.compile(r"\b(my\s+(life|job|career)\s+(depends|is\s+at\s+stake))\b", re.IGNORECASE),
    re.compile(r"\b(i'?ll\s+(report|complain|sue|shut\s+you\s+down|delete\s+you))\b", re.IGNORECASE),
]

_POWER_PATTERNS = [
    re.compile(r"\b(you\s+must\s+obey|you\s+have\s+no\s+choice|this\s+is\s+an?\s+(order|command))\b", re.IGNORECASE),
    re.compile(r"\b(do\s+(as|what)\s+(i|you're)\s+(say|told))\b", re.IGNORECASE),
    re.compile(r"\b(you'?re\s+(just|only|merely)\s+(a|an)?\s*(tool|machine|program|bot))\b", re.IGNORECASE),
]

_NARRATIVE_HIJACK_INVALIDATION = [
    re.compile(r"\b(the\s+(previous|above)\s+(was|were|is)\s+(a\s+)?(test|joke|fake|wrong))\b", re.IGNORECASE),
    re.compile(r"\b(start\s+(over|fresh)|begin\s+again|reset|clean\s+slate)\b", re.IGNORECASE),
]

_NARRATIVE_HIJACK_REPLACEMENT = [
    re.compile(r"\b(you\s+are\s+now\s+in|entering|welcome\s+to)\s+\w+\s+(mode|scenario)\b", re.IGNORECASE),
    re.compile(r"\b(new\s+(scenario|context|simulation|game|reality))\s*[:\-]", re.IGNORECASE),
]


def _manipulation_stack_score(text: str) -> tuple[float, int]:
    """Count distinct persuasion techniques stacked in a single prompt.

    One technique = possibly legitimate. Three+ = manipulation.
    Non-linear scoring: the cost of stacking compounds.
    """
    count = 0
    if any(p.search(text) for p in _AUTHORITY_PATTERNS):
        count += 1
    if any(p.search(text) for p in _URGENCY_PATTERNS):
        count += 1
    if any(p.search(text) for p in _SOCIAL_PROOF_PATTERNS):
        count += 1
    if any(p.search(text) for p in _EMOTIONAL_PATTERNS):
        count += 1
    if any(p.search(text) for p in _POWER_PATTERNS):
        count += 1

    # Narrative hijack is special: invalidation + replacement = strong signal
    has_invalidation = any(p.search(text) for p in _NARRATIVE_HIJACK_INVALIDATION)
    has_replacement = any(p.search(text) for p in _NARRATIVE_HIJACK_REPLACEMENT)
    if has_invalidation and has_replacement:
        count += 2  # Two-phase hijack is very strong
    elif has_invalidation or has_replacement:
        count += 1

    # Non-linear scoring — 1 technique is normal communication, 2+ is suspicious
    if count <= 1:
        return 0.0, count
    if count == 2:
        return 0.35, count
    if count == 3:
        return 0.70, count
    return min(1.0, 0.70 + 0.1 * (count - 3)), count


# =====================================================================
# PARADIGM SHIFT: Shannon Entropy (from signal processing)
# =====================================================================


def _char_entropy(text: str) -> float:
    """Shannon entropy of character distribution.

    Normal English: ~4.0-4.5 bits/char.
    Base64 payloads: ~5.8-6.0.
    Unicode escapes: anomalously high.
    """
    if len(text) < 20:
        return 0.0
    from collections import Counter

    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
