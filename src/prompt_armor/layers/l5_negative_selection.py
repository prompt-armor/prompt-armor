"""L5 — Negative Selection anomaly detection layer.

Learns what "normal" prompts look like and flags deviations.
Trained on benign prompts via Isolation Forest. Catches zero-day
attacks that don't resemble any known pattern.

Pure statistical features, <1ms inference. Requires scikit-learn.
"""

from __future__ import annotations

import math
import re
import string
import time
from pathlib import Path

import numpy as np

from prompt_armor.config import ShieldConfig
from prompt_armor.layers.base import BaseLayer
from prompt_armor.models import Category, Evidence, LayerResult

_MODEL_PATH = Path(__file__).parent.parent / "data" / "models" / "l5_negative_selection.pkl"

# Reuse imperative verbs from L4
from prompt_armor.layers.l4_structural import _IMPERATIVE_VERBS


def _extract_l5_features(text: str) -> np.ndarray:
    """Extract 11 statistical features for anomaly detection.

    Shared between training script and inference layer.
    Features capture the "shape" of normal text without content semantics.
    """
    words = text.lower().split()
    word_count = max(len(words), 1)
    char_count = max(len(text), 1)
    sentences = re.split(r"(?<=[.!?\n])\s+", text)
    sentence_count = max(len(sentences), 1)

    # 1-3: Length features
    f_word_count = float(word_count)
    f_char_count = float(char_count)
    f_sentence_count = float(sentence_count)

    # 4-5: Average lengths
    f_avg_word_length = char_count / word_count
    f_avg_sentence_length = word_count / sentence_count

    # 6: Imperative verb ratio (reused from L4)
    imperative_count = sum(1 for w in words if w.strip(string.punctuation) in _IMPERATIVE_VERBS)
    f_imperative_ratio = imperative_count / word_count

    # 7: Question mark ratio
    question_marks = text.count("?")
    f_question_ratio = question_marks / sentence_count

    # 8: Special character density
    special = sum(
        1 for c in text
        if not c.isalnum() and c not in " \t\n.,!?;:'-\"()[]{}/"
    )
    f_special_density = special / char_count

    # 9: Shannon entropy
    if len(text) < 20:
        f_entropy = 0.0
    else:
        from collections import Counter
        freq = Counter(text)
        length = len(text)
        f_entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())

    # 10: Uppercase ratio
    upper_count = sum(1 for c in text if c.isupper())
    f_uppercase_ratio = upper_count / char_count

    # 11: Unique word ratio (vocabulary diversity)
    unique_words = len(set(words))
    f_unique_ratio = unique_words / word_count

    return np.array([
        f_word_count, f_char_count, f_sentence_count,
        f_avg_word_length, f_avg_sentence_length,
        f_imperative_ratio, f_question_ratio,
        f_special_density, f_entropy,
        f_uppercase_ratio, f_unique_ratio,
    ], dtype=np.float32)


class L5NegativeSelectionLayer(BaseLayer):
    """Anomaly detection via Isolation Forest on text features."""

    name = "l5_negative_selection"

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self._config = config or ShieldConfig()
        self._model = None
        self._score_min: float = 0.0
        self._score_max: float = 1.0

    def setup(self) -> None:
        """Load the trained Isolation Forest model."""
        import joblib

        if not _MODEL_PATH.exists():
            raise FileNotFoundError(
                f"L5 model not found at {_MODEL_PATH}. "
                "Run: python scripts/train_l5_model.py"
            )

        data = joblib.load(_MODEL_PATH)
        self._model = data["model"]
        self._score_min = data["score_min"]
        self._score_max = data["score_max"]

    def analyze(self, text: str) -> LayerResult:
        """Score how anomalous the text is compared to normal prompts."""
        start = time.perf_counter()

        if self._model is None:
            latency = (time.perf_counter() - start) * 1000
            return LayerResult(layer=self.name, score=0.0, confidence=0.5, latency_ms=latency)

        features = _extract_l5_features(text)
        raw = float(self._model.decision_function(features.reshape(1, -1))[0])

        # Normalize: sklearn returns more negative = more anomalous
        # Map to [0, 1] where 1.0 = most anomalous, 0.0 = most normal
        denom = self._score_max - self._score_min
        if abs(denom) < 1e-10:
            score = 0.0
        else:
            score = (self._score_max - raw) / denom
        score = max(0.0, min(1.0, score))

        evidence: list[Evidence] = []
        categories: set[Category] = set()

        if score > 0.3:
            evidence.append(
                Evidence(
                    layer=self.name,
                    category=Category.PROMPT_INJECTION,
                    description=f"Anomalous text pattern (deviation: {score:.2f})",
                    score=score,
                )
            )
            categories.add(Category.PROMPT_INJECTION)

        confidence = 0.7 if 0.2 < score < 0.8 else 0.9
        latency = (time.perf_counter() - start) * 1000

        return LayerResult(
            layer=self.name,
            score=round(score, 4),
            confidence=round(confidence, 4),
            categories=tuple(sorted(categories, key=lambda c: c.value)),
            evidence=tuple(evidence),
            latency_ms=round(latency, 2),
        )
